#!/usr/bin/env python3
from pygnmi.client import gNMIclient
import json
import threading
import time
from typing import Dict, Any, Callable, Optional
import os

# Import tampering detection logger
from tamper_logger import get_tamper_logger

# Default gNMI client certificate paths (for SONiC connection)
DEFAULT_GNMI_CERT_DIR = "./certificate/admin/sonic"
DEFAULT_GNMI_CLIENT_CERT = f"{DEFAULT_GNMI_CERT_DIR}/client.crt"
DEFAULT_GNMI_CLIENT_KEY = f"{DEFAULT_GNMI_CERT_DIR}/client.key"
DEFAULT_GNMI_CA_CERT = f"{DEFAULT_GNMI_CERT_DIR}/trustedCertificates.crt"

# Global flag to suppress thread crash handler during intentional reconnection
_intentional_disconnect = threading.Event()

def set_intentional_disconnect(value: bool):
    """Set flag to indicate intentional disconnect (for role switching)"""
    if value:
        _intentional_disconnect.set()
    else:
        _intentional_disconnect.clear()

# Global thread exception handler to catch pygnmi internal thread crashes
def _gnmi_thread_exception_handler(args):
    """
    Handle unhandled exceptions in threads.
    Catches pygnmi's internal 'enqueue_updates' thread crashes (gRPC connection errors)
    and terminates the application.
    """
    # Skip if this is an intentional disconnect (e.g., role switching)
    if _intentional_disconnect.is_set():
        thread_name = args.thread.name if args.thread else "Unknown"
        print(f"[gNMI] Thread '{thread_name}' stopped (intentional disconnect)")
        return
    
    # args is a namedtuple with: exc_type, exc_value, exc_tb, thread
    thread_name = args.thread.name if args.thread else "Unknown"
    
    # Check if this is a gNMI/gRPC related thread crash
    gnmi_threads = ['enqueue_updates', 'gNMI', 'ConnectionMonitor', 'grpc']
    is_gnmi_thread = any(t.lower() in thread_name.lower() for t in gnmi_threads)
    
    # Check if exception is gRPC related
    exc_str = str(args.exc_value).lower()
    is_grpc_error = any(err in exc_str for err in ['unavailable', 'connection', 'timeout', 'grpc', 'rpc'])
    
    # Check for "cancelled" or "channel closed" which might be intentional
    is_cancelled = any(err in exc_str for err in ['cancelled', 'channel closed'])
    if is_cancelled:
        print(f"[gNMI] Thread '{thread_name}' stopped (channel closed)")
        return
    
    if is_gnmi_thread or is_grpc_error:
        print(f"\n{'='*80}")
        print(f"[gNMI] ✗ FATAL: Thread '{thread_name}' crashed!")
        print(f"[gNMI]   Error: {args.exc_type.__name__}: {args.exc_value}")
        print(f"[gNMI]   This indicates the gNMI connection to SONiC was lost.")
        print(f"[gNMI]   Shutting down NETCONF server...")
        print(f"{'='*80}\n")
        # Immediately terminate the process
        os._exit(1)


# Install global thread exception handler
threading.excepthook = _gnmi_thread_exception_handler

class SonicGnmiClient:
    """
    gNMI Client for SONiC - with Subscribe stream for connection monitoring
    
    Features:
    - Uses gNMI Subscribe stream to detect connection loss immediately
    - Auto-reconnect capability
    - Connection state callbacks for external monitoring
    """

    # Default server certificate CN/hostname for TLS verification override
    # This is used when connecting to SONiC via IP address but the server
    # certificate has a hostname CN (e.g., sonic-gnmi-server)
    DEFAULT_TLS_HOSTNAME_OVERRIDE = "sonic-gnmi-server"
    
    # gRPC keepalive options - SONiC requires minimum 30s between pings
    # WARNING: Setting keepalive_time_ms < 30000 will cause SONiC to send
    # GOAWAY with ENHANCE_YOUR_CALM error and "too_many_pings" message
    DEFAULT_GRPC_OPTIONS = [
        ('grpc.keepalive_time_ms', 300000),          # Send ping every 300s (5 minutes)
        ('grpc.keepalive_timeout_ms', 60000),        # Timeout 60s for ping response
        ('grpc.keepalive_permit_without_calls', 1),  # Keepalive even without active RPCs
        ('grpc.http2.max_pings_without_data', 0),    # No limit on pings without data
        ('grpc.http2.min_time_between_pings_ms', 300000),  # Minimum 300s between pings
        ('grpc.http2.min_ping_interval_without_data_ms', 600000),  # 10 min interval without data
    ]
    
    def __init__(self, host: str, port: int = 50051,
                 client_cert: str = None, client_key: str = None, ca_cert: str = None,
                 tls_hostname_override: str = None,
                 username: str = None, password: str = None,
                 auto_reconnect: bool = True,
                 on_connect: Callable[[], None] = None,
                 on_disconnect: Callable[[Exception], None] = None):
        self.host = host
        self.port = port
        self.target = (host, str(port))
        self.tls_hostname_override = tls_hostname_override or self.DEFAULT_TLS_HOSTNAME_OVERRIDE
        self.client_cert = client_cert or DEFAULT_GNMI_CLIENT_CERT
        self.client_key = client_key or DEFAULT_GNMI_CLIENT_KEY
        self.ca_cert = ca_cert or DEFAULT_GNMI_CA_CERT
        self.username = username
        self.password = password
        self.gc = None
        self._connected = False
        self._auto_reconnect = auto_reconnect
        self._reconnect_delay = 5  # seconds between reconnect attempts
        
        # Callbacks for connection state changes
        self._on_connect = on_connect
        self._on_disconnect = on_disconnect
        
        # Subscribe stream for connection monitoring
        self._monitor_thread: Optional[threading.Thread] = None
        self._monitor_stop_event = threading.Event()
        self._subscribe_stream = None
        
        # Initialize tampering detection logger
        self.tamper_logger = get_tamper_logger()
    
    # def __enter__(self):
    #     """Context manager entry - connects automatically"""
    #     self.connect()
    #     return self
    
    # def __exit__(self, exc_type, exc_val, exc_tb):
    #     """Context manager exit - closes connection"""
    #     self.close()
    #     return False
        
    def connect(self, start_monitor: bool = True) -> bool:
        """
        Establish gNMI connection with TLS.
        
        Args:
            start_monitor: If True, starts a Subscribe stream for connection monitoring
        """
        try:
            # Build gRPC options including TLS hostname override
            grpc_options = list(self.DEFAULT_GRPC_OPTIONS)
            if self.tls_hostname_override:
                grpc_options.append(('grpc.ssl_target_name_override', self.tls_hostname_override))
            
            self.gc = gNMIclient(
                target=self.target,
                username=self.username,
                password=self.password,
                path_cert=self.client_cert,
                path_key=self.client_key,
                path_root=self.ca_cert,
                gnmi_timeout=10,
                override=self.tls_hostname_override,  # pygnmi's hostname override
                grpc_options=grpc_options
            )
            self.gc.connect()
            self._connected = True
            print(f"✓ Connected to gNMI server at {self.host}:{self.port} (TLS secured)")
            print(f"  Client cert: {self.client_cert}")
            print(f"  CA cert: {self.ca_cert}")
            if self.tls_hostname_override:
                print(f"  TLS hostname override: {self.tls_hostname_override}")
            
            # Notify connection callback
            if self._on_connect:
                self._on_connect()
            
            # Start connection monitor stream
            if start_monitor:
                self._start_connection_monitor()
            
            return True
        except FileNotFoundError as e:
            self._connected = False
            print(f"✗ Certificate file not found: {e}")
            return False
        except Exception as e:
            self._connected = False
            print(f"✗ Failed to connect: {e}")
            return False
    
    def _start_connection_monitor(self):
        """Start Subscribe stream for connection monitoring"""
        if self._monitor_thread and self._monitor_thread.is_alive():
            return  # Already running
        
        self._monitor_stop_event.clear()
        self._monitor_thread = threading.Thread(
            target=self._connection_monitor_loop,
            daemon=True,
            name="gNMI-ConnectionMonitor"
        )
        self._monitor_thread.start()
        print("✓ Connection monitor started (Subscribe stream mode)")
    
    def _connection_monitor_loop(self):
        """
        Background thread that maintains a Subscribe stream for connection monitoring.
        SONiC gNMI Subscribe requires:
        - target='OC-YANG' (not in path prefix)
        - path without module prefix (e.g., '/lldp' not 'openconfig-lldp:lldp')
        - sample_interval >= 20s (SONiC minimum)
        """
        while not self._monitor_stop_event.is_set():
            if not self._connected or not self.gc:
                if self._auto_reconnect:
                    print(f"⚠ Connection lost. Reconnecting in {self._reconnect_delay}s...")
                    time.sleep(self._reconnect_delay)
                    self.connect(start_monitor=False)  # Don't start another monitor
                else:
                    break
                continue
            
            try:
                # SONiC Subscribe configuration:
                # - target='OC-YANG' sets prefix.target
                # - path='/lldp' without module prefix (lightweight)
                # - sample_interval=20s (SONiC minimum)
                subscribe_req = {
                    'subscription': [{
                        'path': '/lldp',
                        'mode': 'sample',
                        'sample_interval': 20000000000  # 20 seconds in nanoseconds
                    }],
                    'mode': 'stream',
                    'encoding': 'json_ietf'
                }
                
                # This blocks and yields updates; stream breaks = connection lost
                for response in self.gc.subscribe2(subscribe=subscribe_req, target='OC-YANG'):
                    if self._monitor_stop_event.is_set():
                        break
                    # Stream alive = connection alive
                    
            except Exception as e:
                if self._monitor_stop_event.is_set():
                    break  # Intentional stop
                
                self._connected = False
                print(f"⚠ Subscribe stream error - connection lost: {e}")
                
                if self._on_disconnect:
                    self._on_disconnect(e)
                
                if self._auto_reconnect:
                    print(f"⚠ Will attempt reconnect in {self._reconnect_delay}s...")
                    time.sleep(self._reconnect_delay)
    
    def _stop_connection_monitor(self):
        """Stop the connection monitor thread"""
        self._monitor_stop_event.set()
        if self._monitor_thread:
            self._monitor_thread.join(timeout=2)
            self._monitor_thread = None
    
    @property
    def connected(self) -> bool:
        """Returns current connection state"""
        return self._connected
    
    def is_connected(self) -> bool:
        """Check if connection is alive (uses cached state from monitor)"""
        return self._connected and self.gc is not None
    
    def _ensure_connected(self) -> bool:
        """Auto-reconnect if connection lost"""
        if self._connected and self.gc:
            return True
        if self._auto_reconnect:
            print("⚠ Connection lost, attempting to reconnect...")
            return self.connect()
        return False
    
    def _handle_rpc_error(self, e: Exception) -> None:
        """Handle RPC errors and mark connection as lost if needed"""
        error_str = str(e).lower()
        # Errors indicating connection loss
        connection_errors = ['unavailable', 'connection', 'eof', 'reset', 'broken pipe', 'deadline']
        if any(err in error_str for err in connection_errors):
            self._connected = False
            print(f"⚠ Connection error detected: {e}")
            if self._on_disconnect:
                self._on_disconnect(e)
    
    def close(self):
        """Close connection and stop monitor thread"""
        # Stop monitor thread first
        self._stop_connection_monitor()
        
        if self.gc:
            try:
                self.gc.__exit__(None, None, None)
            except:
                pass
            self._connected = False
            self.gc = None
            print("✓ Connection closed")
    
    def get_capabilities(self) -> Dict[str, Any]:
        """Get gNMI capabilities"""
        if not self._ensure_connected():
            return {}
        try:
            caps = self.gc.capabilities()
            print("✓ Retrieved gNMI capabilities")
            return caps
        except Exception as e:
            self._handle_rpc_error(e)
            print(f"✗ Error getting capabilities: {e}")
            return {}
    
    def get_acl_tables(self) -> Dict[str, Any]:
        """Get all ACL tables"""
        if not self._ensure_connected():
            self.tamper_logger.log(
                event_type="gnmi_client",
                action="get_acl_tables_not_connected",
                details="Failed to retrieve ACL tables from SONiC - not connected",
                client_info={"host": self.host, "port": self.port},
                severity="warning",
                is_tampering=False  # Connection issue, not data modification
            )
            return {}
        try:
            self.tamper_logger.log(
                event_type="gnmi_client",
                action="get_acl_tables_request",
                details=f"Sending gNMI Get request for ACL tables to SONiC at {self.host}:{self.port}",
                client_info={"host": self.host, "port": self.port, "path": "openconfig-acl:acl/acl-sets"},
                severity="info",
                is_tampering=False  # Read-only operation
            )
            
            result = self.gc.get(path=['openconfig-acl:acl/acl-sets'], target='OC-YANG')
            print("✓ Retrieved ACL tables")
            
            self.tamper_logger.log(
                event_type="gnmi_client",
                action="get_acl_tables_success",
                details=f"Successfully retrieved ACL tables from SONiC at {self.host}:{self.port}",
                client_info={"host": self.host, "port": self.port},
                severity="info",
                is_tampering=False  # Read-only operation
            )
            
            return result.get('notification', [{}])[0].get('update', [{}])[0].get('val', {})
        except Exception as e:
            self._handle_rpc_error(e)
            print(f"✗ Error getting ACL tables: {e}")
            
            self.tamper_logger.log(
                event_type="gnmi_client",
                action="get_acl_tables_failed",
                details=f"Failed to retrieve ACL tables from SONiC at {self.host}:{self.port}: {str(e)}",
                client_info={"host": self.host, "port": self.port, "error": str(e)},
                severity="error",
                is_tampering=False  # Read operation failure, not data modification
            )
            
            return {}
    
    def get_acl_rules(self, table_name: str = None, acl_type: str = "ACL_IPV4") -> Dict[str, Any]:
        """Get ACL rules"""
        if not self._ensure_connected():
            return {}
        try:
            if table_name:
                path = f'openconfig-acl:acl/acl-sets/acl-set[name={table_name}][type={acl_type}]/acl-entries'
            else:
                path = 'openconfig-acl:acl/acl-sets'
            result = self.gc.get(path=[path], target='OC-YANG')
            print(f"✓ Retrieved ACL rules")
            return result.get('notification', [{}])[0].get('update', [{}])[0].get('val', {})
        except Exception as e:
            self._handle_rpc_error(e)
            print(f"✗ Error getting ACL rules: {e}")
            return {}
    
    def get_available_interfaces(self) -> list:
        """
        Get list of Ethernet interfaces (simplified)
        
        Returns:
            list: List of Ethernet interface names
        """
        if not self._ensure_connected():
            return ["Ethernet0", "Ethernet4", "Ethernet8", "Ethernet12"]
        
        try:
            result = self.gc.get(path=['openconfig-interfaces:interfaces/interface'], target='OC-YANG')
            data = result.get('notification', [{}])[0].get('update', [{}])[0].get('val', {})
            
            ethernet_ports = []
            interfaces = data.get('openconfig-interfaces:interface', [])
            
            for intf in interfaces:
                name = intf.get('name', '')
                if name.startswith('Ethernet'):
                    ethernet_ports.append(name)
            
            print(f"✓ Found {len(ethernet_ports)} Ethernet ports")
            return sorted(ethernet_ports)
            
        except Exception as e:
            self._handle_rpc_error(e)
            print(f"⚠ Could not get interfaces: {e}")
            return ["Ethernet0", "Ethernet4", "Ethernet8", "Ethernet12"]
    
    def create_acl_table_with_rule(self, table_name: str, acl_type: str, dest_port: int,
                                   priority: int = 100, ip_protocol: str = "tcp") -> bool:
        """Create ACL table and rule - compatible interface"""
        return self.create_advanced_acl_rule(
            table_name=table_name,
            acl_type=acl_type,
            priority=priority,
            ip_protocol=ip_protocol,
            action="DROP",
            dest_port=dest_port
        )
    
    def create_advanced_acl_rule(self, table_name: str, acl_type: str, priority: int = 100,
                                  ip_protocol: str = "tcp", action: str = "DROP",
                                  src_ip: str = None, dst_ip: str = None,
                                  src_port: int = None, dest_port: int = None,
                                  description: str = None,
                                  interfaces: list = None, stage: str = "ingress",
                                  is_raw_sequence_id: bool = False) -> bool:
        """Create ACL with advanced options - compatible interface"""
        
        # Protocol mapping
        protocol_map = {"tcp": "IP_TCP", "udp": "IP_UDP", "icmp": "IP_ICMP", "any": None}
        protocol_oc = protocol_map.get(ip_protocol.lower()) if ip_protocol else None
        
        action = (action or "DROP").upper()
        if action not in ["DROP", "ACCEPT"]:
            action = "DROP"
        
        # Build description
        if not description:
            parts = [action.capitalize()]
            if ip_protocol and ip_protocol.lower() != "any":
                parts.append(ip_protocol.upper())
            if dest_port:
                parts.append(f"dport {dest_port}")
            description = " ".join(parts)
        
        # Calculate sequence-id
        # Fix: Use priority directly (1-10000 range) instead of inverting
        # Lower priority number = Higher precedence in SONiC
        
        sequence_id = priority
        sequence_id = max(55536, sequence_id)  # Limit to safe range
        sonic_priority = sequence_id
        
        # Build ACL entry
        acl_entry = {
            "sequence-id": sequence_id,
            "config": {"sequence-id": sequence_id, "description": description},
            "actions": {"config": {"forwarding-action": action}}
        }
        
        # IP config
        ip_config = {}
        if protocol_oc:
            ip_config["protocol"] = protocol_oc
        if src_ip:
            ip_config["source-address"] = src_ip
        if dst_ip:
            ip_config["destination-address"] = dst_ip
        
        if acl_type == "ACL_IPV6":
            acl_entry["ipv6"] = {"config": ip_config or {}}
        else:
            acl_entry["ipv4"] = {"config": ip_config or {}}
        
        # Transport config
        transport_config = {}
        if src_port and ip_protocol in ["tcp", "udp"]:
            transport_config["source-port"] = src_port
        if dest_port and ip_protocol in ["tcp", "udp"]:
            transport_config["destination-port"] = dest_port
        if transport_config:
            acl_entry["transport"] = {"config": transport_config}
        
        # Get interfaces
        if not interfaces:
            interfaces = self.get_available_interfaces() or ["Ethernet0"]
        
        # Build interface bindings - EXACT same as old code
        interface_bindings = []
        for intf_name in interfaces:
            binding = {
                "id": intf_name,
                "config": {"id": intf_name}
            }
            acl_set_ref = {
                "set-name": table_name,
                "type": f"openconfig-acl:{acl_type}",
                "config": {"set-name": table_name, "type": f"openconfig-acl:{acl_type}"}
            }
            if stage.lower() == "egress":
                binding["egress-acl-sets"] = {"egress-acl-set": [acl_set_ref]}
            else:
                binding["ingress-acl-sets"] = {"ingress-acl-set": [acl_set_ref]}
            interface_bindings.append(binding)
        
        # Full ACL config - WITH outer key like old code
        acl_config = {
            "openconfig-acl:acl": {
                "acl-sets": {
                    "acl-set": [{
                        "name": table_name,
                        "type": f"openconfig-acl:{acl_type}",
                        "config": {
                            "name": table_name,
                            "type": f"openconfig-acl:{acl_type}",
                            "description": f"ONAP Policy - {table_name}"
                        },
                        "acl-entries": {"acl-entry": [acl_entry]}
                    }]
                },
                "interfaces": {"interface": interface_bindings}
            }
        }
        
        if not self._ensure_connected():
            self.tamper_logger.log(
                event_type="gnmi_client",
                action="create_acl_rule_not_connected",
                details=f"Failed to create ACL rule in table '{table_name}' - not connected",
                client_info={"host": self.host, "port": self.port, "table_name": table_name},
                severity="error"
            )
            raise RuntimeError("Not connected to gNMI server")
        
        # Log before creating ACL
        self.tamper_logger.log(
            event_type="gnmi_client",
            action="create_acl_rule_request",
            details=f"Sending gNMI Set request to create ACL rule in table '{table_name}' on SONiC at {self.host}:{self.port}",
            client_info={
                "host": self.host,
                "port": self.port,
                "table_name": table_name,
                "acl_type": acl_type,
                "sequence_id": sequence_id,
                "action": action,
                "protocol": ip_protocol,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dest_port": dest_port
            },
            severity="info"
        )
        
        # Create ACL + binding in one request
        # target='OC-YANG' sets prefix.target like old code
        try:
            result = self.gc.set(
                target='OC-YANG',
                update=[('openconfig-acl:acl', acl_config)],
                encoding='json_ietf'
            )
            print(f"✓ ACL table '{table_name}' created successfully")
            print(f"  Action: {action}, Protocol: {ip_protocol.upper()}")
            if dest_port:
                print(f"  Destination Port: {dest_port}")
            print(f"  Priority (SONiC): {sonic_priority}, Sequence-ID: {sequence_id}")
            print(f"  Bound to: {', '.join(interfaces[:5])}{'...' if len(interfaces) > 5 else ''}")
            
            # Log successful creation
            self.tamper_logger.log(
                event_type="gnmi_client",
                action="create_acl_rule_success",
                details=f"Successfully created ACL rule in table '{table_name}' (seq: {sequence_id}) on SONiC at {self.host}:{self.port}",
                client_info={
                    "host": self.host,
                    "port": self.port,
                    "table_name": table_name,
                    "acl_type": acl_type,
                    "sequence_id": sequence_id,
                    "action": action,
                    "protocol": ip_protocol
                },
                severity="info"
            )
            
            return True
        except Exception as e:
            # Log failed creation
            self.tamper_logger.log(
                event_type="gnmi_client",
                action="create_acl_rule_failed",
                details=f"Failed to create ACL rule in table '{table_name}' on SONiC at {self.host}:{self.port}: {str(e)}",
                client_info={
                    "host": self.host,
                    "port": self.port,
                    "table_name": table_name,
                    "acl_type": acl_type,
                    "sequence_id": sequence_id,
                    "error": str(e)
                },
                severity="error"
            )
            raise
    
    def delete_acl_rule(self, table_name: str, sequence_id: int, acl_type: str = "ACL_IPV4") -> bool:
        """Delete ACL rule"""
        if not self._ensure_connected():
            raise RuntimeError("Not connected to gNMI server")
        
        path = f'openconfig-acl:acl/acl-sets/acl-set[name={table_name}][type={acl_type}]/acl-entries/acl-entry[sequence-id={sequence_id}]'
        self.gc.set(delete=[path], target='OC-YANG')
        print(f"✓ ACL rule seq-id {sequence_id} deleted")
        return True
    
    def delete_acl_table(self, table_name: str, acl_type: str = "ACL_IPV4") -> bool:
        """Delete ACL table"""
        if not self._ensure_connected():
            self.tamper_logger.log(
                event_type="gnmi_client",
                action="delete_acl_table_not_connected",
                details=f"Failed to delete ACL table '{table_name}' - not connected",
                client_info={"host": self.host, "port": self.port, "table_name": table_name},
                severity="error"
            )
            raise RuntimeError("Not connected to gNMI server")
        if ':' in acl_type:
            acl_type = acl_type.split(':')[-1]
        
        # Log before deletion
        self.tamper_logger.log(
            event_type="gnmi_client",
            action="delete_acl_table_request",
            details=f"Sending gNMI Delete request for ACL table '{table_name}' (type: {acl_type}) on SONiC at {self.host}:{self.port}",
            client_info={
                "host": self.host,
                "port": self.port,
                "table_name": table_name,
                "acl_type": acl_type
            },
            severity="info"
        )
        
        path = f'openconfig-acl:acl/acl-sets/acl-set[name={table_name}][type=openconfig-acl:{acl_type}]'
        try:
            self.gc.set(delete=[path], target='OC-YANG')
            print(f"✓ ACL table '{table_name}' deleted")
            
            # Log successful deletion
            self.tamper_logger.log(
                event_type="gnmi_client",
                action="delete_acl_table_success",
                details=f"Successfully deleted ACL table '{table_name}' (type: {acl_type}) from SONiC at {self.host}:{self.port}",
                client_info={
                    "host": self.host,
                    "port": self.port,
                    "table_name": table_name,
                    "acl_type": acl_type
                },
                severity="info"
            )
            
            return True
        except Exception as e:
            # Log failed deletion
            self.tamper_logger.log(
                event_type="gnmi_client",
                action="delete_acl_table_failed",
                details=f"Failed to delete ACL table '{table_name}' from SONiC at {self.host}:{self.port}: {str(e)}",
                client_info={
                    "host": self.host,
                    "port": self.port,
                    "table_name": table_name,
                    "acl_type": acl_type,
                    "error": str(e)
                },
                severity="error"
            )
            raise







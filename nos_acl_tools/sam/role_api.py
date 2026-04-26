#!/usr/bin/env python3
"""
Simple HTTP API for Runtime Role Switching & Policy Management

Provides REST endpoints to:
- View/switch current SONiC role
- View/update ONAP→SONiC role mapping policies
- Get role status

Runs on a separate port alongside NETCONF server.
"""

import json
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Optional, Callable
from sam.role_policy import SonicRole, OnapRole, get_policy_engine, RolePolicyEngine

# Optional imports for backward compatibility
try:
    from service_account import ServiceAccount, get_service_account, RoleChangeEvent
except ImportError:
    ServiceAccount = None
    get_service_account = None
    RoleChangeEvent = None

try:
    from session_context import get_session_manager, SessionContextManager
except ImportError:
    get_session_manager = None
    SessionContextManager = None

try:
    from gnmi_pool import get_gnmi_pool, GnmiConnectionPool
except ImportError:
    get_gnmi_pool = None
    GnmiConnectionPool = None

try:
    from tamper_logger import get_tamper_logger
except ImportError:
    get_tamper_logger = None


class RoleAPIHandler(BaseHTTPRequestHandler):
    """HTTP request handler for role and policy management API"""
    
    # Reference to service account (set by server) - for single-client mode
    service_account = None
    # Reference to policy engine (set by server)
    policy_engine: RolePolicyEngine = None
    # Reference to session manager (set by server) - for multi-client mode
    session_manager = None
    # Reference to gNMI pool (set by server) - for multi-client mode
    gnmi_pool = None
    # Callback for gNMI reconnection (set by server)
    on_reconnect_gnmi: Callable[[], bool] = None
    
    def log_message(self, format, *args):
        """Override to add API prefix to logs"""
        print(f"[RoleAPI] {args[0]}")
    
    def _send_json(self, data: dict, status: int = 200):
        """Send JSON response"""
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(json.dumps(data, indent=2).encode())
    
    def _send_error(self, message: str, status: int = 400):
        """Send error response"""
        self._send_json({"error": message, "success": False}, status)
    
    def _read_json_body(self) -> Optional[dict]:
        """Read JSON from request body"""
        try:
            content_length = int(self.headers.get('Content-Length', 0))
            if content_length > 0:
                body = self.rfile.read(content_length)
                return json.loads(body.decode())
        except:
            pass
        return None
    
    def do_OPTIONS(self):
        """Handle CORS preflight"""
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()
    
    def do_GET(self):
        """Handle GET requests"""
        # ============ Role Endpoints ============
        if self.path == '/role' or self.path == '/role/':
            if not self.service_account:
                self._send_error("Service account not initialized", 500)
                return
            status = self.service_account.get_status()
            self._send_json({
                "success": True,
                "current_role": status["sonic_role"],
                "onap_role": status["onap_role"],
                "allowed_roles": status["allowed_roles"],
                "credentials_exist": status["credentials"]["exists"]
            })
        
        elif self.path == '/role/status':
            if not self.service_account:
                self._send_error("Service account not initialized", 500)
                return
            self._send_json({
                "success": True,
                **self.service_account.get_status()
            })
        
        # ============ Policy Endpoints ============
        elif self.path == '/policy' or self.path == '/policy/':
            # Get all policies
            if not self.policy_engine:
                self._send_error("Policy engine not initialized", 500)
                return
            self._send_json({
                "success": True,
                "policies": self.policy_engine.get_all_policies(),
                "description": {
                    "admin": "ONAP admin role - typically full access",
                    "operator": "ONAP operator role - limited access"
                }
            })
        
        elif self.path.startswith('/policy/'):
            # Get specific policy: GET /policy/{onap_role}
            if not self.policy_engine:
                self._send_error("Policy engine not initialized", 500)
                return
            
            role_str = self.path.split('/')[-1].lower()
            try:
                onap_role = OnapRole(role_str)
            except ValueError:
                self._send_error(f"Invalid ONAP role: {role_str}. Valid: admin, operator", 400)
                return
            
            policy = self.policy_engine.get_policy(onap_role)
            if policy:
                self._send_json({
                    "success": True,
                    **policy.to_dict()
                })
            else:
                self._send_error(f"No policy found for {role_str}", 404)
        
        # ============ Session Endpoints (Multi-Client Mode) ============
        elif self.path == '/sessions' or self.path == '/sessions/':
            # Get all active sessions
            if self.session_manager:
                sessions = self.session_manager.get_all_sessions()
                self._send_json({
                    "success": True,
                    "count": len(sessions),
                    "sessions": sessions
                })
            else:
                self._send_json({
                    "success": True,
                    "mode": "single-client",
                    "message": "Session manager not available (single-client mode)"
                })
        
        # ============ gNMI Pool Endpoints ============
        elif self.path == '/pool' or self.path == '/pool/':
            # Get gNMI pool status
            if self.gnmi_pool:
                self._send_json({
                    "success": True,
                    **self.gnmi_pool.get_status()
                })
            else:
                self._send_json({
                    "success": True,
                    "mode": "single-client",
                    "message": "gNMI pool not available (single-client mode)"
                })
        
        # ============ Interface Endpoints ============
        elif self.path == '/interfaces' or self.path == '/interfaces/':
            # Get available interfaces from SONiC (Ethernet ports only)
            if self.gnmi_pool:
                # Get any available gNMI client from the pool
                gnmi_client = self.gnmi_pool.get_any_client()
                if gnmi_client:
                    # Log to tampering detection
                    if get_tamper_logger:
                        tamper_logger = get_tamper_logger()
                        tamper_logger.log(
                            event_type="gnmi",
                            action="get_interfaces",
                            details="Querying available Ethernet interfaces from SONiC",
                            client_info={"endpoint": "/interfaces"},
                            severity="info"
                        )
                    
                    ethernet_ports = gnmi_client.get_available_interfaces()
                    self._send_json({
                        "success": True,
                        "ethernet_ports": ethernet_ports,
                        "count": len(ethernet_ports)
                    })
                else:
                    self._send_error("No gNMI connection available", 503)
            else:
                self._send_error("gNMI pool not available", 503)
        
        elif self.path == '/health':
            self._send_json({
                "status": "ok",
                "service": "role-api",
                "mode": "multi-client" if self.session_manager else "single-client"
            })
        
        # ============ Tampering Detection Log Endpoints ============
        elif self.path == '/api/logs' or self.path == '/api/logs/':
            # Get logs with optional filtering
            if get_tamper_logger:
                tamper_logger = get_tamper_logger()
                
                # Parse query parameters
                from urllib.parse import urlparse, parse_qs
                query_params = parse_qs(urlparse(self.path).query) if '?' in self.path else {}
                
                limit = int(query_params.get('limit', [None])[0]) if 'limit' in query_params else None
                event_type = query_params.get('event_type', [None])[0] if 'event_type' in query_params else None
                severity = query_params.get('severity', [None])[0] if 'severity' in query_params else None
                
                logs = tamper_logger.get_logs(limit=limit, event_type=event_type, severity=severity)
                
                self._send_json({
                    "success": True,
                    "count": len(logs),
                    "logs": logs
                })
            else:
                self._send_error("Tampering detection logger not available", 500)
        
        elif self.path == '/api/logs/tampering':
            # Get tampering events
            if get_tamper_logger:
                tamper_logger = get_tamper_logger()
                logs = tamper_logger.get_tampering_events(from_file=True)
                
                self._send_json({
                    "success": True,
                    "count": len(logs),
                    "logs": logs
                })
            else:
                self._send_error("Tampering detection logger not available", 500)
        
        elif self.path == '/api/logs/stats':
            # Get log statistics
            if get_tamper_logger:
                tamper_logger = get_tamper_logger()
                all_logs = tamper_logger.get_logs(from_file=True)
                
                # Count by event type
                event_counts = {}
                severity_counts = {}
                
                for log in all_logs:
                    event_type = log["event_type"]
                    severity = log["severity"]
                    
                    event_counts[event_type] = event_counts.get(event_type, 0) + 1
                    severity_counts[severity] = severity_counts.get(severity, 0) + 1
                
                # Count errors (severity = error or critical)
                error_count = severity_counts.get("error", 0) + severity_counts.get("critical", 0)
                
                self._send_json({
                    "success": True,
                    "total_logs": len(all_logs),
                    "by_event_type": event_counts,
                    "by_severity": severity_counts,
                    "tampering_events": len(tamper_logger.get_tampering_events(from_file=True)),
                    "errors": error_count
                })
            else:
                self._send_error("Tampering detection logger not available", 500)
        
        else:
            self._send_error("Not found", 404)
    
    def do_POST(self):
        """Handle POST requests"""
        # ============ Role Switch Endpoints ============
        if self.path.startswith('/role/switch/'):
            if not self.service_account:
                self._send_error("Service account not initialized", 500)
                return
            
            new_role_str = self.path.split('/')[-1].lower()
            try:
                new_role = SonicRole(new_role_str)
            except ValueError:
                self._send_error(f"Invalid role: {new_role_str}. Valid: admin, operator", 400)
                return
            
            event = self.service_account.switch_role(new_role)
            
            if event.success:
                reconnect_success = True
                if self.on_reconnect_gnmi:
                    print("[RoleAPI] Triggering gNMI reconnection with new credentials...")
                    reconnect_success = self.on_reconnect_gnmi()
                
                self._send_json({
                    "success": True,
                    "message": f"Switched to {new_role.value} role",
                    "previous_role": event.previous_role.value,
                    "new_role": event.new_role.value,
                    "gnmi_reconnected": reconnect_success
                })
            else:
                self._send_error(event.error or "Role switch failed", 403)
        
        elif self.path == '/role/admin':
            if not self.service_account:
                self._send_error("Service account not initialized", 500)
                return
            event = self.service_account.switch_to_admin()
            if event.success:
                if self.on_reconnect_gnmi:
                    self.on_reconnect_gnmi()
                self._send_json({"success": True, "message": "Switched to admin role", "new_role": "admin"})
            else:
                self._send_error(event.error or "Failed", 403)
        
        elif self.path == '/role/operator':
            if not self.service_account:
                self._send_error("Service account not initialized", 500)
                return
            event = self.service_account.switch_to_operator()
            if event.success:
                if self.on_reconnect_gnmi:
                    self.on_reconnect_gnmi()
                self._send_json({"success": True, "message": "Switched to operator role", "new_role": "operator"})
            else:
                self._send_error(event.error or "Failed", 403)
        
        # ============ Policy Update Endpoints ============
        elif self.path.startswith('/policy/') and not self.path.endswith('/reset'):
            # Update policy: POST /policy/{onap_role}
            # Body: {"allowed_sonic_roles": ["admin", "operator"], "default_sonic_role": "admin"}
            if not self.policy_engine:
                self._send_error("Policy engine not initialized", 500)
                return
            
            role_str = self.path.split('/')[-1].lower()
            try:
                onap_role = OnapRole(role_str)
            except ValueError:
                self._send_error(f"Invalid ONAP role: {role_str}. Valid: admin, operator", 400)
                return
            
            body = self._read_json_body()
            if not body:
                self._send_error("Request body required. Example: {\"allowed_sonic_roles\": [\"admin\", \"operator\"]}", 400)
                return
            
            # Parse allowed_sonic_roles
            allowed_roles = None
            if "allowed_sonic_roles" in body:
                try:
                    allowed_roles = [SonicRole(r) for r in body["allowed_sonic_roles"]]
                except ValueError as e:
                    self._send_error(f"Invalid SONiC role in allowed_sonic_roles: {e}", 400)
                    return
            
            # Parse default_sonic_role
            default_role = None
            if "default_sonic_role" in body:
                try:
                    default_role = SonicRole(body["default_sonic_role"])
                except ValueError:
                    self._send_error(f"Invalid default_sonic_role: {body['default_sonic_role']}", 400)
                    return
            
            # Update policy
            new_policy = self.policy_engine.update_policy(
                onap_role=onap_role,
                allowed_sonic_roles=allowed_roles,
                default_sonic_role=default_role
            )
            
            self._send_json({
                "success": True,
                "message": f"Policy updated for {onap_role.value}",
                **new_policy.to_dict()
            })
        
        elif self.path == '/policy/reset':
            # Reset policies to defaults
            if not self.policy_engine:
                self._send_error("Policy engine not initialized", 500)
                return
            
            self.policy_engine.reset_to_defaults()
            self._send_json({
                "success": True,
                "message": "Policies reset to defaults",
                "policies": self.policy_engine.get_all_policies()
            })
        
        else:
            self._send_error("Not found", 404)
    
    # Alias PUT to POST
    do_PUT = do_POST


class RoleAPIServer:
    """
    HTTP server for role and policy management.
    
    Supports both single-client mode (backward compat) and multi-client mode.
    Runs in background thread.
    """
    
    def __init__(self, 
                 port: int = 8080,
                 service_account = None,
                 policy_engine: RolePolicyEngine = None,
                 session_manager = None,
                 gnmi_pool = None,
                 on_reconnect_gnmi: Callable[[], bool] = None):
        self.port = port
        self.service_account = service_account
        self.policy_engine = policy_engine or get_policy_engine()
        self.session_manager = session_manager
        self.gnmi_pool = gnmi_pool
        self.on_reconnect_gnmi = on_reconnect_gnmi
        self._server: Optional[HTTPServer] = None
        self._thread: Optional[threading.Thread] = None
        
        # Determine mode
        self.multi_client_mode = session_manager is not None
    
    def start(self):
        """Start API server in background thread"""
        # Configure handler class
        RoleAPIHandler.service_account = self.service_account
        RoleAPIHandler.policy_engine = self.policy_engine
        RoleAPIHandler.session_manager = self.session_manager
        RoleAPIHandler.gnmi_pool = self.gnmi_pool
        RoleAPIHandler.on_reconnect_gnmi = self.on_reconnect_gnmi
        
        # Create server
        self._server = HTTPServer(('0.0.0.0', self.port), RoleAPIHandler)
        
        # Start in background thread
        self._thread = threading.Thread(
            target=self._server.serve_forever,
            daemon=True,
            name="RoleAPI-Server"
        )
        self._thread.start()
        
        mode = "Multi-Client" if self.multi_client_mode else "Single-Client"
        print(f"\n{'='*70}")
        print(f"[RoleAPI] Role & Policy API started on port {self.port} ({mode} Mode)")
        print(f"{'='*70}")
        
        if self.multi_client_mode:
            print(f"[RoleAPI] Session Endpoints:")
            print(f"         GET  /sessions         - List active client sessions")
            print(f"         GET  /pool             - gNMI connection pool status")
            print(f"         GET  /interfaces       - List available interfaces from SONiC")
        else:
            print(f"[RoleAPI] Role Endpoints:")
            print(f"         GET  /role             - Get current SONiC role")
            print(f"         POST /role/admin       - Switch to admin role")
            print(f"         POST /role/operator    - Switch to operator role")
        
        print(f"{'='*70}")
        print(f"[RoleAPI] Policy Endpoints:")
        print(f"         GET  /policy            - Get all ONAP→SONiC policies")
        print(f"         GET  /policy/{{onap}}    - Get policy for ONAP role")
        print(f"         POST /policy/{{onap}}    - Update policy mapping")
        print(f"         POST /policy/reset      - Reset to default policies")
        print(f"{'='*70}\n")
    
    def stop(self):
        """Stop API server"""
        if self._server:
            self._server.shutdown()
            self._server = None
        if self._thread:
            self._thread.join(timeout=2)
            self._thread = None
        print("[RoleAPI] Server stopped")


def create_role_api(
    port: int = 8080,
    service_account = None,
    policy_engine: RolePolicyEngine = None,
    session_manager = None,
    gnmi_pool = None,
    on_reconnect_gnmi: Callable[[], bool] = None
) -> RoleAPIServer:
    """
    Create and start role API server.
    
    Args:
        port: Port to listen on (default: 8080)
        service_account: ServiceAccount instance (single-client mode)
        policy_engine: RolePolicyEngine instance (uses global if None)
        session_manager: SessionContextManager instance (multi-client mode)
        gnmi_pool: GnmiConnectionPool instance (multi-client mode)
        on_reconnect_gnmi: Callback to reconnect gNMI with new credentials
    
    Returns:
        RoleAPIServer instance
    """
    # Try to get global instances if not provided
    if session_manager is None and get_session_manager:
        try:
            session_manager = get_session_manager()
        except:
            pass
    
    if gnmi_pool is None and get_gnmi_pool:
        try:
            gnmi_pool = get_gnmi_pool()
        except:
            pass
    
    server = RoleAPIServer(
        port=port,
        service_account=service_account,
        policy_engine=policy_engine,
        session_manager=session_manager,
        gnmi_pool=gnmi_pool,
        on_reconnect_gnmi=on_reconnect_gnmi
    )
    server.start()
    return server




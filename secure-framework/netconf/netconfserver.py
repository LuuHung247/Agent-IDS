#!/usr/bin/env python3
"""
NETCONF over TLS Server with Multi-Client Certificate Support

Accepts connections from multiple SDN-C clients, each with their own certificate.
Client certificate determines ONAP role (admin/operator), which determines
allowed SONiC roles via policy.
"""

import os
import sys
import ssl
import socket
import threading
from typing import Optional
from netconf_gnmi_adapter import NetconfGnmiAdapter
from netconf.netconf_session import NetconfSession


class NetconfTLSServer:
    """
    TLS-based NETCONF server (RFC 7589) with multi-client support.
    
    Features:
    - Accepts multiple client certificates (admin, operator)
    - Extracts ONAP role from client certificate CN/OU
    - Per-session role context
    - gNMI connection pool for different SONiC roles
    """
    
    def __init__(self, 
                 listen_port: int = 6513,
                 cert_file: str = './certificate/adapter/netconf/server.crt',
                 key_file: str = './certificate/adapter/netconf/server.key',
                 ca_file: Optional[str] = None,
                 require_client_cert: bool = True,
                 adapter: NetconfGnmiAdapter = None,
                 gnmi_pool = None,
                 session_manager = None):
        """
        Initialize NETCONF TLS server.
        
        Args:
            listen_port: Port to listen on (default: 6513)
            cert_file: Server certificate
            key_file: Server private key
            ca_file: CA certificate for client verification
            require_client_cert: Whether to require client certificates
            adapter: NetconfGnmiAdapter instance (for backward compat)
            gnmi_pool: GnmiConnectionPool instance (for multi-role support)
            session_manager: SessionContextManager instance
        """
        self.listen_port = listen_port
        self.cert_file = cert_file
        self.key_file = key_file
        self.ca_file = ca_file
        self.require_client_cert = require_client_cert
        
        # gNMI backend
        self.adapter = adapter
        self.gnmi_pool = gnmi_pool
        self.session_manager = session_manager
        
        # Verify server certificate files
        if not os.path.exists(cert_file):
            raise FileNotFoundError(f"Server certificate not found: {cert_file}")
        if not os.path.exists(key_file):
            raise FileNotFoundError(f"Server private key not found: {key_file}")
        
        print(f"[TLS] Server certificate: {cert_file}")
        print(f"[TLS] Server private key: {key_file}")
        if ca_file:
            print(f"[TLS] CA file for client verification: {ca_file}")
        print(f"[TLS] Client certificate required: {require_client_cert}")
    
    def create_ssl_context(self):
        """Create SSL context for TLS server with client cert support"""
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        
        # Load server certificate
        context.load_cert_chain(certfile=self.cert_file, keyfile=self.key_file)
        
        # Configure client certificate verification
        # Three modes:
        # 1. CERT_REQUIRED - require client cert (for mTLS role-based access)
        # 2. CERT_OPTIONAL - request but don't require (can still get cert if sent)
        # 3. CERT_NONE - don't request client cert at all
        if self.require_client_cert and self.ca_file and os.path.exists(self.ca_file):
            # mTLS: require + verify client cert (zero-trust SDNC→SF)
            context.load_verify_locations(cafile=self.ca_file)
            context.verify_mode = ssl.CERT_REQUIRED
            print(f"[TLS] Client certificate: REQUIRED (mTLS enabled)")
        else:
            # One-way TLS: server auth only, no client cert request sent
            # Zero-trust enforcement at SF→LEAF layer (gNMI mTLS)
            context.verify_mode = ssl.CERT_NONE
            print(f"[TLS] Client certificate: NONE (one-way TLS)")
        
        # Secure ciphers
        context.set_ciphers('ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS')
        context.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1
        
        return context
    
    def _extract_client_info(self, client_socket) -> tuple:
        """Extract client certificate info"""
        cert = None
        cn = None
        ou = None
        
        try:
            cert = client_socket.getpeercert()
            if cert:
                for rdn in cert.get('subject', ()):
                    for key, value in rdn:
                        if key == 'commonName':
                            cn = value
                        elif key == 'organizationalUnitName':
                            ou = value
        except Exception:
            pass
        
        return cert, cn, ou
    
    def handle_client(self, client_socket, client_addr):
        """Handle client connection with session context"""
        session_context = None
        
        try:
            print(f"\n{'='*80}")
            print(f"[CONNECTION] New NETCONF client from {client_addr}")
            print(f"{'='*80}")
            
            # Configure TCP socket
            try:
                client_socket.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
                client_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 60)
                client_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 30)
                client_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 9)
                client_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            except Exception as e:
                print(f"[{client_addr}] WARNING: Could not set socket options: {e}")
            
            # Extract client certificate
            cert, cn, ou = self._extract_client_info(client_socket)
            
            if cert:
                print(f"[{client_addr}] Client certificate:")
                print(f"             CN: {cn or 'N/A'}")
                print(f"             OU: {ou or 'N/A'}")
            else:
                print(f"[{client_addr}] No client certificate provided")
            
            # Create session context (determines ONAP role from cert)
            if self.session_manager:
                session_context = self.session_manager.create_session(client_addr, cert)
                print(f"[{client_addr}] Session context created:")
                print(f"             ONAP role: {session_context.onap_role.value}")
                print(f"             SONiC role: {session_context.sonic_role.value}")
                print(f"             Allowed: {[r.value for r in session_context.allowed_sonic_roles]}")
            
            # Get appropriate gNMI client
            gnmi_client = None
            if self.gnmi_pool and session_context:
                gnmi_client = self.gnmi_pool.get_client(session_context.sonic_role)
                if gnmi_client:
                    print(f"[{client_addr}] Using gNMI {session_context.sonic_role.value} connection")
                else:
                    print(f"[{client_addr}] WARNING: No gNMI connection for {session_context.sonic_role.value}")
            
            # Create adapter for this session
            if gnmi_client:
                session_adapter = NetconfGnmiAdapter(gnmi_client=gnmi_client)
            else:
                session_adapter = self.adapter  # Fallback to shared adapter
            
            if session_adapter is None:
                print(f"[{client_addr}] ERROR: No gNMI adapter available")
                return
            
            # Start NETCONF session
            print(f"[{client_addr}] Starting NETCONF session...")
            session = NetconfSession(client_socket, session_adapter, client_addr)
            session.run()
            
        except Exception as e:
            print(f"[{client_addr}] Client error: {type(e).__name__}: {e}")
            import traceback
            traceback.print_exc()
        finally:
            # Cleanup session context
            if self.session_manager and session_context:
                self.session_manager.remove_session(client_addr)
            
            try:
                client_socket.close()
            except:
                pass
            print(f"[{client_addr}] ✓ Connection closed")
    
    def start(self):
        """Start NETCONF TLS server"""
        ssl_context = self.create_ssl_context()
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(('0.0.0.0', self.listen_port))
        sock.listen(5)
        
        print(f"\n{'='*80}")
        print(f"NETCONF over TLS Server (Multi-Client Certificate Support)")
        print(f"{'='*80}")
        print(f"Listening on port: {self.listen_port}")
        print(f"Server certificate: {self.cert_file}")
        print(f"Client cert required: {self.require_client_cert}")
        if self.gnmi_pool:
            status = self.gnmi_pool.get_status()
            print(f"gNMI Pool port: {status['port']}")
            for leaf_name, leaf_info in status.get('leaves', {}).items():
                for role, connected in leaf_info.get('connections', {}).items():
                    state = "✓" if connected else "✗"
                    print(f"  {state} {role}@{leaf_info['ip']} ({leaf_name})")
        print(f"{'='*80}\n")
        print("Waiting for SDN-C connections...\n")
        print(f"[DEBUG] About to enter accept() loop...")
        sys.stdout.flush()
        
        while True:
            try:
                client, addr = sock.accept()
                
                try:
                    print(f"\n[{addr}] TCP connection accepted, starting TLS handshake...")
                    tls_client = ssl_context.wrap_socket(client, server_side=True)
                    
                    tls_version = tls_client.version()
                    cipher = tls_client.cipher()
                    print(f"[{addr}] ✓ TLS handshake successful")
                    print(f"[{addr}] Protocol: {tls_version}, Cipher: {cipher[0] if cipher else 'unknown'}")
                    
                    # Start client handler thread
                    thread = threading.Thread(
                        target=self.handle_client,
                        args=(tls_client, addr),
                        daemon=True
                    )
                    thread.start()
                    
                except ssl.SSLError as e:
                    print(f"[{addr}] ✗ TLS handshake FAILED: {e}")
                    client.close()
                except Exception as e:
                    print(f"[{addr}] ✗ Connection error: {e}")
                    client.close()
                    
            except KeyboardInterrupt:
                print("\n\n[SERVER] Shutting down...")
                break
            except Exception as e:
                print(f"[SERVER] Error: {e}")


import os
import socket
import ssl
import threading
import time
from typing import Optional, Tuple
from xml.sax import saxutils
from lxml import etree
from netconf_gnmi_adapter import NetconfGnmiAdapter



class NetconfSession:
    """NETCONF session handler for TLS connections"""
    
    # Class-level session counter for unique session IDs
    _session_counter = 0
    _session_lock = threading.Lock()
    
    def __init__(self, tls_socket, adapter: NetconfGnmiAdapter, client_addr):
        self.socket = tls_socket
        self.adapter = adapter
        self.client_addr = client_addr
        self.running = True
        self.buffer = ""
        self.use_chunked = False  # NETCONF 1.1 chunked framing
        self.hello_complete = False  # Track when hello exchange is done
        self.namespace_map = self._build_namespace_to_module_map()  # Namespace→module mapping
        
        # Generate unique session ID
        with NetconfSession._session_lock:
            NetconfSession._session_counter += 1
            # Create session ID based on counter
            self.session_id = NetconfSession._session_counter
        
    def _extract_namespace_from_yang(self, yang_file_path: str) -> Optional[str]:
        """Extract namespace URI from YANG module file"""
        try:
            with open(yang_file_path, 'r', encoding='utf-8') as f:
                for line in f:
                    # Look for namespace declaration
                    # Format: namespace "http://...";
                    line = line.strip()
                    if line.startswith('namespace'):
                        # Extract namespace between quotes
                        parts = line.split('"')
                        if len(parts) >= 2:
                            return parts[1]
                        # Alternative format with single quotes (because some of Yang can have this format)
                        parts = line.split("'")
                        if len(parts) >= 2:
                            return parts[1]
        except Exception as e:
            print(f"[WARNING] Error extracting namespace from {yang_file_path}: {e}")
        return None
    
    def _extract_revision_from_yang(self, yang_file_path: str) -> Optional[str]:
        """Extract most recent revision date from YANG module file"""
        try:
            with open(yang_file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                # Look for revision statements: revision YYYY-MM-DD { ... }
                # Return the most recent (first) revision found
                import re
                revisions = re.findall(r'revision\s+["\']?(\d{4}-\d{2}-\d{2})["\']?', content)
                if revisions:
                    # Sort descending to get most recent
                    revisions.sort(reverse=True)
                    return revisions[0]
        except Exception as e:
            print(f"[WARNING] Error extracting revision from {yang_file_path}: {e}")
        return None
    
    def _extract_imports_from_yang(self, yang_file_path: str) -> list:
        """Extract list of imported modules from YANG file"""
        imports = []
        try:
            with open(yang_file_path, 'r', encoding='utf-8') as f:
                import re
                content = f.read()
                # Find import statements: import module-name { prefix ... }
                # Match: import <module-name> followed by { or ;
                import_matches = re.findall(r'import\s+([a-zA-Z0-9_-]+)\s*[{;]', content)
                imports = list(set(import_matches))  # Remove duplicates
        except Exception as e:
            print(f"[WARNING] Error extracting imports from {yang_file_path}: {e}")
        return imports
    
    
    def _build_namespace_to_module_map(self) -> dict:
        """Build mapping from namespace URI to module name for get-schema requests"""
        # yang folder is in parent directory (project root)
        yang_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'yang')
        namespace_map = {}
        
        if not os.path.exists(yang_dir):
            return namespace_map
        
        try:
            yang_files = [f for f in os.listdir(yang_dir) if f.endswith('.yang')]
            for yang_file in yang_files:
                # Extract module name from filename
                module_name = yang_file[:-5].split('@')[0]
                
                # Extract namespace from file
                yang_path = os.path.join(yang_dir, yang_file)
                namespace = self._extract_namespace_from_yang(yang_path)
                
                if namespace:
                    # Map base namespace (without query params)
                    namespace_map[namespace] = module_name
                    
                    # Extract revision from filename
                    file_parts = yang_file[:-5].split('@')
                    if len(file_parts) > 1:
                        revision = file_parts[1]
                        # Map namespace with revision query parameter
                        namespace_with_rev = f"{namespace}?revision={revision}"
                        namespace_map[namespace_with_rev] = module_name
                    else:
                        # If no revision in filename, extract from file content
                        revision = self._extract_revision_from_yang(yang_path)
                        if revision:
                            namespace_with_rev = f"{namespace}?revision={revision}"
                            namespace_map[namespace_with_rev] = module_name
            
        except Exception as e:
            print(f"[WARNING] Error building namespace map: {e}")
            import traceback
            traceback.print_exc()
        
        return namespace_map
    
    def _generate_hello_message(self) -> str:
        """Generate NETCONF hello message advertising only what SF can actually serve."""
        yang_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'yang')

        # NETCONF protocol capabilities only — no YANG module URNs here
        capabilities = [
            '<capability>urn:ietf:params:netconf:base:1.0</capability>',
            '<capability>urn:ietf:params:netconf:base:1.1</capability>',
            '<capability>urn:ietf:params:netconf:capability:writable-running:1.0</capability>',
            # ietf-netconf-monitoring is mandatory for ODL schema discovery
            '<capability>urn:ietf:params:xml:ns:yang:ietf-netconf-monitoring?module=ietf-netconf-monitoring&amp;revision=2010-10-04</capability>',
        ]

        # Auto-discover YANG modules actually present in yang/ dir
        if os.path.exists(yang_dir):
            for yang_file in sorted(os.listdir(yang_dir)):
                if not yang_file.endswith('.yang'):
                    continue
                yang_path = os.path.join(yang_dir, yang_file)
                namespace = self._extract_namespace_from_yang(yang_path)
                module_name = yang_file[:-5].split('@')[0]
                revision = yang_file[:-5].split('@')[1] if '@' in yang_file else self._extract_revision_from_yang(yang_path)
                if namespace and revision:
                    cap = f'<capability>{namespace}?module={module_name}&amp;revision={revision}</capability>'
                    capabilities.append(cap)
                    print(f"[YANG] Advertising: {module_name}@{revision}")

        print(f"[YANG] Hello capabilities: {len(capabilities)} total")
        
        # Build hello message with unique session ID
        capabilities_xml = '\n        '.join(capabilities)
        hello_msg = f'''<?xml version="1.0" encoding="UTF-8"?>
<hello xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
    <capabilities>
        {capabilities_xml}
    </capabilities>
    <session-id>{self.session_id}</session-id>
</hello>]]>]]>'''
        
        return hello_msg
    
    def send_hello(self):
        """Send NETCONF hello message with auto-discovered YANG modules"""
        hello_msg = self._generate_hello_message()
        hello_bytes = hello_msg.encode('utf-8')
        # logging output
        print(f"\n{'='*80}")
        print(f"[{self.client_addr}] HELLO SENT: {len(hello_bytes)} bytes")
        print(f"{'='*80}")
        print(hello_msg[:500])
        if len(hello_msg) > 500:
            print(f"... ({len(hello_msg) - 500} more bytes)")
        print(f"{'='*80}\n")

        self.socket.sendall(hello_bytes)
    
    def receive_message(self) -> Tuple[Optional[str], bool]:
        """Receive NETCONF message (supports both 1.0 and 1.1 framing)
        Returns: (message, is_closed) - message is None if timeout or closed
                 is_closed=True means connection was closed by peer
        """
        while self.running:
            try:
                self.socket.settimeout(60)  # 60 second timeout for ONAP compatibility
                data = self.socket.recv(8192)  # Larger buffer for ONAP
                if not data:
                    print(f"[{self.client_addr}] RECV: Connection closed by peer (EOF)")
                    return None, True  # Connection closed
                
                print(f"[{self.client_addr}] RECV: {len(data)} bytes")
                self.buffer += data.decode('utf-8', errors='ignore')
                
                # NETCONF 1.1 chunked framing (only AFTER hello exchange)
                if self.use_chunked and self.hello_complete:
                    if '\n##\n' in self.buffer:
                        msg, self.buffer = self.buffer.split('\n##\n', 1)
                        # Decode chunked message
                        decoded = []
                        pos = 0
                        msg = msg.lstrip('\n')
                        
                        # ghép chunk thành chuỗi decoded
                        while pos < len(msg):
                            if msg[pos] == '#':
                                newline_pos = msg.find('\n', pos)
                                if newline_pos == -1:
                                    break
                                
                                try:
                                    size_str = msg[pos+1:newline_pos]
                                    chunk_size = int(size_str)
                                    data_start = newline_pos + 1
                                    data_end = data_start + chunk_size
                                    chunk_data = msg[data_start:data_end]
                                    decoded.append(chunk_data)
                                    pos = data_end
                                    if pos < len(msg) and msg[pos] == '\n':
                                        pos += 1
                                except (ValueError, IndexError) as e:
                                    print(f"[{self.client_addr}] CHUNKED ERROR: {e}")
                                    break
                            else:
                                pos += 1
                        
                        result = ''.join(decoded).strip()
                        print(f"[{self.client_addr}] CHUNKED message decoded: {len(result)} bytes")
                        return result, False  # Got message, connection alive
                
                # NETCONF 1.0 EOM framing (used for hello and optionally for all messages)
                if ']]>]]>' in self.buffer:
                    msg, self.buffer = self.buffer.split(']]>]]>', 1)
                    print(f"[{self.client_addr}] EOM message: {len(msg)} bytes")
                    return msg.strip(), False  # Got message, connection alive
                
            except socket.timeout:
                # Timeout is normal - just continue waiting
                continue
            except ConnectionResetError as e:
                print(f"[{self.client_addr}] RECV ERROR: Connection reset by peer")
                return None, True  # Connection closed
            except BrokenPipeError as e:
                print(f"[{self.client_addr}] RECV ERROR: Broken pipe")
                return None, True  # Connection closed
            except ssl.SSLError as e:
                print(f"[{self.client_addr}] RECV ERROR: SSL error - {e}")
                return None, True  # Connection closed
            except Exception as e:
                print(f"[{self.client_addr}] RECV ERROR: {type(e).__name__}: {e}")
                import traceback
                traceback.print_exc()
                return None, True  # Connection closed on error
        return None, True  # Loop ended, connection considered closed
    
    def send_response(self, response: str, message_id: str = "1"):
        """Send NETCONF RPC response (supports both 1.0 and 1.1 framing)"""
        try:
            # self.use_chunnked = True when  NETCONF 1.1 is negotiated
            if self.use_chunked and self.hello_complete:
                # NETCONF 1.1 chunked framing
                msg_bytes = response.encode('utf-8')
                chunk_msg = f"\n#{len(msg_bytes)}\n{response}\n##\n"
                print(f"[{self.client_addr}] RESPONSE: Sending chunked (1.1): {len(chunk_msg)} bytes")
                self.socket.sendall(chunk_msg.encode('utf-8'))
            else:
                # NETCONF 1.0 EOM framing
                full_msg = response + '\n]]>]]>'
                print(f"[{self.client_addr}] RESPONSE: Sending EOM (1.0): {len(full_msg)} bytes")
                self.socket.sendall(full_msg.encode('utf-8'))
            
            print(f"[{self.client_addr}] RESPONSE: Successfully sent message-id={message_id}")
        except BrokenPipeError as e:
            print(f"[{self.client_addr}] SEND ERROR: Broken pipe - client disconnected")
            self.running = False
        except ConnectionResetError as e:
            print(f"[{self.client_addr}] SEND ERROR: Connection reset by peer")
            self.running = False
        except ssl.SSLError as e:
            print(f"[{self.client_addr}] SEND ERROR: SSL error - {e}")
            self.running = False
        except Exception as e:
            print(f"[{self.client_addr}] SEND ERROR: {type(e).__name__}: {e}")
            import traceback
            traceback.print_exc()
            self.running = False
    
    def handle_rpc(self, rpc_xml: str):
        """Handle NETCONF RPC request"""
        msg_id = '1'
        
        try:
            # Parse RPC XML to element tree(XML)
            root = etree.fromstring(rpc_xml.encode('utf-8'))
            ns = {'nc': 'urn:ietf:params:xml:ns:netconf:base:1.0'}
            
            msg_id = root.get('message-id', '1')
            
            # Extract RPC operation (find <get-config>, <get>, <edit-config>, etc.)
            get_config = root.xpath('.//nc:get-config', namespaces=ns)
            get_rpc = root.xpath('.//nc:get', namespaces=ns)
            edit_config = root.xpath('.//nc:edit-config', namespaces=ns)
            
            # Try to find get-schema with or without namespace prefix 
            get_schema = root.xpath('.//*[local-name()="get-schema"]')
            
            # Thao tác xử lý các session
            lock = root.xpath('.//nc:lock', namespaces=ns)
            unlock = root.xpath('.//nc:unlock', namespaces=ns)
            commit = root.xpath('.//nc:commit', namespaces=ns)
            close = root.xpath('.//nc:close-session', namespaces=ns)
            
            # Check if this is a get request for ietf-netconf-monitoring schemas
            is_monitoring_request = False
            # Lấy danh sách schema (monitoring request)
            if get_rpc:
                # Check for netconf-monitoring namespace in filter
                filter_elem = root.xpath('.//nc:filter', namespaces=ns)
                if filter_elem:
                    filter_str = etree.tostring(filter_elem[0], encoding='unicode')
                    if 'ietf-netconf-monitoring' in filter_str or 'netconf-state' in filter_str:
                        is_monitoring_request = True
            
            if get_config:
                print(f"[{self.client_addr}] RPC: get-config")
                data_xml = self.adapter.handle_get_config(root)
                response = self._build_rpc_reply(data_xml, msg_id)
                self.send_response(response, msg_id)
            
            elif get_rpc and is_monitoring_request:
                print(f"[{self.client_addr}] RPC: get (ietf-netconf-monitoring)")
                # Return list of available schemas
                data_xml = self._build_monitoring_schemas()
                response = self._build_rpc_reply(data_xml, msg_id)
                self.send_response(response, msg_id)
            
            elif get_rpc:
                print(f"[{self.client_addr}] RPC: get")
                data_xml = self.adapter.handle_get(root)
                response = self._build_rpc_reply(data_xml, msg_id)
                self.send_response(response, msg_id)
            
            elif edit_config:
                print(f"[{self.client_addr}] RPC: edit-config")
                print(f"[{self.client_addr}] DEBUG: edit-config request size: {len(rpc_xml)} bytes")
                try:
                    response_xml = self.adapter.handle_edit_config(root)
                    print(f"[{self.client_addr}] DEBUG: edit-config response size: {len(response_xml)} bytes")
                    self.send_response(response_xml, msg_id)
                    print(f"[{self.client_addr}] ✓ edit-config completed successfully")
                except Exception as e:
                    print(f"[{self.client_addr}] ✗ edit-config error: {type(e).__name__}: {e}")
                    import traceback
                    traceback.print_exc()
                    response = self._build_error_reply(msg_id, 'application', 'operation-failed', str(e))
                    self.send_response(response, msg_id)
            
            # lấy nội dung YANG module theo identifier (tên module hoặc namespace URL).
            elif get_schema:
                # Extract module identifier from request (namespace-agnostic)
                identifier_elems = get_schema[0].xpath('.//*[local-name()="identifier"]')
                if identifier_elems:
                    identifier = identifier_elems[0].text
                else:
                    identifier = 'openconfig-acl'
                
                print(f"[{self.client_addr}] RPC: get-schema (identifier={identifier})")
                
                # Check if identifier is a namespace URL or module name
                module_name = identifier

                
                if identifier.startswith('http://') or identifier.startswith('urn:'):
                    # It's a namespace URL - convert to module name
                    # Try exact match first (with revision if present)
                    if identifier in self.namespace_map:
                        module_name = self.namespace_map[identifier]
                        print(f"[{self.client_addr}] ✓ Schema resolved via exact namespace match: '{identifier}' → '{module_name}'")
                    else:
                        # Try without query parameters (base namespace)
                        base_ns = identifier.split('?')[0]
                        if base_ns in self.namespace_map:
                            module_name = self.namespace_map[base_ns]
                            print(f"[{self.client_addr}] ✓ Schema resolved via base namespace: '{base_ns}' → '{module_name}'")
                        else:
                            print(f"[{self.client_addr}] ✗ WARNING: Namespace not found in map: {identifier}")
                            print(f"[{self.client_addr}]   Tried: '{identifier}' and '{base_ns}'")
                            print(f"[{self.client_addr}]   Available namespaces: {len(self.namespace_map)} entries")
                            # Show some matching entries for debugging
                            for ns in sorted(self.namespace_map.keys()):
                                if base_ns in ns:
                                    print(f"[{self.client_addr}]     Found similar: {ns} → {self.namespace_map[ns]}")
                else:
                    print(f"[{self.client_addr}] Schema requested by module name: {module_name}")
                
                print(f"[{self.client_addr}] ✓ Loading YANG schema for essential module: {module_name}")
                response = self._build_schema_response(msg_id, module_name)
                self.send_response(response, msg_id)
                print(f"[{self.client_addr}] ✓ Schema transfer completed for module: {module_name}")
            
            elif lock or unlock:
                print(f"[{self.client_addr}] RPC: {'lock' if lock else 'unlock'}")
                response = self._build_ok_reply(msg_id)
                self.send_response(response, msg_id)
            
            elif commit:
                print(f"[{self.client_addr}] RPC: commit")
                response = self._build_ok_reply(msg_id)
                self.send_response(response, msg_id)
            
            elif close:
                print(f"[{self.client_addr}] RPC: close-session")
                response = self._build_ok_reply(msg_id)
                self.send_response(response, msg_id)
                time.sleep(0.5)  # Allow response to be sent
                self.running = False
            
            else:
                print(f"[{self.client_addr}] RPC: unknown (sending OK)")
                response = self._build_ok_reply(msg_id)
                self.send_response(response, msg_id)
        
        except Exception as e:
            print(f"[{self.client_addr}] RPC ERROR: {e}")
            response = self._build_error_reply(msg_id, 'application', 'operation-failed', str(e))
            self.send_response(response, msg_id)
    
    def _build_rpc_reply(self, data_xml: str, msg_id: str) -> str:
        """Build RPC reply with data"""
        return f'''<?xml version="1.0" encoding="UTF-8"?>
<rpc-reply xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="{msg_id}">
{data_xml}
</rpc-reply>'''
    
    def _build_ok_reply(self, msg_id: str) -> str:
        """Build OK RPC reply"""
        return f'''<?xml version="1.0" encoding="UTF-8"?>
<rpc-reply xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="{msg_id}">
    <ok/>
</rpc-reply>'''
    
    def _build_error_reply(self, msg_id: str, error_type: str, error_tag: str, error_msg: str = "") -> str:
        """Build error RPC reply"""
        msg_part = f'<error-message>{error_msg}</error-message>' if error_msg else ''
        return f'''<?xml version="1.0" encoding="UTF-8"?>
<rpc-reply xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="{msg_id}">
    <rpc-error>
        <error-type>{error_type}</error-type>
        <error-tag>{error_tag}</error-tag>
        {msg_part}
    </rpc-error>
</rpc-reply>'''
    

    # Liệt kê tất cả module YANG trong thư mục /yang và xây dựng danh sách schema cho ietf-netconf-monitoring
    # -> ONAP khám phá được Yang models mà server hỗ trợ
    def _build_monitoring_schemas(self) -> str:
        """Build ietf-netconf-monitoring schemas list (RFC 6022)
        
        Only reports essential IETF modules to avoid ONAP schema validation errors.
        OpenConfig modules are skipped as ONAP has strict version/dependency requirements.
        """
        # yang folder is in parent directory (project root)
        yang_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'yang')
        
        schema_entries = []
        
        if os.path.exists(yang_dir):
            try:
                yang_files = sorted([f for f in os.listdir(yang_dir) if f.endswith('.yang')])
                

                # Filter to only essential modules
                valid_modules = []
                skipped_count = 0
                
                for yang_file in yang_files:
                    module_name = yang_file[:-5].split('@')[0]
                    # Report ALL modules for now (debugging)
                    valid_modules.append(yang_file)
                
                print(f"[{self.client_addr}] MONITORING: Found {len(yang_files)} modules, reporting ALL {len(valid_modules)} modules")
                if len(valid_modules) > 0:
                    print(f"[{self.client_addr}] Sample modules: {', '.join([f[:-5].split('@')[0] for f in valid_modules[:5]])}")
                
                # Build schema entries for valid modules only
                for yang_file in valid_modules:
                    # Parse filename: module-name@YYYY-MM-DD.yang or module-name.yang
                    file_parts = yang_file[:-5].split('@')
                    module_name = file_parts[0]
                    
                    # Try to extract revision from filename first, then from file content
                    revision = file_parts[1] if len(file_parts) > 1 else None
                    
                    # Extract namespace and revision from YANG file
                    yang_path = os.path.join(yang_dir, yang_file)
                    namespace = self._extract_namespace_from_yang(yang_path)
                    
                    # If no revision in filename, extract from file content
                    if not revision:
                        revision = self._extract_revision_from_yang(yang_path)
                    
                    # Fallback defaults
                    if not namespace:
                        namespace = f'urn:yang:module:{module_name}'
                    if not revision:
                        revision = '1970-01-01'
                    
                    # Build schema entry
                    schema_entry = f'''        <schema>
          <identifier>{module_name}</identifier>
          <version>{revision}</version>
          <format>yang</format>
          <namespace>{saxutils.escape(namespace)}</namespace>
          <location>NETCONF</location>
        </schema>'''
                    schema_entries.append(schema_entry)
            except Exception as e:
                print(f"[{self.client_addr}] WARNING: Error building monitoring schemas: {e}")
        
        schemas_xml = '\n'.join(schema_entries)
        
        # Return netconf-state with schemas
        return f'''    <data>
    <netconf-state xmlns="urn:ietf:params:xml:ns:yang:ietf-netconf-monitoring">
      <schemas>
{schemas_xml}
      </schemas>
    </netconf-state>
  </data>'''
    
    def _load_yang_file(self, module_name: str) -> str:
        """Load YANG module from local filesystem - auto-discover from yang directory"""
        
        # Special case: ietf-netconf-monitoring is a core capability we advertise
        # Provide a minimal stub if not available locally
        if module_name == 'ietf-netconf-monitoring':
            # yang folder is in parent directory (project root)
            yang_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'yang')
            filepath = os.path.join(yang_dir, 'ietf-netconf-monitoring@2010-10-04.yang')
            if not os.path.exists(filepath):
                print(f"[{self.client_addr}] Returning built-in ietf-netconf-monitoring stub")
                return '''module ietf-netconf-monitoring {
  namespace "urn:ietf:params:xml:ns:yang:ietf-netconf-monitoring";
  prefix "ncm";
  
  revision 2010-10-04 {
    description "Initial revision.";
  }
  
  container netconf-state {
    config false;
    container schemas {
      list schema {
        key "identifier version format";
        leaf identifier { type string; }
        leaf version { type string; }
        leaf format { type string; }
        leaf namespace { type string; }
        leaf location { type string; }
      }
    }
  }
  
  rpc get-schema {
    input {
      leaf identifier { type string; mandatory true; }
      leaf version { type string; }
      leaf format { type string; }
    }
    output {
      anyxml data;
    }
  }
}'''
        
        # yang folder is in parent directory (project root)
        yang_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'yang')
        
        if not os.path.exists(yang_dir):
            print(f"[WARNING] YANG directory not found: {yang_dir}")
            print(f"[INFO] Run download_yang_modules.py to download required YANG files")
            return f'module {module_name} {{ }}'
        
        # Strategy 1: Try exact match (module-name.yang)
        filename = f'{module_name}.yang'
        filepath = os.path.join(yang_dir, filename)
        
        if os.path.exists(filepath):
            try:
                print(f"[YANG] Loading module '{module_name}' from {filepath}...")
                with open(filepath, 'r', encoding='utf-8') as f:
                    yang_content = f.read()
                    print(f"[YANG] Successfully loaded '{module_name}' ({len(yang_content)} bytes)")
                    return yang_content
            except Exception as e:
                print(f"[WARNING] Error reading YANG file '{filepath}': {e}")
        
        # Strategy 2: Search for files starting with module name (handles revision @YYYY-MM-DD)
        try:
            for file in os.listdir(yang_dir):
                if not file.endswith('.yang'):
                    continue
                
                # Remove .yang extension
                base_name = file[:-5]
                
                # Check if it matches module name (with or without revision)
                # e.g., ietf-inet-types@2013-07-15.yang matches ietf-inet-types
                if base_name == module_name or base_name.startswith(f'{module_name}@'):
                    filepath = os.path.join(yang_dir, file)
                    print(f"[YANG] Loading module '{module_name}' from {filepath}...")
                    with open(filepath, 'r', encoding='utf-8') as f:
                        yang_content = f.read()
                        print(f"[YANG] Successfully loaded '{module_name}' ({len(yang_content)} bytes)")
                        return yang_content
        except Exception as e:
            print(f"[WARNING] Error searching YANG directory: {e}")
        
        # Strategy 3: Not found - return empty module
        print(f"[WARNING] YANG module not found: {module_name}")
        print(f"[INFO] Searched in: {yang_dir}")
        print(f"[INFO] Available modules:")
        try:
            yang_files = [f for f in os.listdir(yang_dir) if f.endswith('.yang')]
            for i, yf in enumerate(sorted(yang_files)[:10], 1):
                print(f"         {i}. {yf}")
            if len(yang_files) > 10:
                print(f"         ... and {len(yang_files) - 10} more")
        except:
            pass
        
        print(f"[INFO] Run resolve_yang_dependencies.py to auto-download missing YANG modules")
        return f'module {module_name} {{ }}'
    
    def _build_schema_response(self, msg_id: str, module_name: str) -> str:
        """Build get-schema response for requested YANG module (RFC 6022)"""
        
        # Get requested module by loading from local filesystem
        yang_text = self._load_yang_file(module_name)
        
        # XML escape the YANG text for proper embedding
        yang_escaped = saxutils.escape(yang_text)
        
        # Return with proper RFC 6022 format - YANG module as escaped text content
        return f'''<?xml version="1.0" encoding="UTF-8"?>
<rpc-reply xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="{msg_id}">
    <data xmlns="urn:ietf:params:xml:ns:yang:ietf-netconf-monitoring">{yang_escaped}</data>
</rpc-reply>'''
    
    def run(self):
        """Run NETCONF session"""
        try:
            # Step 1: TLS connection established (already done in server)
            print(f"[{self.client_addr}] Session NetconfServerSession{{sessionId={self.session_id}}} starting")
            
            # Step 2: Send server hello with capabilities
            print(f"[{self.client_addr}] Starting NETCONF hello message exchange...")
            self.send_hello()
            print(f"[{self.client_addr}] Session negotiation started with hello message on session {self.session_id}")
            
            # Step 3: Receive client hello
            print(f"[{self.client_addr}] Waiting for client hello (timeout 60s)...")
            hello, is_closed = self.receive_message()
            if not hello:
                if is_closed:
                    print(f"[{self.client_addr}] ✗ ERROR: Connection closed before hello received")
                else:
                    print(f"[{self.client_addr}] ✗ ERROR: Timeout waiting for hello")
                return
            
            print(f"[{self.client_addr}] ✓ Hello received from client: {len(hello)} bytes")
            
            # Validate it's a proper hello message
            if '<hello' not in hello:
                print(f"[{self.client_addr}] WARNING: Received message is not a hello")
                print(f"[{self.client_addr}] First 200 chars: {hello[:200]}")
            
            # Step 4: Parse client capabilities
            client_capabilities = []
            if '<capability>' in hello:
                import re
                caps = re.findall(r'<capability>([^<]+)</capability>', hello)
                client_capabilities = caps
                print(f"[{self.client_addr}] Client announced {len(client_capabilities)} capabilities")
            
            # Check client capabilities and set framing mode
            if 'urn:ietf:params:netconf:base:1.1' in hello:
                self.use_chunked = True
                print(f"[{self.client_addr}] ✓ Changing state from: OPEN_WAIT to: ESTABLISHED - NETCONF 1.1 detected")
            else:
                print(f"[{self.client_addr}] ✓ Changing state from: OPEN_WAIT to: ESTABLISHED - NETCONF 1.0")
            
            # Mark hello exchange as complete
            self.hello_complete = True
            print(f"[{self.client_addr}] Session NetconfServerSession{{sessionId={self.session_id}}} established")
            
            # Step 5: Log session preferences (similar to ODL)
            print(f"[{self.client_addr}] Session established with preferences: base={'1.1' if self.use_chunked else '1.0'}, capabilities={len(client_capabilities)}")
            
            # Step 6: Process RPC messages (including schema retrieval)
            print(f"[{self.client_addr}] Remote device ready - starting message processing loop")
            print(f"[{self.client_addr}] Netconf session initiated, starting keepalives (60s interval)")
            request_count = 0
            idle_count = 0
            max_idle = 60  # Allow 60 timeouts (60 minutes) for ONAP
            
            while self.running:
                msg, is_closed = self.receive_message()
                
                if not msg:
                    if is_closed:
                        # Connection was closed - exit immediately
                        print(f"[{self.client_addr}] ✗ Connection closed by peer - exiting RPC loop")
                        break
                    else:
                        # Just a timeout - increment idle counter (keepalive interval)
                        idle_count += 1
                        if idle_count >= max_idle:
                            print(f"[{self.client_addr}] ⏱ Max idle timeout reached ({max_idle}x60s = {max_idle} minutes) - ending session")
                            break
                        if idle_count % 5 == 0:  # Log every 5 timeouts (5 minutes)
                            print(f"[{self.client_addr}] ⏱ Keepalive: waiting for RPC... (idle {idle_count}/{max_idle} intervals)")
                        continue
                
                # Got a message - reset idle counter
                idle_count = 0
                request_count += 1
                print(f"[{self.client_addr}] Handling incoming message #{request_count}")
                self.handle_rpc(msg)
            
            print(f"[{self.client_addr}] ✓ Session ended gracefully - processed {request_count} RPC requests")
        
        except ConnectionResetError:
            print(f"[{self.client_addr}] ✗ Session error: Connection reset by peer")
        except BrokenPipeError:
            print(f"[{self.client_addr}] ✗ Session error: Broken pipe")
        except ssl.SSLError as e:
            print(f"[{self.client_addr}] ✗ Session error: SSL error - {e}")
        except Exception as e:
            print(f"[{self.client_addr}] ✗ Session error: {type(e).__name__}: {e}")
            import traceback
            traceback.print_exc()
        finally:
            try:
                print(f"[{self.client_addr}] Closing socket...")
                self.socket.shutdown(socket.SHUT_RDWR)
                self.socket.close()
                print(f"[{self.client_addr}] Socket closed")
            except:
                pass

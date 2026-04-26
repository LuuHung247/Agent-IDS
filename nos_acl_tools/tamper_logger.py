#!/usr/bin/env python3
"""
Tampering Detection Logger with Non-Repudiation Support

STRIDE Security Model Implementation:
- TAMPERING: Detects unauthorized modifications to data
  * Tracks all data changes (create/update/delete)
  * Records data state before and after modifications (hashes)
  * Logs modification attempts (success and failure)

- REPUDIATION: Ensures actions cannot be denied (Non-Repudiation)
  * Unique transaction IDs for each operation
  * User identity from certificate (CN, OU)
  * Client IP address
  * Cryptographic hash of request data
  * Tamper-evident log entries
"""

from datetime import datetime, timezone
from collections import deque
import threading
import json
import os
import uuid
import hashlib
import hmac
from typing import Optional, Dict, Any


class TamperLogger:
    """
    Centralized logger for detecting tampering (unauthorized data modifications)
    and ensuring non-repudiation (actions cannot be denied).
    
    STRIDE Security Features:
    - Tampering Detection: Hash-based data integrity verification
    - Non-Repudiation: Unique transaction IDs, user identity, request hashes
    """
    
    # Secret key for HMAC log integrity (in production, load from secure storage)
    _LOG_INTEGRITY_KEY = b"tamper_detection_key_change_in_production"
    
    def __init__(self, max_logs=1000, log_file="audit_logs/tamper_logs.json"):
        self.logs = deque(maxlen=max_logs)  # Keep recent logs in memory for quick access
        self.lock = threading.Lock()
        self.log_file = log_file
        self.max_logs = max_logs
        
        # Create log directory if it doesn't exist
        log_dir = os.path.dirname(log_file)
        if log_dir and not os.path.exists(log_dir):
            os.makedirs(log_dir)
        
        # Initialize log file if it doesn't exist
        if not os.path.exists(log_file):
            with open(log_file, 'w') as f:
                f.write('')
        else:
            # Load existing logs from file into memory
            self._load_logs_from_file()
    
    def log(self, event_type, action, details, client_info=None, severity="info", 
            is_tampering=None, transaction_id=None, request_data=None, 
            data_before=None, data_after=None, user_identity=None):
        """
        Log an event with full STRIDE security compliance.
        
        Args:
            event_type: Type of event (netconf, gnmi, policy, auth)
            action: Action performed (connect, disconnect, get, set, delete, etc.)
            details: Additional details about the event
            client_info: Information about the client (IP, cert CN, role, etc.)
            severity: Log severity (info, warning, error, critical)
            is_tampering: Explicitly mark if this is a tampering-relevant event (data modification).
                          If None, will be auto-detected based on action keywords.
                          True = data modification (create/delete/update) or unauthorized access
                          False = read-only operations (get), system events, connection events
            
            NON-REPUDIATION fields (proving who did what):
            transaction_id: Unique identifier for this transaction (auto-generated if None)
            request_data: Original request data (will be hashed for integrity)
            user_identity: Dict with user identification info:
                          {
                              "cn": "client common name from certificate",
                              "ou": "organizational unit from certificate",
                              "ip": "client IP address",
                              "port": "client port",
                              "role": "ONAP/SONiC role",
                              "session_id": "NETCONF session ID"
                          }
            
            TAMPERING DETECTION fields:
            data_before: Data state before modification (will be hashed)
            data_after: Data state after modification (will be hashed)
        """
        with self.lock:
            # Auto-detect tampering relevance if not explicitly set
            if is_tampering is None:
                is_tampering = self._is_tampering_relevant(action, details, severity)
            
            # Generate transaction ID if not provided (for non-repudiation)
            if transaction_id is None:
                transaction_id = str(uuid.uuid4())
            
            # Get precise timestamp with timezone (ISO 8601)
            timestamp = datetime.now(timezone.utc).isoformat()
            
            # Build log entry with STRIDE security fields
            log_entry = {
                # Basic fields
                "timestamp": timestamp,
                "event_type": event_type,
                "action": action,
                "severity": severity,
                "details": details,
                "is_tampering": is_tampering,
                
                # NON-REPUDIATION: Unique transaction identifier
                "transaction_id": transaction_id,
                
                # NON-REPUDIATION: User identity (who performed the action)
                "user_identity": self._build_user_identity(user_identity, client_info),
                
                # NON-REPUDIATION: Request hash (proves original request)
                "request_hash": self._compute_hash(request_data) if request_data else None,
                
                # TAMPERING: Data integrity hashes (before/after state)
                "data_before_hash": self._compute_hash(data_before) if data_before else None,
                "data_after_hash": self._compute_hash(data_after) if data_after else None,
                
                # Legacy client_info for backward compatibility
                "client_info": client_info or {},
            }
            
            # Add log entry integrity signature (tamper-evident)
            log_entry["integrity_signature"] = self._sign_log_entry(log_entry)
            
            self.logs.append(log_entry)
            
            # Write to file
            self._write_to_file(log_entry)
            
            # Print to console for visibility
            self._print_log(log_entry)
            
            return transaction_id  # Return for correlation
    
    def _build_user_identity(self, user_identity: Optional[Dict], client_info: Optional[Dict]) -> Dict:
        """
        Build comprehensive user identity for non-repudiation.
        Combines explicit user_identity with client_info fallback.
        
        Returns a dict that uniquely identifies who performed the action.
        """
        identity = {
            "cn": None,           # Certificate Common Name
            "ou": None,           # Certificate Organizational Unit
            "ip": None,           # Client IP address
            "port": None,         # Client port
            "role": None,         # User role (ONAP/SONiC)
            "session_id": None,   # NETCONF session ID
        }
        
        # Merge from user_identity first
        if user_identity:
            for key in identity.keys():
                if key in user_identity and user_identity[key]:
                    identity[key] = user_identity[key]
        
        # Fallback to client_info
        if client_info:
            if not identity["ip"] and "client_ip" in client_info:
                identity["ip"] = client_info["client_ip"]
            if not identity["ip"] and "client_addr" in client_info:
                addr = client_info["client_addr"]
                if isinstance(addr, (tuple, list)) and len(addr) >= 1:
                    identity["ip"] = str(addr[0])
                    if len(addr) >= 2:
                        identity["port"] = addr[1]
                elif isinstance(addr, str):
                    identity["ip"] = addr.split(":")[0] if ":" in addr else addr
            if not identity["cn"] and "cert_cn" in client_info:
                identity["cn"] = client_info["cert_cn"]
            if not identity["ou"] and "cert_ou" in client_info:
                identity["ou"] = client_info["cert_ou"]
            if not identity["role"] and "onap_role" in client_info:
                identity["role"] = client_info["onap_role"]
            if not identity["role"] and "sonic_role" in client_info:
                identity["role"] = client_info["sonic_role"]
            if not identity["session_id"] and "session_id" in client_info:
                identity["session_id"] = client_info["session_id"]
        
        return identity
    
    def _compute_hash(self, data: Any) -> Optional[str]:
        """
        Compute SHA-256 hash of data for integrity verification.
        Used for:
        - Request hash (proves what was requested - non-repudiation)
        - Data before/after hashes (detects tampering)
        
        Returns hex string of SHA-256 hash.
        """
        if data is None:
            return None
        
        try:
            # Convert to JSON string if not already a string
            if isinstance(data, str):
                data_str = data
            elif isinstance(data, bytes):
                data_str = data.decode('utf-8', errors='replace')
            else:
                data_str = json.dumps(data, sort_keys=True, default=str)
            
            # Compute SHA-256 hash
            hash_obj = hashlib.sha256(data_str.encode('utf-8'))
            return hash_obj.hexdigest()
        except Exception as e:
            return f"hash_error:{str(e)}"
    
    def _sign_log_entry(self, entry: Dict) -> str:
        """
        Create HMAC signature of log entry for tamper-evident logging.
        This allows verification that log entries have not been modified.
        
        Returns hex string of HMAC-SHA256 signature.
        """
        try:
            # Create canonical representation (exclude integrity_signature itself)
            fields_to_sign = {k: v for k, v in entry.items() if k != "integrity_signature"}
            canonical = json.dumps(fields_to_sign, sort_keys=True, default=str)
            
            # Compute HMAC-SHA256
            signature = hmac.new(
                self._LOG_INTEGRITY_KEY,
                canonical.encode('utf-8'),
                hashlib.sha256
            ).hexdigest()
            
            return signature
        except Exception as e:
            return f"signature_error:{str(e)}"
    
    def verify_log_integrity(self, log_entry: Dict) -> bool:
        """
        Verify that a log entry has not been tampered with.
        Returns True if the integrity signature is valid.
        """
        if "integrity_signature" not in log_entry:
            return False
        
        stored_signature = log_entry["integrity_signature"]
        computed_signature = self._sign_log_entry(log_entry)
        
        return hmac.compare_digest(stored_signature, computed_signature)
    
    def _print_log(self, entry):
        """Print log entry to console with non-repudiation info"""
        severity_symbols = {
            "info": "ℹ",
            "warning": "⚠",
            "error": "✗",
            "critical": "🔥"
        }
        symbol = severity_symbols.get(entry["severity"], "•")
        
        # Build identity string for display
        identity = entry.get("user_identity", {})
        identity_str = ""
        if identity.get("cn"):
            identity_str += f" CN={identity['cn']}"
        if identity.get("ip"):
            identity_str += f" IP={identity['ip']}"
        if identity.get("role"):
            identity_str += f" Role={identity['role']}"
        
        # Show transaction ID for traceability
        tx_id = entry.get("transaction_id", "")[:8] if entry.get("transaction_id") else ""
        tx_str = f"[{tx_id}]" if tx_id else ""
        
        # Tampering indicator
        tampering_str = "[DATA_MOD]" if entry.get("is_tampering") else ""
        
        print(f"[{entry['timestamp']}] {symbol} {tx_str} [{entry['event_type'].upper()}] {entry['action']}: {entry['details']}{identity_str} {tampering_str}")
    
    def _write_to_file(self, entry):
        """Write log entry to file"""
        try:
            with open(self.log_file, 'a') as f:
                f.write(json.dumps(entry) + '\n')
        except Exception as e:
            print(f"Error writing to log file: {e}")
    
    def _load_logs_from_file(self):
        """Load recent logs from file into memory on startup"""
        try:
            if os.path.exists(self.log_file):
                with open(self.log_file, 'r') as f:
                    lines = f.readlines()
                    # Load only the last max_logs entries
                    recent_lines = lines[-self.max_logs:] if len(lines) > self.max_logs else lines
                    for line in recent_lines:
                        line = line.strip()
                        if line:
                            try:
                                self.logs.append(json.loads(line))
                            except json.JSONDecodeError:
                                continue
        except Exception as e:
            print(f"Error loading logs from file: {e}")
    
    def get_logs(self, limit=None, event_type=None, severity=None, from_file=False):
        """
        Get logs with optional filtering
        
        Args:
            limit: Maximum number of logs to return
            event_type: Filter by event type
            severity: Filter by severity
            from_file: If True, read from file instead of memory
        
        Returns:
            List of log entries
        """
        with self.lock:
            if from_file:
                logs = self._read_from_file()
            else:
                logs = list(self.logs)
            
            # Filter by event type
            if event_type:
                logs = [log for log in logs if log["event_type"] == event_type]
            
            # Filter by severity
            if severity:
                logs = [log for log in logs if log["severity"] == severity]
            
            # Apply limit
            if limit:
                logs = logs[-limit:] if from_file else logs[:limit]
            
            return logs
    
    def _read_from_file(self):
        """Read all logs from file"""
        logs = []
        try:
            if os.path.exists(self.log_file):
                with open(self.log_file, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line:
                            try:
                                logs.append(json.loads(line))
                            except json.JSONDecodeError:
                                continue
        except Exception as e:
            print(f"Error reading from log file: {e}")
        return logs
    
    def _is_tampering_relevant(self, action: str, details: str, severity: str) -> bool:
        """
        Auto-detect if an event is tampering-relevant (data modification related).
        
        Tampering = malicious modification of data. We track:
        - All data modification operations (create, delete, update, set) - both success and failure
        - Unauthorized access attempts (access denied, permission denied)
        - Error/critical severity events related to modifications
        
        NOT tampering-relevant:
        - Read-only operations (get, get-config, query)
        - System startup/shutdown events
        - Connection/session events (connect, disconnect, initialize)
        """
        action_lower = action.lower()
        details_lower = details.lower()
        
        # Always include error/critical that involve data modifications or auth issues
        if severity in ["error", "critical"]:
            # Check if it's a modification-related error (not just connection errors)
            modification_keywords = ["create", "delete", "update", "set", "modify", "acl", "rule", "table"]
            auth_keywords = ["unauthorized", "denied", "permission", "access denied", "forbidden"]
            
            if any(kw in action_lower or kw in details_lower for kw in modification_keywords + auth_keywords):
                return True
        
        # Data modification operations (CREATE/DELETE/UPDATE) - these ARE tampering-relevant
        modification_actions = [
            "create", "delete", "update", "set", "modify", "edit",
            "create_acl", "delete_acl", "acl_create", "acl_delete",
            "create_acl_rule", "delete_acl_table", "edit_config"
        ]
        if any(mod_action in action_lower for mod_action in modification_actions):
            return True
        
        # Unauthorized access attempts
        auth_failure_keywords = ["unauthorized", "denied", "forbidden", "permission", "not allowed"]
        if any(kw in action_lower or kw in details_lower for kw in auth_failure_keywords):
            return True
        
        # NOT tampering-relevant: read-only operations
        read_only_actions = ["get", "query", "retrieve", "fetch", "list", "read"]
        if any(ro_action in action_lower for ro_action in read_only_actions):
            return False
        
        # NOT tampering-relevant: system/connection events
        system_actions = ["start", "stop", "initialize", "connect", "disconnect", "startup", "shutdown", "session"]
        if any(sys_action in action_lower for sys_action in system_actions):
            return False
        
        # Default: not tampering-relevant
        return False
    
    def log_data_modification(self, event_type: str, action: str, details: str,
                              user_identity: Dict = None, client_info: Dict = None,
                              request_data: Any = None, data_before: Any = None,
                              data_after: Any = None, success: bool = True,
                              error_msg: str = None, transaction_id: str = None) -> str:
        """
        Convenience method for logging data modification operations.
        Ensures all STRIDE tampering/non-repudiation fields are properly set.
        
        Use this for CREATE, UPDATE, DELETE operations.
        
        Args:
            event_type: Type of event (gnmi, netconf, etc.)
            action: Action performed (create_acl, delete_acl, etc.)
            details: Human-readable description
            user_identity: User identification (CN, OU, IP, role)
            client_info: Additional client information
            request_data: Original request (will be hashed for non-repudiation)
            data_before: State before modification (for tampering detection)
            data_after: State after modification (for tampering detection)
            success: Whether operation succeeded
            error_msg: Error message if failed
            transaction_id: Transaction ID (auto-generated if None)
        
        Returns:
            transaction_id for correlation
        """
        severity = "info" if success else "error"
        
        # Build comprehensive client_info
        enhanced_client_info = client_info.copy() if client_info else {}
        enhanced_client_info["success"] = success
        if error_msg:
            enhanced_client_info["error"] = error_msg
        
        return self.log(
            event_type=event_type,
            action=action,
            details=details,
            client_info=enhanced_client_info,
            severity=severity,
            is_tampering=True,  # Data modifications are always tampering-relevant
            transaction_id=transaction_id,
            request_data=request_data,
            data_before=data_before,
            data_after=data_after,
            user_identity=user_identity
        )
    
    def log_access_denied(self, event_type: str, action: str, details: str,
                          user_identity: Dict = None, client_info: Dict = None,
                          request_data: Any = None, transaction_id: str = None) -> str:
        """
        Log unauthorized access attempt (for both tampering detection and non-repudiation).
        Access denial is critical for detecting unauthorized modification attempts.
        
        Args:
            event_type: Type of event (gnmi, netconf, auth)
            action: Attempted action
            details: Description of denial
            user_identity: Who attempted the action
            client_info: Additional context
            request_data: What was requested (for evidence)
            transaction_id: Transaction ID
        
        Returns:
            transaction_id
        """
        enhanced_client_info = client_info.copy() if client_info else {}
        enhanced_client_info["access_denied"] = True
        
        return self.log(
            event_type=event_type,
            action=action,
            details=details,
            client_info=enhanced_client_info,
            severity="critical",  # Access denial is critical security event
            is_tampering=True,    # Unauthorized access attempt
            transaction_id=transaction_id,
            request_data=request_data,
            user_identity=user_identity
        )
    
    def get_tampering_events(self, from_file=False):
        """Get events that indicate potential tampering (data modifications)
        
        Tampering events include:
        - All data modification operations (create, delete, update) - success or failure
        - Unauthorized access attempts
        - Error/critical events related to data modifications
        
        Args:
            from_file: If True, read from file instead of memory
        """
        with self.lock:
            if from_file:
                all_logs = self._read_from_file()
            else:
                all_logs = list(self.logs)
            
            tampering_logs = []
            
            for log in all_logs:
                # Check explicit is_tampering flag first (if present)
                if "is_tampering" in log:
                    if log["is_tampering"]:
                        tampering_logs.append(log)
                    continue
                
                # For older logs without is_tampering field, use auto-detection
                if self._is_tampering_relevant(log["action"], log["details"], log["severity"]):
                    tampering_logs.append(log)
            
            return tampering_logs
    
    def get_logs_by_transaction(self, transaction_id: str, from_file: bool = False) -> list:
        """
        Get all log entries for a specific transaction.
        Used for forensic investigation and non-repudiation verification.
        
        Args:
            transaction_id: Unique transaction identifier
            from_file: Read from file instead of memory
        
        Returns:
            List of log entries for the transaction
        """
        with self.lock:
            if from_file:
                all_logs = self._read_from_file()
            else:
                all_logs = list(self.logs)
            
            return [log for log in all_logs 
                    if log.get("transaction_id") == transaction_id]
    
    def get_logs_by_user(self, cn: str = None, ip: str = None, 
                         from_file: bool = False) -> list:
        """
        Get all log entries for a specific user (by CN or IP).
        Used for audit trails and user activity investigation.
        
        Args:
            cn: Certificate Common Name
            ip: Client IP address
            from_file: Read from file
        
        Returns:
            List of matching log entries
        """
        with self.lock:
            if from_file:
                all_logs = self._read_from_file()
            else:
                all_logs = list(self.logs)
            
            matching = []
            for log in all_logs:
                identity = log.get("user_identity", {})
                if cn and identity.get("cn") == cn:
                    matching.append(log)
                elif ip and identity.get("ip") == ip:
                    matching.append(log)
            
            return matching
    
    def generate_audit_report(self, from_file: bool = True) -> Dict:
        """
        Generate comprehensive audit report for compliance.
        
        Returns:
            Dict containing:
            - total_events: Total number of logged events
            - tampering_events: Number of data modification events
            - access_denials: Number of access denied events
            - by_user: Events grouped by user CN
            - by_action: Events grouped by action type
            - integrity_status: Log integrity verification status
        """
        with self.lock:
            if from_file:
                all_logs = self._read_from_file()
            else:
                all_logs = list(self.logs)
            
            report = {
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "total_events": len(all_logs),
                "tampering_events": 0,
                "access_denials": 0,
                "by_user": {},
                "by_action": {},
                "by_severity": {},
                "integrity_verified": 0,
                "integrity_failed": 0,
                "recent_critical_events": []
            }
            
            for log in all_logs:
                # Count tampering events
                if log.get("is_tampering"):
                    report["tampering_events"] += 1
                
                # Count access denials
                if log.get("client_info", {}).get("access_denied"):
                    report["access_denials"] += 1
                
                # Group by user
                identity = log.get("user_identity", {})
                user_key = identity.get("cn") or identity.get("ip") or "unknown"
                if user_key not in report["by_user"]:
                    report["by_user"][user_key] = 0
                report["by_user"][user_key] += 1
                
                # Group by action
                action = log.get("action", "unknown")
                if action not in report["by_action"]:
                    report["by_action"][action] = 0
                report["by_action"][action] += 1
                
                # Group by severity
                severity = log.get("severity", "info")
                if severity not in report["by_severity"]:
                    report["by_severity"][severity] = 0
                report["by_severity"][severity] += 1
                
                # Verify integrity
                if self.verify_log_integrity(log):
                    report["integrity_verified"] += 1
                else:
                    report["integrity_failed"] += 1
                
                # Track recent critical events
                if severity == "critical":
                    report["recent_critical_events"].append({
                        "timestamp": log.get("timestamp"),
                        "action": action,
                        "user": user_key,
                        "details": log.get("details", "")[:100]
                    })
            
            # Keep only last 10 critical events
            report["recent_critical_events"] = report["recent_critical_events"][-10:]
            
            return report
    
    def clear_logs(self):
        """Clear all logs"""
        with self.lock:
            self.logs.clear()


# Global logger instance
_logger_instance = None
_logger_lock = threading.Lock()


def get_tamper_logger():
    """Get the global tamper logger instance"""
    global _logger_instance
    if _logger_instance is None:
        with _logger_lock:
            if _logger_instance is None:
                _logger_instance = TamperLogger()
    return _logger_instance


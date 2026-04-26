#!/usr/bin/env python3
"""
Session Context Manager — 3S-NOS extension of ZEP-DN.
Adds AGENT role support (OU=auto) and thread-local session tracking
so the adapter can perform AGENT-specific action filtering.
"""

import os
import threading
from typing import Dict, Optional
from dataclasses import dataclass
from sam.role_policy import (
    RolePolicyEngine, get_policy_engine,
    OnapRole, SonicRole, CertCredentials
)

# Thread-local: holds current SessionContext for the active client thread.
# Set by create_session(); read by netconf_gnmi_adapter for AGENT filtering.
_session_local = threading.local()


def is_security_bypassed() -> bool:
    return os.environ.get('SECURITY_BYPASS', '').lower() in ('1', 'true', 'yes')


@dataclass
class SessionContext:
    client_addr: tuple
    onap_role: OnapRole
    sonic_role: SonicRole
    allowed_sonic_roles: list
    client_cn: str = None

    def can_use_role(self, role: SonicRole) -> bool:
        return role in self.allowed_sonic_roles

    def to_dict(self) -> dict:
        return {
            "client_addr": f"{self.client_addr[0]}:{self.client_addr[1]}",
            "client_cn": self.client_cn,
            "onap_role": self.onap_role.value,
            "sonic_role": self.sonic_role.value,
            "allowed_sonic_roles": [r.value for r in self.allowed_sonic_roles]
        }


# SDN-C trusted OUs
TRUSTED_ADMIN_OUS    = {'internal', 'sdnc'}
TRUSTED_OPERATOR_OUS = {'aws'}
TRUSTED_AGENT_OUS    = {'auto'}   # IDS auto-block — DROP-only (enforced in adapter)

# Default role for connections without client cert (SDNC connects via TLS without mTLS cert)
# Zero-trust enforcement is at SF→LEAF layer (gNMI mTLS). SDNC→SF is TLS-encrypted.
NO_CERT_DEFAULT_ROLE = OnapRole.ADMIN


def extract_onap_role_from_cert(cert: dict) -> Optional[OnapRole]:
    """Extract ONAP role from client cert OU field."""
    if is_security_bypassed():
        print("[Auth] SECURITY_BYPASS enabled → ADMIN access")
        return OnapRole.ADMIN

    if not cert:
        print(f"[Auth] No client cert → default role: {NO_CERT_DEFAULT_ROLE.value}")
        return NO_CERT_DEFAULT_ROLE

    subject = {}
    for rdn in cert.get('subject', ()):
        for key, value in rdn:
            subject[key] = value

    ou = subject.get('organizationalUnitName', '').lower()

    if ou in TRUSTED_ADMIN_OUS:
        print(f"[Auth] OU='{ou}' → ADMIN")
        return OnapRole.ADMIN
    elif ou in TRUSTED_OPERATOR_OUS:
        print(f"[Auth] OU='{ou}' → OPERATOR")
        return OnapRole.OPERATOR
    elif ou in TRUSTED_AGENT_OUS:
        print(f"[Auth] OU='{ou}' → AGENT (DROP-only)")
        return OnapRole.AGENT
    elif ou:
        print(f"[Auth] OU='{ou}' is UNTRUSTED → NO ACCESS")
        return None

    print("[Auth] No OU in certificate → NO ACCESS")
    return None


class SessionContextManager:
    def __init__(self, policy_engine: RolePolicyEngine = None):
        self._policy = policy_engine or get_policy_engine()
        self._sessions: Dict[tuple, SessionContext] = {}
        self._lock = threading.Lock()

    def create_session(self, client_addr: tuple, client_cert: dict = None) -> SessionContext:
        onap_role = extract_onap_role_from_cert(client_cert)
        if onap_role is None:
            print(f"[Session] {client_addr} - ACCESS DENIED")
            raise ValueError("Access denied: No valid certificate or untrusted OU")

        client_cn = None
        if client_cert:
            for rdn in client_cert.get('subject', ()):
                for key, value in rdn:
                    if key == 'commonName':
                        client_cn = value
                        break

        allowed_roles = self._policy.get_allowed_roles(onap_role)
        default_role  = self._policy.get_default_role(onap_role)
        if not allowed_roles:
            allowed_roles = [SonicRole.OPERATOR]
            default_role  = SonicRole.OPERATOR

        context = SessionContext(
            client_addr=client_addr,
            onap_role=onap_role,
            sonic_role=default_role,
            allowed_sonic_roles=allowed_roles,
            client_cn=client_cn
        )

        with self._lock:
            self._sessions[client_addr] = context

        # Store in thread-local so adapter can read it without server changes
        _session_local.current = context

        print(f"[Session] {client_addr} CN:{client_cn or 'N/A'} "
              f"ONAP:{onap_role.value} SONiC:{default_role.value}")
        return context

    def get_session(self, client_addr: tuple) -> Optional[SessionContext]:
        with self._lock:
            return self._sessions.get(client_addr)

    def remove_session(self, client_addr: tuple):
        with self._lock:
            if client_addr in self._sessions:
                del self._sessions[client_addr]
                print(f"[Session] {client_addr} - removed")
        _session_local.current = None

    def get_all_sessions(self) -> list:
        with self._lock:
            return [ctx.to_dict() for ctx in self._sessions.values()]

    def count(self) -> int:
        with self._lock:
            return len(self._sessions)


_session_manager: Optional[SessionContextManager] = None

def get_session_manager(policy_engine: RolePolicyEngine = None) -> SessionContextManager:
    global _session_manager
    if _session_manager is None:
        _session_manager = SessionContextManager(policy_engine)
    return _session_manager

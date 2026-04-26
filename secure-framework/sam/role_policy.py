#!/usr/bin/env python3
"""
Role Policy Engine — 3S-NOS extension of ZEP-DN.
Adds OnapRole.AGENT (OU=auto) for IDS auto-block DROP-only access.
"""

import os
import json
import threading
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
from enum import Enum


class SonicRole(Enum):
    """
    SONiC gNMI access roles (CN-based).
    - ADMIN: Full access (CN=sonic-admin) — read/write
    - OPERATOR: Read-only (CN=sonic-operator) — GET only
    """
    ADMIN    = "admin"
    OPERATOR = "operator"


class OnapRole(Enum):
    """
    ONAP SDN-C roles (OU-based from certificate).
      ADMIN    — OU=internal or OU=sdnc — full read/write
      OPERATOR — OU=aws                 — read-only
      AGENT    — OU=auto                — IDS auto-block, DROP-only
                                          (adapter enforces action filter)
    """
    ADMIN    = "admin"
    OPERATOR = "operator"
    AGENT    = "auto"


@dataclass
class CertCredentials:
    cert_file: str
    key_file: str
    ca_cert: str

    def exists(self) -> bool:
        return all(os.path.exists(f) for f in [self.cert_file, self.key_file, self.ca_cert])

    def to_dict(self) -> dict:
        return {
            "cert_file": self.cert_file,
            "key_file": self.key_file,
            "ca_cert": self.ca_cert,
            "exists": self.exists()
        }

    def __repr__(self):
        return f"CertCredentials(cert={self.cert_file})"


@dataclass
class RolePolicy:
    onap_role: OnapRole
    allowed_sonic_roles: List[SonicRole]
    default_sonic_role: SonicRole

    def can_assume(self, sonic_role: SonicRole) -> bool:
        return sonic_role in self.allowed_sonic_roles

    def to_dict(self) -> dict:
        return {
            "onap_role": self.onap_role.value,
            "allowed_sonic_roles": [r.value for r in self.allowed_sonic_roles],
            "default_sonic_role": self.default_sonic_role.value
        }

    @classmethod
    def from_dict(cls, data: dict) -> 'RolePolicy':
        return cls(
            onap_role=OnapRole(data["onap_role"]),
            allowed_sonic_roles=[SonicRole(r) for r in data["allowed_sonic_roles"]],
            default_sonic_role=SonicRole(data["default_sonic_role"])
        )


class RolePolicyEngine:
    CERT_BASE_DIR = "./certificate"

    # ADMIN (OU=internal/sdnc) → can use any SONiC role
    # OPERATOR (OU=aws)        → read-only, operator role only
    # AGENT (OU=auto)          → IDS auto-block: uses admin gNMI channel but
    #                            adapter enforces DROP-only action filter
    DEFAULT_POLICIES = {
        OnapRole.ADMIN: RolePolicy(
            onap_role=OnapRole.ADMIN,
            allowed_sonic_roles=[SonicRole.ADMIN, SonicRole.OPERATOR],
            default_sonic_role=SonicRole.ADMIN
        ),
        OnapRole.OPERATOR: RolePolicy(
            onap_role=OnapRole.OPERATOR,
            allowed_sonic_roles=[SonicRole.OPERATOR],
            default_sonic_role=SonicRole.OPERATOR
        ),
        OnapRole.AGENT: RolePolicy(
            onap_role=OnapRole.AGENT,
            allowed_sonic_roles=[SonicRole.ADMIN],
            default_sonic_role=SonicRole.ADMIN
        ),
    }

    def __init__(self, cert_base_dir: str = None):
        self.cert_base_dir = cert_base_dir or self.CERT_BASE_DIR
        self._lock = threading.Lock()
        self._policies: Dict[OnapRole, RolePolicy] = dict(self.DEFAULT_POLICIES)

    def get_sonic_credentials(self, sonic_role: SonicRole) -> CertCredentials:
        role_dir = os.path.join(self.cert_base_dir, "adapter", "gnmi", sonic_role.value)
        return CertCredentials(
            cert_file=os.path.join(role_dir, "client.crt"),
            key_file=os.path.join(role_dir, "client.key"),
            ca_cert=os.path.join(role_dir, "trustedCertificates.crt")
        )

    def get_policy(self, onap_role: OnapRole) -> Optional[RolePolicy]:
        with self._lock:
            return self._policies.get(onap_role)

    def get_all_policies(self) -> Dict[str, dict]:
        with self._lock:
            return {role.value: policy.to_dict() for role, policy in self._policies.items()}

    def update_policy(self, onap_role: OnapRole,
                      allowed_sonic_roles: List[SonicRole] = None,
                      default_sonic_role: SonicRole = None) -> RolePolicy:
        with self._lock:
            current = self._policies.get(onap_role)
            if allowed_sonic_roles is None:
                allowed_sonic_roles = current.allowed_sonic_roles if current else [SonicRole.OPERATOR]
            if default_sonic_role is None:
                default_sonic_role = current.default_sonic_role if current else SonicRole.OPERATOR
            if default_sonic_role not in allowed_sonic_roles:
                default_sonic_role = allowed_sonic_roles[0] if allowed_sonic_roles else SonicRole.OPERATOR
            new_policy = RolePolicy(
                onap_role=onap_role,
                allowed_sonic_roles=allowed_sonic_roles,
                default_sonic_role=default_sonic_role
            )
            self._policies[onap_role] = new_policy
            print(f"[Policy] Updated: {onap_role.value} → {[r.value for r in allowed_sonic_roles]}")
            return new_policy

    def reset_to_defaults(self):
        with self._lock:
            self._policies = dict(self.DEFAULT_POLICIES)
            print("[Policy] Reset to defaults")

    def can_assume_role(self, onap_role: OnapRole, sonic_role: SonicRole) -> bool:
        policy = self.get_policy(onap_role)
        return policy.can_assume(sonic_role) if policy else False

    def get_allowed_roles(self, onap_role: OnapRole) -> List[SonicRole]:
        policy = self.get_policy(onap_role)
        return policy.allowed_sonic_roles if policy else []

    def get_default_role(self, onap_role: OnapRole) -> Optional[SonicRole]:
        policy = self.get_policy(onap_role)
        return policy.default_sonic_role if policy else None

    def export_policies(self) -> str:
        return json.dumps(self.get_all_policies(), indent=2)

    def import_policies(self, json_str: str):
        data = json.loads(json_str)
        with self._lock:
            for role_str, policy_data in data.items():
                onap_role = OnapRole(role_str)
                self._policies[onap_role] = RolePolicy.from_dict(policy_data)
        print(f"[Policy] Imported {len(data)} policies")


_policy_engine = None

def get_policy_engine(cert_base_dir: str = None) -> RolePolicyEngine:
    global _policy_engine
    if _policy_engine is None:
        _policy_engine = RolePolicyEngine(cert_base_dir)
    return _policy_engine

def reset_policy_engine():
    global _policy_engine
    _policy_engine = None

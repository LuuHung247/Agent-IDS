#!/usr/bin/env python3
"""
3S-NOS Multi-LEAF gNMI Connection Pool

Pool keyed by (SonicRole, leaf_ip). Zone-based routing maps src-prefix
to the correct LEAF for gNMI Set operations.

Target: nos-acl-bridge gNMI server on each LEAF, port 9339 (IANA-registered).
NOT SONiC telemetry :8080 — that runs --noTLS and translib does not handle
custom YANG (3snos-iptables) writes. The bridge daemon hosts its own gNMI
server with mTLS, validates payload, writes ConfigDB locally, applies iptables.

Zone → LEAF mapping (DATAPLANE.md §9.4):
  10.1.100.0/24 (WEB) → LEAF-1  192.168.122.20
  10.1.200.0/24 (DB)  → LEAF-1  192.168.122.20
  10.2.100.0/24 (APP) → LEAF-2  192.168.122.21
  10.2.50.0/24  (MGT) → LEAF-2  192.168.122.21
"""

import ipaddress
import threading
import time
from typing import Dict, List, Optional, Tuple, Callable

from gnmi.gnmiclient import SonicGnmiClient, set_intentional_disconnect
from sam.role_policy import SonicRole, get_policy_engine, RolePolicyEngine, CertCredentials


ZONE_TO_LEAF: Dict[str, str] = {
    "10.1.100.0/24": "192.168.122.20",
    "10.1.200.0/24": "192.168.122.20",
    "10.2.100.0/24": "192.168.122.21",
    "10.2.50.0/24":  "192.168.122.21",
}

_ZONE_NETWORKS = {
    ipaddress.ip_network(prefix): leaf_ip
    for prefix, leaf_ip in ZONE_TO_LEAF.items()
}

DEFAULT_LEAF1 = "192.168.122.20"
DEFAULT_LEAF2 = "192.168.122.21"

# TLS hostname override per LEAF (must match SAN DNS in bridge server cert)
LEAF_TLS_HOSTNAME: Dict[str, str] = {
    DEFAULT_LEAF1: "sonic-leaf-1",
    DEFAULT_LEAF2: "sonic-leaf-2",
}


def ip_to_leaf(src: str) -> Optional[str]:
    """Map a src IP or prefix to the LEAF that owns its zone."""
    try:
        net = ipaddress.ip_network(src, strict=False)
    except ValueError:
        return None
    for zone_net, leaf_ip in _ZONE_NETWORKS.items():
        if net.subnet_of(zone_net):
            return leaf_ip
    return None


class NosGnmiConnectionPool:
    """
    Multi-LEAF gNMI connection pool for 3S-NOS Secure Framework.

    _connections keyed by (SonicRole, leaf_ip).
    get_client(role) — single-arg shim for NetconfTLSServer compatibility.
    get_client_for_zone(role, src_prefix) — zone-routed access for adapter.
    """

    def __init__(
        self,
        leaves: Dict[str, str],
        port: int = 9339,
        username: str = None,
        password: str = None,
        policy_engine: RolePolicyEngine = None,
        on_disconnect: Callable = None,
        cert_override: Optional[CertCredentials] = None,
    ):
        self.leaves = leaves        # {"leaf-1": "192.168.122.20", ...}
        self.port = port
        self.username = username
        self.password = password
        self._policy = policy_engine or get_policy_engine()
        self._on_disconnect = on_disconnect
        # If set, used for ALL (role, leaf) connections instead of policy lookup.
        # Use case: SF runs as Agent-IDS with agent-ids/client.crt (OU=auto → AGENT)
        # Bridge enforces RBAC by cert OU regardless of internal SonicRole label.
        self._cert_override = cert_override

        self._connections: Dict[Tuple[SonicRole, str], Optional[SonicGnmiClient]] = {}
        self._lock = threading.RLock()
        self._enabled: set = set()

    def _key(self, role: SonicRole, leaf_ip: str) -> Tuple[SonicRole, str]:
        return (role, leaf_ip)

    def _make_disconnect_handler(self, role: SonicRole, leaf_ip: str) -> Callable:
        def handler(error: Exception):
            print(f"[NosPool] Lost: {role.value}@{leaf_ip}: {error}")
            with self._lock:
                self._connections[self._key(role, leaf_ip)] = None
            if self._on_disconnect:
                self._on_disconnect(role, leaf_ip, error)
        return handler

    def connect_role_leaf(self, role: SonicRole, leaf_ip: str) -> bool:
        creds = self._cert_override if self._cert_override else self._policy.get_sonic_credentials(role)
        if not creds.exists():
            print(f"[NosPool] ✗ Creds missing for {role.value}: {creds.cert_file}")
            return False

        tls_hostname = LEAF_TLS_HOSTNAME.get(leaf_ip, leaf_ip)
        print(f"[NosPool] Connecting {role.value}@{leaf_ip}:{self.port} (TLS CN={tls_hostname}) ...")
        client = SonicGnmiClient(
            host=leaf_ip,
            port=self.port,
            client_cert=creds.cert_file,
            client_key=creds.key_file,
            ca_cert=creds.ca_cert,
            tls_hostname_override=tls_hostname,
            username=self.username,
            password=self.password,
            auto_reconnect=False,
            on_disconnect=self._make_disconnect_handler(role, leaf_ip),
        )

        # start_monitor=False: bridge does not implement gNMI Subscribe
        if client.connect(start_monitor=False):
            key = self._key(role, leaf_ip)
            with self._lock:
                existing = self._connections.get(key)
                if existing:
                    try:
                        existing.close()
                    except Exception:
                        pass
                self._connections[key] = client
                self._enabled.add(key)
            print(f"[NosPool] ✓ {role.value}@{leaf_ip}")
            return True

        print(f"[NosPool] ✗ Failed: {role.value}@{leaf_ip}")
        return False

    def connect_all(self) -> Dict[Tuple[SonicRole, str], bool]:
        results = {}
        for role in SonicRole:
            for leaf_ip in self.leaves.values():
                results[self._key(role, leaf_ip)] = self.connect_role_leaf(role, leaf_ip)
        return results

    def get_client_by_key(self, role: SonicRole, leaf_ip: str) -> Optional[SonicGnmiClient]:
        with self._lock:
            client = self._connections.get(self._key(role, leaf_ip))
            if client and client.connected:
                return client
            return None

    def get_client_for_zone(self, role: SonicRole, src_prefix: str) -> Optional[SonicGnmiClient]:
        """Zone-routed client lookup: src_prefix → leaf_ip → client."""
        leaf_ip = ip_to_leaf(src_prefix)
        if leaf_ip is None:
            print(f"[NosPool] Unknown zone for {src_prefix}, defaulting to LEAF-1")
            leaf_ip = DEFAULT_LEAF1
        client = self.get_client_by_key(role, leaf_ip)
        if client is None:
            print(f"[NosPool] ✗ No active client for {role.value}@{leaf_ip}")
        return client

    def get_any_client(self, role: SonicRole = SonicRole.ADMIN) -> Optional[SonicGnmiClient]:
        """Return first available client for the given role (any LEAF)."""
        with self._lock:
            for leaf_ip in self.leaves.values():
                client = self._connections.get(self._key(role, leaf_ip))
                if client and client.connected:
                    return client
        return None

    # Shim for NetconfTLSServer which calls pool.get_client(sonic_role)
    def get_client(self, role: SonicRole) -> Optional[SonicGnmiClient]:
        return self.get_any_client(role)

    def reconnect(self, role: SonicRole, leaf_ip: str) -> bool:
        print(f"[NosPool] Reconnecting {role.value}@{leaf_ip} ...")
        set_intentional_disconnect(True)
        try:
            key = self._key(role, leaf_ip)
            with self._lock:
                existing = self._connections.get(key)
                if existing:
                    try:
                        existing.close()
                    except Exception:
                        pass
                    self._connections[key] = None
            time.sleep(1)
            set_intentional_disconnect(False)
            return self.connect_role_leaf(role, leaf_ip)
        except Exception as e:
            print(f"[NosPool] ✗ Reconnect failed {role.value}@{leaf_ip}: {e}")
            set_intentional_disconnect(False)
            return False

    def is_connected(self, role: SonicRole, leaf_ip: str) -> bool:
        with self._lock:
            client = self._connections.get(self._key(role, leaf_ip))
            return client is not None and client.connected

    def get_status(self) -> dict:
        with self._lock:
            status = {"port": self.port, "leaves": {}}
            for leaf_name, leaf_ip in self.leaves.items():
                status["leaves"][leaf_name] = {
                    "ip": leaf_ip,
                    "connections": {
                        role.value: self.is_connected(role, leaf_ip)
                        for role in SonicRole
                    }
                }
            return status

    def close_all(self):
        set_intentional_disconnect(True)
        with self._lock:
            for client in self._connections.values():
                if client:
                    try:
                        client.close()
                    except Exception:
                        pass
            self._connections.clear()
            self._enabled.clear()
        set_intentional_disconnect(False)
        print("[NosPool] All connections closed")


_nos_pool: Optional[NosGnmiConnectionPool] = None


def get_nos_pool(
    leaves: Dict[str, str] = None,
    port: int = 9339,
    username: str = None,
    password: str = None,
    policy_engine: RolePolicyEngine = None,
    cert_override: Optional[CertCredentials] = None,
) -> NosGnmiConnectionPool:
    global _nos_pool
    if _nos_pool is None:
        if leaves is None:
            leaves = {"leaf-1": DEFAULT_LEAF1, "leaf-2": DEFAULT_LEAF2}
        _nos_pool = NosGnmiConnectionPool(
            leaves, port, username, password, policy_engine,
            cert_override=cert_override,
        )
    return _nos_pool


def reset_nos_pool():
    global _nos_pool
    if _nos_pool:
        _nos_pool.close_all()
    _nos_pool = None

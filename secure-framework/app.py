#!/usr/bin/env python3
"""
3S-NOS Secure Framework — Standalone Entry Point

Self-contained NETCONF/TLS → gNMI/TLS adapter for ONAP SDNC ↔ SONiC LEAF.
No external dependencies on Application_demo. All required modules live under
nos_acl_tools/.

Architecture (zero-trust micro-segmentation):
  ONAP SDNC ─NETCONF/TLS:6513─► SF (this app) ─gNMI/TLS:9339─► nos-acl-bridge
                                                                       │
                                                                       ▼
                                                              ConfigDB DB4
                                                              + iptables FORWARD

RBAC (mTLS client cert OU):
  internal/sdnc → ADMIN     (full CRUD)
  aws           → OPERATOR  (read + Set, no delete)
  auto          → AGENT     (DROP-only + source=ids-auto, defense in depth)

Usage:
  python3 app.py \\
      --leaf1-host 192.168.122.20 \\
      --leaf2-host 192.168.122.21 \\
      --gnmi-port 9339 \\
      --client-cert ./certificate/generate/output_3snos/agent-ids/client.crt \\
      --client-key  ./certificate/generate/output_3snos/agent-ids/client.key \\
      --client-ca   ./certificate/generate/output_3snos/agent-ids/trustedCertificates.crt
"""

import sys
import os

# Self-contained: secure-framework/ is the only path needed
NOS_TOOLS = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, NOS_TOOLS)

from netconf.netconfserver import NetconfTLSServer
from sam.role_policy import get_policy_engine, CertCredentials
from sam.session_context import get_session_manager
from nos_gnmi_pool import get_nos_pool
import netconf_gnmi_adapter as _adapter_module
from sam.role_api import create_role_api
from tamper_logger import get_tamper_logger


def main():
    import argparse

    parser = argparse.ArgumentParser(
        description='3S-NOS Secure Framework — multi-LEAF NETCONF→gNMI Adapter',
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    # ── Multi-LEAF gNMI targets (nos-acl-bridge endpoints) ─────────────────────
    parser.add_argument('--leaf1-host', default='192.168.122.20',
                        help='SONIC-LEAF-1 IP (default: 192.168.122.20)')
    parser.add_argument('--leaf2-host', default='192.168.122.21',
                        help='SONIC-LEAF-2 IP (default: 192.168.122.21)')
    parser.add_argument('--gnmi-port', type=int, default=9339,
                        help='nos-acl-bridge gNMI port (default: 9339, IANA-registered). '
                             'Bridge runs on each LEAF, accepts mTLS-authenticated gNMI Set '
                             'on path /nos-iptables:acl/rule[rule-id=...].')
    parser.add_argument('--sonic-user', default='admin')
    parser.add_argument('--sonic-pass', default='YourPaSsWoRd')

    # ── NETCONF/TLS server (faces ONAP SDNC) ───────────────────────────────────
    parser.add_argument('--port', type=int, default=6513,
                        help='NETCONF TLS listen port (default: 6513)')
    parser.add_argument('--cert', default=None,
                        help='NETCONF server certificate '
                             '(default: ./certificate/server/server.crt)')
    parser.add_argument('--key',  default=None,
                        help='NETCONF server private key')
    parser.add_argument('--ca',   default=None,
                        help='CA certificate for SDNC client cert verification')
    parser.add_argument('--require-client-cert', action='store_true', default=True)
    parser.add_argument('--no-require-client-cert', action='store_false',
                        dest='require_client_cert')

    # ── Role management REST API ───────────────────────────────────────────────
    parser.add_argument('--api-port', type=int, default=9090,
                        help='Role management API port (default: 9090)')

    # ── gNMI client cert directory (for connecting to bridge) ──────────────────
    parser.add_argument('--cert-dir', default=os.path.join(NOS_TOOLS, 'certificate'),
                        help='Base certificate directory for gNMI role certs '
                             '(default: ./certificate). Used when --client-cert NOT set.')

    # ── Override: use a single client cert for ALL gNMI bridge connections ─────
    parser.add_argument('--client-cert', default=None,
                        help='Override client cert for gNMI bridge connection. '
                             'Bridge enforces RBAC by cert OU '
                             '(internal/sdnc=ADMIN, aws=OPERATOR, auto=AGENT). '
                             'Default: use per-role certs from --cert-dir.')
    parser.add_argument('--client-key', default=None, help='Client key for --client-cert')
    parser.add_argument('--client-ca',  default=None, help='CA cert for --client-cert')

    args = parser.parse_args()

    # ── Logging ────────────────────────────────────────────────────────────────
    tamper_logger = get_tamper_logger()
    tamper_logger.log("system", "startup",
                      "3S-NOS Secure Framework starting", severity="info")

    # ── Policy + Session ───────────────────────────────────────────────────────
    policy = get_policy_engine(args.cert_dir)
    session_manager = get_session_manager(policy)

    # ── NETCONF server certificates ────────────────────────────────────────────
    cert_file = args.cert or os.path.join(NOS_TOOLS, 'certificate/server/server.crt')
    key_file  = args.key  or os.path.join(NOS_TOOLS, 'certificate/server/server.key')
    ca_file   = args.ca   or os.path.join(NOS_TOOLS, 'certificate/server/trustedCertificates.crt')

    if not os.path.exists(cert_file) or not os.path.exists(key_file):
        print(f"ERROR: NETCONF server certificates not found!")
        print(f"       cert: {cert_file}")
        print(f"       key:  {key_file}")
        print(f"")
        print(f"Generate them with:")
        print(f"  cd {NOS_TOOLS}/certificate/generate")
        print(f"  python3 generate_3snos_certs.py --force")
        print(f"  # Then move output_3snos/sonic/leaf-1/server.* into ./certificate/server/")
        print(f"  # OR pass --cert/--key/--ca explicitly")
        sys.exit(1)

    # ── Multi-LEAF gNMI pool ────────────────────────────────────────────────────
    leaves = {"leaf-1": args.leaf1_host, "leaf-2": args.leaf2_host}

    cert_override = None
    if args.client_cert:
        if not args.client_key or not args.client_ca:
            print("ERROR: --client-cert requires both --client-key and --client-ca")
            sys.exit(1)
        cert_override = CertCredentials(
            cert_file=args.client_cert,
            key_file=args.client_key,
            ca_cert=args.client_ca,
        )
        if not cert_override.exists():
            print(f"ERROR: client cert files not found: {cert_override}")
            sys.exit(1)
        try:
            import subprocess
            subj = subprocess.check_output(
                ['openssl', 'x509', '-in', args.client_cert, '-noout', '-subject'],
                text=True
            ).strip()
            print(f"\n[CertOverride] {args.client_cert}")
            print(f"[CertOverride] {subj}")
            print(f"[CertOverride] Bridge RBAC enforced by OU above.\n")
        except Exception:
            pass

    pool = get_nos_pool(
        leaves=leaves,
        port=args.gnmi_port,
        username=args.sonic_user,
        password=args.sonic_pass,
        policy_engine=policy,
        cert_override=cert_override,
    )

    # Wire pool into adapter for zone routing
    _adapter_module._nos_pool = pool

    print(f"\n{'='*70}")
    print(f"3S-NOS Secure Framework — connecting gNMI pool to bridge endpoints")
    print(f"{'='*70}")
    connection_results = pool.connect_all()

    connected = [(role, lip) for (role, lip), ok in connection_results.items() if ok]
    failed    = [(role, lip) for (role, lip), ok in connection_results.items() if not ok]

    for role, leaf_ip in connected:
        print(f"  ✓ {role.value}@{leaf_ip}")
        tamper_logger.log("gnmi", "connect", f"{role.value}@{leaf_ip} connected", severity="info")
    for role, leaf_ip in failed:
        print(f"  ✗ {role.value}@{leaf_ip} (creds missing or unreachable)")
        tamper_logger.log("gnmi", "connect_failed", f"{role.value}@{leaf_ip} failed", severity="warning")

    if not connected:
        print("\nERROR: No gNMI connections established")
        print("       Check: bridge running on LEAF? cert files valid? IP reachable?")
        sys.exit(1)

    print(f"\n{'='*70}")
    print(f"3S-NOS Secure Framework — READY")
    print(f"{'='*70}")
    print(f"  NETCONF listen : 0.0.0.0:{args.port}    (mTLS for ONAP SDNC)")
    print(f"  LEAF-1 bridge  : {args.leaf1_host}:{args.gnmi_port}")
    print(f"  LEAF-2 bridge  : {args.leaf2_host}:{args.gnmi_port}")
    print(f"  Role API       : http://0.0.0.0:{args.api_port}")
    print(f"\nPolicies (OnapRole → SonicRole):")
    for onap_role, pd in policy.get_all_policies().items():
        allowed  = ', '.join(pd['allowed_sonic_roles'])
        default_ = pd['default_sonic_role']
        print(f"  {onap_role:8s} → [{allowed}] (default: {default_})")
    print(f"{'='*70}\n")

    # ── Role management REST API ────────────────────────────────────────────────
    role_api = create_role_api(
        port=args.api_port,
        service_account=None,
        policy_engine=policy,
        session_manager=session_manager,
        gnmi_pool=pool,
        on_reconnect_gnmi=None,
    )
    tamper_logger.log("api", "start", f"Role API on :{args.api_port}", severity="info")

    # ── NETCONF TLS server ──────────────────────────────────────────────────────
    server = NetconfTLSServer(
        listen_port=args.port,
        cert_file=cert_file,
        key_file=key_file,
        ca_file=ca_file if os.path.exists(ca_file) else None,
        require_client_cert=args.require_client_cert,
        gnmi_pool=pool,
        session_manager=session_manager,
    )
    tamper_logger.log("netconf", "start", f"NETCONF on :{args.port}", severity="info")

    try:
        server.start()
    except KeyboardInterrupt:
        print("\nShutting down 3S-NOS Secure Framework...")
        tamper_logger.log("system", "shutdown", "Shutting down", severity="info")
        pool.close_all()
        role_api.stop()
        sys.exit(0)


if __name__ == '__main__':
    main()

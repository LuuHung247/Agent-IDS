#!/usr/bin/env python3
"""
3S-NOS Secure Framework — Certificate Generator

Extends ZEP-DN PKI (ONAP-SONiC-CA) with multi-LEAF topology certs:
  - LEAF-1 gNMI server cert  (SAN=IP:192.168.122.20, CN=sonic-leaf-1)
  - LEAF-2 gNMI server cert  (SAN=IP:192.168.122.21, CN=sonic-leaf-2)
  - agent-ids client cert    (CN=agent-ids, OU=auto — DROP-only AGENT role)

Reuses existing CA from ZEP-DN so all previously deployed SDNC/adapter
certs remain valid.

Usage:
  python3 generate_3snos_certs.py
  python3 generate_3snos_certs.py --leaf1-ip 192.168.122.20 --leaf2-ip 192.168.122.21
  python3 generate_3snos_certs.py --ca-crt /path/to/ca.crt --ca-key /path/to/ca.key
"""

import os
import subprocess
import argparse
import shutil

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_OUTPUT = os.path.join(SCRIPT_DIR, "output_3snos")

ZEPDN_GENERATE = os.path.normpath(
    os.path.join(SCRIPT_DIR, '..', '..', '..', '..', 'Application_demo',
                 'acl_policy', 'certificate', 'generate')
)
EXISTING_CA_CRT = os.path.join(ZEPDN_GENERATE, "output", "ca.crt")
EXISTING_CA_KEY = os.path.join(ZEPDN_GENERATE, "output", "ca.key")

DEFAULTS = {
    "leaf1_ip": "192.168.122.20",
    "leaf2_ip": "192.168.122.21",
    "leaf1_cn": "sonic-leaf-1",
    "leaf2_cn": "sonic-leaf-2",
    "agent_cn": "agent-ids",
    "agent_ou": "auto",
    "validity_days": 365,
    "key_size": 2048,
}


def run(cmd, cwd=None):
    print(f"  $ {' '.join(cmd)}")
    r = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
    if r.returncode != 0:
        print(f"  ERROR: {r.stderr.strip()}")
        raise RuntimeError(f"Command failed: {' '.join(cmd)}")
    return r.stdout


def ensure_dir(path):
    os.makedirs(path, exist_ok=True)
    return path


def gen_leaf_server_cert(out_dir, ca_crt, ca_key, cn, ip, days, key_size):
    ensure_dir(out_dir)
    key = os.path.join(out_dir, "server.key")
    csr = os.path.join(out_dir, "server.csr")
    crt = os.path.join(out_dir, "server.crt")
    ext = os.path.join(out_dir, "server.ext")
    tca = os.path.join(out_dir, "trustedCertificates.crt")

    print(f"\n[LEAF server] CN={cn}  SAN=IP:{ip}")
    run(["openssl", "genrsa", "-out", key, str(key_size)])
    run(["openssl", "req", "-new", "-key", key, "-out", csr,
         "-subj", f"/CN={cn}/O=3SNOS/OU=gNMI"])

    with open(ext, "w") as f:
        f.write(
            "authorityKeyIdentifier=keyid,issuer\n"
            "basicConstraints=CA:FALSE\n"
            "keyUsage = digitalSignature, keyEncipherment\n"
            f"subjectAltName = IP:{ip},DNS:{cn},DNS:localhost\n"
        )

    run(["openssl", "x509", "-req", "-in", csr, "-CA", ca_crt, "-CAkey", ca_key,
         "-CAcreateserial", "-out", crt, "-days", str(days), "-sha256", "-extfile", ext])

    shutil.copy(ca_crt, tca)
    os.remove(csr)
    os.remove(ext)
    print(f"  ✓ {crt}")


def gen_client_cert(out_dir, ca_crt, ca_key, cn, ou, org, days, key_size):
    ensure_dir(out_dir)
    key = os.path.join(out_dir, "client.key")
    csr = os.path.join(out_dir, "client.csr")
    crt = os.path.join(out_dir, "client.crt")
    tca = os.path.join(out_dir, "trustedCertificates.crt")

    print(f"\n[Client cert] CN={cn}  OU={ou}  O={org}")
    run(["openssl", "genrsa", "-out", key, str(key_size)])
    run(["openssl", "req", "-new", "-key", key, "-out", csr,
         "-subj", f"/CN={cn}/O={org}/OU={ou}"])
    run(["openssl", "x509", "-req", "-in", csr, "-CA", ca_crt, "-CAkey", ca_key,
         "-CAcreateserial", "-out", crt, "-days", str(days), "-sha256"])

    shutil.copy(ca_crt, tca)
    os.remove(csr)
    print(f"  ✓ {crt}")


def verify_cert(crt, ca_crt, label):
    try:
        run(["openssl", "verify", "-CAfile", ca_crt, crt])
        print(f"  ✓ VERIFY OK: {label}")
    except RuntimeError:
        print(f"  ✗ VERIFY FAIL: {label}")


def main():
    parser = argparse.ArgumentParser(
        description="3S-NOS cert generator — extends ZEP-DN PKI for multi-LEAF topology"
    )
    parser.add_argument("--leaf1-ip",  default=DEFAULTS["leaf1_ip"])
    parser.add_argument("--leaf2-ip",  default=DEFAULTS["leaf2_ip"])
    parser.add_argument("--leaf1-cn",  default=DEFAULTS["leaf1_cn"])
    parser.add_argument("--leaf2-cn",  default=DEFAULTS["leaf2_cn"])
    parser.add_argument("--agent-cn",  default=DEFAULTS["agent_cn"])
    parser.add_argument("--agent-ou",  default=DEFAULTS["agent_ou"])
    parser.add_argument("--ca-crt",    default=EXISTING_CA_CRT)
    parser.add_argument("--ca-key",    default=EXISTING_CA_KEY)
    parser.add_argument("--out-dir",   default=DEFAULT_OUTPUT)
    parser.add_argument("--days",      type=int, default=DEFAULTS["validity_days"])
    parser.add_argument("--key-size",  type=int, default=DEFAULTS["key_size"])
    parser.add_argument("--force",     action="store_true")
    args = parser.parse_args()

    print("=" * 60)
    print("3S-NOS Secure Framework — Certificate Generator")
    print("=" * 60)

    if not os.path.exists(args.ca_crt) or not os.path.exists(args.ca_key):
        print(f"\n✗ Existing CA not found:")
        print(f"    ca.crt : {args.ca_crt}")
        print(f"    ca.key : {args.ca_key}")
        print("\n  Run ZEP-DN generate_role_certs.py first, or pass --ca-crt / --ca-key.")
        return 1

    out = args.out_dir
    if os.path.exists(out) and not args.force:
        print(f"\n⚠  Output dir exists: {out}")
        print("   Use --force to overwrite.")
        return 1

    ensure_dir(out)
    shutil.copy(args.ca_crt, os.path.join(out, "ca.crt"))

    ca_crt = args.ca_crt
    ca_key = args.ca_key
    days   = args.days
    ks     = args.key_size

    gen_leaf_server_cert(
        out_dir=os.path.join(out, "sonic", "leaf-1"),
        ca_crt=ca_crt, ca_key=ca_key,
        cn=args.leaf1_cn, ip=args.leaf1_ip,
        days=days, key_size=ks,
    )
    gen_leaf_server_cert(
        out_dir=os.path.join(out, "sonic", "leaf-2"),
        ca_crt=ca_crt, ca_key=ca_key,
        cn=args.leaf2_cn, ip=args.leaf2_ip,
        days=days, key_size=ks,
    )
    gen_client_cert(
        out_dir=os.path.join(out, "agent-ids"),
        ca_crt=ca_crt, ca_key=ca_key,
        cn=args.agent_cn, ou=args.agent_ou, org="3SNOS",
        days=days, key_size=ks,
    )

    print("\n" + "=" * 60)
    print("Verification")
    print("=" * 60)
    verify_cert(os.path.join(out, "sonic", "leaf-1", "server.crt"), ca_crt, "LEAF-1 server")
    verify_cert(os.path.join(out, "sonic", "leaf-2", "server.crt"), ca_crt, "LEAF-2 server")
    verify_cert(os.path.join(out, "agent-ids", "client.crt"),       ca_crt, "agent-ids client")

    print(f"\n{'='*60}")
    print("Output layout:")
    print(f"  {out}/")
    print("  ├── ca.crt")
    print("  ├── sonic/")
    print("  │   ├── leaf-1/server.crt  ← SAN=IP:192.168.122.20")
    print("  │   └── leaf-2/server.crt  ← SAN=IP:192.168.122.21")
    print("  └── agent-ids/client.crt   ← CN=agent-ids, OU=auto")
    print()
    print("Next steps:")
    print("  1. Deploy sonic/leaf-{1,2}/ to /etc/sonic/telemetry/ on each LEAF")
    print("  2. Adapter uses Application_demo/certificate/adapter/gnmi/{admin,operator}/")
    print("  3. agent-ids/client.crt used by Agent-IDS when AGENT role needed")
    print(f"{'='*60}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

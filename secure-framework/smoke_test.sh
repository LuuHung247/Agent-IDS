#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# 3S-NOS Secure Framework — End-to-End Smoke Test
#
# Run ON GNS3VM after SF is running (python3 app.py ...)
# Tests: gNMI direct → bridge, then NETCONF → SF → bridge → iptables
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

SF_DIR="/3s-com/zma/secure-framework"
LEAF1="192.168.122.20"
LEAF2="192.168.122.21"
GNMI_PORT="9339"
NETCONF_PORT="6513"
SF_HOST="127.0.0.1"  # SF runs locally on gns3vm

CERTS="$SF_DIR/certificate/generate/output_3snos"
AGENT_CERT="$CERTS/agent-ids/client.crt"
AGENT_KEY="$CERTS/agent-ids/client.key"
AGENT_CA="$CERTS/agent-ids/trustedCertificates.crt"

PASS=0; FAIL=0

check() {
    local label="$1"; shift
    if "$@" &>/dev/null; then
        echo "  ✓ $label"; ((PASS++)) || true
    else
        echo "  ✗ $label"; ((FAIL++)) || true
    fi
}

echo "=== Smoke Test — 3S-NOS Secure Framework ==="
echo ""

# ── SMOKE 1: bridge reachability ─────────────────────────────────────────────
echo "[SMOKE 1] bridge reachability"
check "LEAF-1 gNMI port open" nc -z -w3 "$LEAF1" "$GNMI_PORT"
check "LEAF-2 gNMI port open" nc -z -w3 "$LEAF2" "$GNMI_PORT"
echo ""

# ── SMOKE 2: SF NETCONF port open ────────────────────────────────────────────
echo "[SMOKE 2] SF NETCONF port"
check "SF :6513 listening" nc -z -w3 "$SF_HOST" "$NETCONF_PORT"
echo ""

# ── SMOKE 3: gNMI Set direct to bridge (agent-ids cert, OU=auto → AGENT) ──
echo "[SMOKE 3] gNMI Set direct → LEAF-1 bridge"
if command -v gnmic &>/dev/null; then
    RULE_ID="smoke-test-$(date +%s)"
    gnmic --address "${LEAF1}:${GNMI_PORT}" \
          --tls-cert "$AGENT_CERT" \
          --tls-key  "$AGENT_KEY" \
          --tls-ca   "$AGENT_CA" \
          set \
          --update-path "/nos-iptables:acl/rule[rule-id=${RULE_ID}]" \
          --update-value "{\"action\":\"DROP\",\"src-ip\":\"10.1.100.1/32\",\"source\":\"ids-auto\",\"priority\":50}" \
          --encoding json_ietf && \
        check "gNMI Set LEAF-1" true || check "gNMI Set LEAF-1" false

    # Verify rule in iptables on LEAF-1
    echo "  [manual] ssh admin@${LEAF1} sudo iptables -L FORWARD -n | grep ${RULE_ID}"
else
    echo "  (gnmic not installed — skip direct gNMI test)"
    echo "  Install: curl -sL https://get-gnmic.kmrd.dev | bash"
fi
echo ""

# ── SMOKE 4: NETCONF edit-config via ncclient ────────────────────────────────
echo "[SMOKE 4] NETCONF edit-config via SF"
python3 - <<PYEOF
import sys
sys.path.insert(0, '$SF_DIR')
try:
    from ncclient import manager
    RULE_ID = "nc-smoke-test"
    PAYLOAD = '''
    <config>
      <acl xmlns="urn:3snos:iptables">
        <rule>
          <rule-id>${RULE_ID}</rule-id>
          <action>DROP</action>
          <src-ip>10.1.100.2/32</src-ip>
          <priority>50</priority>
          <source>ids-auto</source>
        </rule>
      </acl>
    </config>'''
    with manager.connect(
        host='$SF_HOST',
        port=$NETCONF_PORT,
        username='admin',
        password='admin',
        hostkey_verify=False,
        manager_params={'timeout': 10},
    ) as m:
        reply = m.edit_config(target='running', config=PAYLOAD)
        if reply.ok:
            print("  ✓ NETCONF edit-config accepted by SF")
        else:
            print(f"  ✗ NETCONF error: {reply}")
except ImportError:
    print("  (ncclient not installed — pip3 install ncclient)")
except Exception as e:
    print(f"  ✗ NETCONF: {e}")
PYEOF
echo ""

# ── Summary ──────────────────────────────────────────────────────────────────
echo "=== Result: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ] && exit 0 || exit 1

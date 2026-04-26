#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# 3S-NOS Secure Framework — gns3vm Deploy Script
#
# Run this ON THE GNS3VM HOST (the machine that has virbr0 / 192.168.122.0/24)
#
# Usage (from control-plane server):
#   scp /home/dis/deploy/3snos-secure-framework.tar.gz  dis@<gns3vm>:/tmp/
#   scp /home/dis/deploy/Agent-IDS/nos_acl_tools/deploy_gns3vm.sh  dis@<gns3vm>:/tmp/
#   ssh dis@<gns3vm> "bash /tmp/deploy_gns3vm.sh"
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

DEPLOY_DIR="/3s-com/zma/secure-framework"
TARBALL="/tmp/3snos-secure-framework.tar.gz"

echo "=== 3S-NOS Secure Framework — Deployment ==="

# 1. Create deploy directory
sudo mkdir -p "$DEPLOY_DIR"
sudo chown "$(id -u):$(id -g)" "$DEPLOY_DIR"

# 2. Extract
echo "[1/4] Extracting $TARBALL → $DEPLOY_DIR"
tar -xzf "$TARBALL" -C "$DEPLOY_DIR" --strip-components=1

# 3. Install Python dependencies
echo "[2/4] Installing Python dependencies"
cd "$DEPLOY_DIR"
pip3 install --quiet -r requirements.txt

# 4. Quick syntax check
echo "[3/4] Syntax check"
python3 -m py_compile app.py nos_gnmi_pool.py netconf_gnmi_adapter.py \
    tamper_logger.py sam/role_policy.py sam/session_context.py \
    sam/role_api.py netconf/netconfserver.py netconf/netconf_session.py \
    gnmi/gnmiclient.py
echo "      All OK"

# 5. Show ready state
echo "[4/4] Ready"
echo ""
echo "=== Run the Secure Framework ==="
echo "cd $DEPLOY_DIR"
echo "python3 app.py \\"
echo "    --leaf1-host 192.168.122.20 \\"
echo "    --leaf2-host 192.168.122.21 \\"
echo "    --gnmi-port  9339 \\"
echo "    --client-cert ./certificate/generate/output_3snos/agent-ids/client.crt \\"
echo "    --client-key  ./certificate/generate/output_3snos/agent-ids/client.key \\"
echo "    --client-ca   ./certificate/generate/output_3snos/agent-ids/trustedCertificates.crt"
echo ""
echo "=== NETCONF endpoint (for ONAP SDNC mount) ==="
echo "  host : $(ip addr show virbr0 2>/dev/null | grep 'inet ' | awk '{print $2}' | cut -d/ -f1 || echo '192.168.122.1')"
echo "  port : 6513"
echo "  tls  : client cert required (ONAP-SONiC-CA signed)"

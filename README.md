# 3S-NOS Secure Framework — Agent-IDS

## Tổng quan

**Secure Framework (SF)** là adapter zero-trust micro-segmentation, đóng vai trò trung gian giữa ONAP SDNC và các SONiC LEAF switch trong mạng 3S-NOS.

```
ONAP SDNC (ODL)
      │
      │  NETCONF/TLS  :6513
      ▼
┌─────────────────────────┐
│   Secure Framework (SF) │  ← chạy trên Sonic Node 10.10.6.238
│   nos_acl_tools/        │
│   container: nos-sf     │
└─────────────────────────┘
      │                │
      │ gNMI/TLS :9339 │ gNMI/TLS :9339
      ▼                ▼
  LEAF-1           LEAF-2
192.168.122.20   192.168.122.21
      │                │
   iptables        iptables
  FORWARD          FORWARD
```

SF không làm routing hay NAT — chỉ nhận policy từ SDNC và push xuống LEAF qua gNMI. Enforcement thực sự xảy ra trên LEAF (iptables FORWARD chain).

---

## Kiến trúc chi tiết

### Luồng dữ liệu

```
ONAP SDNC
  └─ gửi NETCONF edit-config (YANG: nos-iptables)
        │
        ▼
  SF nhận → parse XML → kiểm tra RBAC (ONAP role)
        │
        ├─ xác định LEAF theo src-ip zone
        │       10.1.100.0/24, 10.1.200.0/24  →  LEAF-1
        │       10.2.100.0/24, 10.2.50.0/24   →  LEAF-2
        │
        ▼
  gNMI Set → nos-acl-bridge (chạy trên LEAF)
        │
        ▼
  ConfigDB DB4  →  iptables FORWARD chain
```

### RBAC — phân quyền theo client certificate (OU)

| OU trong cert | ONAP Role | SONiC Role | Quyền |
|---|---|---|---|
| `internal` / `sdnc` | ADMIN | admin | Full CRUD |
| `aws` | OPERATOR | operator | Read + Set, no delete |
| `auto` | AGENT | admin | DROP-only, `source=ids-auto` |
| _(không có cert)_ | ADMIN | admin | Full CRUD (TLS-only mode) |

> Zero-trust thực sự nằm ở tầng SF→LEAF (gNMI mTLS). Tầng SDNC→SF dùng TLS một chiều — server auth, không yêu cầu client cert.

---

## YANG Model

File: `nos_acl_tools/yang/nos-iptables.yang`  
Namespace: `urn:3snos:iptables`  
Revision: `2026-04-27`

```yang
container acl {
  list rule {
    key "rule-id";
    leaf rule-id   { type string; }          // ID duy nhất
    leaf action    { enum ACCEPT|DROP|RETURN; }
    leaf src-ip    { type string; }          // CIDR, vd: 10.1.100.1/32
    leaf dst-ip    { type string; }
    leaf protocol  { enum tcp|udp|icmp|all; }
    leaf src-port  { type uint16; }
    leaf dst-port  { type uint16; }
    leaf priority  { type uint16; }          // <100: top (IDS), >=1000: append
    leaf source    { enum manual|sdnc|ids-auto; }
    leaf comment   { type string; }
    leaf ttl-seconds { type uint32; }        // 0 = permanent
  }
}
```

---

## Deploy

### Yêu cầu

- Host: Sonic Node (gns3vm) — máy có `virbr0` kết nối tới LEAF-1/2
- Docker + Docker Compose v2
- Port mở: `6513/tcp` (NETCONF), `9090/tcp` (Role API)

### Cấu trúc thư mục

```
/3s-com/zma/secure-framework/
├── app.py                          # entry point
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
├── certificate/
│   ├── server/
│   │   ├── server.crt              # cert SF (SAN: IP:10.10.6.238)
│   │   ├── server.key
│   │   └── trustedCertificates.crt # CA bundle: 3S-NOS CA + ODL CA
│   └── generate/output_3snos/
│       ├── agent-ids/              # cert SF→LEAF (OU=auto, AGENT role)
│       │   ├── client.crt
│       │   ├── client.key
│       │   └── trustedCertificates.crt
│       └── ca.crt
├── yang/
│   ├── nos-iptables.yang
│   └── ietf-netconf-monitoring@2010-10-04.yang
├── netconf/
├── gnmi/
├── sam/                            # RBAC: role policy + session context
└── nos_gnmi_pool.py                # gNMI connection pool (LEAF-1 + LEAF-2)
```

### Build và chạy

```bash
cd /3s-com/zma/secure-framework

# Lần đầu (hoặc sau khi cập nhật code)
docker compose build

# Chạy
docker compose up -d

# Kiểm tra
docker compose ps
docker logs nos-sf

# Dừng
docker compose down
```

Container tự restart khi host reboot (`restart: unless-stopped`).  
Certificates và YANG files được mount làm volume — rotate cert không cần rebuild image.

---

## Kết nối với ONAP SDNC

### Cơ chế

SF dùng **NETCONF-over-TLS (RFC 7589)** thay vì SSH. ODL (OpenDaylight bên trong SDNC) hỗ trợ TLS qua trường `protocol.name=TLS` trong node config.

Flow kết nối:

```
1. ODL mở TCP → SF :6513
2. TLS handshake (SF gửi server.crt, ODL verify CA)
3. NETCONF hello exchange
      SF → ODL: capabilities (nos-iptables, ietf-netconf-monitoring)
      ODL → SF: capabilities
4. ODL gửi get (ietf-netconf-monitoring) → SF trả schema list
5. ODL gửi get-schema cho từng module → SF trả nội dung YANG
6. ODL build schema context → trạng thái: Connected ✓
7. ODL giữ session (keepalive 120s)
```

### Mount node trên ONAP SDNC (ODLUX)

#### Qua RESTCONF API

```bash
curl -X PUT \
  http://<SDNC-SERVICE>:8282/rests/data/network-topology:network-topology/topology=topology-netconf/node=nos-sf \
  -u admin:<ODL_PASSWORD> \
  -H "Content-Type: application/json" \
  -d '{
    "node": [{
      "node-id": "nos-sf",
      "netconf-node-topology:host": "10.10.6.238",
      "netconf-node-topology:port": 6513,
      "netconf-node-topology:tcp-only": false,
      "netconf-node-topology:protocol": { "name": "TLS" },
      "netconf-node-topology:key-based": { "username": "admin", "key-id": "" },
      "netconf-node-topology:max-connection-attempts": 0,
      "netconf-node-topology:connection-timeout-millis": 20000,
      "netconf-node-topology:keepalive-delay": 120
    }]
  }'
```

> `key-id: ""` — không dùng client cert (TLS một chiều). SF nhận kết nối, gán ADMIN role mặc định.

#### Qua ODLUX UI

**Connect → Mount Point → Add**

| Field | Value |
|---|---|
| Name | `nos-sf` |
| Host | `10.10.6.238` |
| Port | `6513` |
| Protocol | `TLS` |
| Required | `false` (không cần client cert) |

### Kiểm tra trạng thái

```bash
# Xem connection status
curl -s -u admin:<ODL_PASSWORD> \
  http://<SDNC-SERVICE>:8282/rests/data/network-topology:network-topology/topology=topology-netconf/node=nos-sf \
  | python3 -m json.tool | grep connection-status

# Expected: "netconf-node-topology:connection-status": "connected"
```

---

## Gửi policy từ SDNC xuống LEAF

### NETCONF edit-config

```python
from ncclient import manager

PAYLOAD = '''
<config>
  <acl xmlns="urn:3snos:iptables">
    <rule>
      <rule-id>block-attacker-001</rule-id>
      <action>DROP</action>
      <src-ip>10.1.100.55/32</src-ip>
      <priority>50</priority>
      <source>sdnc</source>
      <comment>Blocked by ONAP policy</comment>
    </rule>
  </acl>
</config>'''

with manager.connect(
    host='10.10.6.238', port=6513,
    username='admin', password='admin',
    hostkey_verify=False,
    manager_params={'timeout': 10},
) as m:
    reply = m.edit_config(target='running', config=PAYLOAD)
    print("OK" if reply.ok else reply)
```

SF nhận → xác định LEAF theo `src-ip` → gNMI Set tới nos-acl-bridge → iptables rule được insert trên LEAF tương ứng.

---

## Role API

SF expose REST API tại `:9090` để quản lý policy và session:

```bash
# Xem sessions đang active
curl http://10.10.6.238:9090/sessions

# Xem trạng thái gNMI pool
curl http://10.10.6.238:9090/pool

# Xem policy hiện tại
curl http://10.10.6.238:9090/policy
```

---

## TLS Certificate

### Server certificate (SF)

- Subject: `CN=3snos-sf`
- SAN: `IP:10.10.6.238, IP:127.0.0.1, DNS:localhost, DNS:3snos-sf`
- Ký bởi: 3S-NOS CA

### CA bundle (`trustedCertificates.crt`)

Gồm 2 CA để SF tin tưởng cả 2 phía:
- **3S-NOS CA** — ký cert SF server và bridge certs
- **ODL CA** — ký cert của ODL (dự phòng mTLS sau này)

### Client cert SF→LEAF

- Subject: `CN=agent-ids, OU=auto` (AGENT role)
- Bridge trên LEAF enforce RBAC theo OU này

---

## Troubleshooting

| Triệu chứng | Nguyên nhân | Fix |
|---|---|---|
| ODL status: `connecting` liên tục | Hello advertise module không serve được | Kiểm tra `yang/` có đủ file chưa |
| ODL: "unsatisfied imports" | YANG module import dependency không có | Thêm YANG dependency vào `yang/` |
| ODL: "required but not provided" | Module trong hello không có trong monitoring schemas | File `.yang` phải nằm trong `yang/` dir |
| ODL dùng schema cũ sau khi fix | ODL cache module theo revision | Bump revision date trong YANG file |
| TLS handshake fail | SAN cert không match host | Regenerate cert với đúng IP/DNS |
| gNMI connect fail | TLS hostname mismatch | Kiểm tra `LEAF_TLS_HOSTNAME` trong `nos_gnmi_pool.py` |
| `decrypt_error` từ Java (ODL) | Python gửi `CertificateRequest` với `CERT_OPTIONAL` | Dùng `CERT_NONE` — không request client cert |

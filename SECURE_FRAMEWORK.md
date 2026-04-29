# Secure Framework — Pipeline Architecture

> Mô tả chi tiết kiến trúc và luồng đẩy policy từ Control Plane → Dataplane  
> Last updated: 2026-04-29

---

## 1. Tổng quan hệ thống

```
┌──────────────────────────────────────────────────────────────────────────────┐
│  CONTROL PLANE  (Docker @ host máy tính cá nhân)                             │
│                                                                              │
│   ┌────────────────────┐       ┌──────────────────────┐                     │
│   │   ThreatCrush UI   │ HTTP  │     IDS Agent (Go)   │                     │
│   │   Next.js :3000    │──────▶│     :8766            │                     │
│   │   /policy page     │       │   /rules             │                     │
│   │   /monitor page    │       │   /autoblock         │                     │
│   └────────────────────┘       │   /events (SSE/WS)   │                     │
│                                └──────────┬───────────┘                     │
│                                           │ HTTP REST                       │
└──────────────────────────────────────────┼──────────────────────────────────┘
                                           │
                             ╔═════════════▼═════════════╗
                             ║   PUBLIC INTERNET / LAN   ║
                             ╚═════════════╦═════════════╝
                                           │
┌──────────────────────────────────────────┼──────────────────────────────────┐
│  DATAPLANE  (GNS3VM @ 10.10.6.238)      │                                  │
│                                          ▼                                  │
│   ┌─────────────────────────────────────────────────────────────┐           │
│   │  Secure Framework  (container: nos-sf, Python 3.11)         │           │
│   │  Role API  :9090     NETCONF server  :6513                   │           │
│   │                                                             │           │
│   │  ┌────────────────────┐   ┌──────────────────────────────┐ │           │
│   │  │  REST /api/rules   │   │  NETCONF adapter (ONAP SDNC) │ │           │
│   │  │  (role_api.py)     │   │  (netconf_gnmi_adapter.py)   │ │           │
│   │  └────────┬───────────┘   └─────────────┬────────────────┘ │           │
│   │           │                             │                   │           │
│   │           └──────────┬──────────────────┘                   │           │
│   │                      │  gNMI Set (mTLS :9339)               │           │
│   │           ┌──────────▼──────────────────┐                   │           │
│   │           │  nos_gnmi_pool.py            │                   │           │
│   │           │  Zone routing: src-ip→LEAF   │                   │           │
│   │           └──────┬──────────────┬────────┘                   │           │
│   └──────────────────┼──────────────┼────────────────────────────┘           │
│                      │              │                                        │
│      gNMI/mTLS :9339 │              │ gNMI/mTLS :9339                       │
│                      ▼              ▼                                        │
│   ┌────────────────────┐  ┌────────────────────┐                            │
│   │  nos-acl-bridge    │  │  nos-acl-bridge    │  (systemd service)         │
│   │  SONIC-LEAF-1      │  │  SONIC-LEAF-2      │                            │
│   │  192.168.122.20    │  │  192.168.122.21    │                            │
│   │  bridge/           │  │  bridge/           │                            │
│   │   validators.py    │  │   validators.py    │                            │
│   │   iptables.py      │  │   iptables.py      │                            │
│   └────────┬───────────┘  └────────┬───────────┘                            │
│            │                       │                                        │
│            ▼                       ▼                                        │
│   ┌────────────────┐     ┌────────────────┐                                 │
│   │  ConfigDB DB4  │     │  ConfigDB DB4  │  (Redis — survives restart)     │
│   │  iptables      │     │  iptables      │  (FORWARD chain)                │
│   │  FORWARD chain │     │  FORWARD chain │                                 │
│   └────────────────┘     └────────────────┘                                 │
└────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Components

### 2.1 IDS Agent (`ids-agent/`)

Go binary, chạy trong container `ids-agent` trên control plane.

**Vai trò:**
- Bridge SSE/WebSocket từ Suricata IDS → ThreatCrush UI (real-time alerts)
- Auto-block: nhận alert severity ≤ 2 → tự động push DROP rule lên SF
- Proxy REST `/rules` → SF `/api/rules` (cho UI đọc danh sách rules)
- REST `/autoblock` để UI bật/tắt auto-block và push rule thủ công

**Key endpoints:**

| Method | Path | Mô tả |
|--------|------|-------|
| GET | `/events` | SSE stream alerts từ Suricata |
| GET | `/ws` | WebSocket — cùng payload |
| GET | `/rules` | Proxy → SF `/api/rules` |
| GET/POST | `/autoblock` | Status + enable/disable |
| POST | `/autoblock/enable` | Bật auto-block |
| POST | `/autoblock/disable` | Tắt + clear blocked list |
| DELETE | `/autoblock/unblock/{id}` | Xóa 1 rule trên SF |

**Auto-block flow:**
```
Suricata alert (severity ≤ 2)
  → tryAutoBlock()
  → check blockedIPs map (dedup)
  → pushBlockRule(srcIP, "agent-<ip>", reason)
       POST SF /api/rules
       source="agent", action="DROP", priority=50
```

### 2.2 ThreatCrush (`threatcrush/`)

Next.js 15 app, container `threatcrush` :3000 trên control plane.

**Policy page** (`/policy`):
- Đọc rules từ SF qua `/api/ids/rules` (poll 10s)
- Push rule mới: form → POST `/api/ids/rules` → IDS Agent → SF
- Xóa rule: DELETE `/api/ids/rules/{id}`
- Toggle auto-block: POST `/api/ids/autoblock`
- Source field bị ẩn khỏi form — luôn gửi `source="manual"` tự động

**Next.js API routes** (proxy layer):

| Route | Proxies to |
|-------|-----------|
| `/api/ids/rules` GET/POST | IDS Agent `/rules` và `/autoblock` |
| `/api/ids/rules/[id]` DELETE | IDS Agent `/autoblock/unblock/{id}` |
| `/api/ids/autoblock` GET/POST | IDS Agent `/autoblock`, `/autoblock/enable`, `/autoblock/disable` |

### 2.3 Secure Framework (`secure-framework/`)

Python 3.11, container `nos-sf` trên dataplane (10.10.6.238).

**Hai entry point:**
- **NETCONF server** `:6513` — nhận `edit-config` từ ONAP SDNC
- **Role API** `:9090` — nhận REST từ IDS Agent

**Core modules:**

| File | Vai trò |
|------|---------|
| `sam/role_api.py` | HTTP server (ThreadingHTTPServer), REST `/api/rules` CRUD |
| `netconf_gnmi_adapter.py` | Nhận NETCONF XML, translate → gNMI Set |
| `nos_gnmi_pool.py` | Pool kết nối gNMI tới các LEAF, zone routing |
| `sam/session_context.py` | Per-thread session (ONAP role, cert OU) |
| `tamper_logger.py` | Audit log mọi thao tác CRUD |
| `yang/nos-iptables.yang` | YANG model — dùng cho cả NETCONF schema và bridge validation |

### 2.4 nos-acl-bridge (trên mỗi LEAF)

Python systemd service tại `/opt/nos-acl-bridge/`, chạy trên LEAF-1 (192.168.122.20) và LEAF-2 (192.168.122.21).

**Vai trò:** gNMI server nhận Set/Get từ SF → validate → ghi vào ConfigDB DB4 → apply iptables FORWARD.

| File | Vai trò |
|------|---------|
| `bridge/nos_acl_bridge.py` | gNMI server gRPC, dispatch Set/Get |
| `bridge/validators.py` | Validate rule dict theo YANG constraints + RBAC |
| `bridge/iptables.py` | Apply/delete iptables rule từ ConfigDB |
| `bridge/recovery.py` | Replay ConfigDB rules vào iptables sau restart |

---

## 3. Pipeline chi tiết — Push rule từ UI

```
User điền form /policy → nhấn "Push Rule"
        │
        │  POST /api/ids/rules  {rule_id, action, src_ip, priority, comment}
        ▼
  Next.js API route  (source="manual" tự inject)
        │
        │  POST http://ids-agent:8766/autoblock  (body nguyên vẹn)
        ▼
  IDS Agent  (Go)
        │
        │  POST http://10.10.6.238:9090/api/rules
        │  body: {rule_id, action, src_ip, priority, source="manual", comment}
        ▼
  Secure Framework  role_api.py → _handle_post_rule()
        │
        ├─ Validate action ∈ {ACCEPT, DROP, RETURN}
        ├─ ip_to_leaf(src_ip) → chọn LEAF đích
        │       10.1.100.x / 10.1.200.x → LEAF-1  (192.168.122.20)
        │       10.2.100.x / 10.2.50.x  → LEAF-2  (192.168.122.21)
        │       src_ip rỗng hoặc không match → broadcast cả hai
        │
        │  gNMI Set (mTLS, cert OU=sdnc → ADMIN role)
        │  path: /nos-iptables:acl/rule[rule-id={id}]
        │  encoding: json_ietf
        ▼
  nos-acl-bridge  (trên LEAF tương ứng)
        │
        ├─ validate_rule(rule)       ← validators.py
        │     rule-id pattern OK?
        │     action ∈ {ACCEPT,DROP,REJECT}?
        │     src-prefix valid IPv4 CIDR?
        │     priority 1–9999?
        │     source ∈ {manual, sdnc, agent}?
        │     if source=="agent": action phải là DROP
        │
        ├─ enforce_rbac(rule, role)  ← cert OU → role mapping
        │     ADMIN (OU=internal/sdnc): unrestricted
        │     OPERATOR (OU=aws): source phải là sdnc
        │     AGENT (OU=auto): source phải là agent + action=DROP
        │
        ├─ Ghi vào ConfigDB DB4  (Redis)
        │     key: NOS_IPTABLES_RULE|{rule-id}
        │     value: {rule fields}
        │
        └─ Apply iptables FORWARD
              iptables -I FORWARD <priority> -s <src-ip> [-d <dst-ip>]
                       [-p <proto>] [--sport/--dport] -m comment
                       --comment "{rule-id}:{source}" -j {action}
```

**Response ngược lại:**
```
nos-acl-bridge → gNMI OK
SF → {success: true, rule_id, pushed_to: ["10.1.100.x"]}
IDS Agent → forward response
Next.js → {success: true, pushed_to: [...]}
UI → hiển thị "✓ pushed to 10.1.100.x"
UI → reload rules sau 1s
```

---

## 4. Pipeline — Auto-block từ IDS alert

```
Suricata phát hiện violation (e.g., WEB→DB lateral move)
        │
        │  SSE event  data: {src_ip, alert.severity=1, alert.signature}
        ▼
  IDS Agent  consumeSSE() / runPoller()
        │
        ├─ hub.broadcast(msg)  → ThreatCrush /monitor real-time
        │
        └─ if autoBlockEnabled:
               tryAutoBlock(data)
                     │
                     ├─ severity > 2? → bỏ qua (chỉ block P1+P2)
                     ├─ blockedIPs[srcIP]? → dedup, bỏ qua
                     └─ pushBlockRule(srcIP, "agent-<ip>", "auto-block: <sig>")
                               │
                               │  POST SF /api/rules
                               │  {source="agent", action="DROP", priority=50}
                               ▼
                         (pipeline tiếp theo giống mục 3)
                         Bridge enforce: source="agent" → action phải DROP ✓
```

**Priority ordering trên LEAF:**

| Priority | Loại rule | Source | Ví dụ |
|----------|-----------|--------|-------|
| 50 | IDS auto-block động | `agent` | `agent-10-1-100-55` |
| 200 | ZT baseline (microseg) | `sdnc` | `zt-web-app-allow` |
| 9999 | Default deny-all | `sdnc` | `zt-default-drop` |

---

## 5. Pipeline — ONAP SDNC push (NETCONF)

```
ONAP ODL gửi NETCONF edit-config
        │
        │  TCP :6513  →  TLS handshake
        │  XML payload (namespace urn:3snos:iptables):
        │    <acl><rule><rule-id>...</rule-id><action>...</action>...</rule></acl>
        ▼
  Secure Framework  netconf_gnmi_adapter.py
        │
        ├─ Parse XML → dict
        ├─ Detect YANG namespace:
        │     urn:3snos:iptables → native format, dùng trực tiếp
        │     openconfig-acl    → translate sang nos-iptables format
        │
        ├─ AGENT auto-stamp:
        │     session OU=auto? → force action=DROP, source="agent"
        │
        ├─ ip_to_leaf(src_ip) → route tới LEAF đích
        │
        │  gNMI Set (cert OU=sdnc → ADMIN)
        ▼
  (pipeline bridge giống mục 3)
```

---

## 6. RBAC — phân quyền theo cert OU

SF → LEAF dùng **mTLS (mutual TLS)**: cả SF và bridge đều present certificate.  
Bridge đọc OU từ client cert để xác định role, enforce hoàn toàn ở tầng bridge — SF không thể bypass.

| Client cert OU | Role | Được phép |
|----------------|------|-----------|
| `internal` hoặc `sdnc` | ADMIN | Mọi action, mọi source |
| `aws` | OPERATOR | ACCEPT/DROP, chỉ `source=sdnc` |
| `auto` | AGENT | Chỉ DROP, chỉ `source=agent` |

**Cert paths trên SF:**
```
/app/certificate/generate/output_3snos/
  sdnc/
    client.crt    (OU=sdnc)  ← dùng cho push ZT baseline, manual
    client.key
    trustedCertificates.crt
  agent-ids/
    client.crt    (OU=auto)  ← dùng cho auto-block từ IDS Agent
    client.key
    trustedCertificates.crt
```

Hiện tại SF dùng cert SDNC (ADMIN) cho tất cả push từ REST API và NETCONF.  
IDS Agent push qua SF REST → SF relay dùng cert SDNC.  
Nếu IDS Agent push thẳng gNMI (bỏ qua SF) mới cần cert AGENT.

---

## 7. gNMI Connection Pool

`nos_gnmi_pool.py` quản lý pool kết nối tới các LEAF.

```python
# Zone routing — src-ip → LEAF
ZONE_MAP = {
    "10.1.100.": "192.168.122.20",   # WEB  → LEAF-1
    "10.1.200.": "192.168.122.20",   # DB   → LEAF-1
    "10.2.100.": "192.168.122.21",   # APP  → LEAF-2
    "10.2.50.":  "192.168.122.21",   # MGT  → LEAF-2
}

def ip_to_leaf(src_ip: str) -> Optional[str]:
    for prefix, leaf_ip in ZONE_MAP.items():
        if src_ip.startswith(prefix):
            return leaf_ip
    return None
```

Nếu `src_ip` không match zone nào (hoặc rỗng) → `get_any_client()` → push tới LEAF đang available.

**pygnmi params quan trọng:**

```python
SonicGnmiClient(
    host=(leaf_ip, 9339),
    path_cert=client_cert_path,   # client cert (OU=sdnc)
    path_key=client_key_path,
    path_root=ca_cert_path,       # CA để verify bridge server cert
    override="sonic",             # TLS hostname override
    grpc_options=[("grpc.ssl_target_name_override", "sonic")]
)
```

---

## 8. ConfigDB — persistence

nos-acl-bridge ghi rule vào **Redis DB4** dưới key `NOS_IPTABLES_RULE|{rule-id}`.  
Khi bridge restart (hoặc LEAF reboot), `recovery.py` replay toàn bộ DB4 → `iptables -I FORWARD`.

```
ConfigDB DB4 (Redis)
  NOS_IPTABLES_RULE|zt-web-app-allow   → {action:ACCEPT, src-prefix:10.1.100.0/24, ...}
  NOS_IPTABLES_RULE|zt-default-drop    → {action:DROP, priority:9999, ...}
  NOS_IPTABLES_RULE|agent-10-1-100-55  → {action:DROP, src-prefix:10.1.100.55/32, priority:50}
```

Khác biệt với `07-apply-policy.py` cũ: script đó write thẳng iptables → mất sau reboot.  
gNMI Set qua bridge → ConfigDB → iptables → **survive restart**.

---

## 9. YANG Model (`yang/nos-iptables.yang`)

```
module nos-iptables (namespace: urn:3snos:iptables)
  container acl
    list rule  [key: rule-id]
      leaf rule-id      string  1..64  pattern [a-zA-Z0-9_\-]+
      leaf action       enum    ACCEPT | DROP | RETURN        (mandatory)
      leaf src-ip       string  IPv4 CIDR  e.g. 10.1.100.0/24
      leaf dst-ip       string  IPv4 CIDR
      leaf protocol     enum    tcp | udp | icmp | all        (default: all)
      leaf src-port     uint16  1..65535  (only when tcp/udp)
      leaf dst-port     uint16  1..65535  (only when tcp/udp)
      leaf priority     uint16  1..9999                       (default: 1000)
      leaf source       enum    manual | sdnc | agent         (default: sdnc)
      leaf comment      string  0..256
      leaf ttl-seconds  uint32  0..86400                      (default: 0 = permanent)
```

Bridge nhận field tên `src-prefix` / `dst-prefix` thay vì `src-ip` / `dst-ip`  
(YANG model dùng `src-ip`, bridge normalize về `src-prefix` khi lưu ConfigDB).  
UI hiển thị `rule["src-prefix"] ?? rule["src-ip"]` để handle cả hai.

---

## 10. Docker Compose — Control Plane

```yaml
# /home/dis/deploy/docker-compose.yml
services:
  ids-agent:
    build: ./Agent-IDS/ids-agent
    ports: ["8766:8766"]
    env:
      IDS_API_URL: http://10.10.6.238:8765   # Suricata REST
      SF_API_URL:  http://10.10.6.238:9090   # Secure Framework Role API
      AGENT_ADDR:  :8766

  threatcrush:
    build: ./threatcrush
    ports: ["3000:3000"]
    env:
      AGENT_URL: http://ids-agent:8766       # inter-container
    depends_on: [ids-agent]
```

---

## 11. Dataplane deploy workflow

Sau khi thay đổi code SF hoặc bridge:

```bash
# 1. Sync SF code lên dataplane
rsync -av /home/dis/deploy/Agent-IDS/secure-framework/ \
      dis@10.10.6.238:/3s-com/zma/secure-framework/

# 2. Restart SF container
ssh dis@10.10.6.238 "docker restart nos-sf"

# 3. Sync bridge code (nếu thay đổi validators.py, iptables.py, ...)
for leaf in 192.168.122.20 192.168.122.21; do
  scp /home/dis/deploy/Agent-IDS/secure-framework/../nos-acl-bridge/bridge/validators.py \
      admin@$leaf:/tmp/validators.py
  ssh admin@$leaf "sudo cp /tmp/validators.py /opt/nos-acl-bridge/bridge/ \
                   && sudo systemctl restart nos-acl-bridge"
done

# 4. Rebuild control plane (nếu thay đổi ids-agent/ hoặc threatcrush/)
cd /home/dis/deploy
docker compose build
docker compose up -d
```

**Credentials:**
- Dataplane host: `dis@10.10.6.238` / `httt@25`
- LEAF-1/2: `admin@192.168.122.20` (và .21) / `YourPaSsWoRd`
- Kết nối LEAF qua jump host: từ 10.10.6.238, `ssh admin@192.168.122.x`

---

## 12. End-to-end data flow summary

```
[ThreatCrush /policy]
        │ POST /api/ids/rules  {rule_id, action="DROP", src_ip="x.x.x.x/32"}
        │
[Next.js API]  inject source="manual"
        │ POST http://ids-agent:8766/autoblock
        │
[IDS Agent]
        │ POST http://10.10.6.238:9090/api/rules
        │
[SF role_api.py]
  validate action
  ip_to_leaf(src_ip) → 192.168.122.20
        │ gNMI Set /nos-iptables:acl/rule[rule-id=x]  (mTLS OU=sdnc)
        │
[nos-acl-bridge LEAF-1]
  validate_rule()  → OK
  enforce_rbac(role=ADMIN) → OK
  Redis DB4: NOS_IPTABLES_RULE|x = {...}
  iptables -I FORWARD ... -j DROP
        │
        ✓  Rule active trên LEAF-1 iptables FORWARD
```

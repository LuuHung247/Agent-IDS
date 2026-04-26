# 3S-NOS Data Plane Specification

> Document for ONAP SDNC Control Plane AI Agent
> Mục đích: cung cấp đầy đủ thông tin data plane để control plane (ONAP SDNC) implement connector tới các SONiC switch và đẩy/quản lý microsegmentation rules.

**Server**: `112.137.129.232:3080` (GNS3 server)
**Project**: `micro-segmentation-lab` — ID `b6bf1cd6-8d58-41d4-941c-893020abd2a3`
**SDNC reach data plane qua**: GNS3VM host `10.10.6.238` (LAN) hoặc `112.137.129.232` (public NAT)

---

## 1. Topology — Spine-Leaf Fabric

```
               ┌──────────────┐    ┌──────────────┐
               │     NAT1     │    │     NAT2     │
               │ (Cloud/Mgmt) │    │   (GNS3VM)   │
               └──────┬───────┘    └───────┬──────┘
                      │                    │
                ┌─────┴────────────────────┴─────┐
                │         SONIC-SPINE             │
                │   eth0: 192.168.122.x (mgmt)   │
                │   eth1: 10.0.1.1/30 → LEAF-1   │
                │   eth2: 10.0.2.1/30 → LEAF-2   │
                └────────┬───────────────┬────────┘
                         │               │
              ┌──────────┘               └──────────┐
     ┌────────┴─────────┐               ┌───────────┴──────┐
     │   SONIC-LEAF-1   │               │   SONIC-LEAF-2   │
     │ uplink eth0:     │               │ uplink eth0:     │
     │   10.0.1.2/30    │               │   10.0.2.2/30    │
     │ Vlan100 SVI:     │               │ Vlan100 SVI:     │
     │   10.1.100.1/24  │               │   10.2.100.1/24  │
     │ Vlan200 SVI:     │               │ Vlan300 SVI:     │
     │   10.1.200.1/24  │               │   10.2.50.1/24   │
     │ tc mirred → eth4 │               │ tc mirred → eth4 │
     └──┬───┬───────┬───┘               └──┬───┬───────┬───┘
        │   │       │ mirror               │   │       │ mirror
        │   │       └────────────┐  ┌──────┘   │       │
       ┌┴┐ ┌┴┐                   ↓  ↓         ┌┴┐ ┌┴┐
       │W│ │D│                ┌─────────┐    │A│ │M│
       │E│ │B│                │   IDS   │    │P│ │G│
       │B│ └─┘                │ Suricata│    │P│ │T│
       └─┘                    └─────────┘    └─┘ └─┘
```

---

## 2. Node Inventory

| Node | Type | GNS3 Console | Mgmt IP | Role |
|------|------|--------------|---------|------|
| SONIC-SPINE | SONiC-VS | `telnet 112.137.129.232:5006` | 192.168.122.x (DHCP) | L3 core router, inter-LEAF transit |
| SONIC-LEAF-1 | SONiC-VS | `telnet 112.137.129.232:5010` | 192.168.122.x (DHCP) | Gateway WEB+DB, ZT enforcement |
| SONIC-LEAF-2 | SONiC-VS | `telnet 112.137.129.232:5015` | 192.168.122.x (DHCP) | Gateway APP+MGT, ZT enforcement |
| Alpine-Linux-1 | Alpine 3.23 | `telnet 112.137.129.232:5008` | 10.1.100.10/24 | WEB zone host |
| Alpine-Linux-2 | Alpine 3.23 | `telnet 112.137.129.232:5011` | 10.1.200.10/24 | DB zone host |
| Alpine-Linux-3 | Alpine 3.23 | `telnet 112.137.129.232:5014` | 10.2.100.10/24 | APP zone host |
| Alpine-Linux-5 | Alpine 3.23 | `telnet 112.137.129.232:5016` | 10.2.50.10/24 | MGT zone host |
| IDS-Suricata | Alpine 3.23 + Suricata 8.0 | `telnet 112.137.129.232:5018` | 192.168.122.205 (eth2) | IDS, REST API :8765 |

**Login credentials:**
- SONiC: `admin` / `YourPaSsWoRd`
- Alpine: `root` (no password)

---

## 3. Layer 3 — IP Address Plan

### 3.1 Underlay (point-to-point /30)

| Link | SPINE side | LEAF side |
|------|-----------|-----------|
| SPINE ↔ LEAF-1 | `10.0.1.1/30` (eth1) | `10.0.1.2/30` (eth0) |
| SPINE ↔ LEAF-2 | `10.0.2.1/30` (eth2) | `10.0.2.2/30` (eth0) |

### 3.2 Overlay — VLAN/SVI per zone

| Zone | LEAF | VLAN | SVI Gateway | CIDR | Host |
|------|------|------|-------------|------|------|
| **WEB** | LEAF-1 | Vlan100 | 10.1.100.1 | 10.1.100.0/24 | Alpine-1: 10.1.100.10 |
| **DB**  | LEAF-1 | Vlan200 | 10.1.200.1 | 10.1.200.0/24 | Alpine-2: 10.1.200.10 |
| **APP** | LEAF-2 | Vlan100 | 10.2.100.1 | 10.2.100.0/24 | Alpine-3: 10.2.100.10 |
| **MGT** | LEAF-2 | Vlan300 | 10.2.50.1  | 10.2.50.0/24  | Alpine-5: 10.2.50.10 |

### 3.3 Out-of-band — Management

| Interface | IP | Mục đích |
|-----------|-----|----------|
| GNS3VM host eth0 | 10.10.6.238 (LAN) / 112.137.129.232 (public NAT) | SDNC NETCONF/SSH entrypoint |
| virbr0 (libvirt bridge) | 192.168.122.1/24 | Mgmt network — SONiC mgmt + IDS eth2 |
| IDS-Suricata eth2 | 192.168.122.205 | Alert REST API exposure |

---

## 4. Routing — Forwarding Plane

**Mechanism:** Static routes + kernel `ip forwarding=1` trên tất cả interfaces (SONiC-VS không có ASIC, dùng Linux kernel forwarding).

### 4.1 SONIC-SPINE routing table

```
10.0.1.0/30 dev eth1            # to LEAF-1 underlay
10.0.2.0/30 dev eth2            # to LEAF-2 underlay
10.1.100.0/24 via 10.0.1.2      # WEB zone via LEAF-1
10.1.200.0/24 via 10.0.1.2      # DB zone via LEAF-1
10.2.100.0/24 via 10.0.2.2      # APP zone via LEAF-2
10.2.50.0/24  via 10.0.2.2      # MGT zone via LEAF-2
```

### 4.2 SONIC-LEAF-1 routing table

```
10.0.1.0/30 dev eth0            # underlay to SPINE
10.1.100.0/24 dev Vlan100       # WEB direct
10.1.200.0/24 dev Vlan200       # DB direct
10.2.100.0/24 via 10.0.1.1      # APP via SPINE
10.2.50.0/24  via 10.0.1.1      # MGT via SPINE
default via 10.0.1.1            # all else via SPINE
```

### 4.3 SONIC-LEAF-2 routing table

```
10.0.2.0/30 dev eth0            # underlay to SPINE
10.2.100.0/24 dev Vlan100       # APP direct
10.2.50.0/24  dev Vlan300       # MGT direct
10.1.100.0/24 via 10.0.2.1      # WEB via SPINE
10.1.200.0/24 via 10.0.2.1      # DB via SPINE
default via 10.0.2.1
```

### 4.4 Critical fix — SONiC-VS host route

SONiC-VS install route `10.0.X.0/30 dev EthernetX metric 0` (NIC ảo, ARP fail) đè lên `dev eth0`. Cần inject `/32` host route:

```bash
sudo ip route add 10.0.2.1/32 dev eth0 src 10.0.2.2  # trên LEAF-2
sudo ip route add 10.0.1.1/32 dev eth0 src 10.0.1.2  # trên LEAF-1
```

---

## 5. Microsegmentation — Zero Trust Policy

### 5.1 Policy Matrix (nguồn → đích)

| Source ↓ \ Dest → | WEB | DB | APP | MGT |
|---|:---:|:---:|:---:|:---:|
| **WEB** | — | **DENY** | ALLOW | **DENY** |
| **DB**  | **DENY** | — | **DENY** | **DENY** |
| **APP** | **DENY** | ALLOW | — | **DENY** |
| **MGT** | ALLOW | ALLOW | ALLOW | — |

**Verified:** 12/12 flows enforce correct.

### 5.2 Enforcement Point

- **Where:** `iptables FORWARD chain` trên LEAF-1 và LEAF-2 (defense-in-depth — cả 2 LEAF apply rule giống nhau cho flows liên quan).
- **Why iptables, không phải SONiC ACL:** SONiC-VS chạy mode software, không có ASIC để enforce ACL → fallback Linux kernel netfilter.
- **State tracking:** `conntrack` module enabled; rule `ESTABLISHED,RELATED ACCEPT` trước các DROP rule để cho phép reply traffic.

### 5.3 iptables Rules — LEAF-1 (WEB + DB zones)

```bash
# Default policy
iptables -P FORWARD DROP

# Conntrack — cho phép reply
iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# === ZT POLICY: WEB zone (10.1.100.0/24) ===
iptables -A FORWARD -s 10.1.100.0/24 -d 10.1.200.0/24 -j DROP   # WEB→DB BLOCK
iptables -A FORWARD -s 10.1.100.0/24 -d 10.2.50.0/24  -j DROP   # WEB→MGT BLOCK
iptables -A FORWARD -s 10.1.100.0/24 -d 10.2.100.0/24 -j ACCEPT # WEB→APP ALLOW

# === ZT POLICY: DB zone (10.1.200.0/24) — outbound DENY-ALL ===
iptables -A FORWARD -s 10.1.200.0/24 -d 10.1.100.0/24 -j DROP
iptables -A FORWARD -s 10.1.200.0/24 -d 10.2.100.0/24 -j DROP
iptables -A FORWARD -s 10.1.200.0/24 -d 10.2.50.0/24  -j DROP
iptables -A FORWARD -s 10.1.200.0/24 -j DROP

# === Inbound to DB — only from APP ===
iptables -A FORWARD -s 10.2.100.0/24 -d 10.1.200.0/24 -j ACCEPT  # APP→DB ALLOW
iptables -A FORWARD -s 10.2.50.0/24  -d 10.1.200.0/24 -j ACCEPT  # MGT→DB ALLOW

# Drop everything else
iptables -A FORWARD -j DROP
```

### 5.4 iptables Rules — LEAF-2 (APP + MGT zones)

```bash
iptables -P FORWARD DROP
iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# === ZT POLICY: APP zone (10.2.100.0/24) ===
iptables -A FORWARD -s 10.2.100.0/24 -d 10.1.100.0/24 -j DROP   # APP→WEB BLOCK (reverse call)
iptables -A FORWARD -s 10.2.100.0/24 -d 10.2.50.0/24  -j DROP   # APP→MGT BLOCK
iptables -A FORWARD -s 10.2.100.0/24 -d 10.1.200.0/24 -j ACCEPT # APP→DB ALLOW

# === ZT POLICY: MGT zone (10.2.50.0/24) — full access ===
iptables -A FORWARD -s 10.2.50.0/24 -j ACCEPT

# === Inbound to APP — from WEB only ===
iptables -A FORWARD -s 10.1.100.0/24 -d 10.2.100.0/24 -j ACCEPT  # WEB→APP ALLOW

iptables -A FORWARD -j DROP
```

### 5.5 Apply / Rollback / Status

Hiện tại quản lý qua Python helper:

```bash
cd /3s-com/zma/dc-fabric-setup
python3 07-apply-policy.py apply      # push iptables qua console
python3 07-apply-policy.py rollback   # iptables -F FORWARD && -P ACCEPT
python3 07-apply-policy.py status     # iptables -L -n -v
python3 08-verify-policy.py           # 12-flow verification
```

**SDNC AI Agent integration target:** thay thế `07-apply-policy.py` bằng REST/NETCONF call từ ONAP SDNC.

---

## 6. Traffic Mirroring — IDS Tap

### 6.1 tc mirred config (LEAF-1)

```bash
# Mirror Vlan100 ingress (WEB) → eth4 (đến IDS eth0)
tc qdisc add dev Vlan100 handle ffff: ingress
tc filter add dev Vlan100 parent ffff: protocol ip u32 match u32 0 0 \
    action mirred egress mirror dev eth4

# Mirror Vlan200 ingress (DB) → eth4
tc qdisc add dev Vlan200 handle ffff: ingress
tc filter add dev Vlan200 parent ffff: protocol ip u32 match u32 0 0 \
    action mirred egress mirror dev eth4
```

### 6.2 tc mirred config (LEAF-2)

```bash
# Mirror Vlan100 ingress (APP) → eth4 (đến IDS eth1)
tc qdisc add dev Vlan100 handle ffff: ingress
tc filter add dev Vlan100 parent ffff: protocol ip u32 match u32 0 0 \
    action mirred egress mirror dev eth4

# Mirror Vlan300 ingress (MGT) → eth4
tc qdisc add dev Vlan300 handle ffff: ingress
tc filter add dev Vlan300 parent ffff: protocol ip u32 match u32 0 0 \
    action mirred egress mirror dev eth4
```

**Quan trọng:** tc mirred chạy ở `ingress` qdisc, **trước** netfilter. IDS thấy được packet kể cả khi iptables DROP.

---

## 7. Detection Rules — Suricata 8.0

**File:** `/etc/suricata/rules/3s-nos.rules` trên IDS node
**Reload:** `kill -USR2 $(cat /var/run/suricata.pid)` — không cần restart

| SID | Priority | Class | Match | Msg |
|-----|----------|-------|-------|-----|
| 9000001 | P1 | policy-violation | `10.1.100.0/24 → 10.1.200.0/24` | WEB direct to DB |
| 9000002 | P1 | policy-violation | `10.1.200.0/24 → !10.1.200.0/24` | DB initiating outbound |
| 9000006 | P1 | policy-violation | `10.2.100.0/24 → 10.1.200.0/24` | APP direct to DB (lateral) |
| 9000003 | P2 | lateral-movement | `10.2.100.0/24 → 10.1.100.0/24` | APP reverse call WEB |
| 9000004 | P2 | lateral-movement | `10.1.100.0/24 → 10.2.50.0/24` | WEB to MGT |
| 9000005 | P2 | lateral-movement | `10.2.100.0/24 → 10.2.50.0/24` | APP to MGT |
| 9000010 | P3 | reconnaissance | ICMP threshold 3/10s | Ping sweep |
| 9000011 | P3 | reconnaissance | TCP SYN threshold 10/5s | Port scan |
| 9000020 | P4 | audit | `10.2.50.0/24 → ANY` (1/min/src) | MGT zone access |

---

## 8. North-bound API — for ONAP SDNC Integration

### 8.1 IDS Alert API (Suricata side)

Base URL: `http://10.10.6.238:8765` (LAN) / `http://112.137.129.232:8765` (public NAT)

| Method | Path | Response |
|--------|------|----------|
| GET | `/health` | `{status, suricata, ts}` |
| GET | `/alerts` | `{count, summary, alerts[]}` |
| GET | `/alerts?last=N` | last N alerts |
| GET | `/stream` | SSE stream — 1 event = 1 alert JSON |

### 8.2 Go IDS Agent (real-time bridge)

Base URL: `http://10.10.6.238:8766`

| Method | Path | Use |
|--------|------|-----|
| GET | `/health` | Proxy → Suricata `/health` |
| GET | `/alerts` | Proxy → Suricata `/alerts` |
| GET | `/events` | SSE — alerts + heartbeat (15s) + `{type:"connected"}` event |
| GET | `/ws` | WebSocket — same payload as `/events` |

### 8.3 Alert JSON Schema

```json
{
  "timestamp": "2026-04-19T18:13:01Z",
  "event_type": "alert",
  "src_ip": "10.1.100.10",
  "dest_ip": "10.1.200.10",
  "proto": "TCP",
  "alert": {
    "signature": "[ZT-VIOLATION] WEB direct to DB - microsegmentation bypass",
    "signature_id": 9000001,
    "severity": 1,
    "category": "policy-violation"
  }
}
```

---

## 9. Control Plane Integration — What SDNC Needs to Do

### 9.1 Connector Targets

ONAP SDNC AI Agent cần build connector tới:

| Target | Protocol | Endpoint | Action |
|--------|----------|----------|--------|
| SONIC-SPINE | SSH telnet console | `telnet 112.137.129.232:5006` | Routing policy push |
| **SONIC-LEAF-1** | **SSH telnet console** | `telnet 112.137.129.232:5010` | **Apply iptables** (ZT enforcement) |
| **SONIC-LEAF-2** | **SSH telnet console** | `telnet 112.137.129.232:5015` | **Apply iptables** (ZT enforcement) |
| IDS Suricata | REST + SSE | `:8765` / `:8766` | Subscribe alerts |

**Ghi chú:** SONiC-VS không support proper NETCONF/gNMI — cần dùng Linux shell qua telnet console hoặc SSH (nếu enable). Production SONiC sẽ có gNMI/NETCONF chuẩn.

### 9.2 Enforcement Targets — chỉ LEAF cần apply rule

| Switch | Cần apply microsegmentation? | Lý do |
|--------|:-:|------|
| SONIC-SPINE | ❌ | Pure transit, không terminate VLAN, không có host trực tiếp |
| **SONIC-LEAF-1** | ✅ | Terminate WEB+DB SVI, phải enforce intra-leaf (WEB→DB) + inter-leaf rules |
| **SONIC-LEAF-2** | ✅ | Terminate APP+MGT SVI, phải enforce intra-leaf (APP→MGT) + inter-leaf rules |

### 9.3 Suggested SDNC Workflow

```
┌─────────────────────────────────────────────────────────────┐
│ ONAP SDNC AI Agent                                          │
│                                                             │
│  1. Subscribe SSE: GET http://10.10.6.238:8766/events       │
│  2. On P1 alert received:                                   │
│     a. Identify src_ip → determine LEAF (zone mapping)      │
│     b. Build iptables rule:                                 │
│        iptables -I FORWARD 1 -s <src_ip> -j DROP            │
│     c. Push qua SSH/telnet console tới LEAF                 │
│     d. Schedule auto-unblock (e.g., 5 min TTL)              │
│  3. Status feedback:                                        │
│     a. POST event "BLOCKED" về dashboard                    │
│     b. Log audit trail                                      │
└─────────────────────────────────────────────────────────────┘
```

### 9.4 Zone Mapping Helper (for SDNC)

```python
def ip_to_leaf(src_ip: str) -> str:
    """Map source IP → LEAF switch để biết apply rule ở đâu."""
    if src_ip.startswith("10.1.100.") or src_ip.startswith("10.1.200."):
        return "SONIC-LEAF-1"
    if src_ip.startswith("10.2.100.") or src_ip.startswith("10.2.50."):
        return "SONIC-LEAF-2"
    return None

def ip_to_zone(src_ip: str) -> str:
    if src_ip.startswith("10.1.100."): return "WEB"
    if src_ip.startswith("10.1.200."): return "DB"
    if src_ip.startswith("10.2.100."): return "APP"
    if src_ip.startswith("10.2.50."):  return "MGT"
    return None
```

---

## 10. Verification & Test Status

| Test | Result | Date |
|------|--------|------|
| 8-path connectivity matrix | 8/8 PASS | 2026-04-13 |
| 12-flow ZT policy enforcement | 12/12 correct | 2026-04-14 |
| Suricata detection (4 violations) | 4/4 detected | 2026-04-18 |
| End-to-end SC-1 → SC-5 | 5/5 PASS | 2026-04-19 |
| False Positive Rate (SC-5 baseline) | 0% | 2026-04-19 |
| Browser dashboard | 8/8 PASS | 2026-04-19 |
| **Total live alerts captured** | **38** | **2026-04-19** |

---

## 11. Files / Scripts Reference

| File | Purpose |
|------|---------|
| `/3s-com/zma/dc-fabric-setup/05-setup-all.py` | Full fabric setup automation |
| `/3s-com/zma/dc-fabric-setup/06-verify.py` | Connectivity matrix verification |
| `/3s-com/zma/dc-fabric-setup/07-apply-policy.py` | iptables apply/rollback (target for SDNC replacement) |
| `/3s-com/zma/dc-fabric-setup/07-iptables-leaf1.sh` | Raw iptables rules LEAF-1 |
| `/3s-com/zma/dc-fabric-setup/07-iptables-leaf2.sh` | Raw iptables rules LEAF-2 |
| `/3s-com/zma/dc-fabric-setup/08-verify-policy.py` | 12-flow policy verification |
| `/3s-com/zma/dc-fabric-setup/14-ids-webapi.py` | IDS REST API restore |
| `/etc/suricata/rules/3s-nos.rules` (on IDS VM) | 9 detection rules |

---

## 12. Open Items for SDNC Agent

- [ ] Build SSH/telnet connector to SONiC-LEAF console (port 5010, 5015)
- [ ] Implement iptables rule push API (mirror `07-apply-policy.py`)
- [ ] Subscribe to IDS SSE stream (`http://10.10.6.238:8766/events`)
- [ ] Implement auto-block workflow (alert P1 → iptables DROP src_ip on relevant LEAF)
- [ ] Implement auto-unblock TTL (e.g., 5–15 min)
- [ ] Send block-event back to dashboard (new endpoint to design)
- [ ] Audit trail / compliance log (who blocked what, when, why)

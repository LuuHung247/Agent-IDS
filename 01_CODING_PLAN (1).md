# Coding Plan — Intelligence Layer cho Zero Trust Microsegmentation

> **Mục đích tài liệu:** Đưa cho coding agent (Claude Code / Cursor / etc.) để implement Intelligence Layer (LLM Agent) cho hệ thống Zero Trust Microsegmentation. Hệ thống hiện tại đã có Data Plane (SONiC spine-leaf + iptables enforcement) và Monitoring (Suricata + Go IDS Agent + Next.js dashboard).
> **Phạm vi:** Build LLM Agent làm Intelligence Layer, tích hợp vào hệ thống hiện có.
> **Ngôn ngữ chính:** Python 3.12 (Agent), tích hợp qua HTTP/gRPC với Go BE hiện tại.

---

## 1. Project Structure

```
intelligence-layer/
├── pyproject.toml                 # Poetry/uv dependencies
├── .env.example                   # Environment variables template
├── README.md
├── docker-compose.yml             # Redis, Postgres, Chroma services
├── Dockerfile                     # Agent service image
│
├── src/
│   ├── __init__.py
│   ├── main.py                    # FastAPI entrypoint + lifespan
│   ├── config.py                  # Pydantic Settings (env vars)
│   │
│   ├── agent/
│   │   ├── __init__.py
│   │   ├── graph.py               # LangGraph workflow definition
│   │   ├── nodes.py               # Graph nodes (classify, reason, decide, validate)
│   │   ├── state.py               # AgentState schema
│   │   ├── prompts.py             # System prompts + templates
│   │   └── llm_client.py          # Model-agnostic LLM wrapper (OpenAI-compatible)
│   │
│   ├── tools/
│   │   ├── __init__.py
│   │   ├── registry.py            # Tool registration + schemas
│   │   ├── topology.py            # get_zone_info, get_host_info
│   │   ├── policy.py              # query_policy_matrix, check_conflict
│   │   ├── history.py             # get_alert_history, get_recent_decisions
│   │   ├── threat_intel.py        # query_mitre_kb (vector search)
│   │   └── enforcement.py         # generate_policy_intent, push_enforcement
│   │
│   ├── state_manager/
│   │   ├── __init__.py
│   │   ├── snapshot.py            # Hot cache - topology/policy snapshot
│   │   ├── redis_store.py         # Warm cache - alert history, decisions
│   │   └── postgres_store.py      # Cold storage - full audit log
│   │
│   ├── trigger/
│   │   ├── __init__.py
│   │   ├── consumer.py            # Redis Stream consumer (from Go BE)
│   │   ├── filters.py             # Severity, dedup, rate limit, whitelist
│   │   └── gate.py                # Orchestrates filters, decides when to invoke Agent
│   │
│   ├── enforcement/
│   │   ├── __init__.py
│   │   ├── interface.py           # Abstract EnforcementBackend
│   │   ├── ssh_backend.py         # SSH-direct to LEAF (temporary, for dev)
│   │   ├── onap_backend.py        # ONAP SDNC backend (stub, implement later)
│   │   └── mock_backend.py        # Mock for testing
│   │
│   ├── validation/
│   │   ├── __init__.py
│   │   ├── schema_validator.py    # Check LLM output schema
│   │   ├── policy_validator.py    # Check policy conflict
│   │   └── confidence_gate.py     # Confidence threshold check
│   │
│   ├── api/
│   │   ├── __init__.py
│   │   ├── routes.py              # /alerts, /decisions, /health, /stream (SSE)
│   │   └── schemas.py             # Pydantic request/response models
│   │
│   └── observability/
│       ├── __init__.py
│       ├── logging.py             # Structured logging (JSON)
│       └── tracing.py             # OpenTelemetry / LangSmith
│
├── tests/
│   ├── unit/
│   │   ├── test_filters.py
│   │   ├── test_validators.py
│   │   └── test_tools.py
│   ├── integration/
│   │   ├── test_agent_flow.py
│   │   └── test_api.py
│   └── fixtures/
│       ├── alerts.json            # Sample Suricata EVE alerts
│       └── topology.json          # Sample topology snapshot
│
├── scripts/
│   ├── init_db.py                 # Create Postgres tables
│   ├── load_topology.py           # Load topology from GNS3 setup
│   ├── seed_mitre_kb.py           # Seed Chroma with MITRE ATT&CK KB
│   └── benchmark_agent.py         # Performance benchmark
│
└── deploy/
    ├── systemd/
    │   └── agent.service
    └── k8s/                        # Optional, for future
        └── deployment.yaml
```

---

## 2. Dependencies

### Python packages (`pyproject.toml`)

```toml
[project]
name = "intelligence-layer"
version = "0.1.0"
requires-python = ">=3.12"
dependencies = [
    # Core framework
    "langgraph>=0.2.50",
    "langchain>=0.3.0",
    "langchain-openai>=0.2.0",       # OpenAI-compatible clients (works for Groq, DeepSeek, etc.)
    "langsmith>=0.2.0",               # Observability

    # API & async
    "fastapi>=0.115.0",
    "uvicorn[standard]>=0.32.0",
    "httpx>=0.27.0",
    "sse-starlette>=2.1.0",          # SSE for streaming decisions to dashboard

    # Data stores
    "redis[hiredis]>=5.2.0",
    "asyncpg>=0.30.0",               # Postgres async
    "sqlalchemy[asyncio]>=2.0.0",
    "alembic>=1.14.0",               # DB migrations
    "chromadb>=0.5.0",               # Vector DB for MITRE KB

    # Validation & schemas
    "pydantic>=2.10.0",
    "pydantic-settings>=2.6.0",

    # SSH backend (temporary)
    "paramiko>=3.5.0",
    "asyncssh>=2.18.0",

    # Observability
    "structlog>=24.4.0",
    "opentelemetry-api>=1.28.0",
    "opentelemetry-sdk>=1.28.0",

    # Utilities
    "tenacity>=9.0.0",               # Retry logic
    "python-dotenv>=1.0.0",
]

[dependency-groups]
dev = [
    "pytest>=8.3.0",
    "pytest-asyncio>=0.24.0",
    "pytest-cov>=6.0.0",
    "ruff>=0.8.0",
    "mypy>=1.13.0",
]
```

### Infrastructure (`docker-compose.yml`)

Services needed:
- **redis:7-alpine** — Streams (alert queue) + warm cache
- **postgres:16-alpine** — Cold storage, audit log
- **chromadb/chroma:latest** — MITRE KB vector store

Reuse existing:
- Suricata + Go IDS Agent + Next.js dashboard (đã có)

---

## 3. Environment Variables (`.env.example`)

```bash
# LLM Provider (model-agnostic via OpenAI-compatible API)
LLM_API_KEY=your_api_key_here
LLM_BASE_URL=https://api.groq.com/openai/v1   # Groq primary, swap anytime
LLM_MODEL_PRIMARY=openai/gpt-oss-120b          # For complex reasoning
LLM_MODEL_FAST=llama-3.3-70b-versatile         # For simple classification
LLM_TEMPERATURE=0.1                             # Low for security decisions
LLM_MAX_TOKENS=2048
LLM_TIMEOUT_SECONDS=10

# Fallback provider (optional)
LLM_FALLBACK_API_KEY=
LLM_FALLBACK_BASE_URL=https://openrouter.ai/api/v1
LLM_FALLBACK_MODEL=

# Redis
REDIS_URL=redis://localhost:6379/0
REDIS_STREAM_ALERTS=alerts:incoming
REDIS_STREAM_DECISIONS=decisions:outgoing
REDIS_CACHE_TTL_SECONDS=3600

# Postgres
POSTGRES_URL=postgresql+asyncpg://user:pass@localhost:5432/zerotrust

# ChromaDB
CHROMA_HOST=localhost
CHROMA_PORT=8001
CHROMA_COLLECTION=mitre_attack

# Agent behavior
AGENT_CONFIDENCE_THRESHOLD=0.7
AGENT_MAX_RETRIES=2
AGENT_ENABLE_SELF_CONSISTENCY=false   # Stretch goal

# Trigger filters
FILTER_SEVERITY_MIN=2                  # Only P1 + P2 trigger LLM
FILTER_DEDUP_WINDOW_SECONDS=30
FILTER_RATE_LIMIT_PER_MINUTE=30
FILTER_WHITELIST_IPS=                  # Comma-separated

# Enforcement backend (swap for ONAP later)
ENFORCEMENT_BACKEND=ssh                # ssh | onap | mock
SSH_LEAF1_HOST=192.168.122.187
SSH_LEAF1_USER=admin
SSH_LEAF1_KEY_PATH=~/.ssh/leaf1_rsa
# ... similar for LEAF2

# Observability
LANGSMITH_API_KEY=
LANGSMITH_PROJECT=zerotrust-agent
LOG_LEVEL=INFO

# Integration với Go BE
GO_BE_WEBHOOK_URL=http://localhost:8080/api/agent/decision
```

---

## 4. Component Specifications

### 4.1. `AgentState` schema (`src/agent/state.py`)

```python
from typing import TypedDict, Annotated, Sequence
from langchain_core.messages import BaseMessage
from langgraph.graph.message import add_messages

class AgentState(TypedDict):
    # Input
    alert: dict                    # Raw alert from Suricata (parsed)
    alert_id: str
    trigger_time: str              # ISO timestamp

    # Context (pre-loaded, cached)
    topology_snapshot: dict        # Zones, hosts, VLANs
    policy_matrix: dict            # Zone-to-zone rules
    active_enforcement: list       # Current iptables rules

    # Dynamic context (loaded during reasoning)
    alert_history: list            # Recent alerts from same src_ip
    recent_decisions: list         # Agent's recent decisions

    # Agent workflow
    messages: Annotated[Sequence[BaseMessage], add_messages]
    classification: str | None     # "benign" | "suspicious" | "confirmed_threat"
    threat_assessment: dict | None # {mitre_technique, kill_chain_stage, confidence}
    policy_decision: dict | None   # {action, target, duration, rationale}

    # Validation & outcome
    validation_passed: bool
    validation_errors: list
    confidence_score: float
    requires_human_review: bool

    # Enforcement
    enforcement_status: str | None # "pending" | "applied" | "failed"
    enforcement_details: dict | None
```

### 4.2. LangGraph Workflow (`src/agent/graph.py`)

**Graph nodes and flow:**

```
[START]
   ↓
[load_context]      ← Load topology/policy snapshot from hot cache
   ↓
[classify_alert]    ← LLM: benign / suspicious / threat (fast model)
   ↓
{router: is_threat?}
   ├─ no  → [log_and_end]
   └─ yes → [gather_context]   ← Fetch alert history + recent decisions (parallel)
              ↓
          [reason_and_decide]  ← LLM: deep reasoning (primary model)
              ↓
          [validate_decision]  ← Schema + policy conflict + confidence check
              ↓
          {router: validation_passed?}
              ├─ no  → [retry or escalate]
              └─ yes → [enforce_policy]
                         ↓
                     [record_decision]  ← Save to Postgres + Redis + SSE to dashboard
                         ↓
                     [END]
```

### 4.3. Tool Definitions (`src/tools/`)

Each tool returns **structured data** (Pydantic model), not free text. Tools must be **stateless** and **cached** where possible.

**Tool schemas (OpenAI function calling format):**

```python
# tools/topology.py
@tool
async def get_host_info(ip: str) -> HostInfo:
    """Get detailed info about a host by IP. Cached in Redis (TTL=1h)."""

# tools/policy.py
@tool
async def query_policy_matrix(src_zone: str, dst_zone: str) -> PolicyRule:
    """Query policy matrix for zone-to-zone rule. Read from hot cache."""

@tool
async def check_policy_conflict(new_rule: PolicyRule) -> ConflictReport:
    """Check if new rule conflicts with existing rules."""

# tools/history.py
@tool
async def get_alert_history(src_ip: str, window_minutes: int = 5) -> list[Alert]:
    """Get recent alerts from src_ip. Redis cache first, Postgres fallback."""

@tool
async def get_recent_decisions(src_ip: str, window_minutes: int = 30) -> list[Decision]:
    """Get recent Agent decisions affecting src_ip."""

# tools/threat_intel.py
@tool
async def query_mitre_kb(query: str, top_k: int = 3) -> list[MitreTechnique]:
    """Semantic search over MITRE ATT&CK KB. Returns top matches."""

# tools/enforcement.py
@tool
async def generate_policy_intent(
    action: Literal["block", "quarantine", "rate_limit", "log_only"],
    target_ip: str,
    duration_seconds: int,
    rationale: str
) -> PolicyIntent:
    """Generate structured policy intent. Does NOT push to enforcement."""
```

**IMPORTANT:** Tools `get_zone_info`, `get_all_zones`, `get_policy_matrix_full` should NOT be exposed — data is in system prompt snapshot.

### 4.4. State Manager (`src/state_manager/`)

**Tier 1 — Hot Cache (`snapshot.py`):**

```python
class StateSnapshot:
    """Loaded at startup, injected into system prompt."""

    topology: dict          # zones, vlans, hosts mapping
    policy_matrix: dict     # zone-to-zone rules
    active_rules: list      # current iptables rules on LEAFs

    async def load_from_db(self) -> None: ...
    async def refresh(self) -> None: ...   # Called on SIGHUP or every 5min
    def render_for_prompt(self) -> str: ... # Format as text for LLM context
```

**Tier 2 — Warm Cache (`redis_store.py`):**

```python
class RedisStore:
    async def cache_alert(self, alert_id: str, alert: dict, ttl: int = 86400)
    async def get_recent_alerts(self, src_ip: str, window_minutes: int) -> list
    async def cache_decision(self, decision_id: str, decision: dict)
    async def get_recent_decisions(self, src_ip: str) -> list
    async def increment_rate_counter(self, key: str, window: int) -> int
```

**Tier 3 — Cold Storage (`postgres_store.py`):**

SQLAlchemy models needed:
- `Alert` — all alerts received
- `AgentDecision` — all decisions (including rejected)
- `EnforcementRecord` — all enforcement actions + status
- `AuditLog` — full Agent reasoning trace (ReAct steps)

### 4.5. Trigger Layer (`src/trigger/`)

**Consumer (`consumer.py`):**

- Subscribe to Redis Stream `alerts:incoming`
- Parse alert format (Suricata EVE JSON)
- Pass through filter chain
- If passes, invoke Agent graph

**Filter chain (`filters.py`):**

```python
class SeverityFilter:
    """Pass only P1 (severity=1) and P2 (severity=2). P3/P4 → log only."""

class DedupFilter:
    """Group similar alerts (same src, dst_zone, rule) in 30s window."""

class RateLimiter:
    """Max N LLM invocations per minute. Token bucket algorithm."""

class WhitelistFilter:
    """Bypass Agent for known-benign sources (health checks, monitoring)."""
```

**Gate (`gate.py`):** Orchestrates filters in order, returns `ShouldInvokeAgent` boolean.

### 4.6. Enforcement Interface (`src/enforcement/`)

**Abstract interface (`interface.py`):**

```python
class EnforcementBackend(ABC):
    @abstractmethod
    async def apply_policy(self, intent: PolicyIntent) -> EnforcementResult: ...

    @abstractmethod
    async def verify_applied(self, intent_id: str) -> VerificationResult: ...

    @abstractmethod
    async def rollback(self, intent_id: str) -> None: ...
```

**Implementations:**

1. **SSHBackend (`ssh_backend.py`):** Temporary — SSH vào LEAF-1/LEAF-2, exec iptables commands. **Warning in code:** "Dev only, replace with ONAP for production defense."
2. **ONAPBackend (`onap_backend.py`):** Stub, implement later when Hung provides SDNC specs.
3. **MockBackend (`mock_backend.py`):** For unit tests, logs actions without executing.

Backend selected via `ENFORCEMENT_BACKEND` env var.

### 4.7. Validation Layer (`src/validation/`)

**Three validators run in sequence after LLM decision:**

1. **SchemaValidator:** Ensure LLM output matches `PolicyDecision` Pydantic schema. Reject free-form text.

2. **PolicyValidator:**
   - Target IP exists in topology snapshot (no hallucinated IPs)
   - Action is in allowed action set
   - New rule doesn't conflict with existing rules
   - No privilege escalation (e.g., Agent blocking MGT zone — should escalate to human)

3. **ConfidenceGate:**
   - Confidence score >= threshold (default 0.7) → proceed
   - 0.5-0.7 → conservative action (rate-limit instead of block) + human notification
   - <0.5 → escalate to human, no auto-enforce

If validation fails:
- Schema fail → retry Agent with feedback (max 2 retries)
- Policy/Confidence fail → escalate, log, skip enforcement

### 4.8. API Layer (`src/api/`)

**Endpoints:**

```
POST /alerts                    # Receive alert from Go BE (alternative to Redis Stream)
GET  /decisions                 # List recent decisions
GET  /decisions/{id}            # Decision detail + full ReAct trace
GET  /health                    # Health check
GET  /stream/decisions          # SSE stream for dashboard
GET  /stats                     # Agent stats: decisions/min, accuracy, latency
POST /human/review/{id}         # Human approves/rejects escalated decision
```

**Integration với Go BE:**

- Go BE publishes alerts to Redis Stream `alerts:incoming` (preferred)
- Agent publishes decisions to Redis Stream `decisions:outgoing`
- Go BE consumes decisions → forward to Next.js dashboard via existing WebSocket

---

## 5. System Prompt Structure

The system prompt is the **most important asset**. Keep it modular, cached by LLM provider.

**Structure (`src/agent/prompts.py`):**

```
[ROLE]
You are a Zero Trust security analyst for a data center...

[DATACENTER CONTEXT]  ← Loaded from StateSnapshot, ~3-5K tokens
Zones: WEB, DB, APP, MGT (details)
Policy matrix: ...
Active enforcement rules: ...
MITRE TA0008 lateral movement patterns of interest: ...

[TOOLS AVAILABLE]
- get_host_info(ip): Fetch host detail if not in context
- get_alert_history(ip): Fetch recent alerts from src_ip
- query_mitre_kb(query): Semantic search MITRE KB
- generate_policy_intent(...): Generate structured policy intent
(Note: zone/policy info is in DATACENTER CONTEXT — do NOT call tools for these)

[REASONING RULES]
1. Always cite source for every fact: [from context] or [from tool: tool_name]
2. Never assume facts not in context or tool results
3. For single alert, decide based on context first. Call tools only if:
   - Alert history needed AND src_ip not in RECENT ALERTS
   - MITRE technique unclear
4. Output MUST be a generate_policy_intent tool call, not free text.

[DECISION FRAMEWORK]
- Single benign-looking alert from known source → log_only
- Scan pattern (5+ targets in 1min) → block src IP 1h
- Multi-stage attack (WEB→APP→MGT pivot) → quarantine src + tighten zone policy
- High-criticality target (MGT zone) + any suspicious → escalate immediately

[CONFIDENCE SCORING]
Output confidence 0.0-1.0 based on:
- Evidence strength (multiple corroborating signals = higher)
- Pattern match clarity
- Absence of benign explanations
```

---

## 6. Implementation Order (Sprint Breakdown)

### Sprint 1 (Week 1): Foundation
- [ ] Project structure + dependencies
- [ ] Docker compose (Redis, Postgres, Chroma)
- [ ] Config + env management
- [ ] Postgres schema + Alembic migrations
- [ ] Topology loader from GNS3 data (script)
- [ ] StateSnapshot class + render for prompt
- [ ] MITRE KB seeder (Chroma)
- [ ] Basic FastAPI skeleton + health endpoint

**Acceptance:** `curl /health` returns 200. `scripts/load_topology.py` populates DB. Snapshot renders as text.

### Sprint 2 (Week 1-2): Trigger & State
- [ ] Redis Stream consumer (alerts:incoming)
- [ ] Filter chain (severity, dedup, rate limit, whitelist)
- [ ] RedisStore (warm cache operations)
- [ ] PostgresStore (cold storage CRUD)
- [ ] Mock alert generator for testing

**Acceptance:** Publish 100 mock alerts to Redis Stream → only P1/P2 pass filter, dedup works, rate limit triggers.

### Sprint 3 (Week 2-3): Agent Core
- [ ] LLM client (OpenAI-compatible wrapper with fallback)
- [ ] Tool definitions + registry
- [ ] System prompt templates
- [ ] LangGraph workflow (nodes + edges)
- [ ] AgentState management
- [ ] Single-model end-to-end test

**Acceptance:** Inject 1 alert → Agent runs full graph → outputs PolicyIntent JSON. LangSmith trace shows full ReAct steps.

### Sprint 4 (Week 3): Validation & Enforcement
- [ ] Schema validator
- [ ] Policy validator (conflict detection)
- [ ] Confidence gate
- [ ] Retry logic (max 2)
- [ ] SSH enforcement backend
- [ ] Mock backend for tests
- [ ] ONAP backend stub (interface only)

**Acceptance:** End-to-end flow works: alert → Agent decision → validation → SSH push → iptables rule applied on LEAF. Confidence gate escalates correctly.

### Sprint 5 (Week 4): Closed-Loop Feedback
- [ ] Enforcement verification (check rule applied)
- [ ] Alert monitoring post-enforcement (efficacy check)
- [ ] Feedback loop: if threat continues → escalate action
- [ ] Decision audit trail (full ReAct trace in Postgres)

**Acceptance:** Block IP → verify rule exists on LEAF → simulate continued threat → Agent escalates to quarantine.

### Sprint 6 (Week 4-5): Integration + Dashboard
- [ ] SSE endpoint for dashboard stream
- [ ] Integration with existing Go BE (Redis Stream + HTTP webhook)
- [ ] Dashboard page: "Agent Decisions" (in existing Next.js)
- [ ] Display: alert → ReAct trace → decision → enforcement status
- [ ] Human review endpoint for escalated decisions

**Acceptance:** Dashboard shows real-time Agent activity. Click decision → see full reasoning trace.

### Sprint 7 (Week 5-6): Evaluation & Hardening
- [ ] Benchmark script (alerts/sec throughput)
- [ ] 3 config setup (A: flat, B: static microseg, C: full proposed)
- [ ] Evaluation harness for 8 metrics
- [ ] Load test with attack scenarios (SC1-SC5)
- [ ] Documentation + README

**Acceptance:** Benchmark runs 5 scenarios × 3 configs. Metrics report generated.

---

## 7. Integration Points với Hệ Thống Hiện Có

### 7.1. Go IDS Agent (existing)
- Add Redis Stream publisher: push alerts to `alerts:incoming` stream
- Alert format: Suricata EVE JSON + enrichment (severity label, zone mapping)

### 7.2. Go BE (existing, Next.js backend)
- Subscribe to Redis Stream `decisions:outgoing`
- Forward decisions to Next.js via existing WebSocket
- Expose HTTP endpoint `/api/agent/decision` (alternative input)

### 7.3. Next.js Dashboard (existing, Threatcrush)
- Add page `/agent-decisions`
- Components:
  - Real-time decision feed (SSE from Agent)
  - Decision detail modal (ReAct trace visualization)
  - Human review UI (for escalated decisions)
  - Agent stats panel (decisions/min, accuracy, avg latency)

### 7.4. Suricata + SPAN mirroring (existing)
- No changes needed — alerts flow through existing pipeline

### 7.5. SONiC LEAF switches (existing iptables enforcement)
- SSH access from Agent (temporary, until ONAP integration)
- Credentials in env vars, keys managed securely

---

## 8. Testing Strategy

### Unit tests
- Each filter (severity, dedup, rate limit)
- Each validator
- Each tool (with mocked dependencies)
- State snapshot rendering

### Integration tests
- Full Agent graph with mock LLM
- Redis Stream producer-consumer flow
- Enforcement backend (against GNS3 testbed)

### End-to-end tests
- Attack scenario replay (SC1-SC5 from Phase 4)
- Performance benchmark (latency, throughput)

### LLM output testing
- Prompt regression test suite (snapshot testing)
- Hallucination test: inject non-existent IP → verify Agent doesn't fabricate zone

---

## 9. Acceptance Criteria (Overall)

The Intelligence Layer is **complete** when:

1. **Functional:**
   - Agent processes alerts end-to-end with < 2s median latency
   - Correct decisions on 5 MITRE ATT&CK lateral movement scenarios (SC1-SC5)
   - Closed-loop feedback: block → verify → escalate if needed
   - Validation layer blocks hallucinated IPs (test case)

2. **Performance:**
   - Median Agent decision latency < 2s
   - Can handle 30 alert/min sustained
   - Tool call count < 2 per decision (thanks to caching)

3. **Observability:**
   - Full ReAct trace available for every decision
   - LangSmith dashboard shows agent activity
   - Postgres audit log queryable by src_ip, decision_type

4. **Security:**
   - No fabricated facts in outputs (validation catches hallucinations)
   - Confidence gate prevents auto-enforce on low-confidence decisions
   - SSH credentials properly secured (env vars, not hardcoded)

5. **Integration:**
   - Dashboard displays real-time Agent decisions
   - Existing Go BE + Next.js work without breaking changes

---

## 10. Non-Functional Requirements

- **Reliability:** Graceful degradation — if LLM unavailable, Agent falls back to rule-based conservative action (block P1 alerts, log P2)
- **Security:** No secrets in logs, all API keys in env vars, SSH keys restricted permissions
- **Maintainability:** Type hints everywhere, ruff + mypy strict mode, >80% test coverage
- **Cost:** Budget-aware — track LLM tokens used, alert if monthly cost exceeds $20
- **Privacy:** No PII in logs (IP addresses OK for this context, but no user data)

---

## 11. Deliverables

Khi hoàn thành, repo cần có:

- Running Agent service (dockerized)
- CLI tool để replay attack scenarios
- Documentation (README + architecture doc)
- Benchmark report (JSON + Markdown)
- Demo video (optional, for thesis defense)
- Postman/HTTPie collection for API testing

---

**End of Coding Plan.**

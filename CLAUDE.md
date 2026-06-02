# CLAUDE.md

Guidance for working on **NetOps_Observability** in this repository.

> The working directory also contains a `network-automation-mpls-l3vpn/`
> directory — **ignore it**; it is unrelated and out of scope.

The project source lives under `NetOps_Observability/` (a nested dir of the same
name). It has its own `README.md` and `docs/`; read those for depth, this file
is the orientation map and the build/test cheat-sheet.

---

## NetOps_Observability

A Docker-Compose stack: device discovery → multi-protocol telemetry ingestion →
event bus → storage (search / time-series / OLAP) → anomaly correlation → API →
React dashboard, all behind nginx on a single port (`:8000`).

### Components & languages
- **`src/backend/`** — Go API, **stdlib-only by design** (`go.mod` has zero
  dependencies; keep it that way so it builds in a clean offline environment).
  REST + JSON, a WebSocket event hub, a GraphQL stub, and an LLM copilot proxy.
  Subsystems: `alerts/`, `collectors/` (snmp/gnmi/netconf), `notify/`
  (slack/pagerduty/email/sns/twilio), `transport/`, `store/`, `models/`.
- **`src/correlation/`** — Python 3.10 + FastAPI service. Consumes Redpanda
  topics, runs rolling z-score anomaly detection + event correlation, writes
  findings to ClickHouse, serves `/findings`. Deps in `requirements.txt`.
- **`src/frontend/`** — React 18 + TypeScript + Vite + ECharts dashboard
  (small: `App.tsx` ~100 lines). `node_modules/` is gitignored.
- **`src/config/`** — YAML templates mounted into the stack.
- **`deployment/docker/`** — `docker-compose.yml` (~19 services), Dockerfiles,
  per-service configs (nginx, vector, loki, promtail).
- **`scripts/install.py`** — idempotent installer; generates `.env` with random
  secrets, creates `data/` dirs, builds and starts the stack.

### Stack tiers (see `docs/ARCHITECTURE.md`)
Edge ingest (syslog-ng · Telegraf · goflow2) → Vector aggregator → Redpanda
(Kafka API) → Vector router → OpenSearch (hot search) · VictoriaMetrics +
Prometheus (metrics) · ClickHouse (OLAP/flows/findings) → correlation service →
Go API → React UI → nginx. App state in PostgreSQL + Redis. Grafana for
self-observability.

### Build / run / test
```bash
cd NetOps_Observability

# Full stack (requires Docker + Compose v2 plugin; rejects legacy docker-compose)
python3 scripts/install.py            # builds .env + brings stack up on :8000
python3 scripts/install.py --reset-env  # rotate all secrets

# Backend (Go)
cd src/backend && go build ./... && go test ./...

# Correlation (Python)
cd src/correlation && pip install -r requirements.txt && python -m pytest test_anomaly.py

# Frontend
cd src/frontend && npm install && npm run build   # tsc -b && vite build

# Stack ops (from deployment/docker/)
docker compose logs -f
docker compose restart api
docker compose down            # stop, keep data
```
Tests present: `src/backend/{jwt,users,password}_test.go`,
`src/backend/alerts/parse_test.go`, `src/correlation/test_anomaly.py`.

### Conventions & gotchas
- **Backend defaults to the standard library; third-party Go modules are
  allowed ONLY from the allowlist below** (see §6). The rule's *purpose* is a
  clean offline build + minimal attack surface — not dogma. A dependency is
  permitted when it serves a foundational capability the stdlib can't, is
  offline-buildable, pinned, and reviewed. Everything else stays stdlib.
- `data/` and `deployment/docker/.env` are gitignored (generated at install).
  ⚠️ **`.env` is currently tracked in git despite being in `.gitignore`** — it
  was committed before being ignored, so it carries secrets in history. Flag
  this rather than committing further changes to it; consider
  `git rm --cached deployment/docker/.env`.
- Security defaults are scaffold-grade: OpenSearch security plugin disabled,
  copilot off unless `FEATURE_COPILOT=true` + `COPILOT_API_KEY`, SNMP discovery
  defaults to `10.0.0.0/8` (narrow before pointing at a real network).
- Feature flags are env-driven (`ENABLE_SNMP_DISCOVERY`, `ENABLE_GNMI_COLLECTION`,
  `FEATURE_SLACK_NOTIFICATIONS`, etc.) — see `newServer()` in `main.go`.
- Docs live in `docs/`: ARCHITECTURE, INGESTION, STREAMING, ANALYTICS, COPILOT,
  AUTH, DEPLOY_LINUX, UPGRADE, QUICK_REFERENCE.

### Monitoring
- `scripts/stack-watchdog.sh` — external cron watchdog (every 1m). Checks all 18
  compose services running/healthy + probes `:8000`, pings healthchecks.io
  (dead-man's-switch) when healthy, and pushes an ntfy.sh phone alert on
  up↔down transitions. Config in gitignored `scripts/stack-watchdog.env`
  (`NTFY_TOPIC`, `HC_PING_URL`); `--test` sends a probe push. Kept independent
  of the stack's own notifiers on purpose — they can't report their own death.

### Known gotcha (fixed)
- OpenSearch rejects docs whose fields contain dots it reads as object paths.
  The Docker `.label` map (`com.docker.compose.*`) caused a mapping conflict that
  silently dropped *all* app logs. `vector/vector.yaml` now `del(.label)` in the
  applogs/flows transforms. If applog indexing breaks again, suspect dotted-key
  fields first.

---

# AI CODE GENERATION GUARDRAILS (GO / NETOPS PLATFORM)

This file defines mandatory rules for all AI-generated code in this repository.
Any violation = INVALID OUTPUT.

---

## 1. CORE PRINCIPLES

- System must be modular, plug-and-play, and enterprise-grade
- Zero Trust architecture is mandatory everywhere
- No implicit trust between services or modules
- Every dependency must be explicit and injectable
- No hidden coupling between packages
- Simplicity > cleverness
- Production safety > speed of implementation

---

## 2. ARCHITECTURE RULES (STRICT)

### REQUIRED PROJECT STRUCTURE

```
/cmd        → entrypoints only (NO BUSINESS LOGIC)
/internal   → core logic (private domain code)
/pkg        → reusable external-safe libraries
/api        → schemas (OpenAPI / protobuf / contracts)
/plugins    → isolated plugin implementations
/config     → configuration only
```

---

### FORBIDDEN

- Business logic inside /cmd
- Circular dependencies
- Direct cross-domain package calls
- Shared global state
- “utils” dumping ground packages
- Hidden singletons

---

## 3. ZERO TRUST RULES

- Every service must assume all inputs are malicious
- All service-to-service communication must be authenticated
- Use mTLS or signed requests (JWT/HMAC)
- No internal trust shortcuts allowed

### RULES

- Validate ALL inputs at every boundary
- Never trust upstream services
- Never trust plugin outputs
- Never trust cached data without validation

---

## 4. PLUGIN SYSTEM RULES (PLUG-AND-PLAY)

Plugins MUST be isolated.

Allowed models:

### Preferred: RPC-based plugins (gRPC/HTTP)
- Plugins run as separate processes
- Communication only via protobuf/OpenAPI
- No shared memory

OR

### Optional: WASM sandbox plugins
- Must be sandboxed
- Must enforce CPU/memory limits
- Must restrict filesystem/network access

---

### PLUGIN RULES

- Plugins cannot import core system code
- Plugins must be versioned
- Plugins must validate schema on input/output
- Plugins must be replaceable without system change

---

## 5. CODE QUALITY RULES (GO)

- All functions must have explicit types
- No ignored errors (`_ = err` is forbidden unless justified)
- No global variables
- No reflection unless explicitly approved
- No cgo usage unless explicitly approved
- Prefer composition over inheritance
- Use interfaces for all external dependencies

---

## 6. DEPENDENCY RULES

Zero-trust on dependencies stands: **default to the standard library.** A
third-party module is allowed only when it clears ALL of these gates:

1. **Need** — it provides a foundational capability the stdlib genuinely cannot
   (e.g. a database driver), not mere convenience.
2. **Offline-buildable** — vendored or module-cached so `go build` works in a
   clean, network-less environment (the original reason for the stdlib rule).
3. **Pinned & reviewed** — exact version in `go.mod`, justified in the PR.
4. **Minimal surface** — prefer build-time codegen (e.g. sqlc) or a single
   driver over frameworks/ORMs that pull large transitive trees.

### Allowlist (the ONLY third-party modules permitted)

| Module | Purpose | Notes |
|--------|---------|-------|
| `github.com/jackc/pgx` (or `lib/pq`) | PostgreSQL driver | Required for the relational app-state store (M0). Build-tagged/opt-in; default file build stays dependency-free. |
| `sqlc` (build-time, not a runtime import) | type-safe SQL → Go codegen | Generated code is checked in; runtime keeps only the driver. |

Anything not in this table is **forbidden without first amending this table.**
No automatic addition of libraries. Keep the dependency graph minimal. When in
doubt, stdlib.

---

## 7. AI CODE GENERATION RULES

When generating code:

### REQUIRED OUTPUT STRUCTURE

1. Interfaces first
2. Core implementation
3. Tests
4. Example usage

---

### MODIFICATION RULES

- One bounded context per change
- Do NOT modify unrelated modules
- Do NOT refactor multiple domains in one change
- Keep changes isolated and minimal

---

### FORBIDDEN AI BEHAVIOR

- Do not invent APIs that do not exist
- Do not assume hidden framework behavior
- Do not skip error handling
- Do not bypass architecture rules for convenience

---

## 8. SECURITY RULES

- No secrets in code
- No hardcoded credentials
- No unsafe deserialization
- No unsafe shell execution
- Validate all external inputs
- Sanitize all logs (no PII leakage)

Mandatory tools:
- govulncheck
- gosec
- staticcheck
- golangci-lint

---

## 9. RELIABILITY RULES (NETOPS PLATFORM)

- All IO must have timeout
- All network calls must retry with backoff + jitter
- All queues must be bounded
- All services must support backpressure
- All operations must be idempotent where possible

---

## 10. OBSERVABILITY RULES

- Structured logging only
- Every service must emit metrics
- Tracing must be supported (OpenTelemetry preferred)
- No silent failures allowed
- All errors must be observable

---

## 11. TESTING RULES

- Every module MUST have unit tests
- Integration tests required for service boundaries
- Mock telemetry streams required for validation
- No feature is complete without tests

---

## 12. CI/CD GUARDRAILS

Pipeline must enforce:

- go vet ./...
- go test ./...
- go test -race
- golangci-lint
- staticcheck
- govulncheck
- gosec scan

ANY failure = BLOCK MERGE

---

## 13. ARCHITECTURE VALIDATION RULES

System must enforce:

- no cross-domain imports
- plugin isolation
- schema compatibility
- API contract stability
- event format consistency

---

## 14. FINAL RULE

If a requirement conflicts with these rules:

👉 ALWAYS choose safety, modularity, and zero-trust design over speed or convenience.

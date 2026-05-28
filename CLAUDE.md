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
- **Backend stays dependency-free** — do not add third-party Go modules.
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

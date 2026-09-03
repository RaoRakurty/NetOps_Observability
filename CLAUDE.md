# CLAUDE.md

Guidance for working on **NetOps_Observability** in this repository.

> The working directory also contains a `network-automation-mpls-l3vpn/`
> directory — **ignore it**; it is unrelated and out of scope.

The project source lives under `NetOps_Observability/` (a nested dir of the same
name). It has its own `README.md` and `docs/`; read those for depth, this file
is the orientation map and the build/test cheat-sheet.

**Current work state = `docs/TRACKER.md` (open items only) + `docs/audit/INVARIANTS.md`
(what is PROVEN vs merely built).** Anything under `docs/archive/` is frozen
history — **never read it to decide what is open, shipped, or next**, only to
recover the rationale behind a past decision; where it disagrees with
`docs/TRACKER.md`, the tracker wins. When an item ships, DELETE its tracker row
rather than marking it ✅ — the archived tracker reached 263 KB because nothing
was ever removed, and an item filed there as "open research" turned out to have
shipped months earlier. Verify a premise against the code before building on it.

---

## NetOps_Observability

A Docker-Compose stack: device discovery → multi-protocol telemetry ingestion →
event bus → storage (search / time-series / OLAP) → anomaly correlation → API →
React dashboard, all behind nginx on a single port (`:8000`).

### Stack tiers (see `docs/ARCHITECTURE.md` for the full topology)
Kafka is single-node KRaft (service `kafka`, profile `embedded-bus`); every
client resolves it via `BROKER_URLS` — external Kafka-compatible brokers are
supported. Redpanda, Redis and Prometheus are fully removed (licensing, #97) —
**never reintroduce them.**

### Build / run / test
Standard per-language invocations apply (`go build ./...`, `npm run build`,
`pytest`). The two that are NOT guessable:
```bash
cd NetOps_Observability
# Requires Docker + Compose v2 plugin; the installer rejects legacy docker-compose.
python3 scripts/install.py              # builds .env + brings stack up on :8000
python3 scripts/install.py --reset-env  # rotate all secrets
```

### Conventions & gotchas
- **Backend defaults to the standard library; third-party Go modules are
  allowed ONLY from the allowlist below** (see §6). The rule's *purpose* is a
  clean offline build + minimal attack surface — not dogma. A dependency is
  permitted when it serves a foundational capability the stdlib can't, is
  offline-buildable, pinned, and reviewed. Everything else stays stdlib.
- `data/` and `deployment/docker/.env` are gitignored (generated at install).
  History audit (2026-06-12): `.env` was briefly tracked (until `6c02200`,
  2026-06-07) but **only ever as a secret-free placeholder comment** — no
  credential has ever been committed (verified across all history + gitleaks
  full-history scan). No rotation or history rewrite needed on its account.
- Security defaults are scaffold-grade: OpenSearch security plugin disabled,
  copilot off unless `FEATURE_COPILOT=true` + `COPILOT_API_KEY`, SNMP discovery
  defaults to `10.0.0.0/8` (narrow before pointing at a real network).
- Feature flags are env-driven (`ENABLE_SNMP_DISCOVERY`, `ENABLE_GNMI_COLLECTION`,
  `FEATURE_SLACK_NOTIFICATIONS`, etc.) — see `newServer()` in `main.go`.

### Monitoring
Three layers, and **each must work without the other two** — that requirement
comes from the 2026-09-02 outage, where the correlation engine consumed nothing
for 3 h while every container read `healthy` and the one alert that did fire was
delivered nowhere. `docs/runbooks/engine-not-consuming.md` is the post-mortem +
first response; `docs/runbooks/engine-liveness-matrix.md` is the per-service
inventory of what "doing its job" actually means.

1. **vmalert rules** — `src/config/rules.yaml` (also read by the in-API engine)
   and `src/config/rules-scale-slo.yaml` (**vmalert only**, so it keeps firing
   when the api is the thing that is down). The `engine-liveness` group there
   carries a `tier` label: exactly four conditions are `tier: page` (an engine
   consumer not consuming · ingest silent when it should not be · storage
   refusing writes · the alerting heartbeat missing); everything else is
   `warning`. Rules are unit-tested with promtool — `src/config/rules-tests/*.test.yaml`,
   run by `scripts/preflight-configs.sh`; `tests/test_alert_rule_coverage.py`
   guards that the harness is actually aimed at them.
2. **Delivery** — vmalert POSTs to the api's Alertmanager-v2 receiver
   (`/api/internal/vmalert/api/v2/alerts`), which fans into `notify.Dispatcher`.
   Platform-global, shared-secret authed (`VMALERT_WEBHOOK_TOKEN`).
   `VMALERT_NOTIFIER_FLAG=-notifier.blackhole` is the explicit opt-out.
   The always-firing `AlertingHeartbeat` rule is **not** routed to a human — the
   receiver just stamps `netops_alert_webhook_heartbeat_timestamp_seconds`,
   which is the only end-to-end proof that the delivery chain works.
3. **`scripts/stack-watchdog.sh`** — external cron watchdog (every 1m), the only
   layer that survives the whole stack dying. Checks every compose service
   running/healthy + probes `:8000` + api liveness, and (2026-09-02) queries
   VictoriaMetrics directly for **consumer-group membership** (correlation and
   every `netops-router-*` lane) and the **alert-delivery heartbeat** —
   `ENGINE_CONSUMER_CHECK=0` disables that block. Pings healthchecks.io
   (dead-man's-switch) when healthy and pushes an ntfy.sh phone alert on
   per-problem-class transitions. Config in gitignored `scripts/stack-watchdog.env`
   (`NTFY_TOPIC`, `HC_PING_URL`); **`--test` sends a real push to the owner's
   phone** — don't run it casually. Kept independent of the stack's own
   notifiers on purpose: they can't report their own death.

`scripts/deploy-qualify.sh` runs the bootstraps (Kafka ACLs, `kafka-init`,
`opensearch-init`) after a `compose up` and then *proves* the engines are
consuming. `docker compose up` exiting 0 is not evidence of anything.

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

## 3a. TENANT / ORG ISOLATION (MANDATORY — every feature, no exceptions)

Isolation is NOT organic — it is a build-time requirement. Every tenant/org gets a
unique view of every feature. A data-returning surface that does not scope by the
caller's tenant is a CROSS-TENANT LEAK and INVALID OUTPUT. When building or
changing ANY feature that stores or returns data:

1. **Scope by the principal, default-closed.** Derive `principalTenant(claims)` →
   `(tenant, cross)` and filter every list/get/search/aggregate by it. A non-cross
   caller must NEVER receive another tenant's rows. Cross-tenant resource access by
   id returns **404** (never reveal another tenant's id), cross-tenant write/delete
   is refused.
2. **Stamp the owner from the token, never the request body.** On create/update set
   `TenantID` from the authenticated principal; ignore any tenant in the payload.
3. **Pick the right gate.** Per-tenant data → `requirePerm` + tenant filter.
   Platform-GLOBAL plumbing (auth providers, LLM keys, token policy, notification
   channels, stack config) → `requirePlatformAdmin` / `requireCrossTenant` — a
   tenant/org admin holds full `administration:admin`, so a scope-blind
   `requireAdmin` on platform-global config is a privilege leak.
4. **Storage layer enforces it.** PG tables: add the `tenant_iso` FORCE-RLS policy
   migration AND query via `withTenant`. ClickHouse: inject `chTenantScope`.
   OpenSearch: per-tenant index + `osTenantFilter`. VictoriaMetrics: device/tenant
   label filter. File/kv & in-memory stores: key/filter by tenant in the store
   itself (no unscoped "list all"). Org isolation is DERIVED from tenant isolation
   (org = its tenants; `reachesTenant` bounds cross-org reach) — keep it that way.
5. **Ship an isolation test with the feature (REQUIRED).** A cross-org test
   (`org_isolation_test.go` is the template) asserting: own-only list, cross-tenant
   get/put/delete → 404, `as_tenant` into another org ignored. No feature is
   complete without it (extends §11 TESTING RULES).

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
| `golang.org/x/crypto/ssh` | SSH client for the device-login gateway | A correct, audited SSH client (host-key verification, kex/cipher negotiation, PTY channels) is **not** in the stdlib and must never be hand-rolled. **Already in the dependency graph** (transitive via pgx → `golang.org/x/crypto`, pinned `v0.56.0`, vendored) — using the `ssh` subpackage promotes it to direct, adding no new module. Gates: ✅ need (foundational, stdlib can't), ✅ offline (vendored), ✅ pinned (`v0.56.0` in `go.mod`, bumped from v0.37.0 for govulncheck GO-2026-5018/5019/5020, then to v0.55.0 on 2026-09-01 for CVE-2026-56854 — trivy CRITICAL, ssh source-address restriction bypass, fixed in 0.55.0; requires go ≥ 1.25) → **v0.56.0 on 2026-09-02 for GO-2026-6354/6355 (x/crypto/ssh DoS); requires go ≥ 1.26 — toolchain raised 1.25.13 → 1.26.8 in the same change (go.mod `go 1.26.0`/`toolchain go1.26.8`, CI `GO_VERSION`, Dockerfile.backend digest, gate-tool pins: staticcheck 2026.2.1, gosec v2.29.0, govulncheck v1.7.0)**, ✅ minimal (one subpackage of an already-present module). Powers the opt-in `FEATURE_DEVICE_SSH` WebSocket→SSH proxy (`device_ssh.go`); dormant by default. |
| `golang.org/x/net` (`ipv4` + `icmp`) | Path discovery (modern, Paris-consistent traceroute) | Hop-by-hop path measurement needs **per-packet IP TTL control** and **ICMP message construction/parsing** — neither is exposed by the stdlib `net` package, and hand-rolling raw IP/ICMP framing is exactly the kind of error-prone wire code the zero-trust rule exists to avoid. Gates: ✅ need (foundational, stdlib genuinely can't set TTL / parse ICMP), ✅ offline (vendored from module cache, `v0.57.0`; transitive `x/sys`/`x/text` already present — no version conflict), ✅ pinned (`v0.57.0` in `go.mod`; bumped from v0.55.0 for CVE-2026-46600 in `dns/dnsmessage` — trivy HIGH, blocking supply-chain gate — then to v0.57.0 on 2026-09-01 because x/crypto v0.55.0 (CVE-2026-56854) requires x/net ≥ v0.57.0; we import only `ipv4`+`icmp` but stay current per allowlist hygiene; unchanged by the 2026-09-02 x/crypto v0.56.0 / go 1.26.8 raise — v0.57.0 already satisfies it), ✅ minimal (two subpackages, `ipv4` + `icmp`, of one module). Powers the opt-in `FEATURE_TRACEROUTE` collector (`collectors/traceroute.go`, ICMP + TCP-SYN methods); dormant by default. Needs `CAP_NET_RAW` at runtime. |

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

The gate is enforced mechanically in `.github/workflows/` (vet, test, `-race`,
staticcheck, gosec, govulncheck — all blocking). ANY failure = BLOCK MERGE.

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

---

## 15. AI / LLM RUNTIME SECURITY (OWASP LLM TOP 10)

Any feature that sends data to, or renders output from, an LLM (today: the
copilot proxy `copilot.go` + the ChatGPT UI; tomorrow: any GenAI assist) MUST
be designed against the **OWASP Top 10 for LLM Applications**. The five risks
that intersect with our code and are mitigatable at dev time:

- **LLM01 Prompt Injection** — the **system prompt is server-controlled**; never
  let a client override it or inject a `system`-role turn. Sanitize/normalize
  the message list server-side (`sanitizeCopilotMessages`). Treat all model
  output as untrusted: a "valid" input can still be malicious.
- **LLM02 Insecure Output Handling** — never execute or `dangerouslySetInnerHTML`
  model output. The SPA renders assistant text as **escaped React text** only.
  Anything derived from model output (SQL, shell, paths) is data, not code —
  parameterize and validate it like any external input.
- **LLM03 Training-Data Poisoning / Overreliance** — AI-generated code is
  untrusted until reviewed: it goes through the **same CI gate** (§12: vet,
  test, race, staticcheck, gosec, govulncheck) and human review as hand-written
  code. No "the model wrote it" exemption.
- **LLM06 Sensitive Information Disclosure** — the copilot forwards only what the
  caller supplies; the backend must **not auto-inject secrets, credentials,
  other tenants' data, or PII** into prompts. Secrets stay write-only and out of
  logs; redact before sending anything to an external provider.
- **LLM07 Insecure Plugin / Tool Design** — any LLM tool/plugin obeys §4
  (isolation, schema validation, least privilege) and authenticates + authorizes
  every call. No implicit trust of model-requested actions (LLM08: least
  privilege / no excessive agency).

**Cost/DoS (LLM04):** LLM endpoints must be authenticated + audited, **bound the
request** (`MaxBytesReader`, message/char caps) and **cap output tokens**. No
unbounded provider calls.

When in doubt, the §3 zero-trust rule applies to the model too: never trust LLM
input or output.

---

## 16. OPERATIONAL SCRIPTS & CRON (SAME BAR AS THE CODE)

Shell scripts, cron jobs, watchdogs, hygiene sweepers and installers are
**production software that runs unattended on the host customer data flows
through.** They get the FAANG-grade bar the Go code gets — not "it's just a
script."

The full rules (16.1 never swallow an error · 16.2 cron's hostile environment ·
16.3 bash hygiene · 16.4 event-driven release artifacts · 16.5 ship-safety) live
in **`NetOps_Observability/scripts/CLAUDE.md`**, which loads automatically when
you work on scripts. **Read it before writing or editing ANY shell script in
this repo** — including ones outside `scripts/` (`tests/`, `deployment/docker/`).

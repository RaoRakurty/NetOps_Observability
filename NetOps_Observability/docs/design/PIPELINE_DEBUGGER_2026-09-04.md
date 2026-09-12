# Pipeline debugger — `correlix-debug` (design, 2026-09-04)

**Owner ask (2026-09-04):** "a debug module for the entire pipeline, accessed via
CLI — log files showing the debug of telemetry parsers, VictoriaMetrics and the
other modules as traffic gets ingested, all the way to the UI. Build log files
separately for each module."

## 1. What it is
One host-side CLI, `correlix-debug` (Go, stdlib only, built from
`src/backend/cmd/correlix-debug`, shipped in the bundle next to the installer),
with three verbs. Every run creates a **session directory**
`data/debug/<UTC-timestamp>-<verb>-<id>/` containing **one log file per module**
(§3), a `timeline.json`, a `summary.txt`, and `manifest.json` (versions, flags,
redaction applied). Platform-admin only: the CLI logs in with the admin
credentials from `deployment/docker/.env` or an admin token, and every call it
makes lands in the audit log.

| verb | what it does |
|---|---|
| `trace` | Injects ONE marked synthetic record through the REAL ingress (`--kind syslog\|trap\|flow\|gnmi`, `--device`, `--tenant`) and follows the marker hop by hop (§2). Per-stage log file + `timeline.json` with the record as each stage saw it, latency between stages, and an honest verdict per stage: `seen`, `not seen after <N>s`, `stage not observable (<reason>)`. Exit 0 only if the record reached the UI-facing API. `--passive --device X --since 10m` follows real traffic instead of injecting. |
| `logs` | Raises the log level of chosen modules (`--modules parser,vector,router,correlation,api`) to debug for a **bounded window** (`--for 5m`, hard cap 30 m, auto-revert on exit or timeout, revert also runs from the watchdog if the CLI dies) and tails each module's output into its own file. Never leaves a module at debug. |
| `bundle` | Packages a session (or the last N) into `correlix-debug-<id>.tar.zst` with `SHA256SUMS`, redacted (§5), for support. |

## 2. Stages and the evidence source for each (`trace`)
The record carries a marker `cx_debug=<ulid>` in the field each kind naturally
has (syslog MSG, trap varbind `sysName`-adjacent string OID, flow `src` in a
reserved documentation prefix + marker in the exporter id, gNMI: a `description`
leaf on the lab device is NOT written — gNMI trace is passive-only, read-only rule).

| stage | module log file | evidence source | how observed |
|---|---|---|---|
| 1 ingress | `ingress.log` | syslog-ng / snmptrap collector / flow collector / gnmic | the collector's own debug line for the marker (level raised for the trace window) |
| 2 parser | `parser.log` | Go collectors (`collectors/`, `internal/showparse` where used) and Vector VRL transforms | NEW: a parser debug hook — when `DEBUG_PARSE_MARKER` (runtime, set through the api's debug route) matches, each parser logs the decision path (matched profile/rule, extracted fields, drops with reason) as structured lines; Vector via its API `tap` on the transform outputs filtered by marker |
| 3 bus | `kafka.log` | Kafka topics | the api's debug route peeks the topic for the marker using an ephemeral consumer in the CORRELATION container (Python aiokafka — Go has no Kafka client by design), returning topic/partition/offset/timestamp/payload |
| 4 router | `router.log` | vector-router lanes | Vector API tap + the lane's per-topic metrics delta |
| 5 storage | `opensearch.log`, `victoria.log`, `clickhouse.log` | the three stores | query by marker (OpenSearch: term on the message field, tenant index; VictoriaMetrics: `/api/v1/export` on the marker label/series the record produces; ClickHouse: the row in the raw table) — each with the exact query used and the row/series returned |
| 6 correlation | `correlation.log` | correlation engine | evidence row (`corr_evidence` by marker), grounding outcome, DLQ check, and the engine's debug lines for the marker (level raised for the window) |
| 7 api | `api.log` | api | the api's own request/handler debug lines for the marker plus the search/findings response that contains it |
| 8 ui | `ui.log` | frontend | the route + query the SPA would issue for that record (recorded from the api's UI-query contract), and the served bundle's route check; a headless browser is NOT required — the UI stage is "the data the UI asks for is returned by the api for this record" |

`timeline.json` = ordered stage entries `{stage, module, seen, t_first_seen,
latency_from_prev_ms, evidence_ref, verdict, reason}`. Latencies are wall-clock
deltas between first-seen timestamps at each stage.

## 3. Log file layout (one file per module — owner requirement)
```
data/debug/20260904T1105Z-trace-01J9.../
  manifest.json      versions, flags, redaction, who ran it
  summary.txt        the stage table a human reads first
  timeline.json      machine-readable stage timeline
  ingress.log parser.log kafka.log router.log
  opensearch.log victoria.log clickhouse.log
  correlation.log api.log ui.log
```
Each module file is line-oriented JSON (`ts, module, level, marker, msg, …`) so
`jq`/`grep` work, with a first line stating the module, the window, and how the
lines were obtained (docker logs / API tap / query). A module that is not
observable writes ONE line saying so and why — never an empty file that looks
like "nothing happened".

## 4. Server side (api) — the parts the CLI cannot do from the host
Platform-admin route family, `requirePlatformAdmin`, audited, bounded:
- `POST /api/debug/trace` (kind, device, tenant, ttl) → marker + injection
  receipt; `GET /api/debug/trace/{id}` → stage status (async, polled).
- `PUT /api/debug/loglevel` `{module, level, for_seconds}` → runtime level
  change with auto-revert (api, collectors, correlation via its health sidecar
  route; Vector via its API; syslog-ng via a bounded restart-free method if one
  exists, else "not runtime-switchable" honestly). Hard cap 30 m.
- `GET /api/debug/stage/{stage}?marker=` → the per-stage evidence query (§2).
Isolation: debug output can contain tenant data → platform-admin only, session
dirs `0700`, marker records are tagged synthetic and excluded from customer
views (`cx_synthetic=true` filter in the UI queries — verify it exists, add if not).

## 5. Redaction and safety
Bundle redaction reuses the TAC-bundle redactor (`internal/protocoldiag/redact.go`):
secrets, communities, keys, tokens; tenant ids kept (support needs them). No
device is written to: gNMI stays passive, trap/syslog/flow injection targets the
STACK's ingress, not a device. Debug level auto-reverts; the watchdog gets a
`DEBUG_LEVEL_STUCK` problem class if a module stays at debug past its window.

## 6. Waves
- **W1 (build now):** CLI skeleton + session layout + `trace` for syslog and
  trap end-to-end using existing observability (docker logs, Vector API tap,
  Kafka peek via the correlation container, store queries, api search), `logs`
  for api/correlation/vector with auto-revert, `bundle`. Per-module files. Tests:
  unit (stage parsers, timeline, redaction), an integration test against the
  lab (`tests/test_correlix_debug_lab.py`, skipped without the stack).
- **W2:** parser debug hook in the Go collectors and VRL, flow + passive gNMI
  trace, the `ui` stage contract, watchdog class, docs-portal page ("Debug the
  pipeline") + runbook, bundle inclusion in `make-installer.sh`.
- **W3:** in-GUI trace viewer (reads a session) — after the CLI is proven.

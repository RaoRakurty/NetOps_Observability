# Runbook — debugging the pipeline with `correlix-debug`

**Design of record:** `docs/design/PIPELINE_DEBUGGER_2026-09-04.md`
**Status:** W1 (`trace` for syslog + trap, `logs`, `bundle`). W2 owes the parser
debug hook, flow + passive gNMI, the UI-stage contract, the watchdog class, the
docs-portal page and bundle inclusion in `make-installer.sh`.

Use this when telemetry "goes in and does not come out" and you need to know
*which hop* lost it — the question the 2026-09-02 outage took three hours to
answer while every container read `healthy`.

---

## 1. The one thing to understand first

`correlix-debug trace` answers one question per hop, with **three** possible
answers, never two:

| verdict | means |
|---|---|
| `seen` | the marked record was observed at this stage |
| `not_seen` | the stage **was** inspected and the record was not there |
| `not_observable` | the stage could **not** be inspected — always with the reason |

`not_observable` is not a failure and not a pass. Treat it as "this hop was not
checked". The summary says so explicitly at the bottom of every trace. A stage
that could not be looked at must never be read as a stage that lost the record —
that inversion is the defect this tool exists to remove.

Exit code is **0 only when the record reached the UI-facing API**. Anything else
exits 1, so `correlix-debug trace … && echo ok` is safe in a script.

---

## 2. Safety — what it does and does not touch

* **No device is ever written to.** `--device` only decides which device the
  synthetic record *claims* to come from, so the pipeline's device→tenant
  attribution is exercised for real. The syslog frame goes to the stack's own
  syslog collector and the trap PDU to the stack's own trap receiver. gNMI has
  no injectable form at all and is passive-only (W2).
* **Every injected record is tagged `cx_synthetic=true`** and is excluded from
  the customer-facing log search (`logsScope` in the api, guarded by
  `pipedebug_synthetic_test.go`). The trap OID sits under the IANA *experimental*
  arc `1.3.6.1.3`, so a probe can never decode as `coldStart`, `linkDown` or any
  other notification the correlation engine reasons about.
* **A raised log level always comes back down.** Three independent mechanisms:
  the module's own process arms the revert timer, the CLI reverts when the
  window ends, and it reverts again on Ctrl-C. If the CLI is `SIGKILL`ed the
  module's own timer still fires.
* **Platform admin only.** The four `/api/debug/*` routes are
  `requirePlatformAdmin` and audited. Session directories are `0700`, files
  `0600`.
* Every session file is **redacted at write time** (the shared
  `internal/protocoldiag` pass, plus bearer/authorization stripping). Tenant ids
  are deliberately kept — support needs them.

---

## 3. Usage

```bash
cd NetOps_Observability
go build -o ./correlix-debug ./src/backend/cmd/correlix-debug   # or take it from the bundle

# follow ONE marked record end to end
./correlix-debug trace --kind syslog --device spine1 --ttl 60s

# … a trap instead
./correlix-debug trace --kind trap --device spine1

# raise chosen modules to debug for a bounded window and tail each one
./correlix-debug logs --modules api,correlation,vector --for 5m

# package the last session (or --session <dir>) for support
./correlix-debug bundle --last 1
```

Credentials: the CLI logs in with `ADMIN_USERNAME` / `ADMIN_INITIAL_PASSWORD`
from `deployment/docker/.env`. Pass `--token` (or `CORRELIX_TOKEN`) instead when
running from somewhere that file is not readable. `--api` overrides the base URL
(default `http://localhost:$BASE_PORT`). `--project` names the compose project
(default `netops`) — the CLI resolves containers by compose **label**, never by
guessing a name.

Bounds you cannot exceed: `--for` is capped at **30 minutes**, `--ttl` at
**5 minutes**.

---

## 4. What a session looks like

```
data/debug/20260904T1105Z-trace-01j9…/
  manifest.json      versions, flags, who ran it, which redaction pass, warnings
  summary.txt        the stage table you read first
  timeline.json      machine-readable: stage, verdict, reason, latency, evidence ref
  ingress.log parser.log kafka.log router.log
  opensearch.log victoria.log clickhouse.log
  correlation.log api.log ui.log
```

One file per module — **always all ten**, even for stages nothing collected. A
module that was not observed contains exactly one line saying so and why; an
empty file (which would read as "nothing happened") is a bug, and
`session_test.go` fails the build on it.

Each file is line-oriented JSON, so `jq` and `grep` work:

```bash
jq -r '.msg' data/debug/2026*/parser.log
jq '.entries[] | select(.verdict != "seen") | {stage, verdict, reason}' data/debug/2026*/timeline.json
```

The **first line** of every module file states the module, the window, and *how*
the lines below were obtained (`docker logs`, `vector tap`, or which API query).
Every stage also records the **exact query or command** it used, verbatim, so you
can re-run it by hand instead of trusting this tool's summary of it.

---

## 5. Reading each module file

| file | where the evidence comes from | what "not observable" means here |
|---|---|---|
| `ingress.log` | `vector tap --outputs-of syslog_in` / `trap_in` on the aggregator | the tap could not attach (aggregator down, `docker exec` refused) |
| `parser.log` | `vector tap --outputs-of syslog_normalized` / `snmptrap_normalized` | same. The Go-collector parser hook is **W2** |
| `kafka.log` | the api proxies a bounded, group-less peek to the correlation container's debug sidecar | `CORR_DEBUG_TOKEN` is unset — see §7 |
| `router.log` | `vector tap --outputs-of syslog_tagged` / `snmptrap_tagged` on vector-router | tap could not attach |
| `opensearch.log` | `match_phrase` on the analysed `message` field of the tenant index | the store refused the query, or answered something undecodable |
| `victoria.log` | `GET /api/v1/export` on the marker's series | **expected for syslog/trap**: those records mint no per-record series. VM holds pipeline counters, which move for every record and cannot be attributed to one marker |
| `clickhouse.log` | the kind's raw table | **expected for syslog/trap**: they have no ClickHouse raw row. Flows do; correlation *output* is covered by `correlation.log` |
| `correlation.log` | `netops.corr_evidence` by marker + the dead-letter/quarantine counters | ClickHouse or the health snapshot was unreachable |
| `api.log` | the api's own bounded in-memory ring, keyed by marker | the ring is not wired (a build without the debug routes) |
| `ui.log` | **W2** — the UI-query contract | always, in W1 |

### The two verdicts people misread

* **`correlation` = `not_seen` for a syslog probe is normal.** The engine's
  ingest pre-filter admits only records its parser corpus recognises, and a
  debug probe is deliberately unparseable. The line also carries the dead-letter
  counters, so "the engine dropped it" and "the engine could not persist it" are
  distinguishable.
* **`router` taps the `*_tagged` remap, not `*_store_route`.** A Vector `route`
  transform exposes only its *named* outputs to the tap, so tapping the route
  would show an empty router stage for every healthy record.

---

## 6. Runtime log levels — and what is honestly not switchable

`logs` raises each module and reports what actually happened. It never fakes a
success:

| module | switchable? |
|---|---|
| `api` | **yes** — its own logger, auto-revert armed in-process |
| `correlation` | **yes**, when `CORR_DEBUG_TOKEN` is set (§7); auto-revert armed in the correlation process |
| `vector`, `router` | **no.** Vector reads `VECTOR_LOG` at process start and exposes no log-level mutation on its API. `vector tap` — which `correlix-debug` already collects for the parser and router stages — is the substitute, and it is strictly *more* evidence than a debug log line |
| `ingress` (syslog-ng) | **no.** Its level is set in the config file and applied at (re)start; restarting the ingest edge during an incident is not an acceptable debug action |

A non-switchable module is still **tailed**: `docker logs` is available either
way, and the first line of its file records that the level was not raised, with
the reason.

---

## 7. Enabling the Kafka peek and the correlation log level

Both live on the correlation container's health sidecar and are **default-closed**:
with no shared secret they answer 503 and say so, and a trace reports the bus
stage as `not_observable` with that reason.

To turn them on, put the SAME value on both services (compose already reads it):

```bash
# deployment/docker/.env
CORR_DEBUG_TOKEN=<a long random string>
```

then redeploy. Set `CORR_DEBUG_SIDECAR_URL` only if the sidecar is not reachable
at `CORRELATION_URL`'s host on `CORR_HEALTH_SIDECAR_PORT` (8094) — that is the
derivation the api uses when it is unset, and it preserves the scheme so the
internal-mTLS client still verifies by name.

The peek is bounded on every axis: an ephemeral consumer with **no group id**
(it cannot join the engine's group or move its offsets), at most 10 seconds, at
most 20 records, seeking by a bounded lookback time rather than to the beginning
of the topic.

---

## 8. Bundling for support

```bash
./correlix-debug bundle --last 3
```

Produces `correlix-debug-<UTC>.tar.zst` (or `.tar.gz` when `zstd` is not
installed on the host — the codec is printed and is in the file name, never
implied), with `SHA256SUMS` inside the archive **and** beside it, plus a
`BUNDLE-README.txt` naming the redaction pass that ran. Verify with:

```bash
sha256sum -c SHA256SUMS      # inside the extracted directory
```

Redaction happened when each line was written, so the session directory on disk
is already safe to share; `bundle` cannot be the step that forgot.

---

## 9. When the trace itself will not run

| symptom | cause |
|---|---|
| `404` from `/api/debug/trace` | the api in front of you predates this feature — redeploy |
| `403 platform administrator required` | the token is a tenant/org admin. These routes are platform-global |
| receipt says `injected: false` | the injection socket is wrong or unreachable. Check `DEBUG_SYSLOG_TARGET` / `DEBUG_TRAP_TARGET`; for traps, `FEATURE_SNMP_TRAPS` must be `true` or nothing is listening |
| every stage `not_seen` | start at `ingress.log`. If ingress is also `not_seen`, the record never entered the stack — suspect the injection target, not the pipeline |
| the taps report 0 matched but hundreds scanned | the tap attached but the record did not cross that component. That is a real finding: the hop before it is where to look |

## 10. Related

* `docs/runbooks/engine-not-consuming.md` — the correlation-consumer outage
  post-mortem and first response.
* `docs/runbooks/engine-liveness-matrix.md` — what "doing its job" means per
  service.
* `tests/test_correlix_debug_lab.py` — the live integration test; it skips
  (never silently passes) without a stack.

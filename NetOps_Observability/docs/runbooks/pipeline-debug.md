# Runbook — debugging the pipeline with `correlix-debug`

**Design of record:** `docs/design/PIPELINE_DEBUGGER_2026-09-04.md`
**Status:** W2. `trace` covers syslog, trap, flow and (passively) gNMI; the
parser stage carries the DECISION path from both the VRL transforms and the Go
trap decoder; stage 10 runs the SPA's own query; the watchdog carries a
`DEBUG_LEVEL_STUCK` class; the binary ships in the installer bundle. W3 is the
in-GUI trace viewer.

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
  syslog collector, the trap PDU to the stack's own trap receiver, and the
  NetFlow v5 export to the stack's own flow collector
  (`DEBUG_SYSLOG_TARGET` / `DEBUG_TRAP_TARGET` / `DEBUG_FLOW_TARGET`).
  **gNMI has no injectable form at all and is passive-only.** A gNMI update
  originates on the device, so the only way to mint one would be to write a leaf
  on a live router. There is no `DEBUG_GNMI_TARGET` and no `InjectGNMI` seam —
  the absence is the enforcement. `--passive` on any other kind is *refused*,
  in the CLI and again at the api, rather than degraded into an injection the
  operator explicitly declined.
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

# … a flow (a NetFlow v5 export into the stack's own goflow2 listener)
./correlix-debug trace --kind flow --device spine1

# gNMI is PASSIVE-ONLY: follow the REAL updates a device is streaming
./correlix-debug trace --kind gnmi --passive --device spine1 --since 10m
./correlix-debug trace --kind gnmi --passive --device spine1 --path in-octets

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
| `parser.log` | `vector tap --outputs-of syslog_normalized` / `snmptrap_normalized` (the event **plus** its `cx_parse_trace` decision string), merged with the Go trap decoder's decisions from the api's debug ring | the tap could not attach. A kind parsed outside this process (syslog in Vector, flow in goflow2) reports the Go half as not-observable with that reason, never as a miss |
| `kafka.log` | the api proxies a bounded, group-less peek to the correlation container's debug sidecar | `CORR_DEBUG_TOKEN` is unset — see §7 |
| `router.log` | `vector tap --outputs-of syslog_tagged` / `snmptrap_tagged` on vector-router | tap could not attach |
| `opensearch.log` | `match_phrase` on the analysed `message` field of the tenant index; for a flow, the fingerprint tuple | the store refused the query or answered something undecodable — **and, for a flow, a miss is always not-observable**: OpenSearch holds a 1-in-50 SAMPLE of that lane, so ~98% of healthy flow records are legitimately absent and ClickHouse is the authoritative store |
| `victoria.log` | `GET /api/v1/export` — the marker's series, or (passive gNMI) the device's whole raw `gnmi_*` lane in the window | **expected for syslog/trap/flow**: none of them mints a per-record series. VM holds pipeline counters, which move for every record and cannot be attributed to one probe. For passive gNMI this file is the load-bearing evidence |
| `clickhouse.log` | the kind's raw table | **expected for syslog/trap**: they have no ClickHouse raw row. **For a flow this is the authoritative stage** (`netops.flows`, matched on the full fingerprint); correlation *output* is covered by `correlation.log` |
| `correlation.log` | `netops.corr_evidence` by marker + the dead-letter/quarantine counters | ClickHouse or the health snapshot was unreachable |
| `api.log` | the api's own bounded in-memory ring, keyed by marker | the ring is not wired (a build without the debug routes) |
| `ui.log` | the UI-query contract — the api runs the SPA's own query for this record | the api could not be reached for the stage, or no contract exists for the kind |

### How each kind carries the marker — and what that costs in evidence

| kind | carrier | what a `seen` proves |
|---|---|---|
| `syslog`, `trap` | `cx_debug=<ulid>` inside the record's free text | **this record** crossed this hop |
| `flow` | a derived TUPLE in RFC 5737 documentation address space — src `192.0.2.x`, dst `198.51.100.x`, ephemeral ports, RFC 6996 private ASNs, 1 byte / 1 packet | **this record** crossed this hop, matched on ~66 bits inside a 30-minute window on address space that carries no production traffic |
| `gnmi` | nothing — the follow is passive, by device + path + window | **some** traffic from this device crossed this hop in the window |

A flow record has no free-text field (every `netops-flows` column is an
ip/int/keyword) and NetFlow v5 has no vendor-extension space, so there is
nowhere for a token to ride. That is why the tuple exists, and why the
`kafka.log` line for a flow says the bus needle was the probe's source address
alone and that the **api then verified the full tuple** before filing the record
as this trace's evidence. The counters are 1 byte / 1 packet so a probe can
never move a top-talkers ranking.

The gNMI row is the honest one to read twice: a passive follow cannot name a
single update, and `victoria.log` says so in its own words rather than borrowing
a marked trace's stronger wording.

### The parser stage has TWO halves

`parser.log` carries both, and they answer different questions:

* the **Vector** half — the tap shows the event as it left each transform, and
  a marked record additionally carries `cx_parse_trace`: the matched branch, the
  tenant-registry hit/miss, the extracted fields, and **every drop with its
  reason** (`tenant_reason=DROPPED-ATTRIBUTION:…`, `parser_status=unparsed`,
  `ts_reason=DROPPED:…`). A drop leaves no event to tap, so this string is the
  only record of it.
* the **Go** half — the SNMP trap decoder emits the same shape (matched trap
  OID/MIB name, severity, vendor, extracted varbinds, unresolved OIDs, the
  varbind-cap and message-cap reasons) into the api's bounded debug ring.

For a *syslog* probe the Go half is honestly `not_observable` — syslog is parsed
in Vector, so an empty Go-side answer says nothing about whether it was parsed.

**Tracing a REAL, unmarked record.** An injected record carries its own marker,
so nothing has to be armed. A device's own log line carries none, and the
runtime switch is what makes its decision path appear:

```bash
curl -X PUT -H "Authorization: Bearer $TOKEN" \
  -d '{"marker":"spine1","for_seconds":300}' \
  http://localhost:8000/api/debug/parsemarker      # arm on any bounded needle
curl -X PUT -H "Authorization: Bearer $TOKEN" \
  -d '{"off":true}' http://localhost:8000/api/debug/parsemarker
```

It is default-off, hard-capped at 30 minutes, and the disarm timer is armed
**inside the traced process**, so it comes back off even if the caller dies. The
needle is deliberately **not** written to the audit trail verbatim — an operator
may legitimately trace by a fragment of a customer's log line.

### Stage 10 — the UI-query contract

`ui.log` answers one sentence: *the api returned the record for the UI's own
query: yes/no.* No browser runs; one that did would be testing React, not the
pipeline. The route per kind is a table in `internal/pipedebug/uiquery.go`, and
a Go test reads `src/frontend/src/services/api.ts` and fails the build if the
SPA no longer issues it — so the check can never quietly drift onto a route
nobody calls.

| kind | what the SPA issues | who answers |
|---|---|---|
| `syslog`, `trap` | `POST /api/logs/search` (`api.searchLogs`) | OpenSearch |
| `flow` | `GET /api/flows/top?since=…&src=…&dst=…` (`api.topTalkers`) | ClickHouse |
| `gnmi` | `GET /api/metrics/query_range?query=…` (`api.metricsQueryRange`) | VictoriaMetrics |

For flow and gNMI the api runs the **real handler**, in-process, on a clone of
your request — so the tenant scoping and the row policies are the production
ones. For the log kinds it re-runs the SPA's own scope with **one clause
lifted**: the `cx_synthetic=true` exclusion, which by design hides probes from a
customer's log search. A probe that came back from the unmodified query would
mean that control had failed. `ui.log` states the lift on every run.

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

### `DEBUG_LEVEL_STUCK` — the fourth revert

The three reverts in §2 all live **inside the stack**. The external watchdog
(`scripts/stack-watchdog.sh`, gate `DEBUG_LEVEL_CHECK`, default on) is the
fourth, and the only one that still works when the api is itself the thing that
is wedged — which is precisely the case in which the module's own in-process
timer did not fire. Every minute it reads, from VictoriaMetrics over the same
seam as the consumer-group and alert-delivery probes:

| series | meaning |
|---|---|
| `netops_debug_level_active{module}` | 1 while that module is at debug |
| `netops_debug_level_revert_at_seconds{module}` | unix seconds the raise auto-reverts; **0 = no auto-revert armed** |
| `netops_debug_parse_marker_active` | 1 while the parser decision-trace marker filter is armed |
| `netops_debug_parse_marker_revert_at_seconds` | as above, for the filter |

All four are exported **even when they read 0**, so an ABSENT series is not
"nothing is raised" — it means this api predates the debug routes or is not
being scraped, i.e. a stuck level would not be detected here at all. The
watchdog says exactly that in its log and neither passes nor pages.

It reports, as the advisory class `DEBUG_LEVEL_STUCK`:

* a module still at debug more than `DEBUG_LEVEL_STUCK_GRACE_SEC` (default
  300 s) past its armed revert time, **naming the module**;
* a module at debug with **no auto-revert armed at all** (`revert_at` 0) — the
  more serious of the two, because that raise never expires on its own;
* the same two conditions for the parser decision-trace marker filter.

Remedy in every message: `correlix-debug logs` reverts on exit, the module's own
timer reverts on its own, and
`PUT /api/debug/loglevel {"module":"…","level":"info"}` (platform admin) forces
it down now.

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
| `opensearch` says the store answered `429` / `cluster_block_exception` | the cluster crossed the flood-stage disk watermark and marked its indices `read-only-allow-delete`. Nothing is being indexed. Check `df -h` and `_cat/allocation` before suspecting any hop; this is the "storage refusing writes" tier-`page` condition |
| a flow trace: `ingress` and `parser` are both `not_observable` | that is CORRECT and permanent for this kind. goflow2 is both the flow ingress and the flow parser, it is not a Vector component, and with the `kafka://` transport it writes no per-record line. The bus is the flow lane's first observable hop |
| `--passive` refused | `--passive` exists for `--kind gnmi` only. Every other kind carries an exact per-record marker, which is strictly better evidence |
| the taps report 0 matched but hundreds scanned | the tap attached but the record did not cross that component. That is a real finding: the hop before it is where to look |

## 10. Related

* `docs/runbooks/engine-not-consuming.md` — the correlation-consumer outage
  post-mortem and first response.
* `docs/runbooks/engine-liveness-matrix.md` — what "doing its job" means per
  service.
* `tests/test_correlix_debug_lab.py` — the live integration test; it skips
  (never silently passes) without a stack.

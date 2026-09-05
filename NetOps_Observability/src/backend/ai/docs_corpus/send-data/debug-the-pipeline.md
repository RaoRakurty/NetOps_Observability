---
title: Debug the pipeline
description: Trace one marked record from the ingress socket to the query the console issues, and read a per-hop verdict that never reports an uninspected hop as a lost record.
page_type: task
sidebar_position: 6
---

# Debug the pipeline

`correlix-debug` sends one marked record into the stack's own ingress and
follows it hop by hop. Per hop it answers one question, and only that question:
did this record cross here? Each of the ten modules gets its own log file, so
the answer for a hop is readable without reading the hop before it.

Use it when telemetry goes in and does not come out, and the console does not
say which hop lost it.

## Before you begin

- **Platform administrator.** The five `/api/debug/*` routes are platform-global
  configuration, not per-tenant data. A tenant or organization administrator
  receives `403`. Every call the tool makes lands in the audit log.
- Shell access on the Correlix host, with permission to reach the Docker daemon.
- The `correlix-debug` binary. The installer bundle ships it next to
  `install-correlix.sh`. From a source checkout, build it:
  `go build -o ./correlix-debug ./src/backend/cmd/correlix-debug`.
- `CORR_DEBUG_TOKEN` in `deployment/docker/.env`, read by both the api and the
  correlation container. The installer mints it on a fresh install and adds it
  on upgrade. Without it the bus hop reports `not_observable` with that reason,
  and the other nine hops still run.
- The identifier of the device the record claims to come from. No device is
  written to, contacted or reconfigured at any point.
- Credentials. The tool signs in with `ADMIN_USERNAME` and
  `ADMIN_INITIAL_PASSWORD` from `deployment/docker/.env`. Pass `--token`, or set
  `CORRELIX_TOKEN`, when that file is not readable from where you run it.

## Steps

To trace one marked record:

1. Run a trace on the telemetry lane you suspect.

   ```bash
   cd NetOps_Observability
   ./correlix-debug trace --kind syslog --device spine1 --ttl 60s
   ./correlix-debug trace --kind trap   --device spine1
   ./correlix-debug trace --kind flow   --device spine1
   ```

2. For gNMI, follow real traffic instead. `--kind gnmi` is passive only and
   injects nothing.

   ```bash
   ./correlix-debug trace --kind gnmi --passive --device spine1 --since 10m
   ```

3. Read `summary.txt` in the session directory the run prints. It carries the
   marker, the stage table and the verdict line.

4. Open the module log file named by the first hop whose verdict is not `seen`.
   The file's first line states the module, the window, and how the lines below
   were obtained.

5. List every hop that did not see the record, with its reason.

   ```bash
   jq '.entries[] | select(.verdict != "seen") | {stage, verdict, reason}' \
     data/debug/2026*/timeline.json
   ```

6. Package the session for support when the answer needs another pair of eyes.

   ```bash
   ./correlix-debug bundle --last 1
   ```

To raise log levels for a bounded window instead of tracing a record:

1. Name the modules and the window. The window is capped at 30 minutes.

   ```bash
   ./correlix-debug logs --modules api,correlation,vector --for 5m
   ```

2. Read the per-module report the command prints. `api` and `correlation` are
   runtime-switchable. `vector`, `router` and `ingress` are not, and the tool
   says so with the reason rather than reporting a raise that did not happen.
   Vector reads its level once at process start, so the Vector tap is what
   `correlix-debug` collects for those modules.

3. Let the command exit. Every raise reverts on exit, on Ctrl-C, and on the
   module's own in-process timer.

## What you see

A session directory under `data/debug/`, holding one file per module and always
all ten, plus the three session files:

```
data/debug/20260904T1105Z-trace-01j9…/
  manifest.json      versions, flags, who ran it, which redaction pass, warnings
  summary.txt        the stage table to read first
  timeline.json      stage, verdict, reason, latency, evidence reference
  ingress.log parser.log kafka.log router.log
  opensearch.log victoria.log clickhouse.log
  correlation.log api.log ui.log
```

A module that could not be observed contains exactly one line saying so and why.
An empty file would read as "nothing happened", so an empty file is a bug and
`session_test.go` fails the build on one.

`summary.txt` is written in this format, one row per hop, in pipeline order:

```
CORRELIX PIPELINE DEBUG — TRACE SUMMARY
======================================
marker   : <26-character marker>
kind     : syslog | trap | flow | gnmi
device   : <device, or - when none>
tenant   : <tenant, or - when none>
started  : <RFC 3339 timestamp>
session  : <session directory>

#  STAGE         VERDICT         Δ PREV     EVIDENCE / REASON
--------------------------------------------------------------------------------
<one row per hop: index, stage, verdict, latency from the previous SEEN hop,
 and either the evidence reference or, for a hop that is not `seen`, the reason>

stages: <n> seen, <n> not seen, <n> not observable
VERDICT: the record reached the UI-facing API (exit 0)
NOTE:    a 'not observable' stage was NOT checked — it is neither a pass nor a fail.
```

That block is the format the tool writes, taken from `RenderSummary` in
`internal/pipedebug/summary.go`. It is not a captured run.

The verdicts a real run produced, recorded in commit `79bfc9f9` for a syslog
trace on the validation lab (marker `01m1kyybjwne1fpjzktftka0wd`, device
`spine1`, tenant `lab`):

| Hop | Verdict in that run |
|---|---|
| ingress, parser, router, opensearch, api | `seen` |
| correlation | `not_seen`. The engine grounds only what its rules make evidence, and a probe is deliberately unparseable |
| kafka | `not_observable` until `CORR_DEBUG_TOKEN` is set on both services |
| victoria, clickhouse | `not_observable`. A syslog record mints no per-record series and has no flow row |
| ui | `not_observable` in that build. The UI-query contract landed afterwards and is described below |

Exit code is 0 only when the record reached the UI-facing API. Anything else
exits 1, so `correlix-debug trace … && echo ok` is safe in a script.

## The three verdicts

Every hop reports one of three values, never two.

| Verdict | What it means |
|---|---|
| `seen` | The marked record was observed at this hop. |
| `not_seen` | The hop **was** inspected and the record was not there. |
| `not_observable` | The hop could **not** be inspected. Always carries the reason. |

`not_observable` is neither a pass nor a fail. Read it as "this hop was not
checked", and `summary.txt` says exactly that under the verdict line whenever
one is present.

The third verdict is the reason this tool exists. On 2026-09-02 the correlation
engine consumed nothing for three hours while every container reported healthy.
A check that cannot run, reported as a check that passed, is what let that
outage stay invisible. A hop nobody could look at must never read as a hop that
lost the record, so the debugger spends a whole verdict on the difference and
names the reason every time.

The same rule runs downward into the individual hops. A flow probe is absent
from the sampled log store about 98 percent of the time by design, so an empty
answer there is reported as `not_observable` with the sampling rate, never as
`not_seen`.

## What each kind can prove

The four kinds carry different evidence, and the strength of the claim differs
with it.

| Kind | Identity carried | Mode |
|---|---|---|
| `syslog` | A 26-character marker in the message text | Injected into the stack's syslog collector |
| `trap` | The same marker in a varbind string | Injected into the stack's trap receiver |
| `flow` | A tuple derived from the marker, because a flow record has no text field | Injected into the stack's goflow2 listener |
| `gnmi` | None. Real updates are followed by device and window | Passive only |

### syslog and trap

The record carries `cx_debug=<marker>` inside the free-text field the kind
already has, so every downstream query is a match on that exact token. This is
the strongest evidence the tool produces: a hop that returns the record has
returned **this** record.

### flow

A NetFlow v5 record has no free-text field, so the marker cannot travel inside
it. The debugger derives a deterministic tuple from the marker instead: a source
address in `192.0.2.0/24` and a destination in `198.51.100.0/24` (RFC 5737
documentation space), ephemeral ports, RFC 6996 private AS numbers, one byte and
one packet, protocol UDP. The tuple carries 66 bits of marker-derived entropy.

State the difference plainly: a tuple is weaker identity than a text marker. Two
records could in principle share a fingerprint, where two records can never
share a marker. The bus hop is where that matters most, because the peek needle
is only the probe's source address, so the api verifies the **full** tuple on
every record the bus returns before it accepts one as this trace's record.

One byte and one packet mean a probe cannot move a top-talkers ranking, and
documentation space means it cannot be mistaken for customer traffic.

Captured on the validation lab, 2026-09-04. A flow probe built by
`internal/pipedebug`, sent to the stack's own goflow2 listener on UDP 2055:

```text
marker: 01m1q9dd26cj4fvh2p5tm2fj8b
fingerprint: 192.0.2.117:57596 -> 198.51.100.197:60385 proto=17 src_as=65413 dst_as=65174
ch_predicate: src_addr = '192.0.2.117' AND dst_addr = '198.51.100.197' AND src_port = 57596 AND dst_port = 60385 AND src_as = 65413 AND dst_as = 65174
netflow: 72-byte NetFlow v5 export left this process -> 127.0.0.1:2055 (goflow2)
```

The row the analytics store returned for that predicate:

```text
Row 1:
──────
ts:              2026-09-04 22:42:46.462
src_addr:        192.0.2.117
dst_addr:        198.51.100.197
src_port:        57596
dst_port:        60385
proto:           17
bytes:           1
packets:         1
sampler_address: 172.18.0.1
flow_type:       netflow
tenant_id:
```

That is the whole flow lane proven end to end in 1.0 second: goflow2, then
`netops.flows.raw`, then the router's rekey, then `netops.flows`, then the
decode, then the analytics store.

### gnmi

A gNMI update originates on the device. The collector dials in and the device
streams, so there is no wire form the debugger could send to the stack that
would produce one. Minting a gNMI update would mean writing a leaf on a live
router, and the debugger never writes to a device. `--kind gnmi` is therefore
passive only, and `--passive` on any other kind is refused rather than accepted
and quietly downgraded.

Read the result for what it is. A passive follow proves that **some** traffic
from this device crossed this hop inside the window. It does not prove that a
particular record did. Every verdict a passive follow produces says so in its
reason instead of borrowing the wording a marked trace has earned.

## The parser decision path

Stage 2 has two evidence sources, and one `parser.log` carries both.

The Vector transforms stamp `.cx_parse_trace` on a record that carries a marker.
The field is one flat string naming the matched branch, the extracted fields and
every drop with its reason: which tenant the record resolved to and why, whether
the body parser matched a profile or matched nothing, the severity the record
arrived with and the one it normalized to. The transform emits the same line to
the container log at `info`, because Vector reads its level once at process
start and a `debug` line there would never appear.

The Go trap decoder emits its decisions through the api's bounded debug ring, so
the parser hop does not depend on the pipeline it is inspecting. A kind that
never crosses a Go parser reports `not_observable` with that reason, never
`not_seen`, because an empty Go-side answer for a syslog record says nothing
about whether the record was parsed.

To trace a **real** record, one that carries no marker, arm the runtime filter:

```bash
curl -s -X PUT -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"marker":"spine1","for_seconds":300}' \
  http://localhost:8000/api/debug/parsemarker
```

The filter is default-off, bounded by the same 30-minute cap, and auto-disarms
inside the traced process even if the caller dies. The needle is not written to
the audit log verbatim, because a fragment of a customer log line in an
immutable trail is a data leak. Its length and the window are recorded instead.
Send `{"off":true}` to disarm immediately.

## The UI-query contract

The last hop makes a narrow, checkable claim: the api returns this record for
the very query the console issues to display records of that kind. No headless
browser runs. A browser test would be testing React rather than the pipeline.

`ui.log` records the route, the api client function that calls it, the store
that answers, the query with this trace's values substituted, and the answer in
those words: the api returned the record for the UI's own query, yes or no. The
route table lives in Go and a test reads the console's own API client to prove
each route in it is still the route the console calls.

| Kind | Route the console issues | Store that answers |
|---|---|---|
| `syslog`, `trap` | `POST /api/logs/search` | The tenant log index |
| `flow` | `GET /api/flows/top` | The analytics store, `netops.flows` |
| `gnmi` | `GET /api/metrics/query_range` | The metric store |

For the log kinds this hop lifts one clause. Every injected record is tagged
`cx_synthetic=true`, and the console's log search excludes that tag so a probe
can never appear as device traffic in a customer's search. Run verbatim, the
console's own query must therefore **not** return a probe. Reporting that
correct exclusion as "the console cannot see the record" would be a false alarm
about a working control, so the hop runs the query with the synthetic clause
lifted and says so in the reason and in `ui.log`. What is proved is that
everything the console's query depends on returns the record. What is
deliberately not proved is that a synthetic probe is visible, because it must
not be.

## Safety

| Rule | How it holds |
|---|---|
| No device is ever written to | `--device` only decides which device the record claims to come from. Injection targets the stack's own ingress socket, and gNMI has no injectable form at all |
| Probes stay out of customer views | Every injected record is tagged `cx_synthetic=true` and excluded from the console's log search. The probe trap OID sits under the IANA experimental arc `1.3.6.1.3`, so it cannot decode as `coldStart`, `linkDown` or any notification correlation reasons about |
| A raised level always comes back down | The module's own process arms the revert timer, the tool reverts when the window ends, and it reverts again on Ctrl-C. A `SIGKILL` leaves the module's own timer running |
| A stuck level is caught from outside | `scripts/stack-watchdog.sh` reads four gauges from the metric store every minute and raises the problem class `DEBUG_LEVEL_STUCK`, naming the module. Set `DEBUG_LEVEL_CHECK=0` to disable it |
| Sessions are readable only by their owner | Session directories are `0700` and files `0600` |
| Redaction happens at write time | Each line is redacted as it is written, by the same pass the TAC bundle uses, so the directory on disk is already safe to share. Tenant identifiers are kept, because support needs them |
| Every call is authorized and audited | Platform administrator only, on all five routes |

The four gauges the watchdog reads are exported even when they read 0. An absent
series therefore means one thing only: this api predates the debugger, or it is
not being scraped. The watchdog reports that as an unproven gap and neither
passes nor pages on it.

## Related

- [Send flow records](/send-data/flows)
- [Send syslog](/send-data/syslog)
- [Send SNMP traps](/send-data/traps)
- [Set up gNMI streaming telemetry](/onboard-devices/streaming-gnmi)
- [Verify a deployment is doing work](/deploy/verify-deployment)
- [Troubleshooting](/reference/troubleshooting)
- [What an empty result means](/reference/honest-states)

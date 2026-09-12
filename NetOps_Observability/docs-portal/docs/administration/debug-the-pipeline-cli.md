---
title: Debug the pipeline from the CLI
description: Run correlix-debug on the host, read the session directory it writes, and tell a hop that lost a record from a hop nobody could inspect.
page_type: task
sidebar_position: 14
---

# Debug the pipeline from the CLI

`correlix-debug` runs on the Correlix host. It sends one marked record into the
stack's own ingress, follows the marker hop by hop, and writes one log file per
module into a session directory you can read, `grep` and hand to support.

Use it when telemetry goes in and does not come out and the console does not say
which hop lost it. The same five routes drive the **Platform → Tools → Pipeline
Debugger** page in the console; the command line is what you reach for when the
console itself is the thing you are debugging. For what each hop proves and why
the marker takes a different form on each telemetry lane, read
[Debug the pipeline](/send-data/debug-the-pipeline).

## Before you begin

- **Permission: platform administrator.** The five `/api/debug/*` routes are
  platform-global configuration, not per-tenant data. A tenant or organization
  administrator receives `403`. Every call the tool makes is audited.
- Shell access on the Correlix host, with permission to reach the Docker daemon.
  The tool resolves containers by compose label, never by guessing a name.
- The `correlix-debug` binary. The installer bundle ships it beside
  `install-correlix.sh`. From a source checkout, build it:

  ```bash
  cd NetOps_Observability/src/backend
  go build -o ../../correlix-debug ./cmd/correlix-debug
  ```

- Credentials. The tool signs in with `ADMIN_USERNAME` and
  `ADMIN_INITIAL_PASSWORD` from `deployment/docker/.env`. Pass `--token`, or set
  `CORRELIX_TOKEN`, when that file is not readable from where you run it.
- `CORR_DEBUG_TOKEN` set to the same value on the api and the correlation
  container, if you want the bus hop inspected. Without it that hop reports
  `not_observable` with the reason, and the other nine hops still run. See
  [Read the bus hop](#read-the-bus-hop).
- The identifier of the device the record claims to come from. No device is
  written to, contacted or reconfigured at any point.

## Steps

The tool has three verbs: `trace` follows one record, `logs` raises log levels
for a bounded window, and `bundle` packages a session for support.

To trace one record end to end:

1. Run the trace on the telemetry lane you suspect. `--ttl` is capped at five
   minutes.

   ```bash
   cd NetOps_Observability
   ./correlix-debug trace --kind syslog --device spine1 --ttl 60s
   ./correlix-debug trace --kind trap   --device spine1
   ./correlix-debug trace --kind flow   --device spine1
   ```

2. For gNMI, follow real traffic instead. `--kind gnmi` is passive only and
   injects nothing, because a gNMI update originates on the device and the tool
   never writes to a device.

   ```bash
   ./correlix-debug trace --kind gnmi --passive --device spine1 --since 10m
   ```

3. Read the stage table the run prints, and the same table in `summary.txt` in
   the session directory it names.

4. Open the module log file named by the first hop whose verdict is not `seen`.
   The first line of every module file states the module, the window, and how
   the lines below were obtained.

5. List every hop that did not see the record, with its reason.

   ```bash
   jq '.entries[] | select(.verdict != "seen") | {stage, verdict, reason}' \
     data/debug/2026*/timeline.json
   ```

To raise log levels for a bounded window:

1. Name the modules and the window. The window is capped at 30 minutes.

   ```bash
   ./correlix-debug logs --modules api,correlation,vector --for 1m
   ```

   The command reports what it actually did, module by module. On the validation
   lab it returned:

   ```text
   session: data/debug/20260905T0311Z-logs-01m1qrswb7t2mcgghk9b83xr9q
   window : 1m0s (hard cap 30m0s)
     api          level: debug until 2026-09-05T03:12:42Z
     correlation  level: debug until 2026-09-05T03:12:42Z
     vector       level: unchanged — not runtime-switchable: Vector reads VECTOR_LOG at process start and exposes no log-level mutation on its API. Use the per-event `vector tap` stream instead — correlix-debug already collects it for the parser and router stages
   ```

2. Let the command exit. Every raise reverts on exit, on Ctrl-C, and on the
   module's own in-process timer, so a killed CLI still leaves nothing raised.

To package a session for support:

1. Bundle the most recent sessions. Pass `--session <dir>` to name one instead.

   ```bash
   ./correlix-debug bundle --last 1
   ```

   ```text
   bundle : data/debug/correlix-debug-20260905T0311Z.tar.zst
   codec  : zstd -19
   sha256 : 85abc18c88f27b8651c129b5553e91a48aa202623a85fb789db04999566b35e3
   sessions: 1
   ```

   The codec is printed and is in the file name, never implied: the archive is
   `.tar.gz` when `zstd` is not installed on the host. `SHA256SUMS` is written
   inside the archive and beside it, with a `BUNDLE-README.txt` naming the
   redaction pass that ran.

2. Verify the archive where it lands.

   ```bash
   sha256sum -c SHA256SUMS
   ```

   Each line was redacted as it was written, by the pass the TAC bundle uses, so
   the session directory on disk is already safe to share.

### Trace a real, unmarked record {#arm-the-parse-marker}

An injected record carries its own marker, so nothing has to be armed. A
device's own log line carries none. Arm the runtime filter to make its decision
path appear in `parser.log`:

```bash
curl -s -X PUT -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"marker":"spine1","for_seconds":300}' \
  http://localhost:8000/api/debug/parsemarker
```

```json
{"armed":true,"marker":"spine1","until":"2026-09-05T03:17:57.967695569Z","reason":"auto-disarms at the stamped time inside the traced process, even if the caller dies"}
```

The filter is default-off and bounded by the same 30-minute cap, and the disarm
timer is armed inside the traced process, so it comes back off even if the
caller dies. The needle is not written to the audit log verbatim, because a
fragment of a customer log line in an immutable trail is a data leak. Its length
and the window are recorded instead. Send `{"off":true}` to disarm now:

```json
{"armed":false,"until":"0001-01-01T00:00:00Z","reason":"off — an injected record carrying its own cx_debug marker is still traced; this switch is for tracing a REAL, unmarked record"}
```

### Read the bus hop {#read-the-bus-hop}

The bus peek and the correlation log level both live on the correlation
container's health sidecar, and both are default-closed. With no shared secret
they answer `503`, and a trace reports the bus hop as `not_observable` with that
reason.

To open them, put the same value on both services in `deployment/docker/.env`,
then redeploy:

```bash
CORR_DEBUG_TOKEN=<a long random string>
```

The installer mints the value on a fresh install and adds it on upgrade. Set
`CORR_DEBUG_SIDECAR_URL` only when the sidecar is not reachable at the
`CORRELATION_URL` host on `CORR_HEALTH_SIDECAR_PORT`, which is the derivation the
api uses when the variable is unset.

The peek is bounded on every axis: an ephemeral consumer with no group id, so it
cannot join the engine's group or move its offsets, at most 10 seconds, at most
20 records, seeking by a bounded lookback time rather than to the start of the
topic.

## What you see

A session directory under `data/debug/`, mode `0700` with `0600` files, holding
the three session files and one file per module.

Captured on the validation lab, 2026-09-05, for a syslog trace against device
`spine1` with `CORR_DEBUG_TOKEN` set:

```text
CORRELIX PIPELINE DEBUG — TRACE SUMMARY
======================================
marker   : 01m1qrq1t7cp6yc504da8pb2n2
kind     : syslog
device   : spine1
tenant   : -
started  : 2026-09-05T03:10:08Z
session  : data/debug/20260905T0310Z-trace-01m1qrq0b3vbp85h65mqbyr4mg

#  STAGE         VERDICT         Δ PREV     EVIDENCE / REASON
--------------------------------------------------------------------------------------------
1  ingress       seen            -          ingress.log
2  parser        seen            0 ms       parser.log
3  kafka         seen            0 ms       netops.syslog[2]@3764834
4  router        seen            0 ms       router.log
5  opensearch    seen            0 ms       netops-syslog-t_d3d501aa08e2395893b378a453b8af67-2026.09....
6  victoria      not_observable  -          a syslog record produces no per-record metric series; Vic...
7  clickhouse    not_observable  -          a syslog record has no ClickHouse raw row (ClickHouse hol...
8  correlation   not_seen        -          no corr_evidence row cites the marker — the engine's in...
9  api           seen            250 ms     api.log
10 ui            seen            -250 ms    netops-syslog-t_d3d501aa08e2395893b378a453b8af67-2026.09....

stages: 7 seen, 1 not seen, 2 not observable
VERDICT: the record reached the UI-facing API (exit 0)
NOTE:    a 'not observable' stage was NOT checked — it is neither a pass nor a fail.
```

The directory that run wrote:

```text
data/debug/20260905T0310Z-trace-01m1qrq0b3vbp85h65mqbyr4mg/
  manifest.json      versions, flags, who ran it, which redaction pass, warnings
  summary.txt        the stage table above
  timeline.json      stage, verdict, reason, latency, evidence reference
  ingress.log parser.log kafka.log router.log
  opensearch.log victoria.log clickhouse.log
  correlation.log api.log ui.log
```

There is always one file per module, all ten, even for a hop nothing collected.
A module that was not observed holds exactly one line saying so and why. An
empty file would read as "nothing happened", so an empty file is a defect and
`session_test.go` fails the build on one.

Every file is line-oriented JSON, so `jq` and `grep` work on it:

```bash
jq -r '.msg' data/debug/2026*/parser.log
```

### The per-module files

| File | Where the evidence comes from | What `not_observable` means here |
|---|---|---|
| `ingress.log` | `vector tap --outputs-of syslog_in` or `trap_in` on the aggregator | The tap could not attach: the aggregator is down, or `docker exec` was refused |
| `parser.log` | `vector tap --outputs-of syslog_normalized` or `snmptrap_normalized`, carrying the event and its `cx_parse_trace` decision string, merged with the Go trap decoder's decisions from the api's debug ring | The tap could not attach. A kind parsed outside the Go process reports the Go half as not observable with that reason, never as a miss |
| `kafka.log` | The api proxies a bounded, group-less peek to the correlation container's debug sidecar | `CORR_DEBUG_TOKEN` is unset. See [Read the bus hop](#read-the-bus-hop) |
| `router.log` | `vector tap --outputs-of syslog_tagged` or `snmptrap_tagged` on the router | The tap could not attach |
| `opensearch.log` | `match_phrase` on the analysed `message` field of the tenant index; for a flow, the fingerprint tuple | The store refused the query or answered something undecodable. For a flow, a miss is always not observable: the log store holds a 1-in-50 sample of that lane |
| `victoria.log` | `GET /api/v1/export` for the marker's series, or for a passive gNMI follow the device's whole raw `gnmi_*` lane in the window | Expected for syslog, trap and flow: none of them mints a per-record series. For a passive gNMI follow this file is the load-bearing evidence |
| `clickhouse.log` | The kind's raw table | Expected for syslog and trap: neither has a raw row. For a flow this is the authoritative hop, matched on the full fingerprint |
| `correlation.log` | `netops.corr_evidence` by marker, plus the dead-letter and quarantine counters | The analytics store or the health snapshot was unreachable |
| `api.log` | The api's own bounded in-memory ring, keyed by marker | The ring is not wired, which means a build without the debug routes |
| `ui.log` | The api runs the console's own query for this record | The api could not be reached for the hop, or no query contract exists for the kind |

Each file also records the exact query or command it used, verbatim, so you can
re-run it by hand instead of trusting the summary of it.

### The three verdicts

Every hop reports one of three values, never two.

| Verdict | What it means |
|---|---|
| `seen` | The marked record was observed at this hop |
| `not_seen` | The hop **was** inspected and the record was not there |
| `not_observable` | The hop could **not** be inspected. It always carries the reason |

`not_observable` is neither a pass nor a fail. Read it as "this hop was not
checked", and `summary.txt` says exactly that under its verdict line whenever
one is present.

The third verdict is the reason the tool exists. On 2026-09-02 the correlation
engine consumed nothing for three hours while every container reported healthy.
A check that cannot run, reported as a check that passed, is what let that
outage stay invisible.

Two verdicts in the captured run are normal and are read wrongly often:

- `correlation` reads `not_seen` for a syslog probe because the engine admits
  only records its parser corpus recognises, and a probe is deliberately
  unparseable. The line carries the dead-letter counters, so a record the engine
  dropped and a record the engine could not persist stay distinguishable.
- `victoria` and `clickhouse` read `not_observable` because a syslog record
  mints no per-record series and has no raw flow row. Neither is a gap in the
  pipeline.

Exit code is 0 only when the record reached the UI-facing api. Anything else
exits 1, so `correlix-debug trace … && echo ok` is safe in a script.

## Related

- [Debug the pipeline](/send-data/debug-the-pipeline) for what each telemetry
  kind can prove, the parser decision path and the console-query contract.
- The operator runbook `docs/runbooks/pipeline-debug.md` in the source tree,
  which carries the symptom index for a trace that will not run and the
  `DEBUG_LEVEL_STUCK` watchdog contract.
- [Audit log](/administration/audit-log) for the record each call leaves.
- [Verify a deployment is doing work](/deploy/verify-deployment)
- [Troubleshooting](/reference/troubleshooting)

# ClickHouse write-integrity + restore drill — the phase plan and its audit

**Why this file exists.** The 10-phase programme that landed 2026-07-21→23 was
driven by an owner prompt that lived only in a chat session. Nothing in the repo
recorded what the phases *were*, so "are we done with ClickHouse?" could not be
answered without archaeology — commit subjects mention Phases 2, 3, 6, 8 and 10
and nothing explains 1, 4, 5, 7, 9. This file is the missing source of truth:
the plan, and an evidence-backed audit against it (2026-07-25).

---

## The plan (owner prompt, 2026-07-21, condensed to its testable obligations)

**Premise.** ~19 of 20 ClickHouse insert sites discarded the write result;
coverage was a per-file source-token scan; ClickHouse was the only major seam
without behavioural fault injection; backups were produced but never restored;
stores may share a failure domain.

| Phase | Obligation |
|-------|-----------|
| 0 | Inventory every CH write: file/line, service, table, criticality, batching, retries, whether the result is ignored, whether a checkpoint advances, tenant id, engine, partitions, MV/Distributed/async involvement. Determine CH version, engines, partition/sorting keys, MVs, `async_insert`, dedup settings, part thresholds, replication. |
| 1 | ONE write boundary. No bare `bool`. Explicit `Committed` / `Rejected` / `Unknown` outcome + typed error (HTTP status, CH code, query id, retryable, classification). Context, injected client, deadline, body always closed, bounded body read, `X-ClickHouse-Exception-Code`, `X-ClickHouse-Query-Id`, exception-inside-HTTP-200 detection, transport-vs-rejection distinction, no credential/payload leakage. |
| 2 | ONE centralized classifier: permanent (401/403, schema, bad SQL, policy) vs transient (refusal, 5xx, overload, `TOO_MANY_PARTS` **by CH exception code, not by assuming 429**) vs unknown-commit. Bounded backoff + jitter, honour `Retry-After`, retry budget, no checkpoint advance while retrying. |
| 3 | Deterministic idempotency: stable operation id from immutable source coordinates (topic/partition/first+last offset/table/schema version); byte-identical retries; CH dedup token where the engine actually supports it; document the limits (finite dedup window, non-replicated MergeTree, MVs, Distributed, multi-partition, async, reordering). **Do not advertise exactly-once.** |
| 4 | Migrate every call site: no ignored booleans, typed errors propagated, explicit retry ownership, counters/logs reflect the result, checkpoint behaviour verified, tenant identity preserved, poison data cannot loop forever, quarantine durable **before** acknowledging the source message. |
| 5 | 20 behavioural HTTP tests (`httptest` / injected `RoundTripper`) — see the acceptance list. |
| 6 | Real integration tests against an empty CH pinned to the deployed version, on the actual schema/engines. |
| 7 | Architectural guard: fail on a raw CH `INSERT` outside the approved package, direct endpoint calls, `bool`-returning insert helpers, discarded writer errors, classifier bypass. Replace/demote the source-token scan. |
| 8 | Metrics by table and result (committed/rejected/unknown, retries, permanent, auth, schema, too-many-parts, retry exhaustion, quarantine writes, latency, consumer lag, oldest blocked checkpoint, active parts) + structured logs with batch id, table, tenant, rows, attempt, status, CH code, query id, outcome, classification — **no secrets, no full rows**. |
| 9 | `scripts/restore-drill.sh` + disposable compose profile: drill id, canary before backup, real backup path, restore into EMPTY scratch stores, validate **content** not exit status, RPO/RTO, machine-readable JSON report, nonzero on failure, safe cleanup, never touch live volumes. Assert CH schema/engines/partition+sorting keys/TTLs/MVs/canary/row counts/tenant id/**strict row policies**/users+grants; PG migrations/canary/FKs/extensions/service start; OpenSearch repo verification/non-partial snapshot/restore into empty indices/canary docs/mappings/aliases/templates. Classify every other store: must-back-up / reconstructable / ephemeral. |
| 10 | Backup failure-domain check: does the backup share filesystem, block device, host, cloud account, credentials or deletion permissions with the primary? **A same-filesystem copy is not DR.** |

---

## Audit — 2026-07-25

Method: read the shipped code and tests, not the commit subjects.

| Phase | Verdict | Evidence |
|-------|---------|----------|
| 1 | ✅ met | `src/backend/chhttp/chhttp.go` — `Outcome` (`OutcomeCommitted/Rejected/Unknown`), typed `Error{Op,Status,Code,Message,QueryID,Outcome,Classification}`. `QueryID` documented as the handle that resolves an Unknown against `system.query_log`. |
| 2 | ✅ met | Central `classify`/`classifyTransport` in the same package; `too_many_parts` classified by CH exception code; truncated/lost response → `OutcomeUnknown` with the comment "the statement may well have applied in full". |
| 3 | ✅ met | `a3549021` dedup tokens; `57a38fbf` bounded retry with jitter and byte-identical payload; `set_dedup_coord(topic, partition, offset)` per message in `src/correlation/main.py`. |
| 4 | ✅ met (structurally) | `TestClickHouseAccessGoesThroughTheSeam` proves no file hand-rolls a CH request; exemptions must carry a stated reason or the test fails. |
| 5 | ✅ met | `chhttp/chhttp_test.go` — 16 test functions incl. the 200-with-exception, auth, schema, `too_many_parts`, transport and truncation cases. |
| 6 | ✅ met | `7eec55b8` — 7/7 against pinned `clickhouse-server:24.8.14.39`, incl. dedup-token e2e, MV propagation, `TOO_MANY_PARTS` reported not lost. Distributed/async cases honestly omitted: the repo runs neither (verified 0 of each). |
| 7 | ✅ met, and better than asked | `clickhouse_seam_test.go` is **AST-based and function-scoped** — it flags a function that both resolves the CH endpoint and builds its own request. The spec's complaint about per-file scanning is directly addressed. |
| 8 | ✅ met | `89d7562c` — `netops_clickhouse_write_outcomes_total{outcome}` + `netops_clickhouse_failures_total{class}`, package-level atomics recorded centrally so no call site can forget. |
| 9 | ✅ met | `2e977825` `restore-drill.sh`; `450a66e0` CH + OpenSearch legs proven live; `4d234387` found the search tier had had **no backups for 11 days** — two real bugs. |
| 10 | ✅ met | `bf8d4a30` + `docs/audit/BACKUP-FAILURE-DOMAIN.md`; `4ebd951b` off-host push hook. Off-host DR is code-complete and tagged for first-customer validation (`TAG:OFFHOST-DR`). |
| 0 | ⚠️ not retained | The inventory drove the work but was never checked in, so the "19 of 20" claim can't be re-derived from the repo. `TestClickHouseAccessGoesThroughTheSeam` now enforces the end state continuously, which matters more than the historical snapshot — but the inventory itself is gone. |

### The one substantive gap — acceptance criterion 8

> *"No source checkpoint advances on uncommitted or unknown outcomes."*
> Constraint 7: quarantine must be durable **before** acknowledging the source message.

`src/correlation/main.py` constructs its `AIOKafkaConsumer` with
**`enable_auto_commit=True`**. Offsets therefore advance on aiokafka's timer,
independent of whether the ClickHouse write committed. The code is honest about
it — the quarantine path's own comment reads *"the offset has already
auto-committed"* — and there is a real compensating control: handler failures
raise, are quarantined, and are appended to a durable NDJSON dead-letter file
(`CORR_DLQ_DIR`, defaulted to `/data/deadletter` in `docker-compose.yml:918`,
with a startup warning when unset).

The prompt permits the DLQ branch ("*or* the rejected batch has been durably
written to an approved quarantine/DLQ"), so this is close to compliant — but the
**ordering is inverted**. The spec wants durable-quarantine-then-ack; what ships
is ack-then-quarantine. The residual exposure is narrow but real: if the process
dies between the timer's auto-commit and the DLQ append, that event is gone with
no record of it — exactly the silent-loss class the programme set out to kill.

**Closing it** means manual offset commit gated on handler success, which is a
consumer-loop change with its own redelivery/duplicate implications (mitigated
by the Phase 3 dedup tokens already in place). Filed as tracker item **#126**.

### Conditional exclusions worth re-reading before they bite

Phase 6 skipped Distributed-table and `async_insert` cases because the repo uses
neither. Correct today, and honestly stated. But it is a *conditional* — the day
a Distributed table or `async_insert` is introduced, that coverage gap opens
with nothing to announce it. A guard asserting "still zero Distributed engines,
still no async_insert" would convert the assumption into a tripwire.

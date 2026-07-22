# Correlix — System Invariants Register

> Companion to `FINDINGS-2026-07-21.md`. That register tracks *defects*; this
> one tracks the *properties* the platform must hold, and — the part that
> actually matters — whether each is **enforced by something that fails a
> build**, or merely believed.
>
> Last measured: 2026-07-22. Every "enforced" claim below names the specific
> test or gate. If a row says NOT ENFORCED, that is a real gap, not a to-do
> someone forgot to tick.

## Why this file exists

The 2026-07-21 audit found 84 defects sharing one generator: *remediation was
applied to the instance and not the class*. The deeper reason that was possible
is that the platform's invariants lived in prose — in `CLAUDE.md`, in code
comments, in reviewers' heads — where nothing could check them. 285 Go test
files were green throughout, because every one of them tested the happy path.

An invariant that no gate enforces is a preference.

## Enforcement ladder

| Level | Meaning |
|---|---|
| **BUILD** | A test fails if the property is violated. `go test` is merge-blocking, so this is the strongest tier available. |
| **GATE** | A CI job outside the test suite blocks merge (lint, vuln, config preflight). |
| **RUNTIME** | Enforced in production, but a violation is only visible after it happens (alert/metric). |
| **PROSE** | Written down; nothing checks it. |
| **NONE** | Not stated anywhere. |

---

## 1. Data durability

> *No event is acknowledged until it is durably stored or safely recoverable.*

| Aspect | Status | Enforced by |
|---|---|---|
| Ingest tier returns 2xx only after the sink accepts | ✅ | `acknowledgements: enabled` + disk buffers (F-04); **RUNTIME** |
| Bus producer surfaces non-2xx / transport failure | ✅ | **BUILD** — `bus_producer_failure_test.go` (7 status codes, transport, timeout) |
| Settings writes report a failed persist | ✅ | **BUILD** — `settings_persist_failure_test.go`, `TestNoVoidSaveLocked`, `TestSaveResultsAreChecked` |
| Operator-created devices survive a restart | ✅ | **BUILD** — `device_persist_test.go` (restart simulated via a second aggregator over the same backend) |
| ClickHouse writes check their status | ✅ | **BUILD** — `TestClickHouseHTTPWritesCheckTheirStatus` |
| Dead-letter path captures the reason | ✅ | **GATE** — ingest-contract-ci + `scripts/vrl-harness.py` |
| Backup/restore actually produces a restorable artifact | 🟡 | Script exits non-zero on a partial dump (F-59), but the OpenSearch snapshot repo + SM policy are **syntax-checked only, never exercised against a live cluster** |

**Gap:** nothing proves a restore works. A backup that has never been restored is a hypothesis.

## 2. No silent failures

> *Every failure must become visible.*

| Aspect | Status | Enforced by |
|---|---|---|
| A metric-based alerting engine exists at all | ✅ | vmalert (F-16); **RUNTIME** — was entirely absent before 2026-07-21 |
| Unintentional ingest discards alert | ✅ | `VectorEventsDiscarded` (F-13/F-18); **RUNTIME** |
| Per-document index rejections are visible | ✅ | `doc_status.4xx` scraped + alerted (F-17); **RUNTIME** |
| `writeJSON` cannot emit an empty 200 | ✅ | **BUILD** — `TestWriteJSONMarshalsBeforeCommittingTheStatus` |
| Alert delivery failures are counted, not logged and forgotten | ✅ | **BUILD** — `notify/delivery_test.go` |
| Every alert rule names a metric that is actually produced | ✅ | **GATE** — ingest-contract-ci metric-name guard |
| CI gates report *why* they failed | ✅ | `preflight-configs.sh` always emits a reason (2026-07-22) |

## 3. Bounded execution

> *Every external operation has bounded execution time.*

| Aspect | Status | Enforced by |
|---|---|---|
| HTTP clients carry timeouts | ✅ | Measured: 28/28 clients bounded |
| ClickHouse reads carry execution guards + cancellation | ✅ | **BUILD** — `TestClickHouseReadsCarryExecutionGuards` |
| No unbounded response-body reads | ✅ | **BUILD** — `TestNoUnboundedResponseBodyReads` (source scan) |
| Pre-auth handlers cap their body | ✅ | **BUILD** — `TestPreAuthRoutesAreBodyCapped` |
| Postgres `statement_timeout` / pool bound | 🟡 | Implemented (F-60), **compile-reviewed only — never exercised against a live database** |
| Bus produce is context-bounded | ✅ | **BUILD** — `TestProduceIsBoundedWhenTheBridgeHangs` |

## 4. Idempotent processing

> *Retries must not corrupt data.*

| Aspect | Status | Enforced by |
|---|---|---|
| Ticket creation adopts an existing ticket | ✅ | outbox + `LookupByCorrelationID`; **BUILD** (ticketing tests) |
| Inbound ITSM sync dedupes against the audit ledger | ✅ | **BUILD** — and it now LOGS if the ledger read is truncated rather than silently duplicating |
| kv key migration is idempotent | ✅ | **BUILD** — `TestMigrateIsIdempotent` |
| Consumer redelivery is safe | 🟡 | Deterministic `signal_id` makes it safe by construction; **PROSE** — no test forces a redelivery |

## 5. Backpressure

> *Slow downstream systems cannot crash upstream systems.*

| Aspect | Status | Enforced by |
|---|---|---|
| Alert fan-out is a bounded queue + fixed worker pool | ✅ | **BUILD** — `TestFanOutIsBounded`, `TestQueueOverflowIsCountedNotSilent` |
| Consumer lag is measurable | ✅ | kafka-exporter + `KafkaConsumerLag*` (F-46); **RUNTIME** |
| Unbounded maps evict | ✅ | **BUILD** — dashboard `seen`, export rate-limit windows, mem ticketing audit |
| Reads are paginated with a true total | ✅ | **BUILD** — `TestPaginatedReadsReportTheirTotal` |

## 6. Tenant isolation

> *Tenant A can never access tenant B data.*

| Aspect | Status | Enforced by |
|---|---|---|
| DB-layer row policies exist and fail closed | ✅ | Verified live: `cloud_costs` 0 → 1 policy, 15 → 18 total (F-50) |
| Every feature ships an isolation test | 🟡 | **PROSE** (CLAUDE.md §3a rule 5). Widely followed, but **no gate proves a new data-returning route has one** |
| One tenant's failed write cannot destroy another's data | ✅ | **BUILD** — `TestAITenantConfigFailedSaveDoesNotDestroyOtherTenants` (F-64) |
| GraphQL enforces the same RBAC as REST | ✅ | **BUILD** — `TestGraphQLEnforcesTheSameRBACGateAsREST` (was an auth bypass) |
| Ingest ports authenticate the producer | ✅ | **BUILD** — `TestProduceCarriesIngestAuth`; fail-closed config (F-08) |

**Gap — the highest-value one in this file:** §3a rule 5 is mandatory and unenforced. A guard that fails when a new tenant-scoped route lacks an isolation test would close the class the way `TestNoVoidSaveLocked` closed its own.

## 7. Recoverability

> *Every failure has a recovery mechanism.*

| Aspect | Status | Enforced by |
|---|---|---|
| A refused write rolls back in-memory state | ✅ | **BUILD** — `TestSettingsRollBackInMemoryStateOnFailedPersist` |
| Orphaned store keys self-heal | ✅ | **BUILD** — `kv_legacy_migrate_test.go` (copy-not-move, never overwrites live data) |
| A deleted device stays deleted | ✅ | **BUILD** — `TestDeletedDeviceStaysDeleted` (F-69 tombstones) |
| Demo estates are removable | ✅ | `demo_lab.py teardown` — manifest-driven, never pattern-matched |
| Restore from backup | ❌ | **NOT ENFORCED** — see §1 |

## 8. Schema / contract compatibility

| Aspect | Status | Enforced by |
|---|---|---|
| Ingest field contract | ✅ | **GATE** — ingest-contract-ci; every stamped field must be declared |
| Bus wire shape | ✅ | **BUILD** — `TestProduceWireShapeIsOneEnvelopePerRecord` |
| ClickHouse TTLs converge on existing installs | ✅ | **BUILD** — every `TTL` in `init.sql` must have a converge entry (F-58) |
| API response-shape stability | 🟡 | **PROSE** — `docs/design/sot-provider-model.md` pins some shapes; nothing checks them |

## 9. Configuration safety

> *Invalid configuration fails safely.*

| Aspect | Status | Enforced by |
|---|---|---|
| Configs survive a fresh load | ✅ | **GATE** — `preflight-configs.sh` in fresh-install-integrity |
| Store keys are absolute | ✅ | **BUILD** — `TestStoreKeysAreAbsolute` |
| Bounded query params fail closed | ✅ | **BUILD** — `TestBoundedQueryParamsFailClosed`, `TestNoDiscardedIntParseInQueryHandling` |
| Ingest auth is fail-closed | ✅ | `${INGEST_TOKEN:?}` — Vector refuses to start without it |
| Documented switches actually work | 🟡 | `BUS_BRIDGE_URL=""` claimed to disable emit and did not (fixed 2026-07-22). **No general guard** that a documented env switch behaves as documented |

---

## Standing gaps, ranked

1. **Restore is never exercised.** Backups exit non-zero on a partial dump, but no test or drill restores one. (§1, §7)
2. **§3a rule 5 is unenforced.** Isolation tests are mandatory in prose; a new route can ship without one. (§6)
3. **Postgres-dependent paths are compile-reviewed only.** `statement_timeout`, the migration advisory lock, `pgAuditStore.Count/Offset`, `sweepAuditRetention`'s DELETE — none executed against a live database. (§3)
4. **`go test -race` runs only in CI.** No local gate; the sandboxes used for this work had no cgo.
5. **Documented env switches are unverified as a class.** One was found lying; nothing checks the rest. (§9)
6. **API response-shape stability is prose.** Totals currently ride on headers to avoid breaking the SPA — a header-blind client silently misses them. (§8)

## How to use this file

When adding a feature, state its invariant and pick the tier you will enforce it
at. If the answer is PROSE, say so out loud in the PR rather than leaving a
future reader to assume a gate exists. When an audit finding is closed, add the
guard that makes its *class* unrepeatable and record it here — that is the
difference between fixing an instance and fixing a generator.

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
| ClickHouse writes check their status | ✅ | **BUILD** — `chhttp/chhttp_test.go` fires real failures (21 tests: the TOO_MANY_PARTS-vs-schema-bug 500 pair, 9-case taxonomy, transport, hang, mid-body reset, truncation). Structure held by `TestClickHouseAccessGoesThroughTheSeam` (AST) |
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
| An unreadable audit trail cannot render as an empty one | ✅ | **BUILD** — `audit_failure_test.go` (F-73): a failing `auditRepo` must produce 503, never `200 {"events":[]}`. `Count` returns −1, never 0, for an unknown total |

## 3. Bounded execution

> *Every external operation has bounded execution time.*

| Aspect | Status | Enforced by |
|---|---|---|
| HTTP clients carry timeouts | ✅ | Measured: 28/28 clients bounded |
| ClickHouse reads carry execution guards + cancellation | ✅ | **BUILD** — `chhttp` applies `max_execution_time` + `cancel_http_readonly_queries_on_client_close` to EVERY call unconditionally; `TestRequestSettingsReachTheWire` proves they reach the wire |
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
| A revoked session/token stays revoked | ✅ | **BUILD** — `logout_revocation_test.go` (F-70): revokes return `(killed, persistErr)`, and the tests inject a persist failure rather than trusting the in-memory map. A logged-out refresh token is proven unable to mint a new session |
| A credential is never accepted into non-durable storage | ✅ | **BUILD** — `credential_durability_test.go` (F-76): the cloud-connector store returns nil off Postgres so the 501 guards are reachable; NMS refuses credential writes while still serving its catalog |
| An inbound webhook that lost events asks the sender to redeliver | ✅ | **BUILD** — `integrations_inbound_test.go` (F-75): `received` counts durable events, and any failure is a 500 so the sender's retry — the only recovery path — fires |
| A compliance record is written only for an action that persisted | ✅ | **BUILD** — `TestAdminSessionKillDoesNotReport204OnAFailedPersist`; `SESSION_REVOKED` is no longer emitted for a kill that did not stick |
| Demo estates are removable | ✅ | `demo_lab.py teardown` — manifest-driven, never pattern-matched |
| Restore from backup | ✅ | **SCRIPT+DRILL** — `scripts/restore-drill.sh` restores all THREE durable stores into empty scratch containers and asserts a canary (magic + exact timestamp) survived: Postgres (pg_dumpall), ClickHouse (schema + FORMAT Native data), OpenSearch (snapshot→delete→restore). Proven live: **17/17 assertions, RTO pg 21s / ch 9s / os 52s**. Local-copy path only — off-host DR is still unconfigured (BACKUP-FAILURE-DOMAIN.md) |

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
| A security setting an operator enables is actually read | ✅ | **BUILD** — `TestEverySecuritySettingHasAReadSite` fails when any `SecuritySettings` field has no read site outside its own definition; `TestF68SettingsAreEnforced` pins the seven by name. Proven to fire (a field added with no reader fails the build) |
| A persisted struct field has a SQL column | ✅ | **BUILD** — `TestPersistedStructFieldsHaveColumns` (F-77). Proven to fire. Caveat stated in-file: it proves the column NAME is in the list, not that the value is bound in the right position |
| A persist function can report failure | ✅ | **BUILD** — `TestNoVoidPersistFuncs` (F-78) covers the whole `save`/`persist`/`flush` family, not just `saveLocked()`. Widening it **found 3 instances the 84-finding audit never listed** |
| A tenant setting reaches the surface it is named for | ✅ | **BUILD** — `rca_window_test.go` (F-80): `tenantRcaSince` on all 3 RCA surfaces, explicit `?since=` fails closed |
| …and enforced correctly, not merely read | ✅ | **BUILD** — `account_policy_test.go` (rules, pure) + `account_policy_http_test.go` (wired through the real login handler, incl. the rehash-must-not-reset-the-expiry-clock regression) |

---

## Standing gaps, ranked

1. **Restore is exercised for all three durable stores; off-host DR is not.** `restore-drill.sh` proves PG, ClickHouse and OpenSearch each restore with content intact (17/17 assertions). What remains is the FAILURE DOMAIN: backups still live on the same disk/host as primary data, and the live OpenSearch snapshot repo is unregistered — the drill proves the mechanism, not a geographically-separate copy. (§1, §7, BACKUP-FAILURE-DOMAIN.md)
2. **§3a rule 5 is unenforced.** Isolation tests are mandatory in prose; a new route can ship without one. (§6)
3. **The tenant-create rollback is compile-reviewed only.** F-81's handler deletes a half-created tenant when `operator_restricted` cannot be applied, but `s.tenants` is a concrete `*tenantStore` with no interface seam, so a mid-request failure cannot be injected. Breaking the store path makes the CREATE fail first and the test would pass for the wrong reason — stated in `rca_window_test.go` rather than papered over. Extracting a `tenantRepo` interface is the change that would make it testable. (§7)
4. **Postgres-dependent paths are compile-reviewed only.** `statement_timeout`, the migration advisory lock, `pgAuditStore.Count/Offset`, `sweepAuditRetention`'s DELETE — none executed against a live database. (§3)
5. **`go test -race` runs only in CI.** No local gate; the sandboxes used for this work had no cgo.
6. **Documented env switches are unverified as a class.** One was found lying; nothing checks the rest. (§9)
7. **API response-shape stability is prose.** Totals currently ride on headers to avoid breaking the SPA — a header-blind client silently misses them. (§8)

### Closed

- ~~**ClickHouse is the last un-fault-injected seam.**~~ **Closed 2026-07-22** by the `chhttp` package. All six seams — kv/settings, bus, notification, audit, credentials, ClickHouse — now have real fault injection. Building it found five things the source scan could not: 9 call sites still hand-rolling their own request, `chInsertJSON` accepting a `ctx` and discarding it, no execution ceiling on the rollup worker, the API proxy forwarding raw `DB::Exception` text to callers, and an unbounded `io.Copy` on that same path.

## How to use this file

When adding a feature, state its invariant and pick the tier you will enforce it
at. If the answer is PROSE, say so out loud in the PR rather than leaving a
future reader to assume a gate exists. When an audit finding is closed, add the
guard that makes its *class* unrepeatable and record it here — that is the
difference between fixing an instance and fixing a generator.

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

**The CLASS is now enforced, not just instances (2026-07-27).** Until this date
every row below was a single *instance* of §10, and the general rule — CLAUDE.md
§10 "No silent failures allowed / All errors must be observable" — sat at **no
tier at all**. The 2026-07-27 audit found ~60 live instances of one defect: *an
error routed to the same branch as a benign empty state*, so a failure rendered
as "nothing wrong". The seed (`alerts/engine.go`) made a VictoriaMetrics outage
indistinguishable from "no rules firing" and therefore **mass-resolved live
alerts, closing pages during the outage**. Nothing caught it because the code is
structurally perfect — the error *is* checked; the defect is which branch is
taken — and every pre-existing guard asked a structural question. Two guards now
move the class to BUILD tier, and the guard *scope* itself was the deeper bug:
`goSources()` read only the root package, leaving **201 subpackage files
(alerts/, notify/, collectors/, nms/, ai/ …) outside every structural guard in
this repo**, while its anti-vacuity floor passed comfortably on the root package
and thereby certified the blind scope as healthy.

| Aspect | Status | Enforced by |
|---|---|---|
| Guards see the WHOLE module, not just the root package | ✅ | **BUILD** — `goSources()` now walks subpackages; floor raised to 400 so a regression to root-only (296) fails. Widening it immediately caught 3 real defects that had been invisible for months (two void persist funcs in `notify/`, an `Sscanf("%d")` in `collectors/`) |
| Every background launch in main() is drained or explicitly listed | ✅ | **BUILD** — `TestEveryBackgroundLaunchIsTrackedOrDocumented` (AST over `func main()`): a new goroutine must either join `workerGroup` or be named in `cancelOnlyWorkers()`. Closes CONC-MED-3, where `drain()` reported success while collectors, discovery, the report pipeline and 30-minute backfills were still mid-write. Current honest state: **15 tracked, 30 cancel-only** (adoption backlog in TRACKER) |
| gosec taint rules (G703/G704/G706) are excluded on a recorded basis | 🟡 | **PROSE** — the exclusion is not enforced by a gate. 35 findings triaged 2026-07-27 against pinned gosec v2.27.1: **zero reachable from untrusted HTTP input** (every sink is an env-configured URL/path, or is guarded by `isUUIDToken`/`indexBase`/`tenantSegRe`). Basis + reproduce command recorded in `src/backend/.golangci.yml`. Residual risk stated there: a genuinely tainted NEW sink would not be caught |
| A guard cannot silently stop covering a file | ✅ | **BUILD** — AST guards parse RAW source and treat a parse failure as FATAL. `stripComments` truncates at the first `//`, so any file with a URL literal was unparseable and was being **skipped with `continue`** — 54 files invisible, 8 with live findings. The guard written to catch "an error treated as a benign state" contained that exact defect |
| `package main` does not grow | 🟡 | **BUILD (ratchet, not a fix)** — `TestFlatPackageMainDoesNotGrow` pins the root package (originally 296 non-test files; **204 as of 2026-07-29** after the fifty-three Phase-1 extractions listed in docs/design/package-decomposition-plan.md); a new file fails the build and must go in a subpackage, and moving files out requires lowering the ceiling in the same commit. Proven to fire both directions. **This does NOT yet satisfy §2**: the 2026-07-29 four-reader audit measured **~23k LOC of business logic still in the root** (protocol clients, pure algorithm files, SQL builders, config stores, worker state machines) — the sized Phase-2 sequence is in the plan doc; see standing gap #8 |
| An error is never conflated with a benign empty state | ✅ | **BUILD** — `TestErrorIsNotConflatedWithABenignState` (AST). Blocking for new code; 39-file frozen baseline, **shrink-only**, each entry to be triaged and fixed or moved to the reasoned allowlist |
| A health flag can actually report unhealthy | ✅ | **BUILD** — `TestHealthFlagsCanBeFalsified`: a health bool assigned literal `true` and never falsified anywhere fails the build. Caught `alerts.Engine.healthy` (true at construction, never false, reported by `Health()` forever) |
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
| Postgres `statement_timeout` / pool bound | ✅ | **CI** — `pg-integration` (backend-ci.yml, `33cb45f2`) runs `TestPGStatementTimeoutIsApplied` against a live postgres:16-alpine: `SHOW statement_timeout` = the F-60 pool param |
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
| Every feature ships an isolation test | ✅ | **BUILD** — `TestEveryScopedRouteHasIsolationCoverage`: a new scoped route needs a real isolation test or fails the build (§3a rule 5). 82 pre-existing routes baselined, set shrinks only |
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
| Documented switches actually work | ✅ | **BUILD** — `TestEveryDocumentedEnvSwitchIsConsumed` (gap #6, 2026-07-30): every env token the operator docs present in code spans must be consumed somewhere real (backend Go incl. test-gated vars, deployment configs, scripts, sibling services); exemptions need a reason. Proven to fire: first run caught `LOKI_RETENTION_PERIOD` documented in DEPLOY_LINUX.md with no Loki anywhere in the stack (row deleted). Scope stated in-file: it proves existence/consumption, not per-switch BEHAVIOUR — that stays with each feature's tests (the `BUS_BRIDGE_URL=""` behavioural lie class, pinned by bus_producer's own regression test since 2026-07-22) |
| A security setting an operator enables is actually read | ✅ | **BUILD** — `TestEverySecuritySettingHasAReadSite` fails when any `SecuritySettings` field has no read site outside its own definition; `TestF68SettingsAreEnforced` pins the seven by name. Proven to fire (a field added with no reader fails the build) |
| A persisted struct field has a SQL column | ✅ | **BUILD** — `TestPersistedStructFieldsHaveColumns` (F-77). Proven to fire. Caveat stated in-file: it proves the column NAME is in the list, not that the value is bound in the right position |
| A persist function can report failure | ✅ | **BUILD** — `TestNoVoidPersistFuncs` (F-78) covers the whole `save`/`persist`/`flush` family, not just `saveLocked()`. Widening it **found 3 instances the 84-finding audit never listed** |
| A tenant setting reaches the surface it is named for | ✅ | **BUILD** — `rca_window_test.go` (F-80): `tenantRcaSince` on all 3 RCA surfaces, explicit `?since=` fails closed |
| …and enforced correctly, not merely read | ✅ | **BUILD** — `account_policy_test.go` (rules, pure) + `account_policy_http_test.go` (wired through the real login handler, incl. the rehash-must-not-reset-the-expiry-clock regression) |

---

## Standing gaps, ranked

1. **Restore proven for all 3 stores (17/17); OpenSearch repo registered + snapshotting daily.** Off-host DR and disk-sizing are CODE-COMPLETE and 🏷️ **tagged for first-customer validation** — see `docs/runbooks/first-customer-acceptance.md` §9 (TAG:OFFHOST-DR, TAG:F55-DISK). They are deferred, not open: the lab has no off-host store or large disk to finish the proof against; a real customer environment does. Not code. (§1, §7, BACKUP-FAILURE-DOMAIN.md)
2. ~~**§3a rule 5 is unenforced.**~~ **CLOSED 2026-07-23** — `TestEveryScopedRouteHasIsolationCoverage` fails the build when a NEW scoped route has neither a real HTTP isolation test nor a frozen-baseline entry. Proven to fire on an injected uncovered route. 82 pre-existing scoped routes (store/RLS-covered) are baselined; the set only shrinks as dedicated tests are written. (§6)
3. ~~**The tenant-create rollback is compile-reviewed only.**~~ **CLOSED 2026-07-26** — the named fix was made: `s.tenants` is now the `tenantRepo` interface (tenants.go), and `failRestrictRepo` (rca_window_test.go) injects the exact mid-request failure the gap said was impossible — CREATE succeeds, only `SetOperatorRestricted` fails. `TestTenantCreateRollsBackWhenRestrictionFails` and `TestOnboardRollsBackWhenRestrictionFails` exercise both F-81 rollbacks end-to-end through the real router (500 + tenant removed; onboard also removes the org). Proven to fire: deleting the handler's rollback `Delete` makes the test fail with "tenant still exists". (§7)
4. ~~**Postgres-dependent paths are compile-reviewed only.**~~ **CLOSED 2026-07-25** (`33cb45f2`) — the `pg-integration` job in `backend-ci.yml` runs the build-tagged Postgres tests against a pinned postgres:16-alpine every CI run: `statement_timeout`, the migration advisory lock, `pgAuditStore.Count/Offset`, `sweepAuditRetention`'s DELETE. (§3)
5. **`go test -race` runs only in CI.** No local gate; the sandboxes used for this work had no cgo. **2026-08-12:** the #151 branch is many commits ahead of origin and its CI — `-race`, staticcheck, gosec, govulncheck, the pg-integration job, the new `tls-install-boot` leg — has NOT executed; first run awaits the owner's push. Stated in the assurance report the same way.
6. ~~**Documented env switches are unverified as a class.**~~ **CLOSED 2026-07-30** — `TestEveryDocumentedEnvSwitchIsConsumed` guards the class mechanically (documented ⇒ consumed, exemptions carry reasons; fired on first run: the phantom `LOKI_RETENTION_PERIOD` row). Per-switch behaviour remains each feature's own tests — the honest limit, stated in the guard. (§9)
7. ~~**API response-shape stability is prose.**~~ **CLOSED 2026-07-30** — the shape is now pinned by build-time tests (`internal/httppage/contract_test.go`: the five header LITERALS, all-five-stamped-on-every-write, the envelope's exact keys) and documented for integrators (`docs/API_ACCESS.md` § Pagination & totals contract). The header-blind-client hazard has a documented, tested escape hatch: `?envelope=1` carries the same numbers in the body. Renaming any of it fails the build. (§8)
8. ~~**`package main` still holds substantial business logic, against the repo's
   own §2.**~~ **CLOSED 2026-07-30** — the programme ran to its finale. Phase 1
   (steps 18–59) extracted 53 domains; Phase 2 ran waves W0–W4, the RA re-audit
   classified EVERY remaining root file (61 INTEGRATOR / 34 FAT-deferred / 22
   FAT-CRITICAL — all 22 critical lifts shipped, RA.1–RA.16), and the **W5
   `/cmd` split landed**: the root is now the importable `backend` package,
   `cmd/api/main.go` is the sole `package main` (one line of wiring, §2
   satisfied), build ldflags + the shutdown-drain AST guard repointed. What
   remains in the root is inventoried WITH VERDICTS (plan doc § re-audit):
   handlers/wiring by design plus 34 FAT-deferred files extractable
   opportunistically. Security/correctness cores all live behind compiler
   boundaries; **growth stays ratcheted** (ceiling 200, lowered with every
   further extraction).

### Closed

- ~~**ClickHouse is the last un-fault-injected seam.**~~ **Closed 2026-07-22** by the `chhttp` package. All six seams — kv/settings, bus, notification, audit, credentials, ClickHouse — now have real fault injection. Building it found five things the source scan could not: 9 call sites still hand-rolling their own request, `chInsertJSON` accepting a `ctx` and discarding it, no execution ceiling on the rollup worker, the API proxy forwarding raw `DB::Exception` text to callers, and an unbounded `io.Copy` on that same path.

## How to use this file

## 8. Transport security (SEC-001.3, 2026-08-04)

The invariant: **no unauthenticated or plaintext hop between Correlix-owned
components exists in production.** As-built per-hop truth:
`docs/security/transport-inventory.yaml`; programme: tracker #151 →
`docs/security/CORRELIX_SECURITY_IMPLEMENTATION_BACKLOG.md`. The production
security validator (`internal/secprofile`, 16 rules, boot-refusal in the prod
profile — note its rule ids `SEC-00x` predate and do NOT correspond to the
backlog's `SEC-xxx` epics) is what puts a hop at RUNTIME; hops it has no rule
for sit at **NONE**, which is the honest reading of "nothing checks this".

**Post-programme state (2026-08-12):** #151 steps 1–3 ran to completion — the
enforce wave (2026-08-09), the 13-phase assurance run, and step-3 fixes
F-1…F-12 incl. the F-11 seal-or-quarantine build. The proof ledger is
`docs/security/TLS_ASSURANCE_REPORT_2026_08.md`; the inventory is now
service-complete *mechanically*
(`test_every_compose_service_appears_in_the_transport_inventory` — adding a
compose service without a transport decision fails the contract suite), and
its rows are pinned honest against shipped epics
(`test_transport_inventory_rows_reflect_shipped_epics`). What was PROVEN vs
merely built is per-row below. Gaps that REMAIN after the programme, stated
plainly: **(a)** no secprofile rule covers the bus or ingest lanes — a prod
boot with a plaintext bus would not be refused; **(b)** the CI legs `-race`,
staticcheck, gosec, govulncheck have NOT executed on this branch (no local
gcc; awaits the owner's push — extends standing gap 5); **(c)** the shipped
`compose.tls.yml` still publishes plaintext `:8000` (removed on the lab only);
**(d)** `api→gotenberg` (tenant PDFs) and two metrics-scrape hops remain
declared plaintext pending an owner decision (F-5 rows).

| Hop | Tier today | Raised by | Target tier |
|---|---|---|---|
| browser → nginx (ingress TLS; plaintext :8000 REMOVED on the lab 2026-08-09 — `ports: !override` 443-only; compose.tls.yml keeps :8000 until install.py messaging is TLS-aware) | PROSE | SEC-004 (promote profile; retire :8000 in the shipped variant with the installer work) | GATE + RUNTIME |
| nginx → api | **RUNTIME + wire-proven** (TLS-001/002/003; step-2 phase 6: no-cert refused, wrong-but-valid identity refused AND counted via `netops_tls_identity_rejected_total`) | — (accept-set narrowing proven on the wire 2026-08-09) | RUNTIME + BUILD |
| api → OpenSearch / ClickHouse / VictoriaMetrics / Postgres / Valkey | **RUNTIME + GATE** — the stores SERVE TLS (step-2 phase 5 wire identities; phase 6 negatives: OS anon 401 / write-only-read 403, valkey NOAUTH+plaintext refused); postgres additionally REFUSES plaintext TCP server-side (F-4 2026-08-10: `test_postgres_tls_entrypoint_requires_hostssl` + `TestPostgresRefusesPlaintextTCP`); per-edge contract rows with negatives pinned in `mtls-edges.yaml` (contract suite) | — (delivered by SEC-008…012 + F-4) | RUNTIME + BUILD |
| api → correlation | **RUNTIME + wire-proven** (APP-001; correlation serves its SVID on :8443, peer scoping enforced — monitor SVID 403 on app paths; step-2 phases 5–6) | — | RUNTIME + BUILD |
| victoria → api (metrics scrape) | RUNTIME (mTLS listener rejects certless scrape in prod) | SEC-003.3 registry formalizes the victoria SVID | RUNTIME + BUILD |
| vector-router → api (per-tenant sealing keys) | **BUILD + wire-proven feature-ON** (SEC-018.1 gate matrix proven live twice — step-2 phase 11 and the step-3 e2e re-run 2026-08-11 after F-6/F-7: router-SVID 200/audited, wrong SVID 401, stolen token 401, no cert refused, feature-off 404; end-to-end seal→store→audited-unseal PASS) | — (feature remains OFF on the lab by owner state; the property is proven, not dormant-assumed) | RUNTIME + BUILD |
| **every producer/consumer → Kafka** | **RUNTIME-adjacent** (ENFORCED live 2026-08-09: default-deny authorizer + PLAINTEXT:9092 removed, only MTLS:9094/FLOWS:9095/CONTROLLER:9093-SSL listen; tlsprobe probes all three + posture join; step-2 phase 6: ANONYMOUS sees 1/17 topics, Write netops.flows only, consume refused). No `secprofile` bus RULE yet — a prod boot with a plaintext bus would not be refused by the validator (GAP, remains) | SEC-006/007 remainder: a secprofile bus rule | RUNTIME + BUILD |
| collectors/prober → Vector ingest lanes | **RUNTIME-adjacent** (SEC-013.1/.2 mTLS client-cert requirement + per-lane tokens; shared-token fallback REMOVED — narrowing matrix proven live 2026-08-09: 4× per-lane 200 / shared 401; class guard in test_ingest_contract.py). No `secprofile` lane rule (GAP, remains) | a secprofile lane rule | RUNTIME + BUILD |
| syslog-ng → vector-aggregator | **GATE + RUNTIME** (F-1 fix 2026-08-11: mesh TLS with REQUIRED client cert — TLS-on never means server-only on this hop; pin `test_syslog_hop_serves_and_requires_mesh_tls`; proven live: no-cert refused, plaintext reset, marker landed over the TLS hop; tlsprobe + rotation sweep now cover :6601) | — (delivered by SEC-014.1/F-1) | RUNTIME |
| gnmic → devices (`skip-verify: true`) | **RUNTIME** (DEV-001 refuses in prod) | SEC-016 (Phase 2+) | RUNTIME + BUILD |
| device → syslog-ng (plaintext 514) | **RUNTIME** (DEV-002: lane must be *declared*) | SEC-014.2/.3 (Phase 2+ lane; v1 = declaration) | RUNTIME |
| device → SNMP trap (v3 fail-open for unknown senders) | **NONE** | SEC-015 (Phase 2+) — the fail-open closure | BUILD |
| device → goflow2 (protocol cannot encrypt) | PROSE | SEC-017.2: becomes a DECLARED plaintext risk acceptance | RUNTIME (declaration asserted) |
| backup destination encryption | RUNTIME (BKP-001, operator-asserted) | #150 GUI surfaces it | RUNTIME |

### 8a. Attribution + quarantine invariants (F-10/F-11, 2026-08-12)

New properties from the step-3 fixes; proof = the named test or the F-11
acceptance battery in the assurance report (F11.1–F11.12, run live on the lab
with the full TLS mesh and sealing custody ON).

| Invariant | Status | Enforced by |
|---|---|---|
| A device→tenant assignment takes effect on BOTH vector tiers without a restart (bound ≈ one export tick + content poll, ~75 s) | ✅ | **BUILD/GATE** — `TestWriteEnrichmentCSV_UnchangedContentDoesNotRewrite` + `test_vector_tiers_reload_enrichment_on_change` (F-10); live e2e measured **61 s** convergence (re-proven in the F-11 battery, INV-F11-11) |
| **No durable telemetry payload is stored in plaintext because tenant attribution failed** — registry-MISS events are sealed wholesale into `netops-quarantine-*` under the dedicated `quarantine` key scope. BOUNDARY: holds when sealing custody is enabled (the feature's own boundary — custody off means no tenant sealing exists either, so there is no asymmetry; the claim may not be spoken for such a deployment) | ✅ | **GATE + RUNTIME** — generated-stage tests (`processors/quarantine.go`+test) + VRL-harness discriminator matrix; live F11.2 (sealed envelope, zero plaintext leak, absent from every syslog index). Fail-closed: missing key ⇒ Vector exit-78 refusal (live-demonstrated); runtime seal failure ⇒ drop_on_abort, NO deadletter reroute, `VectorQuarantineSealFailures` alert (promtool-tested) |
| Authenticated producer stamps (`producer_stamped`) never downgrade to quarantine — Case-1 preserved | ✅ | **GATE** — VRL-harness matrix + live F11.1 (known tenant, unknown device → tenant index, zero quarantine docs) |
| Quarantine isolation: no tenant-facing read path (scoped OS patterns incl. `_cat`, dashboards, correlation identities) can reach the quarantine index | ✅ | **BUILD** — `TestQuarantineIndexUnreachableFromTenantPaths` + OS role grants (writer/api only); live F11.8 (scoped search empty) + F11.9 (correlation refuses `identity_unattributable`, quarantined NOT persisted, no RCA/ticket path) |
| Re-attribution is idempotent and crosses the key boundary through the real pipeline (quarantine-decrypt → authenticated bus → tenant rules under the tenant's key; tenant derived from live inventory, never the caller) | ✅ | **BUILD + RUNTIME-proven** — `TestQuarantineRoutesArePlatformOnly` + `TestQuarantineReattributeRequiresSensitiveDataAdmin` + `TestQuarantineReattributeHappyPathAndReplay`; live F11.3/F11.11: restore → replay → router restart ⇒ exactly ONE tenant doc (`id_key` on the five OS event sinks — a fix the battery itself forced). Residual: a re-restored FLOWS event re-inserts into ClickHouse (no upsert semantics there; report §8.5) |
| Quarantine retention is bounded (default 30 d, `QUARANTINE_RETENTION_DAYS`) | 🟡 | ISM policy `netops-quarantine-retention` attached to the live index (F11.4) + contract-pinned deletion action; the 30-day wall-clock deletion has NOT been simulated — attachment proven, expiry asserted |

## 10. Storm-time scale SLO (P4, ratified 2026-08-30)

The invariant, **ratified by the owner on 2026-08-30** (`docs/scale/P4_PROGRAMME_WRITEUP_2026-08-29.md`
§8, Option A) — quoted verbatim because this is the shipped contract:

> *Under a 15-minute 1,000-eps storm on 2,500 devices, the platform MUST
> evaluate the whole workload within 45 minutes of burst end, lose nothing
> (injected == persisted, 0 DLQ), stay within memory caps, and keep RCA accuracy
> ≥ 93 %. T1 p95 is measured and published every run but is not a pass/fail
> gate.*

Every clause is **PROVEN**, not believed: it is asserted by the `t-storm-2.5k`
9-gate sweep in `scripts/scale-miniladder.py` and was met end-to-end on
**storm-s04** (run `08300637l2bv`, image `2852ad6f`, fresh-recreated replicas,
aggregation plane OFF — the shipping default). Verdict:
`docs/scale/STORM_S04_2P5K_VERDICT_2026-08-30.md`.

**Honest tier note.** The sweep is a *rig* gate: it runs on the 4-core scale box
against a live stack, not in CI, so no push can be blocked by it. Its clauses
therefore sit at **RIG-GATE** — stronger than PROSE (a real assertion fails a
real run and the run is the release evidence), weaker than GATE (nothing
mechanical stops a regression from merging between sweeps). Read every ✅ below
as "proven on the named run", not "cannot regress".

| Aspect | Status | Enforced by |
|---|---|---|
| Whole workload evaluated within 45 min of burst end | ✅ | **RIG-GATE** — `correlation_completion`; storm-s04 **144 s** against the 2,700 s budget (19× margin) |
| Lossless: injected == persisted, 0 DLQ | ✅ | **RIG-GATE** — `accounting`; storm-s04 **900,001 == 900,001, exact, 0 DLQ**. The fault path was exercised unforced on that run: 3 `netops.findings` transport failures, all retried under the dedup token and recovered, 0 rows lost |
| Stays within memory caps | ✅ | **RIG-GATE** — `memflat`; storm-s04 **79.5 % of cap, slope ×0.961 (FLAT)** |
| RCA accuracy ≥ 93 % | ✅ | **RIG-GATE** — twin scorer against seeded ground truth; storm-s04 **326/345 = 94.49 %** (best recorded), detection 100 %, specificity 100 %. Residual misses are one clause on chained outages (trackers 187/184) |
| T1 p95 is published every run and is NOT a gate | ✅ | **RIG-GATE (by construction)** — `scripts/scale-rca-latency.py` T0..T6 emits it; no clause consumes it. storm-s04 **832 s**. Deliberate: the storm p95 is queueing time behind the burst on one shard (T3−T1 = 0 at max on every leg), not a decision cost |
| The SLO holds under a genuinely overloading storm, not only the nominal one | ✅ | **RIG-GATE (single leg)** — P3 A/B 25 % storm rung: with `CORR_AGGREGATION_PLANE` **ON**, an arm that was **INCOMPLETE** (78,663 objects pending at the 2,700 s cap) **completed in 192 s** and accuracy moved **81 % → 89 %**; 58.1 % of signals suppressed before the engine. `docs/scale/P3_AB_2P5K_VERDICT_2026-08-29.md`. **BOUNDARY: this is the ON arm; the plane is OFF by default**, so this row proves the SLO is reachable under 25 % storm share *with the plane*, not on the shipping configuration |
| A loop stall cannot cost the consumer its partitions | 🟡 | **RIG-GATE, but the threshold is stale.** storm-s04 took 0/0/0 restarts — yet `reconcile.find_continuation` **BLOCKED the loop for 27,844 ms** (92.9 % of the 29,974 ms worst stall) and passed only because the session timeout was widened 30 s → 60 s. The harness's own `stability` gate still tests against a hard-coded 30,000 ms (`scale-miniladder.py:1876`) and s04 cleared it by **26 ms**. Bounding the stall = tracker 185; re-deriving the gate = tracker 190 |

**What is NOT claimed.** Option B (per-identity-class latency relative to burst
end) was NOT adopted — the first-occurrence/repeat classifier exists only inside
the aggregation plane, so no such property is measurable on the shipping OFF
path. Option C (plane ON at storm rungs) is a **candidate, not an invariant**:
it is contingent on a matched fresh-container OFF/ON `t-storm-2.5k` pair that is
not yet approved to run, and at the 2 % neutrality rung the ON arm regressed
T1 p95 (+13.1 %/+28.9 % against a 13.11 % OFF-vs-OFF spread) and failed `memflat`
and `onboard`. Until that pair clears the guard, the plane stays OFF by default.

When adding a feature, state its invariant and pick the tier you will enforce it
at. If the answer is PROSE, say so out loud in the PR rather than leaving a
future reader to assume a gate exists. When an audit finding is closed, add the
guard that makes its *class* unrepeatable and record it here — that is the
difference between fixing an instance and fixing a generator.

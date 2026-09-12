# Code-Lightening Audit — 2026-08-03

**Owner directive:** analyze the entire application for duplicate code,
unnecessary/hanging code, and modernization opportunities; make it lighter.
Two read-only audits (backend Go, frontend React) ran 2026-08-03; their full
reports follow VERBATIM below. Execution is tracked as **#147**.

## Synthesis — the execution tranches

| Tranche | Contents | Est. saving | Risk |
|---|---|---|---|
| T1 backend zero-risk | delete `store/`+`transport/` scaffolds, 33 truly-dead funcs, Phase-2 root residue, misc prod-dead, `min`/`max` builtins, `sync.OnceValue` | **~875 LOC** | compiler + existing suites |
| T2 frontend zero-risk | delete 7 dead components (~1,100 LOC) + `brand-samples/` (1.0 MB), 4 dep removals, geist font | ~1,100 LOC + 1 MB artifact | grep-verified orphans |
| T3 frontend bundle | lazy routes in `nav.tsx`, dynamic-import elkjs, echarts/core wrapper, lazy xterm, font trim | **~3.1–3.4 MB raw / ~900 KB gzip off initial JS** | medium-low, needs browser smoke |
| T4 backend dedup | dupl clone groups (~160 LOC), jira/servicenow notifier core (150–250), notify_config generic handler (~250) | ~550–650 LOC | behavior pinned by suites |
| T5 owner-gated wire-or-retire | `segclass` (~908), `portintel` analysis half (~630 + ~150 test), `appid`/`cloud` built-ahead lanes (~320); wireless dormant = HOLD (owner 2026-07-27) | **~2,000 LOC** | needs owner intent per lane |
| T6 opportunistic | `authorize` migration (~200 net, 68 call sites), `slices`/`maps`/`strings.Cut` on touch, `admin.tsx` split, DataTable/modal convergence | ~600–1,600 LOC | do when touching files |

Explicitly REJECTED after assessment: `log/slog` migration (churn, no
capability gain, Vector log-contract risk); consolidating the §2 no-utils
micro-helpers (~350 LOC across 60+ packages is the priced-in cost of the rule
— recorded here so it stays a decision, not an accident).

Overlaps with `docs/design/package-decomposition-plan.md` are marked ⟳ inside
the reports; the plan's 34 FAT-deferred files (~4.7k LOC) remain governed by
the plan, not this audit.

## EXECUTED 2026-08-03 (same day) — results

Owner decisions: T1–T4 GO · segclass **RETIRE** · portintel scoring **KEEP**
(wiring planned) · appid/cloud lanes **KEEP** (owner: "not sure if I need it,
but keep it" — revisit when the RCA app-identity lane firms up; do not
re-flag as junk). Commits `c6f09366` (T2/T3), `6b39bd1a` (T1 + segclass),
`35566d14` (T4).

| Tranche | Shipped result |
|---|---|
| T1 | ~575 LOC removed; 5 audit entries SKIPPED on live-caller discovery (QueryIDOf, ExecWithRetry, BackendFor, tacacsHeader, pathgraph.NewMemStore — audit errata); integration/ordering confirmed deliberate supersession and documented |
| T2 | 7 dead components (~1,100 LOC) + brand-samples (1.0 MB) deleted; deps 19→15 |
| T3 | Initial JS **4.6 MB → 302 KB raw / 1,388 → 90 KB gzip**, 79 chunks; elk/echarts/xterm/xyflow all lazy; new `components/EChart.tsx` over echarts/core |
| T4 | Net −229 production LOC, zero non-test dupl groups remain; +554 LOC NEW characterization tests (F-62 accounting had no prior coverage); clone behavioral differences parameterized explicitly (channel severity defaults, ntfy watchdog refusal, SMTP starttls) |
| T5 | segclass deleted (~908 LOC + CIDR embed, ratchet log annotated); portintel + appid/cloud kept per owner |
| T6 | NOT scheduled work — opportunistic-on-touch guidance only (slices/maps/strings.Cut, authorize migration, DataTable/modal convergence, admin.tsx split) |

Grand total removed: **~2,800 production LOC + ~4.3 MB initial-bundle weight
+ 1 MB static assets**; added: ~554 LOC of characterization coverage. All
gates green at every step (full suite, vet, CI-image golangci, growth +
isolation-coverage + silent-failure ratchets — two of which advanced).

---

# PART 1 — Backend report (verbatim)

**Scope:** `src/backend` (read-only, 2026-08-03).
**Baseline:** module `netops/backend`, Go 1.25.0. 153.6k non-test LOC + 87.1k test LOC (vendor/testdata excluded). Root is now `package backend` — 201 non-test files / 50.1k LOC, ratchet ceiling `rootPackageCeiling = 201` (`package_growth_guard_test.go:312`). Phase 2 of the decomposition plan (`docs/design/package-decomposition-plan.md`) is **COMPLETE** through W5 (2026-07-30), leaving 34 FAT-deferred files (~4.7k LOC) and 61 reasoned INTEGRATOR verdicts. This audit builds on that plan; overlaps are marked ⟳, new findings ★.

**Tooling used:** `golang.org/x/tools/cmd/deadcode` (whole-program, from `cmd/api`, run both with and without `-test` reachability), golangci-lint v2.12.2 `dupl` (150-token threshold, the CI docker image per `scripts/ci-backend-guard.sh`), targeted grep/perl counts. Every file:line below was verified against the tree.

## Top-20 findings (ranked by LOC-saved × risk-inverse)

### 1. ★ Delete the `store/` and `transport/` scaffold packages — 126 LOC, zero risk
`store/store.go` (45 LOC, "The scaffold ships with in-memory stubs…") and `transport/*.go` (81 LOC: `transport.go`, `grpc.go`, `http.go`, `snmp.go`, `ssh.go`) have **zero importers** (`grep -rl 'netops/backend/store"'` / `'netops/backend/transport"'` → nothing) and every function is unreachable **even with tests** (deadcode `-test`). They are day-one scaffolding superseded by `internal/platformdb` and the injected `verify.Dialers`/collector transports. *Fix: `git rm -r store transport`.* **Save: 126 LOC + 2 packages.**

### 2. ★ `portintel`'s analysis half is dormant — ~630 LOC prod-dead (owner decision)
The store/taxonomy half is live (`port_handlers.go:49,140,169,214` uses `PortFilter`/`ListPorts`/`TaxonomyReference`/`SignatureCatalog`), but the entire optical-module detection/scoring engine has **no production caller**: `portintel/module.go` (263 LOC — `Detect`, `normalizeFamily`, `mediaFor`, …), `portintel/score.go` (232 LOC — `Score`, `laneDivergenceDebit`, `stateFor`), `portintel/threshold.go:35` (`DefaultPolicy`, 56 LOC), `portintel/topics.go:22` (`AllTopics`, 24 LOC), and all five `Validate` payload methods in `portintel/domain.go:222–275` (~60 LOC; `CoherentPMPayload.Validate` is dead even with tests). Nothing outside the package calls `portintel.Detect`/`Score`. Same shape as the segclass finding the plan recorded at step 16: a built engine whose ingest wiring never landed. *Fix: owner decides wire-or-retire; if retired also drop `score_test.go`/half of `portintel_test.go` (~150 test LOC).* **Save: ~630 LOC (+~150 test).**

### 3. ⟳ Retire or wire `internal/segclass` — ~908 LOC (plan step 16 already flagged it)
`internal/segclass/classifier.go` (705 LOC) + `classifier_test.go` (203) + the `segmentdata/` go:embed snapshot: deadcode confirms **every** function from `newSegmentClassifier` (classifier.go:355) down is prod-unreachable; only `package_growth_guard_test.go` imports the package. The plan's ✅16 row already says "the classifier has ZERO production consumers in Go … worth deciding whether the ingest-side stamping is still planned or the mirror should be retired". Decision is still pending — this is now the single largest dead block in the tree. **Save: ~908 LOC + embedded CIDR data.**

### 4. ★ Finish (or abandon) the `authorize` migration — ~200 LOC of repeated auth prologue
`server.authorize` (`authz.go:73`) is nolint-annotated *"migration target — handlers still use requirePerm"* and is unreachable **even with tests**. Meanwhile the exact 5-line prologue `claims, ok := s.requirePerm(w,r,…); if !ok { return }; tenant, cross := principalTenant(claims)` appears verbatim **68 times** (perl multiline count; 180 total `requirePerm` call sites — hotspots `ticketing_http.go` ×11, `nms_http.go` ×10, `services.go` ×9, `port_handlers.go` ×7). Migrating handlers to `authorize` collapses 5 lines → 2 per site, revives the centralized 404-vs-403 existence-hiding rule (§3a), and deletes the dead func + two nolint pragmas. *Fix: mechanical per-handler migration, one bounded context at a time (§7).* **Save: ~200 LOC net; risk moderate (auth-path churn, well-tested).**

### 5. ★ dupl clone groups (150-token bar) — 12 production groups, ~330 LOC involved
Verified non-test clones (golangci `dupl`, CI image):
- `auth_config.go:67-96` ≡ `auth_config.go:299-327` and `:146-170` ≡ `:396-420` — the LDAP vs TACACS sealed-config store `load`/`persist` pair (~55 LOC dup). Same-file consolidation via a small generic sealed-kv-config helper.
- `collectors/cdp.go:70-123` ≡ `collectors/lldp.go:127-183` — the neighbor-poll `pollOnce` harness (~54 LOC). Shared in-package poll runner.
- `notify_config.go:282-321` ≡ `:459-498` ≡ `:539-578` — a **triple** (~80 LOC dup) — this is exactly the plan's Wave-3 note "notify_config … plus ~250 thinnable via a generic handler" ⟳.
- `itsm_config.go:106-137` ≡ `:141-172` (~32), `wireless_http.go:17-48` ≡ `:51-82` (list-or-get handler pair, ~32), `internal/ticketing/store.go:587-615` ≡ `:696-721` (~28), `pathgraph/store.go:464-488` ≡ `:515-539` (~25), `appid.go:71-106` ≡ `services.go:143-178` (GET/DELETE resource handler, ~36), `notify/jira.go:436-461` ≡ `notify/servicenow.go:430-455` (~26).
Plus 9 clone groups in `_test.go` files. *Fix: consolidate within package where a real seam exists; leave cross-package handler clones to finding 4's helper.* **Save: ~160 LOC net.**

### 6. ★ `notify/jira.go` + `notify/servicenow.go` are structurally parallel — ~970 LOC pair
Beyond the dupl hit: both (478 / 491 LOC) independently implement the open-ticket dedup map, `saveLocked` state persistence with the F-62/F-78 write-failure accounting, `stateWriteFailures`/`lastStateErr` counters, and retry shaping (`grep -l stateWriteFailures notify/` → exactly these two). A shared stateful-ticket-notifier core inside `notify/` (same package — no §2 issue) is a genuine consolidation. **Save: est. 150–250 LOC; risk moderate (delivery-path behavior must be pinned by the existing suites).**

### 7. ★ Truly dead functions (deadcode `-test`: unreachable even from tests) — ~200 LOC beyond findings 1–3
33 functions total; excluding store/transport/segclass/portintel already counted: `chhttp/chhttp.go:219,225,237,246,291` (`Committed`, `OutcomeOf`, `QueryIDOf`, `ClassificationOf`, `Code` — ~45 LOC of error-taxonomy accessors nothing consumes) and `chhttp.go:718 ExecWithRetry` (prod-dead); `ai/orchestrator.go:1632 SortedModuleIDs`; `ai/registry.go:305 EnabledModules`; `appid/adapter/adapter.go:152 NamespaceVendorID`; `cloudconn/capability.go:83 AllPacks`; `cloudconn/connection.go:132 ParseLifecycleState`; `collectors/bgpls.go:1184 FetchTopologyNodes`; `internal/platformdb/kv.go:60 Active`; `internal/rbac/scopes.go:33 ScopeResource`; `internal/tacacs/tacacs.go:93 Client.Host` (+ `:137 tacacsHeader` prod-dead); `internal/tenant/router.go:50 isolationImplemented`, `:72 SharedRouter.BackendFor`; `wireless/identity.go:163 ClientEntityID`. *Fix: delete; each is compiler-verifiable.* **Save: ~200 LOC, near-zero risk.**

### 8. ★ Phase-2 extraction residue in root — ~10 orphaned wrappers, ~90 LOC
Prod-unreachable wrappers left behind by the RA/W moves, now called only by tests (or nothing): `account_policy.go:30 evaluateAccountPolicy` + `:38 pushPasswordHistory` (RA.2 shims over `secpolicy`), `security_settings.go:28 defaultSecuritySettings`, `oidc.go:258 newOIDCProvider`, `tacacs_wiring.go:18 newTACACS`, `identity_ids.go:62 isTenantID` / `:67 isOrgID`, `region_router.go:114 tenantDataPlane`, `path_metric_resolver.go:189 ResolvedPathMetric.Tier` / `:291 resolvedSources`, `binding_sync.go:133 bindingDerivedScope` (the self-described "Phase A conformance bridge / seed of the Phase-B union decider" — Phase B shipped as `internal/rbac/access.go` in W4.15, so the bridge is a supersession candidate; plan's INTEGRATOR note "~35-LOC pure pair could join rbac later" ⟳). *Fix: delete or fold into their tests.* **Save: ~90 LOC.**

### 9. ★ Prod-dead exported surface in `appid`/`cloud` — ~320 LOC, owner-gated
Whole files with no production caller: `appid/replay.go` (48 LOC — `ReplayFusion`, `codeContains`), `appid/rca_emit.go` (73 LOC — `EmitRCAEvidence`, `AnalyzeSeamImpact`), plus `appid/fusion.go:191 BuildExplanation`, `appid/explain.go:60 ExplanationCodes`, `appid/identity.go:26,43` (`ConfidenceBand.rank`, `BandFor`). In `cloud/`: `resolve.go:147 Resolve` + `:207 sourceTrust` (the documented tag>graph>domain>ip precedence resolver — ~110 LOC with helpers), `topology.go:73 LoadTopologies`, `provider.go:72 NewFixtureProvider`. These look like built-ahead pipeline stages (like portintel/segclass) — the RCA-emit and identity-fusion lanes may be planned wiring. *Fix: owner triage wire-vs-delete per lane.* **Save: up to ~320 LOC.**

### 10. ★ Dormant `wireless` identity/edge derivations — ~150 LOC, **hold** (do not delete without owner)
`wireless/edges.go:41-118` (`Edge.Authoritative`, `tunnelsToController`, `DeriveEdges`, `HasEdge`) and `wireless/identity.go:57-174` (`IsRandomizedMAC`, `MemberID`, `SessionID`, entity-ID minters) are prod-unreachable. Wireless Phase 9 is ON HOLD by owner decision (2026-07-27), so these are dormant-by-decision, not junk — record, don't touch.

### 11. ★ Test-only doubles living in production files — ~250 LOC (hygiene, not deletion)
`cloudconn/store.go:116-249` — the entire `MemStore` (~140 LOC) is prod-unreachable because the durable-only selector forbids RAM-only credential storage; it exists solely for tests. Similarly `ai/llm.go:29 MockLLM.Complete`, the four `New*AdapterWithClient` ctors (`internal/ticketing/adapter_jira.go:55`, `adapter_pagerduty.go:52`, `adapter_servicenow.go:118`, `adapter_slack.go:44`), `cloudconn/identityprovider.go:181-201` (`NewAdapterWithExchanger`, `NewAWSAdapter`, `NewAzureAdapter`, `NewGCPAdapter`), and ~10 `*ForTest` hooks (deliberate idiom — keep). *Fix (optional): move `cloudconn.MemStore` to an `export_test.go`-style file so the prod binary stops carrying it; the `*ForTest` hooks stay per the plan's idiom.* **Save: ~140 LOC from the shipped binary.**

### 12. ★ Misc prod-unreachable functions — ~250 LOC, quick kills after a per-item check
`integration/ordering.go:50 Order` + `:80 Dedup` (~60 — the §4a ordering pair; check the reconciler didn't lose its caller in W44), `internal/verify/modules.go:612 verifyModuleNames`, `nms/run_integration.go:38 RunPoll` (superseded by `nms/scheduler.go` from W4.17), `notify/delivery.go:287 statsSnapshot`, `collectors/poller.go:295 tcpProbe` + `:388 MetricsPushStats`, `collectors/ingest_auth.go:90 IngestAuthConfigured` + `:134 IngestRejections`, `collectors/dom_adapters.go:173 openconfigTransceiverMetric`, `collectors/oidindex.go:50 oidIndexVersion`, `internal/rca/rca_report.go:177 evidenceAccounting`, `internal/rca/rca_report_wording.go:398 rcaLaneWindowCoverage`, `ai/goldenset.go:64,77` (`Category`, `LoadGoldenSet`), `ai/kb.go:88,91` (`KB.All/Get`), `ai/product_kb.go:113 ProductKB.All`, `internal/sealedfields/sealedfields.go:123,128` (`NewProvider`, `NewEngine`), `internal/vault/dormant.go:15-27`, `safego/safego.go:86 Recover`, `internal/loginguard/throttle.go:88`, `cloudconn/registry.go:126 Descriptor`, `processors/managed.go:286,288`, `pathgraph/store.go:141 NewMemStore`, `internal/discovery/snmp_source.go:93`. **Save: ~250 LOC.**

### 13. ⟳ The 34 FAT-deferred files — ~4.7k LOC already dispositioned by the plan
The Phase-2 re-audit's "FAT — lift deferred (extract opportunistically when touched)" list (plan lines 351-367: `path_graph_api`, `topology_view`, `snmp_profiles`+seed, `path_metric_resolver`, `cloud_console`, `fusion_worker`, `system_backup`, …) sums to ~4.7k LOC. Nothing new to add — findings 2/3/9 are *retirement* candidates, which is cheaper than extraction. This audit's only amendment: `path_metric_resolver.go` (finding 8) has two dead members to drop *before* any lift.

### 14. ★ Go 1.25 `min`/`max` builtins — 8 hand-rolled comparators, ~35 LOC
Replaceable by builtins: `topology_path_ifmetrics.go:143 maxf`, `reports/dataset.go:45 maxf`, `appid/verdict.go:296 minF`, `timeintel/calculator.go:208 minConf`, `internal/rca/rca_report.go:1748 maxInt`. **Not** replaceable: `internal/rca/rca_coverage.go:869 maxTime` / `:876 minTime` (`time.Time` isn't `cmp.Ordered`). *Fix: delete funcs, use builtins at call sites.* **Save: ~35 LOC, zero risk.**

### 15. ★ `slices`/`maps` adoption is near-zero — ~70-150 LOC of idiom shrink
Only 3 non-test files import `"slices"`, zero import `"maps"`. 72 `sort.Strings` sites (many the 3-line append-keys+sort idiom → `slices.Sorted(maps.Keys(m))`, 1 line), 138 `sort.Slice` + 38 `sort.SliceStable` sites → `slices.SortFunc`/`SortStableFunc` (type-safe, ~1 line saved each). Hand-rolled `contains` helpers replaceable by `slices.Contains`: `copilot.go:292 slicesContains`, `ai/policy.go:114 contains`, `appid/replay.go:41 codeContains` (dead anyway). *Fix: opportunistic only — do it when a file is already being touched (the plan's "extract opportunistically" discipline); a blanket sweep is churn.* **Save: ~70-150 LOC.**

### 16. ★ `strings.Cut` — 8 exact `SplitN(…, 2)` sites + a subset of 22 `strings.Index` sites
`auth.go:25` (XFF first-hop), `stack_health.go:88`, `internal/noclabel/labels.go:47`, `internal/seam/bootstrap_rules.go:381`, `region_router.go:67`, `wireless_actions.go:155`, `incidents_http.go:201`, `integrations_http.go:191`. Clarity win, ~0 LOC. Opportunistic only.

### 17. ★ `sync.OnceValue` — 2-3 sites
`report_preview_http.go:21` (`previewOnce` + `previewHTML`/`previewXLSX` pair → `sync.OnceValues`) and `collectors/ingest_auth.go:40` (`ingestOnce`+`ingestCred`). ~10 LOC, trivial.

### 18. ★ `log/slog`: assessed — **do not migrate**
`internal/applog` is 74 LOC, pinned by tests, already emits structured JSON (§10 satisfied), and has 93-file fan-in through the root wrappers (`logInfo`/`logWarn`/`logError`). slog would add zero capability (no levels/handlers we need beyond what exists), touch ~100 files, and risk log-contract drift with Vector's applog pipeline (the dotted-key gotcha in CLAUDE.md). The honest verdict: churn, not modernization.

### 19. ★ The measured cost of the no-utils rule — ~70 duplicated helper defs, ~350 LOC (recommend: keep)
Full census of deliberately duplicated micro-helpers (non-test defs): `normTenant` ×17 (e.g. `topology/store.go:45`, `cloud/store.go:197`, `internal/users/pg.go:59`…), `firstNonEmpty` ×9 (+`firstNonEmptyStr` ×2, `firstNonBlank` ×1), `randHex` ×8, `newUUIDv4` ×5, `sameTenant` ×4 + `sameTenantStrict` ×3, `orDefault` ×4, `envOr` ×4/`envInt` ×3/`envDuration` ×3, `sleepCtx` ×3, `slugify` ×3, `asString` ×3/`asFloat` ×3, `isUniqueViolation` ×2, `shortID` ×2, `intQuery` ×2, `isUUIDToken` ×2. This is the priced-in cost of §2's no-utils-package rule and the plan's "duplicate the few lines" doctrine; ~350 LOC across 60+ packages, each copy trivially verifiable. The only defensible consolidation would be `normTenant` into `internal/tenant` (domain-owned, not a utils dump) — but it adds an import edge from every store to the tenant package for a 3-line function. **Recommendation: leave as-is; record the number so it stays a decision, not an accident.**

### 20. ★ Weight watch: `ai/orchestrator.go` (1,639 LOC) is the largest un-dispositioned business-logic file
Top-10 files: `main.go` 2,551 (entrypoint wiring — DoD-compliant), `internal/rca/rca_report.go` 1,891, **`ai/orchestrator.go` 1,639**, `internal/rca/rca_report_wording.go` 1,461, `collectors/bgpls.go` 1,337, `collectors/snmptrap.go` 1,139, `auth.go` 1,131, `cloud_connectors_handlers.go` 1,029 (INTEGRATOR ⟳), `internal/ldap/ldap.go` 1,002, `cloud/rollup.go` 991. Top packages: root 50.1k/201 files, `internal/rca` 11.2k, `collectors` 10.5k, `ai` 7.0k, `cloud` 6.4k, `cloudconn` 6.1k. The plan explicitly scoped out `ai/` ("already subpackages — not part of this work"), so the orchestrator's growth has no owner; it also hosts a dead func (finding 7). No generated code exists anywhere (`sqlc` from the §6 allowlist is unused — all SQL is hand-written). *Fix: file-level split within `ai/` when next touched; no new package needed.*

## Summary table — estimated removable/consolidatable LOC

| Dimension | Zero-risk (compiler-verifiable) | Owner-gated (wire-or-retire) | Opportunistic (churn-bounded) |
|---|---|---|---|
| B. Dead/unnecessary | store+transport 126 · truly-dead funcs ~200 · root residue ~90 · misc prod-dead ~250 ≈ **~670** | portintel ~630 (+150 test) · segclass ~908 · appid/cloud lanes ~320 · wireless ~150 (HOLD) ≈ **~2,000** | cloudconn MemStore relocation ~140 |
| A. Duplication | dupl groups ~160 | notify jira/servicenow core 150–250 · notify_config generic handler ~250 ⟳ | authorize migration ~200 · cdp/lldp harness ~50 · helper census ~350 (recommend keep) |
| C. Weight | — | — | plan's 34 FAT-deferred ~4,700 ⟳ · ai/orchestrator split (move, not delete) |
| D. Modernization | min/max ~35 · OnceValue ~10 | — | slices/maps ~70–150 · strings.Cut ~0 · slog: **rejected** |
| **Totals** | **~875 LOC** | **~2,650 LOC** | **~600 LOC** (excl. the plan's own 4.7k) |

**Net new opportunity beyond the existing plan: ~3.5–4.1k LOC**, of which ~875 is deletable immediately with only the compiler and existing suites as evidence.

## Overlap map with the Phase-2 decomposition plan

| This audit | Plan reference | Relationship |
|---|---|---|
| #3 segclass retirement | ✅ step 16 ⚠️ note | Plan raised the question 2026-07-27; still undecided — this audit re-confirms zero consumers and adds the LOC total |
| #5 notify_config triple clone | Wave 3 row "notify_config … ~250 thinnable via a generic handler" | Same finding, now with dupl line-range evidence |
| #8 binding_sync bridge | INTEGRATOR list "binding_sync (Phase-A mirror; ~35-LOC pure pair could join rbac later)" | Audit upgrades it: the bridge func is now prod-unreachable → retire rather than lift |
| #13 FAT-deferred ~4.7k | Phase-2 re-audit FAT list (plan lines 351-367) | Fully covered by plan; no duplication here |
| #4 authorize migration | authz.go's own nolint comment (RA.1 residue) | Plan moved the policy core; the handler migration it anticipated never started |
| #19 helper duplication | "duplicated helpers per the no-utils rule" (sequencing invariants) | Audit prices the standing cost (~350 LOC); recommends keeping the policy |

**Caveats:** deadcode's whole-program analysis is sound here because the repo forbids reflection (§5) and has a single entrypoint (`cmd/api`); its one blind spot would be symbols reached only via `go:linkname`/plugins, of which there are none. All "owner-gated" items follow the plan's own precedent (segclass): built-ahead engines may be awaiting wiring — verify intent before deleting. No dependency additions are proposed anywhere in this report; every fix is stdlib or intra-package.

---

# PART 2 — Frontend report (verbatim)

**Scope:** `src/frontend` — read-only; no files changed (analysis uses the fresh `dist/` from 2026-08-02 19:10, which post-dates all `src/` edits).

## Baseline

| Metric | Value |
|---|---|
| Initial JS chunk `dist/assets/index-CF7-z7vW.js` | **4.6 MB raw / 1,388 KB gzip** |
| Lazy chunks (only 2 + geojson) | SigmaTopologyView 182 KB, GeoTopologyMap 5 KB, world-geo 170 KB |
| CSS `index-D_QOMw_O.css` | 336 KB raw / 58 KB gzip |
| Fonts emitted to dist | **1.5 MB, 99 files** (5 families) |
| Static brand images in dist | 1.4 MB (`dist/brand-samples/` 1.0 MB unused) |
| Runtime deps | 19 |
| Source | ~66,400 non-test LOC + ~12,000 test LOC |

The app is a single eagerly-loaded bundle: `src/nav.tsx:5-66` statically imports every page (~50 views), so ELK, ECharts, xterm, and React Flow all land in the initial chunk (verified in the bundle: `org.eclipse.elk` ×343, `echarts`/`zrender` markers, `xterm-` ×73, `react-flow__` ×52 occurrences in `index-CF7-z7vW.js`).

## Top findings (ranked by savings × risk-inverse)

**1. No route-level code splitting — every page eagerly imported (≈3 MB+ off initial load, low risk).**
Evidence: `src/nav.tsx:5-66` imports all pages/tabs statically, including `TopologyCanvas` (line 26 — pulls @xyflow ~400 KB min + elkjs + 3.5 k LOC of mock topologies), `MetricsExplorer`/`Flows` (ECharts), and `tabs/admin.tsx` (3,977 LOC). Only 2 `lazy()` calls exist in the whole app (`TopologyCanvas.tsx:77,80`).
Fix: wrap `NavLeaf.render` targets in `React.lazy` + one `<Suspense>` in App.tsx — mechanical, the hash-router already remounts per route.

**2. elkjs (1.6 MB) statically bundled into the main chunk (~1.4 MB, near-zero risk).**
Evidence: `src/features/topology/layout/elkLayout.ts:7` and `src/pages/appobs/ServiceMap.tsx:26` both do `import ELK from "elkjs/lib/elk.bundled.js"` (file is 1,607,470 B); `org.eclipse.elk` appears 343× in the shipped index chunk.
Fix: `const ELK = (await import("elkjs/lib/elk.bundled.js")).default` inside the async layout functions (both call sites are already async layout paths); optionally elk-worker.

**3. Full ECharts (1.1 MB min) bundled untree-shaken via `echarts-for-react` (~600 KB raw / ~200 KB gz, medium-low risk).**
Evidence: `node_modules/echarts-for-react/lib/index.js` does `require("echarts")` (whole package, `echarts.min.js` = 1,121,883 B); 9 non-test files import the default wrapper (`src/pages/panels.tsx:10`, `src/tabs/MetricsExplorer.tsx:2`, `src/tabs/Flows.tsx:2`, `src/pages/DeviceGeomap.tsx:2`, etc.). Two files already use `echarts/core` (`GeoTopologyMap.tsx:18`) — the tree-shakeable path is proven in-tree.
Fix: a ~40-line function-component wrapper around `echarts/core` + only the used renderers/charts (also retires the class-based, tslib-dragging `echarts-for-react` dep — the modernization win).

**4. xterm.js (290 KB) in the initial bundle for a page most users never open (low risk).**
Evidence: `src/pages/DeviceTerminal.tsx:2-4` statically imported by `src/pages/Devices.tsx:6`; `xterm-` ×73 in index chunk; backend gates this behind opt-in `FEATURE_DEVICE_SSH` (dormant by default per CLAUDE.md).
Fix: `lazy(() => import("./DeviceTerminal"))` in Devices.tsx (or covered by #1).

**5. 1.0 MB of rejected brand-sample PNGs shipped in every deploy (zero risk).**
Evidence: `public/brand-samples/` (blogo1–5, 1.0 MB) → copied verbatim to `dist/brand-samples/`; **zero references** anywhere in `src/` or `index.html` (grep: no hits). Only `blogo5*.png` + `eye-hero.webp` under `public/brand/` are used (`TopBar.tsx:159-160`, `Login.tsx:11`, `index.html:15`).
Fix: delete `public/brand-samples/`.

**6. Five font families / 99 dist font files, one unused, one redundant (~1.0 MB artifact, ~100–200 KB wire, low risk).**
Evidence: `@fontsource-variable/geist` in `package.json` but **never imported** (only a dead `"Geist"` name in the CSS stack at `styles.css:190,194` — unloaded, falls through to Inter). `main.tsx:4-17` loads Inter ×4 weights (960 KB dist), Space Grotesk ×3 (252 KB), IBM Plex Mono ×2 (224 KB), Manrope Variable (84 KB). Manrope is the primary face only in the v2 shell (`styles.css:544`); Inter serves the legacy v1 shell + fallback.
Fix: uninstall geist now; drop Inter (or trim to 400/600) when v1 shell retires (finding 10); fontsource `/latin.css` subset imports would also cut emitted files sharply.

**7. Dead components: ~1,100 LOC with zero non-test importers (zero risk, verified individually).**
- `src/components/BrandMark.tsx` — 447 LOC, orphan
- `src/pages/DeviceDetail.tsx` — 186 LOC, superseded by `DeviceDetailPage.tsx` (which Devices.tsx uses)
- `src/components/RevealSealedValue.tsx` — 143 LOC (sealed-fields UI exists live in `ProcessorsAdmin.tsx`/`SensitiveDataAccess.tsx`)
- `src/components/brand/CorrelixLogo.tsx` — 126 LOC (+ its test); favicon is now an inline data-URI in `index.html:13`
- `src/components/MfaCard.tsx` — 115 LOC, orphan even though backend MFA is live (`src/backend/auth.go`) — it's unwired UI, and it is the **sole consumer of `qrcode.react`** → removing it removes a dependency
- `src/components/graph/FlowEdge.tsx` — 79 LOC (only a comment mentions it, `shapes.tsx:20`)
- `src/components/NotificationCenter.tsx` — 6-LOC placeholder returning null
Fix: delete all seven + associated tests; uninstall `qrcode.react`.

**8. Unused / misplaced dependencies (hygiene, zero bundle risk).**
`@fontsource-variable/geist` (see 6); `graphology-types` in **runtime deps** though never imported — types-only peer of graphology, belongs in devDependencies; `jsdom` (dev) unused — `vitest.config.ts` sets `environment: "happy-dom"` and Playwright doesn't need it (~6 MB node_modules). Fix: one package.json edit.

**9. Marketing demo page shipped to all users (724 LOC + eager ECharts usage, low risk).**
Evidence: `src/nav.tsx:123-125` — "Marketing demo board" leaf renders `DemoShowcase` (190 LOC) + `demoPanels.tsx` (534 LOC) with no `platformOnly` gate. Fix: gate it `platformOnly` or make it the first lazy route.

**10. Two complete app shells maintained in parallel (duplication + the Inter font dependency).**
Evidence: `src/App.tsx:94-108` — v2 shell default-ON since the sticky opt-out (`localStorage "shellV2"`); v1 path keeps `TopBar` user-menu mode, `Sidebar`, `SubNav` alive alongside v2's `IconRail`/`NavFlyout`, and forces dual font families (finding 6). Fix (product decision): retire v1, delete the `shellV2` branch and v1-only components/CSS.

**11. 22 files still hand-roll `<table>` despite a shared `DataTable` (consistency + LOC).**
Evidence: 59 raw `<table` sites across 22 non-test files (`tabs/admin.tsx`, `tabs/Rules.tsx`, `pages/Reports.tsx`, `pages/Wireless.tsx`, …) while `components/DataTable.tsx` is already used by 31 files. Fix: migrate opportunistically per-page; est. 400–800 LOC over time.

**12. ~10 bespoke drawer/modal implementations beside the shared primitives.**
Evidence: local `Drawer`/`*Modal` components in `PortsWorkbench.tsx:81`, `Reports.tsx:690,707`, `ProcessorsAdmin.tsx:503`, `NmsIntegrations.tsx:548`, `AppObservability.tsx:837,1356,1391`, etc., while `components/ui.tsx` (Modal), `BottomDrawer.tsx`, and `appobs/badges.tsx:269` (EvidenceDrawer) exist. Fix: converge on Modal/EvidenceDrawer; est. 200–400 LOC.

**13. Copy-pasted micro-helpers.**
Evidence: `fmtBytes` ×2 (`components/board/panels.tsx:17`, `tabs/Flows.tsx:21`), duration formatters ×3 (`reliabilityMeta.ts:6`, `RcaReports.tsx:22`, `appobs/impact.ts:25`), `fmtWhen` ×2 (`RcaVerifyPanel.tsx:25`, `RcaTicketCard.tsx:19` — despite `lib/time.ts`), SVG sparkline ×4 (`WanCircuits.tsx:33`, `FrontPage.tsx:64`, `panels.tsx:826`, `NmsVendorArt.tsx:116`), Badge/Pill ×3. Fix: fold into `lib/` + `components/ui.tsx`; ~150–250 LOC.

**14. 3.5 k LOC of mock topology data eagerly bundled.**
Evidence: `src/features/topology/mock/` (physicalTopology 980 LOC, cloudTopology 568, …, 3,516 total) imported statically by `TopologyCanvas.tsx:73` and all workflows — rides into the initial chunk today. Fix: falls out of finding 1's topology split; or `await import("../mock")` inside `topologyApi.ts`.

**15. Monolith files hurt both maintainability and splitting granularity.**
Evidence: `services/api.ts` 4,169 LOC (single flat client — good discipline: only 3 stray `fetch()` sites outside it, and `appobs/api.ts` is a mapping layer, not a duplicate client); `tabs/admin.tsx` 3,977 LOC exporting 9 admin views that all load together. Fix: split `admin.tsx` per view before lazy-routing it; api.ts split is optional (types-only churn risk).

**Strategic note (no quick fix):** three topology renderers coexist — React Flow (eager), Sigma+graphology+forceatlas2 (lazy, 182 KB chunk — correctly done), and ECharts-geo. Consolidation is a product decision, not a cleanup.

**What's already good:** no router/UI-kit/moment-style deps (hand-rolled hash routing, own Icon set); Sigma and geo maps already lazy; world geojson split; sourcemaps disabled for ship (#97); modern function components throughout (1 `React.FC`, no classes, no `defaultProps`); fetch centralization.

## Estimated total savings

| Dimension | Current | After fixes 1–6 | Saving |
|---|---|---|---|
| Initial JS (raw) | 4.6 MB | ~1.2–1.5 MB | **~3.1–3.4 MB** |
| Initial JS (gzip) | 1,388 KB | ~400–500 KB | **~900 KB** |
| Dist artifact (images+fonts) | ~2.9 MB | ~0.8 MB | **~2.1 MB** |
| Source LOC (dead+demo+dedupe, findings 7,9,13) | 66.4 k | — | **~2,200 LOC** (plus 400–1,200 more from 11–12 over time) |
| Runtime deps | 19 | 15 | −4 (geist, graphology-types→dev, qrcode.react, echarts-for-react) |

Highest-leverage single change: finding 1 (lazy routes in `nav.tsx`) — it alone strands elk/echarts/xterm/xyflow/mocks out of the critical path; findings 2–4 then make those chunks small rather than merely deferred.

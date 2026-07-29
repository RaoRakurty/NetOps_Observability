# `package main` decomposition — the executable plan

**Status:** fifty-three domains shipped (`internal/chschema`, `internal/openapi`,
`internal/totp`, `internal/rca` waves 1+2, `internal/vault`, `internal/vuln` +
`internal/compliance`, `internal/ratelimit`, `internal/metricval`,
`internal/noclabel`, `internal/ticketing`, `internal/gqlparse`,
`internal/verify`, `internal/segclass`, `internal/seam`, all 2026-07-27;
`internal/token`, `internal/session`, `internal/jwks`, `internal/apikey`,
`internal/tenant` (+ `tenant.Collection`), `internal/snmpcred`,
`ai/toolwire`, `wireless/store`, `nms/store`, `ticketing/store`,
`pathgraph/store`, `token/password`, `internal/users`, `tenant/org`,
`cloud/store`, `ticketing` adapters, `policy/store`, `cloudconn/store`,
`pathgraph/health`, `cloud/bizsvc`, `internal/loginguard`,
`appid/appstore`, `timeintel/store`, `internal/incident`,
`internal/discovery` (+ devstore), `reports` pg stores, `integration`
pg stores, `internal/saved`, `ai/evidence_language`, `topology/store`, `ai/feedback_store`,
`ticketing/worker`, `internal/selfheal`, `cloudconn/broker`, `internal/audit`, `internal/platformdb`, 2026-07-28;
`internal/applog`, `timeintel/derive`, `audit/retention`, 2026-07-29).
**204** non-test files remain in `package main`. This document is the ordered sequence for the
rest.

**Why this exists:** CLAUDE.md §2 mandates `/cmd /internal /pkg /api /plugins
/config` and forbids business logic in the entrypoint package. ~98k LOC of it
lives there. In one package the compiler cannot enforce a boundary, so §13 (no
cross-domain imports) and §4 (plugin isolation) are *unenforceable*, not merely
unenforced. It is also the substrate that hid the guard-scope bug: when "the
package" is "the whole product", a root-only scan looks complete.

**PROGRAM STATE (revised 2026-07-29, after the Phase-2 measurement): Phase 1
(the store/library extraction sequence, steps 18–59) is COMPLETE — but the
2026-07-28 claim that the extractable surface was exhausted is WRONG.** A
four-reader audit of all 35 files ≥500 LOC plus a 20-file sample of the 88
mid-tier files (200–500 LOC) found **~23k LOC of genuine business logic still
in the root** (~35% of its 64.7k LOC): protocol implementations (`ldap.go` is a
950-LOC BER/LDAP client), pure algorithm files (`rca_path_view.go` is 97%
pure), SQL-builder clusters, config stores with rollback semantics, and worker
state machines. The sized, ordered Phase 2 sequence is at the bottom of this
document (§ Phase 2). What is TRUE from the earlier verdict: fifty-three
domains are behind compiler-enforced boundaries, the storage substrate is
`internal/platformdb`, and `main.go`/`auth.go`/the `*_handlers.go` shape are
already Definition-of-Done-compliant integrators.

**Nothing is exposed by this today.** It is deferred by owner decision and
sequenced behind live-risk work. Growth is ratcheted
(`TestFlatPackageMainDoesNotGrow`) so it cannot get worse while it waits.

---

## The finding that shapes the whole plan

The intra-package dependency graph was reconstructed (it is invisible to
`go list`, because every reference inside one package is a bare name):

- **Zero of the 296 files had zero fan-in.** Every file is referenced by at
  least one other. There is no free leaf to pluck.
- 78 files have exactly one caller; the distribution then thins out slowly.

So "move a file" is never the unit of work. **The unit is a domain**, chosen by
*low fan-out* (it can move cleanly) plus a real conceptual boundary — not by
smallest-file-first, which just relocates coupling.

### The screen that actually predicts a clean extraction (added after step 2)

Fan-in alone is **not** sufficient — it ranked `geomap.go` as an easy win, and
the move exposed nine leaks straight into the auth/tenancy core. The reliable
signal is whether a file is LIBRARY code or HANDLER code:

    grep -c 'func (s \*server)'                      # handler methods
    grep -cE 'jwtClaims|principalTenant|visibleDevices|requirePerm|http.ResponseWriter'

A file with **zero of both** is library code and moves cleanly. A file dominated
by `*server` methods is entrypoint code that should STAY — extract its pure core
instead and leave a thin handler behind (`internal/openapi` is the worked
example: the document builder moved, `handleOpenAPI` stayed as four lines).

**Measured on the tree: 113 of 289 files (39%) are pure library code by that
screen.** That is the real extractable surface, and it is where the remaining
steps should be drawn from. `wan_circuits.go` (11 handler methods) and
`geomap.go` are NOT in it, despite low fan-in — both were listed above on the
weaker criterion and are struck below.

## The method, proven on step 1

1. **Measure.** Recompute the graph (`scripts/…/pkgmap.py` idiom: symbol →
   defining file, then file → referenced files). Pick a domain whose members
   have low fan-out and, ideally, one non-test caller.
2. **`git mv`**, so history follows. Rename detection must show the moves.
3. **Let the compiler enumerate the coupling.** Every `undefined:` is a real
   dependency that was invisible before. Resolve each *on its merits*:
   - pure helpers that belong to the domain → move them in;
   - a hand-rolled utility with a stdlib equivalent → use the stdlib;
   - a tiny generic helper → duplicate the few lines. **Do not create a shared
     `utils` package — §2 forbids it outright.**
   - anything requiring config → pass it in, or let the package own knobs that
     are genuinely its own.
4. **Split tests by what they assert.** Pure-unit assertions move with the code;
   assertions about the *relationship* between the code and its integrator stay
   with the integrator. Step 1 split three boot-convergence tests back to
   `package main` this way and lost no coverage.
5. **Watch for relative paths.** Tests reaching repo files via `../../` break
   silently at a new depth. Resolve the root by walking up for a marker.
6. **Lower the ratchet** in the same commit, appending to its migration log.
7. **Verify:** `go build ./...`, `go vet ./...`, `gofmt -l`, `golangci-lint run
   ./...` (0 issues), the full backend suite, and every guard.

## Ordered sequence

Ordered by `max fan-in` within the domain — the number of files that must gain
an import — so each step is as cheap as it can be. LOC is indicative.

| # | Domain | Files | LOC | Max fan-in | Notes |
|---|---|---|---|---|---|
| ✅ 1 | `internal/chschema` | 6 | ~730 | 1 | **Done.** Surfaced a duplicated 8 MiB response cap. |
| ✅ 2 | `internal/openapi` | 1 | 126 | 1 | **Done.** Pure `Spec(version)`; handler stayed in main. |
| ✅ 3 | `internal/totp` | 1 | 89 | 1 | **Done.** Zero coupling — the cleanest move so far. |
| ✗ — | `internal/geo`, `internal/wan` | — | — | — | **Rejected on inspection.** Low fan-in but handler-dominated (`wan_circuits.go` has 11 `*server` methods; `geomap.go` leaked 9 symbols into auth/tenancy). Kept here as the worked example of why the fan-in-only screen was wrong. |
| ✅ 2 | `internal/chsql` (`chISO` + query fragments) | 1 | 23 | 21 | **Done** (2026-07-27) — folded into `chschema.ISO` as the row suggested (no sibling package). 21 call sites gained the qualifier; the wire-format contract doc moved with it; `TestNoZonelessDatetimeToStringInSQL` now walks subpackages recursively (with an anti-vacuity floor) so moved SQL stays guarded. |
| ✅ 3 | `internal/compliance` + `internal/vuln` **together** | 2 | ~1090 | 1 | **Done** (2026-07-27). Moved as a pair; the seam kept `vuln.Entry` (compliance imports vuln), and the `SNMPCredential` coupling was resolved the *other* way: compliance got its own `SNMPProfile` input type carrying only identity + crypto parameters, so secrets (community/keys) can no longer cross the boundary. Thin `vulns_http.go` / `compliance_http.go` handlers stayed in main. |
| ✅ — | `internal/rca` (5 pure analysis files) | 5 | — | — | **Done** (2026-07-27, drawn from the 13+ pool). |
| ✅ — | `internal/vault` (secret custody) | 1 | — | — | **Done** (2026-07-27). Storage + warn logging INJECTED (`vault.Store`, `vault.Warnf`) — the wiring adapter idiom later steps reuse. |
| 4 | `internal/openapi` | 1 | 126 | 1 | Trivial; good warm-up for a new contributor. |
| ✅ 7 | `portintel` (extend existing) | 1 | 487 | 2 | **Done** (2026-07-27). `port_store.go` → `portintel/store.go`; the pg plumbing is INJECTED (`portintel.DB` wraps `withTenant`), backend selection + handlers stayed in main. `port_handlers.go` is handler-dominated and stays per the screen. Root count 283 → 282. |
| ✗ 8 | `internal/svc` | 3 | 725 | 2 | **Rejected on inspection** (2026-07-27, the geo/wan precedent). All three files carry `*server` methods + auth/audit plumbing, and their dependencies fan into domains that are NOT moving: services catalog (`Service`, `svcSelectorSet`, `buildSelectorCondition`), health scoring (`aggregateHealthScore`), CH plumbing (`chRows*`), tenancy (`addrTenantClauseFor`). The pure core is 4 small already-unit-tested functions — extracting them would cost 6+ injection seams for no real boundary. Revisit only after the services-catalog domain itself moves (13+ tier). |
| ✗ 9 | `internal/breakglass` | 1 | 198 | 3 | **Rejected on inspection** (2026-07-27). 4 `*server` methods; the non-handler half (`hasBreakGlass`, `effectiveRestrictedIDs`) is PBAC-core logic over `RoleBinding`/`s.bindings`/`scopeAncestorOrSelf`/`s.tenants` — it moves WITH the auth/tenancy tier (13+), not before it. Pure core is a 5-line predicate; nothing to extract on its own. |
| ½✅ 11 | `internal/export` → **`internal/ratelimit`** | 1 | 90 | 6 | **Split on inspection** (2026-07-27). `export_ratelimit.go` was never export-specific — it also limits verify + copilot — so it shipped as `internal/ratelimit` (callers now pass their per-minute budget; the env read left the package; the white-box F-33 tests moved in). `export_policy.go` is REJECTED: its mechanism is literally "push knobs into the process env for main's readers" + a handler — inseparable from the composition root by design. |
| ½✅ 12 | `internal/metrics` → **`internal/metricval`** | 1 | 69 | 7 | **Split on inspection** (2026-07-27). Only `metric_float.go` (the F-21 parse boundary) passed the screen; it shipped as `internal/metricval` (Parse/FiniteOrZero/Sanitize, counter read-only via `NonFinite()`). `metrics_query.go` (4 handlers, the PromQL scope-injection) and `metrics_forecast.go` (handler + tenant scoping around 2 pure fns) are handler-dominated and STAY. |
| ✅ 11 | `internal/noclabel` | 1 | 200 | ~15 | **Done** (2026-07-27). Executed as the first wave-2 seam pre-step: `ai_labels.go` moved whole (passed the screen; deps = regexp+strings only) and `kindNoc` joined it from `events_feed.go` — same domain, the server-side mirror of the frontend label library. Injection would have meant four func-valued fields on the report input for what is a freestanding display-language domain. |
| ✅ 12 | `internal/ticketing` | 2+1 type | ~600 | ~14 | **Done** (2026-07-27). Second wave-2 seam pre-step: `ticketing_model.go` + `ticketing_policy.go` whole, `corrTicketFacts` per-symbol out of `ticketing_payload.go`. The payload BUILDERS stayed — they read `rcaPathView` (not moving). The DAG is payload→ticketing, payload→rca, rca→ticketing: no cycle. |
| ✅ 13 | `internal/rca` **wave 2** (the report/analysis family) | 13 | ~8300 | high (internal to the family) | **Done** (2026-07-27) — but as **ONE commit, not the predicted 2–3**: the executed AST map showed the family is a single strongly-connected component (`rca_report.go` depends on all 12 others, everything depends back on it, plus a `wording ↔ html` cycle), so no staged move could compile. The feared shared-type seam (`Incident`/`Service`/`Region`/`Confidence`) was **entirely ident-shadowing false positives** (composite-literal field names) — the compiler needed none of them; likewise `first`/`merge` were never real deps. Per-symbol moves from stayers: integrity block + `ComputeReportIntegrity` (register/HTTP stayed), promotion model + pure `EvaluatePromotion` (store/handlers stayed), `FriendlyReasons`/`IsValidationSignal` (path-view handler stayed). `Report.ownerTenant` stays unexported (structurally unserializable) behind `SetOwnerTenant`/`OwnerTenant` accessors. 20 pure test files moved with fixtures + snapshots; endpoint/store/HTTP assertions were shuttled back. The move surfaced and fixed a latent register bug: `Quality.EvaluatedAt` escaped snapshot normalization, so identical re-renders straddling a second boundary minted spurious revisions. **Known residue:** minute-scale elapsed-display strings (at-a-glance "last", management summary) also escape normalization on ACTIVE cases — pre-existing, documented-intent gap, deliberately not widened into this change. |
| ✅ 14 | `internal/gqlparse` | 1 | 581 | 1 | **Done** (2026-07-27). The F-72 GraphQL subset parser: ZERO real external deps (the 2026-07-27 re-measure of all 263 root files ranked it cleanest), one consumer (`graphql.go`, which kept the handler + RBAC gate). Parser-contract tests moved; handler/isolation tests stayed; the F-72 source guard now pins `gqlparse.Parse`. |
| ✅ 15 | `internal/verify` | 2 | ~1250 | ~4 | **Done** (2026-07-27). The Active Verification engine + prebuilt modules (closed command tables, deterministic parsers). `Dialers` was already an injected seam, so the SSH runner (`verify_ssh.go`, TOFU host store), service, trigger and HTTP stayed cleanly. Helper knob-readers duplicated per the no-utils rule. The `User` "dependency" was a struct-field false positive. Test split: engine/modules/parser contracts moved; the fake-SSH transport + TOFU tests and boundedBuf overflow (SILENT-CRITICAL-1's runner half) stayed with the integrator. |
| ✅ 16 | `internal/segclass` | 1 | 697 | **0** | **Done** (2026-07-27). The Go mirror of the Python segment/device classifier, with its go:embed'd provider-CIDR snapshot (`segmentdata/` moved with it; `scripts/refresh_provider_ranges.py` re-pointed and dry-run-verified). Every mapped seam (`tierRank`, `Region`, `Service`, `Confidence`) was a field-name false positive; only `orDefault` was real (duplicated). ⚠️ **Finding for the owner: the classifier has ZERO production consumers in Go** — only its own test references it. The file says it stamps segment/role at ingest; that wiring either never landed or lives Python-side only. Worth deciding whether the ingest-side stamping is still planned or the mirror should be retired. |
| ✅ 17 | `internal/seam` | 1 | 640 | ~5 | **Done** (2026-07-27). The canonical seam inventory (five FINAL types, lifecycle state machine, validation, deterministic ids) + its pg store, with `seam.DB` INJECTED via the portintel adapter idiom — the store moved WITH its SQL, main kept backend selection, handlers and the bootstrap suggestion rules. Watch for handler locals named `seam` shadowing the package (two renamed). Pure lifecycle/validation/id tests moved; rule tests stayed. |
| ✅ — | `internal/token` (the `jwt` security change) | 1 | ~130 | 94 (via alias) | **Done** (2026-07-28) — see the formerly-deferred item below for the full record. |
| ✅ 18 | `internal/session` | 2 | ~720 | ~6 | **Done** (2026-07-28), first of the ungated auth tier. `session_store.go` + `refresh.go` (both 0-handler/0-authref by the screen) moved whole; kv persistence + error logging INJECTED (`session.KV`, `session.Errorf` — the vault idiom, wired in `session_wiring.go`); env reads (`SESSIONS_FILE`, `REFRESH_FILE`, `refreshTokenTTL`) stayed in main. `randHex` re-homed to `audit.go` for its 14 root users (package keeps its own copy per the no-utils rule). Test split: the CONC-HIGH-1 concurrency suite, refresh rotation/reuse contract and the store lifecycle unit test moved in — losing the process-global `withBackend`/`withFailingKV` swaps for real injection; HTTP-boundary suites (flow, logout/F-70, account-policy) stayed and use two documented test hooks (`RewindForTest`, `SetKVForTest`) where they used to poke unexported fields. `Status*`/`MaxSessionsPerUser` exported; `TTL()` accessor added for the token-policy live-update assertion. |
| ✅ 19 | `internal/jwks` | 1 | ~300 | 2 | **Done** (2026-07-28). OIDC discovery + JWKS-based RS256 verification (pure stdlib — the reason federation lives in Keycloak). `Cache`/`Claims`/`Discovery` exported; the `OIDC_JWKS_TTL_MIN` env read moved to `oidc.go` (TTL injected, ratelimit precedent); main's token exchange got its own `http.Client` instead of borrowing the cache's unexported one. `Refresh()`/`KeyCount()` exported as real surface (pre-warm/probe — the live Duende test uses them); the hermetic SSO tests seed discovery via `SeedDiscoveryForTest`. `TestRoleFromScopes` shuttled back to `apikeys_test.go` — it was API-key logic co-located in the jwks test file. |
| ✅ 20 | `internal/apikey` | 1 | ~460 | ~6 | **Done** (2026-07-28). The scoped tenant-bound API-key store: hash-only custody, RFC 7591 metadata validation, fixed-window per-key limiter, the multi-writer/Reload multi-instance semantics. Kv INJECTED via the now-shared `platformKV` adapter (renamed from `kvSessionKV`); `APIKEY_RATE_LIMIT_PER_MIN` + the `TenantGlobal` ownership default moved to the composition root (`NewStore(path, limit, defaultTenant, kv)`). `roleFromScopes` STAYED (moved to `auth.go`) — it maps scopes onto main's Role constants, and its test went with it. `Get(id)` and `SetMultiWriter` exported (cred_cache_reload used to reach into `mu`/`multiWriter` directly). Store-contract tests moved in. |
| ✅ 21 | `internal/tenant` | 2 | ~520 | ~75 (via alias) | **Done** (2026-07-28). The tenant model, store and isolation-mode router. Cross-domain inputs INJECTED as `tenant.Deps` (kv via `platformKV`, `DefaultOrg`, id-mint + slug rules from `identity_ids.go`, region validation from `regions.go`) — main keeps a `newTenantStore(path)` wrapper so the ~10 constructor sites didn't change, and `tenant_wiring.go` aliases (`Tenant`, `tenantRepo`, `TenantGlobal`, isolation consts) keep the 75-file fan-in source-compatible — the jwtClaims technique. `status()` → `EffectiveStatus()`, `restrictedIDs()` → `RestrictedIDs()`; `orgOf` stayed in main (`orgs.go`, it bridges to the org domain) with the same rule internal to the store against the injected default. F-81 fault injection now uses `SetKVForTest` instead of assigning the unexported `path`. `tenantkv.go` deliberately NOT taken — separate step. |
| ✅ 22 | `tenantkv.go` → `tenant.Collection[T]` | 1 | ~150 | 3 | **Done** (2026-07-28). The §3a default-closed per-tenant collection primitive joined `internal/tenant` (same bounded context — the tenant-isolation storage plane). Kv injected; a GENERIC alias `type tenantKV[T any] = tenant.Collection[T]` + wrapper in `tenant_wiring.go` kept the three consumers (sites, device sites, WAN policies) call-shape identical. `Path()` accessor replaced a white-box `.kv.path` reach in sites_test. |
| ✅ 23 | `internal/snmpcred` | 1 | ~380 | 4 | **Done** (2026-07-28). SNMP credential profiles (v1/v2c/v3 USM): model, redacting `Public()` projection, validation, and the vault-enveloped store (encrypt-at-rest copies; in-memory stays plaintext for `Resolve`). Kv INJECTED; `internal/vault` imported directly (already a package, no cycle); `slugify` duplicated from rbac.go per the no-utils rule; `reload` → `Reload`. Four consumer files qualified directly — fan-in too small to justify aliases. Store-contract tests moved; vault-integration + tenancy + sentinel tests stayed with the integrator. |
| ✅ 24 | `copilot_tools.go` → `ai/toolwire.go` | 1 | ~320 | 3 | **Done** (2026-07-28). The per-provider (OpenAI/Anthropic/Gemini) tool-calling wire codecs joined the `ai/` subpackage whose `ToolSpec`/`ToolCall`/`ToolReply` shapes they encode — `AgentTurn` + `CallTools` exported, transport INJECTED as `ai.DoFunc` (main's `providerDo` keeps timeout/retry/redaction policy). The §15 LLM04 output cap hoisted to `ai.MaxOutputTokens` so no provider body can be built without it (was `maxCopilotOutputTokens` in copilot.go). Wire-format fixture tests moved with the codecs. |
| ✅ 25 | `wireless_store.go` → `wireless/store.go` | 1 | ~730 | 3 | **Done** (2026-07-28). The first BIG STORE gets the portintel treatment: the canonical wireless inventory store (mem + FORCE-RLS pg backends over `wireless.Controller/AccessPoint/WLAN/BSSID`) joins its domain package. Pg plumbing INJECTED via `wireless.DB`; main's `portintelPG` adapter GENERALIZED to `rlsPG` — one adapter now serves every extracted RLS seam. The data-column encoder contract test moved in. |
| ✅ 26 | `nms_store.go` → `nms/store.go` | 1 | ~760 | 4 | **Done** (2026-07-28). The NMS integration store (config + run records + external states + health rollup; mem + FORCE-RLS pg; vault-enveloped credentials) joins its connector package. `DB` seam injected via `rlsPG`; the F-76 durability marker exported (`ErrStorageNotDurable`, `NewNonDurableStore`, `StoreDurable`); `Key` exported (the scheduler's bookkeeping shares the composite key). Store contract tests moved in; `TestNMSSchedulerDue` shuttled back (the runtime is integrator code). |
| ✅ 27 | `ticketing_store.go` → `internal/ticketing/store.go` | 1 | ~930 | ~10 | **Done** (2026-07-28). The ticketing repository (policies with the single-enabled invariant, links, leased outbox, ring-buffered audit; mem + FORCE-RLS pg) joins the model/policy package. `DB` seam via `rlsPG`; backend selection stayed in `main.go`; `ErrPolicyConflict` + paging bounds (`MaxPage`, `*DefaultPage`) exported; `orDefault` STAYED in main with its many non-ticketing consumers (package keeps its own copy); `intToString` → stdlib `strconv.Itoa` on the way through. Pagination (F-66/F-67) + ring-buffer (F-33) contract tests moved in; drift-seeding http tests use `SeedPolicyForTest` instead of writing the map. |
| ✅ 28 | `path_graph_store.go` → `pathgraph/store.go` | 1 | ~830 | ~8 | **Done** (2026-07-28). The last big store: endpoint/definition registries + observation/hop streams over the mem (per-tenant retention/eviction) and pg+ClickHouse hybrid backends. `DB` via `rlsPG`; a NEW `pathgraph.CH` seam (`InsertJSON`/`Select`/`Exec`) adapted by main's `chSeam{}` — Exec keeps the no-CH-configured→no-op purge semantics in main. Ingest-boundary validators exported (`IsPathToken`, `IsAddressToken`, `ScopeFor`, `CHTime`, `LiveOnly`); eviction logging injected via `SetInfof`; decode helpers (`str`/`parseCHTime`/`asFloat`-via-metricval) duplicated per the no-utils rule. Retention white-box suite moved in. |
| ✅ 29 | `password.go` → `internal/token/password.go` | 1 | ~115 | ~10 | **Done** (2026-07-28). The PBKDF2-SHA256 KDF (hash/verify/needs-rehash + the SR-013 `MaxPasswordLen` amplification bound) consolidated into the auth-crypto boundary; `password.go` DISSOLVED — its only other content, the `jwtClaims` alias, moved to `auth.go`. Password POLICY (length rules, history, account predicates) stayed in main. KDF contract tests moved; policy tests shuttled back. |
| ✅ 30 | `internal/users` | 2 | ~1040 | ~59 (via alias) | **Done** (2026-07-28). The identity store — file + per-row FORCE-RLS pg backends, the last-super-admin floor (shared pure helpers so the backends can't drift), federated JIT provisioning, MFA/lifecycle fields. Cross-domain inputs INJECTED as `users.Deps`: kv, `Errorf`, the SR-025 `GuardRole` (env-read stays in main), `IsSuperAdmin`, account_policy's `ApplyPasswordChange`, `DefaultTenant`, `MaxUsers`. `User`/`usersRepo` aliased in `users_wiring.go` (the jwtClaims technique); `sameTenant`/`normTenant`/`isUniqueViolation` duplicated at the boundary per the no-utils rule (business_service_store keeps its own unique-violation copy). Backdating tests use `MutateForTest`; cap tests set `Deps.MaxUsers` instead of poking the field; store CRUD/seed suites moved in with local `testDeps()`. |
| ✅ 31 | `orgs.go` → `internal/tenant/org.go` | 1 | ~270 | ~8 | **Done** (2026-07-28). The Org layer (top-level customer boundary: SSO connection, home region, note) joins the tenant bounded context — §3a: org isolation is DERIVED from tenant isolation. `tenant.Deps` extended with the org-store inputs (`MintOrgID`, `NormalizeRegion`, `DefaultRegion`, checked by `NewOrgStore` only); `Org`/`orgUpdate`/`OrgGlobal` aliased in `tenant_wiring.go`; `orgOf` kept on main's side (tenancy.go). |
| ✅ 32 | `cloud_store.go` + `cloud_store_pg.go` → `cloud/` | 2 | ~750 | ~8 | **Done** (2026-07-28). The Cloud App Observability inventory store pair (resources + identity mappings + provenance; server-side filter + keyset pagination) joins the `cloud` package that owns its types. `DB` seam via `rlsPG`; the paging surface exported (`PageDefault`/`PageMax`/`ListHardCap`, `ErrBadCursor`, `FilterValues`, cursor codecs); backend selector stayed in `main.go`; the family-match contract test moved in; white-box mem literals in two main tests replaced by `NewMemStore()`. |
| ✅ 33 | The four ITSM adapters → `internal/ticketing/adapter_*.go` | 4 | ~1550 | ~14 | **Done** (2026-07-28). ServiceNow, Jira, PagerDuty and Slack wire adapters join the ticketing package with the shared `Adapter`/`SystemConfig`/`Ref`/`RemoteIncident` types, the #103 delivery-error taxonomy (`PermanentDeliveryError`, `RateLimitedError`) and `DedupeKey`/`Truncate` — adapters produce the classifications the worker consumes, so they live together. Worker, sweeper, inbound, http and itsm-config (with its `systemConfig` resolver) STAYED. `NewXAdapterWithClient` constructors added so integrator tests inject their httptest clients; adapter wire-contract test files moved in; worker/sweeper/policy-resolution tests shuttled back with duplicated fixtures (test files cannot cross packages). |
| ✅ 34 | `policy_store.go` → `policy/store.go` | 1 | ~420 | 4 | **Done** (2026-07-28). The #24 security-policy document store (scope-chain resolution over the builtin catalog, hardening-only override validation) joins the `policy` engine package. Kv + error sink INJECTED (`policy.KV`, errlog func; nil-kv is a wiring-time panic like MustCompile); main's tests stayed as integration through the wiring. |
| ✅ 35 | `cloud_connectors_store.go` + `_pg.go` → `cloudconn/` | 2 | ~500 | ~10 | **Done** (2026-07-28). The connector-credential repository (draft→active lifecycle, optimistic versioning, vault-backed `SecretRef`) joins the `cloudconn` package that owns Provider/Scope/IdentityConfig. Mem + FORCE-RLS pg via the `DB` seam; `ConnectorIDPrefix`/`SecretRefIDPrefix`/`ErrVersionConflict` exported; the durable-storage-required selector (credentials must never live only in RAM) stayed in `main.go`. |
| ✅ 36 | `path_health.go` → `pathgraph/health.go` | 1 | ~390 | 3 | **Done** (2026-07-28). The pure Path Behavior Health scoring core (severity curves, weighted blend with the anti-averaging floor, health bands including the unknown-not-healthy rule, confidence rules, the baseline-source cascade + readiness gates, NOC evidence strings) joins `pathgraph`. Zero I/O — enums/candidates/scorers exported; the VM-percentile fetcher and `/api/paths/health` handler stayed in main. §12 acceptance suite + the unknown-band regression tests moved in. |
| ✅ 37 | `business_service_store.go` → `cloud/bizsvc_store.go` | 1 | ~260 | 3 | **Done** (2026-07-28). The Business Service Observability pg store (services + resource mappings, owner stamped from the principal) joins the cloud domain its mappings resolve against. `DB` seam via `rlsPG`; `ErrNotFound`/`ErrConflict` + `MappingsByResource` exported; `newUUIDv4` duplicated; the pg-only selector (nil on file backend → handlers 503) stayed in `main.go`. |
| ✅ 59 | `audit_retention.go` → `internal/audit/retention.go` | 1 | ~120 | 2 | **Done** (2026-07-29). The F-57 retention half joins the audit store it bounds: the opt-in, OFF-by-default hourly sweeper (WHERE-bounded on ts, 10k-row batch cap — deliberately NOT the platformdb saveRows path, whose unbounded `DELETE FROM` would truncate the whole cross-tenant trail). `TxRunner` seam satisfied by `platformdb.DB.WithTenant` directly; the `AUDIT_RETENTION_DAYS` env read stays in main via `ParseRetentionDays` (typo → retention stays OFF, never "delete everything"); main gates the start on `ActivePG()` (the file backend self-bounds). `SweepRetention` exported for the pg integration test; parse/no-op suite moved in. Ceiling 205 → 204. |
| ✅ 58 | `timeintel_derive.go` → `timeintel/derive.go` | 1 | ~430 | 4 | **Done** (2026-07-29). The pure lifecycle derivation (`CorrTimeFacts` + `ITSMTimeFacts` → `timeintel.Lifecycle`, source-attributed stamps) joins the package whose types it produces. Four root consumers qualify directly; the `*server` method `itsmTimeFacts` renamed `itsmFactsFor` so it no longer shadows the now-exported type. Derive suite moved with it. Ceiling 206 → 205. |
| ✅ 57 | `logs.go` core → `internal/applog` | ½ | ~75 | ~93 (via wrappers) | **Done** (2026-07-29). The process-wide structured JSON logger behind `logInfo`/`logWarn`/`logError` (93 root files fan in) moves behind a boundary so extractions can IMPORT it instead of injecting ad-hoc warn sinks (retention, above, is the first consumer). Root keeps the historical names as one-line wrappers; caller-fields-win merge pinned by package tests; `SwapWriterForTest` replaces unexported-field poking. Count unchanged (logs.go remains as the wrapper file). |
| ✅ 56 | **INFRASTRUCTURE FINALE pt 1**: `db.go` + `pgstore.go` + `kvstore.go` + `migrations/` → `internal/platformdb` | 3+dir | ~840 | everything | **Done** (2026-07-28). The storage substrate every extracted seam adapts onto is now ONE package: the kv `Backend` contract + `FileKV`, the per-row FORCE-RLS `PGStore` (rowSpec registry, legacy file-state import), and the `DB` pool (RLS-capability assertion, embedded migrations + advisory-locked apply, exported `WithTenant`/`Close`). Main keeps `initStoreBackend` (the env switch → `UseFile`/`UsePostgres`) and `platformKV`; the 24 backend selectors now go through `ActivePG()`; **the `rlsPG` adapter is DELETED** — `DB.WithTenant` satisfies every package's DB seam directly. Loggers injected once via `SetLoggers`; PG_* pool knobs stay package-owned per the plan's knob rule. `SwapBackendForTest`/`BeginForTest` hooks replace global pokes; `MigrationsFS` exported for the two migration-reading tests; `provisionAppRole` fixture duplicated. **Pt 2 verdict (same day): NOT A MOVE.** `clickhouse_client.go` is, by its own header, "the main package's adapter onto the chhttp seam" — env-credential wiring over the already-extracted `chhttp` transport package; `backend_client.go` is the mTLS transport wiring fed by the CA bootstrap. Both are exactly what the Definition of Done says main SHOULD consist of. The infrastructure tier is COMPLETE. |
| ½✅ 55 | `clickhouse_policies.go` DDL → `chschema/policies.go` | ½ | ~100 | 4 | **Done** (2026-07-28). `RowPolicyDDL` + `ConvergeStmts(extra ...[]string)` join the schema package; the ensure/retry loop and env stay in main, composing domain-owned DDL (cloud costs, path baselines) INTO the converge set — dependency inverted rather than reached across. Count unchanged. |
| ✅ 54 | `audit_pg.go` + audit.go's store core → `internal/audit` | 1½ | ~330 | ~6 | **Done** (2026-07-28). The audit-trail storage: `Event`/`Query`/`Repo`, the bounded in-memory file ring, and the per-row FORCE-RLS pg trail with the F-73 (errors never read as "no privileged actions") and F-57 (true Count makes growth observable) contracts. Kv/DB/errf injected; the capture chokepoint (`withAudit`), org-scoped merge reads, and handlers STAYED in `audit.go` (openapi split pattern); `normTenant` re-homed to main for its ~40 users. |
| ✅ 53 | `cloud_connectors_broker.go` + `_metrics.go` → `cloudconn/` | 2 | ~495 | ~10 | **Done** (2026-07-28). The Identity Broker — the ONLY component that decrypts connector secrets — joins its store and adapters: the (tenant, connector)-isolated scoped-token cache, secret custody via the envelope Vault, and the exchange metrics. The audit sink is injected as a NEUTRAL `AuditFn` (main adapts onto its `AuditEvent`); `AdapterFor`/`SetAdapter`/`Metrics` exported; the cache-isolation white-box suite + metrics tests moved in; the fake adapter + connector fixtures duplicated for main's ingest/isolation/live suites. |
| ✅ 52 | `self_heal.go` → `internal/selfheal` | 1 | ~270 | 2 | **Done** (2026-07-28). The ingest self-healer (disk-pressure watermark with hysteresis, OpenSearch read-only-block detection/clear, deterministic disk injection for tests, operator paging via the platform notify lane). Env reads + the mTLS-aware HTTP client + log sinks injected via `selfheal.Config`; `Run`/`CurrentSnapshot` exported for the worker start and `/api/stack/health`. |
| ✅ 51 | `ticketing_worker.go` → `internal/ticketing/worker.go` | 1 | ~475 | ~8 | **Done** (2026-07-28). The outbox worker joins its store + adapters: claim → resolve → dispatch with the #103 error classification (permanent → dead-letter, Retry-After honored), backoff+jitter, the tenant-mismatch delivery refusal, link upserts and audit entries. Log sinks injected; `Tick`/`RegisterAdapter`/`SetMaxRetries` exported (tests drove unexported internals before). Sweeper/inbound/HTTP stayed (they hold `srv`); `canonicalCorrTenant` + `randID` duplicated at the boundary. |
| ½✅ 50 | `appid_fusion_store.go` split → `appid/fusion_store.go` | 1 | ~160 | 4 | **Done** (2026-07-28), the metricval-style split: the appid-specific observation/identity batch builders (deterministic-id idempotent inserts, tier codes) moved behind an `appid.CHWorker` seam; the worker-scope CH plumbing (`chWorkerExec`/`chWorkerQuery` — shared by the fusion, timeintel-backfill and svc-rollup workers) STAYED in main with `jsonEachRow` re-homed for its remaining user. Root count unchanged (the plumbing file remains). |
| ✅ 49 | `ai_feedback_store.go` → `ai/feedback_store.go` | 1 | ~156 | 3 | **Done** (2026-07-28). Copilot answer feedback (per-tenant up/down rows + aggregation; mem + FORCE-RLS pg) joins `ai`; `FeedbackDB` seam via `rlsPG`; selector stayed in `main.go`; contract tests moved. |
| ✅ 48 | `topology_store.go` → `topology/store.go` | 1 | ~165 | 3 | **Done** (2026-07-28). The graph-records store (mem + FORCE-RLS pg) joins `topology`; `DB` seam via `rlsPG`; selector stayed in `main.go`. |
| ✅ 47 | `ai_evidence_language.go` → `ai/evidence_language.go` | 1 | ~260 | 2 | **Done** (2026-07-28). The ranking-contract renderer (frozen `scoring.py` hypotheses blob → cited `ai.EvidenceItem`s with NOC modality/controller language) plus `TopHypothesisVoice` (operator phrase + confidence label) join the `ai` package whose types they produce. `firstNonBlank`/`shortID` duplicated — shortID's dash-prefix branch initially missed and caught on review (citation-id stability). Full fixture suite moved with it. |
| ✅ 46 | `saved.go` + `saved_pg.go` → `internal/saved` | 2 | ~370 | ~11 | **Done** (2026-07-28). The saved-objects store (dashboards/report specs; file + FORCE-RLS pg). Kv/DB/errf INJECTED; backend selection stayed in `main.go`; `SavedObject` → `saved.Object` via direct qualification; `randID` re-homed to `audit.go` — at its TRUE 16-byte width (a first shim mistakenly halved it; caught on review before commit). |
| ✅ 45 | `device_persist.go` → `internal/discovery/devstore.go` | 1 | ~240 | 3 | **Done** (2026-07-28). The manual-device + F-69 tombstone store joins the aggregator it backs (the earlier adapter shims dissolved — the exported methods ARE the store surface now). Kv + errf INJECTED; `Unreadable()` exported (the three-state boot contract: absent ≠ corrupt ≠ loaded — writes refused while unreadable so deletes can't resurrect); `DEVICES_STORE_PATH` env read moved to main. Persistence + corrupt-store suites updated in place. |
| ✅ 44 | `integration_repo_pg.go` + `config_pg.go` + `timeline.go` → `integration/` | 3 | ~490 | ~6 | **Done** (2026-07-28). The #43 ITSM-sync repository joins its provider package: mapping rows with ordering watermarks (§4a), vault-enveloped webhook secrets, per-provider configs (`MappingEngineFor` exported — was an unexported method), and the merged per-incident timeline (now consuming `incident.Event` across the two extracted domains). `DB` seam via `rlsPG`. Reconciler/handlers/sync worker stayed. |
| ✅ 43 | The three reports pg stores → `reports/` | 3 | ~550 | 3 | **Done** (2026-07-28). `report_jobs_pg.go` (durable queue: FOR UPDATE SKIP LOCKED claims, visibility-timeout leases, dead-lettering), `report_executions_pg.go` (immutable executions + phase timings) and `report_deliveries_pg.go` (per-destination delivery records, `DeliveryRecorder`) join the `reports` package whose `JobQueue`/`ExecutionStore` interfaces they implement. `DB` seam via `rlsPG`; `ErrLeaseLost` exported; helpers duplicated. The pipeline/scheduler/workers (`report_pipeline.go` — rejected, holds `srv`) stay in main and consume the exported surface. |
| ✅ 42 | `discovery.go` → `internal/discovery` | 1 | ~815 | ~20 | **Done** (2026-07-28). The device-discovery domain: the §4 plugin CONTRACT (`DiscoverySource`), the aggregator (identity merge/dedupe, F-69 delete-suppression, vendor enrich, health stats), `StaticSource` (hand-rolled YAML subset) and `NetboxSource` (paginated pull with same-host guard). `DeviceStore` seam INJECTED (main's deviceStore gains adapter methods) — with a nil-interface guard where the old code leaned on a nil-pointer-receiver-tolerant method (found by a failing test, fixed before commit); `NetboxConfig` + direction doctrine moved (main aliases; store/handlers stayed); warn sink injected into NetboxSource; `PollOnceForTest` replaces test poking. Dedup + direction suites moved in; `fakeSource` fixture duplicated. ⚠️ Screen note: `report_pipeline.go` REJECTED same day — it holds `srv *server` (77 refs); the `func (s *server)` grep misses `p.srv` shapes, so read the file, not just the counters. |
| ✅ 41 | `incidents.go` + `incidents_pg.go` → `internal/incident` | 2 | ~690 | ~14 | **Done** (2026-07-28). The incident domain: model, severity/status lifecycle rules (validated transitions, terminal states), dedup-key derivation, auto-ticket policy, and the FORCE-RLS pg repository (Ingest-dedup, true-total Count, ITSM sync/notify marks). `DB` seam via `rlsPG`; the lifecycle surface exported (`Status*`, `ValidTransition`, `DisplayID`, `DedupKeyFor`, `ClampLimit`, `ErrNotFound`/`ErrBadTransition`); aliases + the pg-only selector hosted in `incidents_http.go` (the port_handlers idiom). filterSQL contract tests moved in; handler/paging suites stayed. |
| ✅ 40 | `timeintel_store.go` → `timeintel/store.go` | 1 | ~180 | 4 | **Done** (2026-07-28). The incident timeline store (guarded events keyed tenant+corr; mem + FORCE-RLS pg) joins `timeintel`; `DB` seam via `rlsPG`; selector stayed in `main.go`. |
| ✅ 39 | `appid_store.go` → `appid/appstore.go` | 1 | ~240 | 4 | **Done** (2026-07-28). The Application catalog store (mem + FORCE-RLS pg) joins the `appid` package; `DB` seam via `rlsPG`; `ValidateApplicationInput` + backend constructors exported; the selector stayed in `main.go`. ⚠️ Lesson recorded: a rename sweep briefly leaked into six SUBPACKAGES that use the word `Application` — caught by the compiler, reverted via git before commit; future sweeps must exclude every package dir, not just internal/. |
| ✅ 38 | `login_throttle.go` → `internal/loginguard` | 1 | ~250 | 4 | **Done** (2026-07-28) — the auth tier's last store-like piece. The F-25 account-lockout throttle (fail-closed saturation, spray-eviction under the cap, janitor sweep) moves whole; the warning sink is injected; the observability counters are exported as accessors (`Evictions`/`Sweeps`/`Saturations`) so `/metrics` keeps reading them; `NewThrottleWithLimits` provides the cap/clock injection the failure-path tests need. Pure white-box suite moved in; server-integration halves stayed. |
| ✗ — | `tls_ca.go` | 1 | 195 | — | **Rejected on inspection** (2026-07-28). Passes the grep screen but is bootstrap WIRING: env-driven CA bootstrap (`TLS_INTERNAL_CA`, cert/key file overrides), provisioning-from-env and the reissue loop are process-lifecycle code interleaved with the custody core. Extracting the custody half would leave both sides thinner than the seam. Revisit only if a second consumer of the CA custody appears. |
| — | **PHASE ASSESSMENT (2026-07-28, after step 55):** the store/library surface is EXHAUSTED. What remains in the root falls into exactly three classes: (1) **the infrastructure finale** — `db.go`, `pgstore.go`, `kvstore.go`, `clickhouse_client.go`, `backend_client.go`: the kv/RLS/CH/mTLS plumbing every extracted package's seams (`platformKV`, `rlsPG`, `chSeam`, `CHWorker`) adapt onto. Moving it relocates every adapter + selector at once — do it as ONE dedicated, carefully-designed step (`internal/platformdb` + `internal/chclient`), nothing else in flight. (2) **worker/orchestration loops that hold `srv` or compose many domains** (report pipeline/scheduler, nms_scheduler, cloud monitor eval, sweeper, reconciler, appid/ngfw refresh caches) — integrator code by the same verdict as report_pipeline; the appid/ngfw caches could ride along with the CH-client move. (3) **handlers + wiring** (~190 files) — the legitimate entrypoint layer; per the Definition of Done they SHRINK (thin wrappers over extracted packages) rather than move. | — | — | 4–10 | The big stores (`ticketing_store`, `path_graph_store`, `nms_store`, `wireless_store`) pass the auth screen but need the portintel-style pg-injection treatment. The auth tier is now UNGATED: the `jwt` security change shipped as `internal/token` (below). |

## Deferred deliberately, with reasons

**`jwt` / `token` (auth crypto).** ✅ **Done** (2026-07-28) as `internal/token`,
exactly per the deferral note: `jwtClaims` (94 consumer files) stayed source-
compatible via `type jwtClaims = token.Claims`; `signJWT`/`verifyJWT`/`errJWT`
became `token.Sign`/`token.Verify`/`token.ErrInvalid` (8 call sites qualified);
the stale-commented `hasScope` (it was in fact live in auth/mfa/cloud-ingest)
became `Claims.HasScope`. The security core: `actingTenant` had to become the
exported `ActingTenant`, so its unmarshal-immunity was re-established as
`json:"-"` and PINNED by `TestCraftedTokenCannotSetActingTenant` (a correctly
HMAC-signed token carrying every key spelling must verify with the field empty
— mutation-checked: removing the tag fails the test) plus
`TestSignDoesNotEmitActingTenant` (the override never leaks into a minted
token). Watch-fors that materialized: two `token` locals in `auth.go` shadowed
the new package (the seam-step gotcha; renamed `access`/`bearer`), and
`jwks_test.go` kept a local `b64url` for RS256 test-minting. Password hashing
stayed in `password.go` — it is not token crypto.

**Anything under `alerts/`, `notify/`, `collectors/`, `nms/`, `ai/`.** Already
subpackages. Not part of this work.

## Definition of done

`package main` contains entrypoint wiring only — `newServer`, route
registration, worker startup, shutdown — and the ratchet's ceiling reflects it.
At that point §13 and §4 become enforceable by the compiler, and standing gap #8
in `docs/audit/INVARIANTS.md` can close.

---

## Phase 2 — the measured follow-on (audited 2026-07-29)

Four parallel readers audited every root file ≥500 LOC (all 35, in full) and a
20-of-88 sample of the 200–500 LOC tier. Verdicts per file: THIN (already a
DoD-compliant wrapper), FAT (real extractable core), INTEGRATOR (legitimately
stays, may shed a little). Result:

| tier | files | LOC | verdict mix | extractable |
|---|---|---|---|---|
| ≥500 LOC (read in full) | 35 | ~24.5k | 29 FAT · 3 THIN · 3 INTEGRATOR | **~12.4k LOC** |
| 200–500 LOC (20 sampled + mechanical bucketing) | 88 | ~27.5k | ~75% FAT · ~10% THIN · ~15% INTEGRATOR | **~10–12k code LOC** |
| <200 LOC (unaudited) | 81 | ~12.7k | presumed mostly thin | small |
| **total root** | **204** | **64.7k** | | **~23k LOC** |

The THIN exemplars prove the target shape exists: `auth.go`, `identity_handlers.go`,
`nms_http.go`, `port_handlers.go`, `seam_handlers.go` — wrappers over extracted
packages. The FAT majority is three recurring shapes: tenant-keyed config/stores
with rollback semantics, bounded worker loops (budget/backoff/checkpoint), and
SQL-builder + fold + validator clusters.

### Cross-cutting enablers (do these FIRST — they unpin everything else)

1. **`chquery`** — consolidate the shared ClickHouse read path (`chQuery`,
   `chQueryCtx`, `chSelect`, `chRows`/`chRowsScope`, `proxyClickHouse`,
   `chTenantScope`, `chClientFor`, `chWorkerBudget`) scattered across
   report_scheduler.go / correlations.go / flows.go. Unblocks
   report_scheduler, cloud_signals, correlations, path_ingest, seam_bootstrap,
   flows, ai_datasource at once.
2. **Unpin the utility hostages** — several files can't move because they HOST
   package-wide helpers: `orDefault` (itsm_config.go), `envInt`/`envDuration`/
   `merge`/`errf`/`corr`/`sleepCtx` (report_pipeline.go), `secEnvDuration`
   (device_ssh.go), `asStr`/`affectedDevices` (ai_datasource.go), `fmtSscanf`
   (flows.go), `wsMagic`/`wsOriginAllowed` (events.go). Consolidate into a
   deliberate root util file (per the no-utils-package rule they stay in main —
   the point is the *file* being extracted must not be their home).

### Wave 1 — clean lifts, no prerequisites (~4.3k LOC)

| move | LOC | target |
|---|---|---|
| ldap.go (whole BER/LDAP client, minus handler) | ~950 | NEW `internal/ldap` |
| rca_path_view.go (97% pure; blocks ticketing_http later) | ~640 | `internal/rca` |
| wan_circuits.go projection/policy/target derivation | ~500 | NEW `wan` |
| services.go store+validation (deps: platformdb only) | ~300 | NEW `internal/servicecat` |
| timeintel_backfill.go stores + derivation | ~320 | `timeintel` |
| verify_service.go config+run stores | ~330 | `internal/verify` |
| alert_episodes.go episode store/state machine | ~350 | `alerts` |
| sot_import.go parsers (+ planner if Site moves) | ~290 | NEW `internal/sotimport` |
| device_ssh.go WS codec + SSH bridge (dedups events.go WS) | ~460 | NEW `internal/ws` + `internal/devssh` |

### Wave 2 — after `chquery` (~3.7k LOC)

report_scheduler datasets+renderers → `reports` (~900) · cloud_signals
classifiers/SQL/cursors → `cloud` (~650) · path_ingest buildPathRecords/seam
index → `pathgraph` (~550) · correlations mergeTimelineEvidence → `internal/rca`
+ list SQL → `chschema` (~450) · seam_bootstrap R1–R5 rules → `internal/seam`
(~450) · ai_datasource query bodies → NEW `aiquery` (~490) · flows SQL builders
(~250).

### Wave 3 — config stores + the rest of the top-35 (~4.4k LOC)

itsm_config → `internal/ticketing` (~480; its `srv` field is never read) ·
tenant_governance → `internal/tenant` (~420; needs cloud_signals consts injected)
· auth_config + tacacs.go with the Wave-1 ldap move (~450) · rca_action_items →
`internal/rca` (~380; needs seamOwnerEntry decoupled) · health_score → NEW
`internal/healthscore` (~380 w/ fetcher ports) · copilot provider transport +
prompt hygiene → `ai` (~360) · logs.go index-pattern/DSL builders → NEW
`internal/oslog` (~230) · logs_export encode/fetch → NEW `logexport` (~350) ·
ai_tenant_config store → `ai` (~250) · cloud_connectors_handlers projections →
`cloudconn` (~250) · notify_config channel builders → `notify` (~200, plus ~250
thinnable via a generic handler) · snmp_discovery scanner/policy →
`internal/discovery`+`collectors` (~230).

### Wave 4 — the mid-tier sweep (~65 FAT files, ~10–12k code LOC)

Start with the 25 files that contain NO handler at all (pure stores/workers/
evaluators — no HTTP surface to preserve). Confirmed FAT by reading:
cloud_monitors, cloud_service_map, cloud_monitor_eval, copilot_agent,
appid_catalog, bindings, access, rbac, wireless_actions, nms_scheduler,
corr_current_reconcile, svc_rollup_worker, path_graph_enrichment, oidc,
timeintel_reliability, search_unified, pagination (the bounded-read contract
library), bindings_api, stack_health, flows_services, cloud_costs.

### Wave 5 — the finale

The `/cmd` split: root stops being `package main`; AST guards repointed; do it
LAST, alone, like the infrastructure finale.

### Sequencing invariants (learned in Phase 1, still binding)

Same commit-per-step discipline; ship the isolation test with each move (§3a.5);
env reads stay in main; `*ForTest` hooks not field pokes; duplicated helpers
per the no-utils rule; rename sweeps must exclude every package dir; lower the
ratchet ceiling in the same commit. Dependency edges found by the audit:
rca_path_view **before** ticketing_http/ticketing_payload (shared `rcaPathView`
type); ldap.go + auth_config.go + tacacs.go as ONE combined move; Site/
DeviceSiteBinding must move for sot_import's planner half; `providerCandidates`
(ai_tenant_config) can't move until copilot config is a package.

**Size estimate: comparable to Phase 1** — ~23k LOC across ~90 fat files vs
Phase 1's 92 files. At Phase-1 velocity (steps 18–59 in two continuous days),
Phase 2 is plausibly 2–4 focused days of the same discipline, plus the /cmd
finale.

### Phase-2 progress log (LAUNCHED 2026-07-29, owner go-ahead)

| step | what | state |
|---|---|---|
| W0a | chquery consolidation: the shared CH read path (chQuery/chQueryCtx, chRows/chRowsScope/chSelect, chTenantScope/proxyClickHouse/writeEmptyClickHouse, chWorkerExec/chWorkerQuery/jsonEachRow) re-homed into `clickhouse_client.go`, the designated chhttp adapter. report_scheduler.go / correlations.go / flows.go no longer host package-wide plumbing; `appid_fusion_store.go` emptied and DELETED. Ceiling 204 → 203. | **Done** (2026-07-29) |
| W1.1 | `rca_path_view.go` → `internal/rca/path_view.go` (~640 LOC). The 97%-pure evidence→path-overlay mapping (`BuildPathView`, annotations, path assembly, cloud projection, narration, evidence summary) joins the rca package it already imported. Handler + `rcaPathView`/`rcaPath`/`rcaAnnotation`/`rcaAppImpact` aliases hosted in correlations.go; the `apps()` method became `rca.(*AppImpact).AppNames` (a method cannot attach to an aliased foreign type); `ownerOf` exported as `rca.OwnerOf`; the pure fixture suite moved wholesale; rca's existing `asFloat` absorbed main's copy. Ceiling 203 → 202. | **Done** (2026-07-29) |
| W1.2 | `services.go` store half → NEW `internal/servicecat` (~340 LOC). The Service-catalog domain: `Service`/`ServiceSelector`/`ServiceBinding`/`SelectorSet`, `ValidateInput`, `ValidCriticality`/`ValidBindingKind`, and `Store` (all 9 pg methods over `platformdb.DB.WithTenant`). Handlers + `newServiceStore` selector stayed; aliases per the jwtClaims technique; **`errNotFound` in main became `= servicecat.ErrNotFound`** — same sentinel object, so `errors.Is` matches across the boundary for its 7 main-package consumers; `newUUIDv4` kept in main for appid_overrides + private copy in the package; `ValidCriticality` exported for the cloud business-service handlers; pure test trio moved (with a duplicated `isUUIDToken` fixture); the pg isolation test now constructs via `NewStore`. Count unchanged (handlers remain). | **Done** (2026-07-29) |
| W1.3 | `alert_episodes.go` store → `alerts/episodes.go` (~380 LOC). The episode fold/close/reopen state machine, flap detection, per-tenant retention/eviction, suppression and triage join the `alerts` package whose Engine feeds them (OnTransition/SuppressNotify). Env knobs read in main and passed to `NewEpisodeStore` (zero → documented defaults, flap floor stays in-package); `closeWindow`/`flapFlips`/`flapWindow`/`now` field accesses became accessors + `SetNowForTest` (the *ForTest idiom — the isolation test's `store.now` poke updated too); `reachable` exported as `Reachable`; `sameTenantStrict` + `randHex` duplicated at the boundary (`sameTenant`, `episodeID` — the latter grew an entropy-failure fallback since the package can't panic main). Pure store suite moved; HTTP-triage/audit + adapter tests stayed with duplicated clock fixtures. Count unchanged (handlers/adapters remain). | **Done** (2026-07-29) |
| W1.4 | `verify_service.go` stores → `internal/verify/service_store.go` (~330 LOC). The per-tenant opt-in `ConfigStore` (vault-sealed SSH custody, the F-62/F-63 three-state load with rollback-on-failed-persist and the refuse-to-overwrite-unread-state rule) and the bounded latest-run-per-case `RunStore` join the verify engine package. `publicView` became `PublicView(tenant, featureOn)` — the FEATURE_ACTIVE_VERIFICATION env read stays with the caller; store methods exported (Get/Set/Unavailable/EnabledTenants/SSHCredFor/Latest/Put); logging via applog. Case lookup, target resolution and run orchestration stayed (they hold `srv`). Watch-for that materialized: a blanket `.unavailable()` rename sweep in the shared error-vs-empty test hit the DISCOVERY config store too — caught by vet, reverted for the non-verify stores. Count unchanged. | **Done** (2026-07-29) |
| W1.5 | `timeintel_backfill.go` stores + derivation → `timeintel/metrics_store.go` (~330 LOC). `MetricRow`, the `MetricsStore` interface, both backends (mem with prefer-version dedupe; pg with the `DISTINCT ON` window read + idempotent upsert), `DeriveMetricRow` and `SnapshotCap` join the package whose lifecycle/driver derivations they call — dropping the `timeintel.` qualifier on move. Selector, the CH backfill worker, ticker and handler stayed in main (they hold `srv`/`chWorkerQuery`); `nullableTime`/`scanMetricRows` moved as private; the package's existing `normTenant` absorbed main's usage. Derivation + mem-isolation tests moved; handler-gate test stayed; the reliability tests' mem-store literals became `NewMemMetricsStore()`. Count unchanged. ⚠️ **Guard fired post-commit:** moving the mem-isolation test out of main removed the incidental corpus credit `TestEveryScopedRouteHasIsolationCoverage` gave `/api/reliability/time-metrics` — fixed forward with a DEDICATED cross-org HTTP isolation test (own-only list, acting-tenant ignored, backfill trigger platform-admin-only). Phase-2 rule from this: when a moved test file carried §3a route coverage, the route needs a real main-package isolation test in the same step — and verify the suite verdict from the OUTPUT FILE, not the background task's exit code. | **Done** (2026-07-29) |
| W1.6 | `wan_circuits.go` pure core → NEW `wan` package (~250 LOC). The endpoint/circuit model, per-tenant `MeasurementPolicy` (WithDefaults/Validate), the ranked `DeriveTarget` (next-hop override → LLDP/CDP peer → reachability anchor), `CircuitID` (SHA-1 fingerprint pinned for series continuity), `NeighborIndex` (now PURE — main fetches links via its DI seam and passes them in), `IsMgmtInterface`, `IfKey`/`SplitIfKey`. The projector (`wanProject`), policy store (tenantKV), echo publisher, VM spark reads, `WanInterfaceRow` (holds main's `PathSource`) and handlers stayed — the phase-1 rejection of this file as handler-dominated was RIGHT about the file, but its pure half still extracts cleanly. Isolation test updated to the exported names in place. Count unchanged. | **Done** (2026-07-29) |
| W1.7 | `sot_import.go` parsers → NEW `internal/sotimport` (~230 LOC). The three site parsers (CSV with header aliases, JSON, RFC 7946 GeoJSON with the [lng, lat] order rule), the bindings parsers, `parseCoords` (both-or-neither), the `Result`/`RowResult` accumulator and `MaxBody` — all pure, zero coupling. The IDENTIFY/RECONCILE planners, device resolver and handler stayed (they hold `srv` + the `Site`/`DeviceSiteBinding` domain types — moving those waits for a sites-domain step). Parser tests moved; planner + isolation tests stayed (route coverage intact — the W1.5 lesson applied). Count unchanged. | **Done** (2026-07-29) |
| W1.8 | `ldap.go` → NEW `internal/ldap` (~1000 LOC — the largest single clean lift). The complete stdlib LDAP/AD client: BER codec, RFC 4515 filter compiler, RFC 4511 bind/search, StartTLS/LDAPS via tlsconfig (the SR-014 dev-only skip-verify gate moved intact), role mapping with privilege precedence, plus the config DOMAIN from auth_config.go (`Normalize`/`Validate`/`Public`/`Test` — `Test` needs package-private `dial`, which is what makes the combined move right). `authenticate` exported as `Authenticate`; role/tenant vocabulary pinned as string literals mirroring main's consts; `firstNonEmpty` duplicated. Main keeps `ldap_wiring.go` (env constructor + login handler + aliases — ldap.go dissolved, so net count unchanged) and the kv/vault store in auth_config.go. Protocol suite + the SR-014 TLS test (from security_p1_test.go) moved in; env-constructor tests re-homed to main. tacacs client move queued next. | **Done** (2026-07-29) |
| W1.9 | `tacacs.go` → NEW `internal/tacacs` (~290 LOC). The RFC 8907 TACACS+ wire client: header/body framing, the MD5-chained obfuscation pad (protocol-mandated), PAP START/REPLY, and `Authenticate` with the empty-credential rejection. `TACACS` → `tacacs.Client` behind `New(...)` — env/kv resolution stays with the callers (main's `tacacs_wiring.go` env constructor + `tacacsConfig.client()`); `Addr`/`Timeout`/`DefaultRole`/`DefaultTenant` accessors replace field pokes in the status handler and tests. Protocol + simulated-server suites moved; env-constructor tests re-homed (`tacacs_env_test.go`). tacacs.go dissolved — net count unchanged. | **Done** (2026-07-29) |
| W1.10 | device_ssh.go WS codec → NEW `internal/ws` (~220 LOC). The hand-rolled RFC 6455 bidirectional codec: handshake-by-hijack `Upgrade` (now taking the caller's origin predicate, DENYING cross-origin when nil — the SR-006 check can't be forgotten), masked-frame `ReadMessage` with ping/pong + size bounds, locked `WriteBinary`/`WriteJSON`, `AcceptKey`, `Magic`, `OriginAllowed`. `SetReadDeadline`/`Closed()` accessors replace `ws.conn` field pokes in the SSH bridge; events.go's server-push impl now shares `ws.Magic` (full dedup of its writer is a follow-on). The SSH bridge, TOFU host-key store and handler stayed (→ a future `internal/devssh` once the bridge gets an audit-sink seam). RFC 6455 example-vector test moved in. Count unchanged. **WAVE 1 COMPLETE** — 10 lifts, 5 new packages (servicecat, wan, sotimport, internal/ldap, internal/tacacs, internal/ws = 6), ~4.5k LOC extracted. | **Done** (2026-07-29) |
| W2.1 | `report_scheduler.go` datasets + legacy renderers → `reports/dataset.go` (~900 LOC). The seven dataset builders, their seven legacy text-renderer twins, `fleetHealth`, `AlertFromViewModel` and the pure formatter/condition helpers join the reports package behind a NEW `reports.DataSource` seam (tenant-scoped Devices/Alerts/DeviceKeys closures + CHQuery/VMMap/StartedAt) — the package does no I/O and never sees a principal; scoping is the closures' contract. Scheduler, delivery, spec parsing, `tenantDevices`/`tenantAlerts`/`reportDeviceKeys` (the closure impls) and `vmQueryMap` (env+HTTP) stayed. ⚠️ Watch-for that materialized: duplicating `toMap` from memory produced a type-assertion version — the real one is a JSON round-trip that converts STRUCTS too; caught against the source before commit (duplicate-by-copy, never duplicate-by-recall). Pure helper tests moved; spec/chQuery/vmQueryMap tests stayed. Count unchanged. | **Done** (2026-07-29) |
| W2.2 | `cloud_signals.go` domain → `cloud/signals.go` (~700 LOC). Bounded-window clamps, the keyset cursor codec with shape-validated ts/id tokens (SR-011), the corr_signals/corr_current SQL builders, the classifier vocabulary (health state/severity, change type/confidence, verdict confidence), evidence phrasing (`EvidenceReason` keeps its injected namer — noclabel stays in-package), row/attr projections. `chJSONRows`/`chScalarInt` went to clickhouse_client.go instead (CH plumbing, not cloud domain). Handlers, `tenantWindowHours` (governance) and `parseSignalPage`/`requireCloudApp` (http) stayed; ~10 sibling cloud files' call sites qualified; window consts aliased for tenant_governance. Count unchanged. | **Done** (2026-07-29) |
| W2.3 | `path_ingest.go` derivation core → `pathgraph/ingest.go` (~450 LOC). `IngestConfig`, the `NetContext` mapper (fallback now a parameter — env stays in main), the `SeamIndex` with the multi-seam disambiguation rule + `TunnelSeamTypes`, `BuildRecords` (the contract's pure heart — its two env reads became injected `DefaultVantageID`/`VantageAddrFor` fields so the package reads no environment), `HopKindFor`, `AddressFamily`. Fact assembly from live inventories, the ingest loop, persistence and `vantageAddressFor` (env) stayed; `randHex`/`firstNonEmptyStr` duplicated; api file's seam-index uses qualified. Test fixtures wire the injected fields explicitly. Count unchanged. | **Done** (2026-07-29) |
| W2.4 | `seam_bootstrap.go` rules → `internal/seam/bootstrap_rules.go` (~430 LOC). The five suggestion rules R1–R5 (traceroute boundary, BGP peering, flow boundary, tunnels + redundancy groups), `ClampConf`, `PrivateIP` + its SQL twin `PrivateIPSQL`, and the fetcher row types (`BGPPeer`/`FlowBoundary`/`Tunnel`) join the seam package next to the `Suggest`/`SuggestGroup` types they produce. The CH fetchers, bootstrap loop and enrichment exporter stayed (chClientFor/budget/srv). Count unchanged. | **Done** (2026-07-29) |
| W2.5 | correlations.go evidence merge → `internal/rca/timeline_evidence.go` (~250 LOC). `MergeTimelineEvidence` (the read-side re-derivation of per-signal graph linkage from corr edges — the meatiest pure algorithm in the file) with `SignalNodeKey` and its private helpers (`groundingTokens` — pinned in lock-step with the Python engine's node tokens, `tokensIntersect`, `attachedReason`, `missingOrUnknownIdentity`). The list/summary SQL builders and `loadCorrSlice` stayed (handler-adjacent, chTenantScope-coupled). White-box merge + grounding-token suites moved with their sig/edge/ev fixtures. Count unchanged. | **Done** (2026-07-29) |
| ✗ W2.6 | `ai_datasource.go` query bodies | **Re-scoped on inspection** (2026-07-29). The file IS the server-side implementation of the already-extracted `ai.DataSource` interface — the §4-style boundary exists and this is its adapter. Its query bodies are welded to main's tenant-guard seams (`chRowsScope`, `addrTenantClauseFor`, `deviceTenantCondFor` — the untagged-row app-layer guards) and compose six domains; moving them would relocate the coupling, not remove it (the report_pipeline verdict). The package-wide value helpers ALREADY left in W0b (`asStr`/`affectedDevices` → main.go). Verdict: INTEGRATOR — stays; shrinks only if the tenant-guard seams themselves ever become a package. | — |
| ✗ W2.7 | `flows.go` SQL templates | **Re-scoped on inspection** (2026-07-29). The audit's own caveat ("the most legitimately handler-shaped of the FATs") holds: nine handlers each parse params → compose a tenant clause (via main's visibility resolvers, which must stay) → concatenate a template → `proxyClickHouse`. Extracting bare SQL strings into a `flowsql` package would split each query from the one validation context that makes it safe, for no compiler-enforceable gain. Verdict: legitimate entrypoint SQL — stays. **WAVE 2 COMPLETE** — 5 moves (~2.7k LOC: reports datasets, cloud signals, pathgraph ingest, seam rules, rca evidence merge) + 2 reasoned INTEGRATOR verdicts. | — |
| W3.1 | `itsm_config.go` → `internal/ticketing/itsm_config.go` (~480 LOC). The per-tenant ITSM connector config domain: the four connector configs, the kv store with legacy-format migration + write-only secret merge, SSRF `ValidateOutboundURL`, live-connector rebuild and the `SystemConfigFor` resolve the RCA worker uses. THREE env seams injected (`envDefault`, `stateFileFor`, `legacyAlertITSM` — the deprecated broadcast lane's gate); **the `srv` back-pointer was never read and is deleted**; `ConfigFor`/`SetConfigForTest`/`NewITSMConfigStoreForTest` replace the notify/sweeper/worker tests' field pokes; `rcaNotifyTargets` became a main-side function over `ConfigFor`. Store suite moved in (de-served); env ctor + handlers stayed. Count unchanged. | **Done** (2026-07-29) |
| W3.2 | `tenant_governance.go` store → `internal/tenant/governance.go` (~400 LOC). Required tags, the RCA window, attribution precedence and the seam-owner registry (the store rca_action_items was blocked on), with the three-state load / rollback-on-failed-persist discipline and closed-vocabulary normalizers. The RCA-window bounds now import `cloud.SignalWindowHours`/`SignalWindowMaxHours` (dependency inverted — main's const aliases no longer needed by the package); `SeedForTest` replaces the persistence-matrix test's mu/cfgs pokes. Watch-for that materialized: the `tenant` PACKAGE name is shadowed by every handler's `tenant` local — the handlers file imports it as `tenantpkg` (the seam-step shadow gotcha, third occurrence this program). Handlers + env path stayed. Count unchanged. | **Done** (2026-07-29) |
| W3.3 | `rca_action_items.go` → `internal/rca/action_items.go` (~380 LOC). The action-item register: closed vocabularies, the remediation state machine with validated transitions, the tenant-keyed JSON store with rollback-on-persist-failure, field validation, overdue derivation, and `SuggestActionItems` over a `Report` + the seam-owner registry (typed against `tenant.SeamOwnerEntry` — the W3.2 unblock). Handler + env path stayed. Count unchanged. | **Done** (2026-07-29) |
| W3.4 | `health_score.go` core → NEW `internal/healthscore` (~230 LOC pure). Signal-class weights, `Aggregate` (weighted blend, anti-averaging floor, coverage honesty, deficit distribution), `HingeN` curves, `BandFromScore` (unknown-not-healthy), `ReduceConfStr` and the number formatters. The four signal-class fetchers, `qVecBy`/`qVecBy2` (VM transport) and the handler stayed in main — the fetcher-port design from the audit deferred until a second consumer appears (they're best-effort srv reads, not domain). Recovery note: a failed mkdir mid-move lost the cut block from the worktree; recovered from git HEAD — cut-then-write must mkdir FIRST. Count unchanged. | **Done** (2026-07-29) |
| W3.5 | `copilot.go` transport + hygiene → `ai/llm_transport.go` (~380 LOC). The wire `ChatMessage`, `SanitizeMessages` (LLM01: client system turns rejected server-side; `MaxMessages`/`MaxInputChars` caps exported), the doc-ref anti-fabrication strip, `ProviderDo` (timeout, bounded reads, `RedactSecrets` on egress — now beside the redactor it calls) with the three provider clients + parsers, `CallProvider`, `NormalizeProvider`, `DefaultSystemPrompt`. `ai.CallTools` now takes `ai.ProviderDo` directly — the seam it was designed for. Env resolution (chain/keys/models), the embedded knowledge doc, docs index, agent loop and handler stayed. `SwapProviderHTTPForTest` replaces the DLP egress test's client poke; parser tests moved in-package; the `containsStr` collision with routes_test resolved (`providerListed`/`slicesContains`). Count unchanged. | **Done** (2026-07-29) |
| W3.6 | `logs.go` projection core → NEW `internal/oslog` (~200 LOC). The index-pattern algebra (the vector.yaml CONTRACT comments moved intact), `IndexTenantSeg`, `TenantIndexPattern`/`TenantCatPattern`, the per-doc `TenantFilter` DSL with restricted-tenant exclusion, `QueryOrAll`, `ParseTimeFlexible`, and `AppLogPatternAllowed` — now parameterized on a `platformOwner bool` so the claims resolution stays with the caller. `logsScope` (visibility resolver), the env OpenSearch client and handlers stayed. Watch-for: a nested-call regex rewrite mangled two call sites (logs_export + a test) — caught by the compiler; prefer plain replaces over regex for nested args. Count unchanged. | **Done** (2026-07-29) |
| W0b | Utility hostages unpinned: `orDefault` (itsm_config), `secEnvDuration` (device_ssh), `envInt`/`envDuration`/`merge`/`errf`/`corr` (report_pipeline), `asStr`/`affectedDevices` (ai_datasource), `truthy`/`asFloat`/`asString` (health_score) re-homed to main.go beside envOr/envBool. `sleepCtx` stayed (single consumer); `fmtSscanf` was already in sscanf.go; wsMagic/wsOriginAllowed deferred to the ws-codec extraction. Count unchanged. | **Done** (2026-07-29) |

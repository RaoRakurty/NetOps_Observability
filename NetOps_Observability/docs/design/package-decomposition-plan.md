# `package main` decomposition — the executable plan

**Status:** thirty-six domains shipped (`internal/chschema`, `internal/openapi`,
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
`appid/appstore`, `timeintel/store`, 2026-07-28).
**229** non-test files remain in `package main`. This document is the ordered sequence for the
rest.

**Why this exists:** CLAUDE.md §2 mandates `/cmd /internal /pkg /api /plugins
/config` and forbids business logic in the entrypoint package. ~98k LOC of it
lives there. In one package the compiler cannot enforce a boundary, so §13 (no
cross-domain imports) and §4 (plugin isolation) are *unenforceable*, not merely
unenforced. It is also the substrate that hid the guard-scope bug: when "the
package" is "the whole product", a root-only scan looks complete.

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
| ✅ 40 | `timeintel_store.go` → `timeintel/store.go` | 1 | ~180 | 4 | **Done** (2026-07-28). The incident timeline store (guarded events keyed tenant+corr; mem + FORCE-RLS pg) joins `timeintel`; `DB` seam via `rlsPG`; selector stayed in `main.go`. |
| ✅ 39 | `appid_store.go` → `appid/appstore.go` | 1 | ~240 | 4 | **Done** (2026-07-28). The Application catalog store (mem + FORCE-RLS pg) joins the `appid` package; `DB` seam via `rlsPG`; `ValidateApplicationInput` + backend constructors exported; the selector stayed in `main.go`. ⚠️ Lesson recorded: a rename sweep briefly leaked into six SUBPACKAGES that use the word `Application` — caught by the compiler, reverted via git before commit; future sweeps must exclude every package dir, not just internal/. |
| ✅ 38 | `login_throttle.go` → `internal/loginguard` | 1 | ~250 | 4 | **Done** (2026-07-28) — the auth tier's last store-like piece. The F-25 account-lockout throttle (fail-closed saturation, spray-eviction under the cap, janitor sweep) moves whole; the warning sink is injected; the observability counters are exported as accessors (`Evictions`/`Sweeps`/`Saturations`) so `/metrics` keeps reading them; `NewThrottleWithLimits` provides the cap/clock injection the failure-path tests need. Pure white-box suite moved in; server-integration halves stayed. |
| 18+ | `oidc` (rest), `copilot` (rest), `snmp` (rest), discovery, report_pipeline, … — the remainder is increasingly handler-/wiring-dominated; re-run the screen before each next step. | — | — | 4–10 | The big stores (`ticketing_store`, `path_graph_store`, `nms_store`, `wireless_store`) pass the auth screen but need the portintel-style pg-injection treatment. The auth tier is now UNGATED: the `jwt` security change shipped as `internal/token` (below). |

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

# `package main` decomposition — the executable plan

**Status:** fourteen domains shipped (`internal/chschema`, `internal/openapi`,
`internal/totp`, `internal/rca` waves 1+2, `internal/vault`, `internal/vuln` +
`internal/compliance`, `internal/ratelimit`, `internal/metricval`,
`internal/noclabel`, `internal/ticketing`, `internal/gqlparse`,
`internal/verify`, `internal/segclass`, `internal/seam`, all 2026-07-27).
**258** non-test files remain in `package main`. This document is the ordered sequence for the
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
| 18+ | `session`, `oidc`, `tenant`, `copilot`, `snmp`, `wireless`, … | — | — | 4–10 | The big stores (`ticketing_store`, `path_graph_store`, `nms_store`, `wireless_store`) pass the auth screen but need the portintel-style pg-injection treatment. The `jwt` security change (see below) gates the auth tier. |

## Deferred deliberately, with reasons

**`jwt` / `token` (auth crypto).** `jwtClaims` is used by **94 files**, which a
Go **type alias** (`type jwtClaims = token.Claims`) would handle without
touching any of them — the right technique. But the struct carries an
**unexported** `actingTenant` field, and its unexportedness *is* the security
control: it is what stops JSON unmarshal from populating a platform-owner
tenant override from a token. Moving the type across a package boundary forces
exporting it, and the property would then have to be re-established explicitly
(`json:"-"`) **and asserted by a test**. That is a deliberate security change,
not a mechanical move. Do it as its own commit, with a test proving a crafted
token cannot set `actingTenant`.

**Anything under `alerts/`, `notify/`, `collectors/`, `nms/`, `ai/`.** Already
subpackages. Not part of this work.

## Definition of done

`package main` contains entrypoint wiring only — `newServer`, route
registration, worker startup, shutdown — and the ratchet's ceiling reflects it.
At that point §13 and §4 become enforceable by the compiler, and standing gap #8
in `docs/audit/INVARIANTS.md` can close.

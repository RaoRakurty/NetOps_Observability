# `package main` decomposition — the executable plan

**Status:** step 1 shipped (`internal/chschema`, 2026-07-27). 290 non-test files
remain in `package main`. This document is the ordered sequence for the rest.

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
| 2 | `internal/chsql` (`chISO` + query fragments) | 1 | 23 | 21 | Cheap logic, 23 import updates. Consider folding into `chschema` and widening its doc to "the ClickHouse SQL this platform emits". |
| 3 | `internal/compliance` + `internal/vuln` **together** | 2 | ~1090 | 1 | Single caller and an already dependency-inverted seam (`evaluateCompliance` takes its collaborators as parameters, and the only `*server` method is the HTTP handler, which STAYS in package main). **But `vulnEntry` is defined in `vulns.go` and appears in that seam's signature**, so compliance cannot move alone without either dragging the type or inventing a narrow duplicate. Verified 2026-07-27. Move the pair, or give compliance its own input type and adapt at the call site — a design decision, not a mechanical move. |
| 4 | `internal/openapi` | 1 | 126 | 1 | Trivial; good warm-up for a new contributor. |
| 7 | `internal/portintel` (extend existing) | 2 | 640 | 2 | A `portintel` package already exists — move these in rather than creating a sibling. |
| 8 | `internal/svc` | 3 | 725 | 2 | Service rollup/health. |
| 9 | `internal/breakglass` | 1 | 198 | 3 | Security-sensitive; move with tests, no behaviour change. |
| 11 | `internal/export` | 2 | 246 | 6 | |
| 12 | `internal/metrics` | 3 | 665 | 7 | `metric_float` etc. Do **not** merge with the ClickHouse packages — different concern. |
| 13+ | `session`, `oidc`, `tenant`, `seam`, `copilot`, `snmp`, `wireless`, … | — | — | 4–10 | Larger blast radius; take after the pattern is routine. |

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

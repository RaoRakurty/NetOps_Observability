package main

// package_growth_guard_test.go — a RATCHET on the flat `package main`.
//
// THE PROBLEM (2026-07-27 audit, item 9)
// CLAUDE.md §2 mandates /cmd /internal /pkg /api /plugins /config and forbids
// business logic in the entrypoint package. Reality: 296 non-test files and
// ~98k lines of business logic sit in ONE `package main`, and none of those
// directories exist (an empty, untracked cmd/ is the residue of an abandoned
// move). In a single package the compiler cannot enforce ANY boundary — every
// file can reach every other file's unexported state — so §13 "no cross-domain
// imports" and §4 "plugins cannot import core system code" are not merely
// unenforced, they are unenforceable.
//
// WHY IT IS NOT JUST STYLE
// This is the substrate that made the guard-scope bug possible. Because "the
// package" and "the whole product" were the same thing, a guard that scanned
// only the root directory LOOKED like it scanned everything — and its
// anti-vacuity floor passed comfortably on 296 files while 201 subpackage files
// (alerts/, notify/, collectors/, nms/, ai/) went unguarded for months, hiding
// three real defects. A flat package makes "scan everything" ambiguous.
//
// WHAT THIS GUARD IS, AND IS NOT
// It is a RATCHET, not a fix: it fails when the root package GROWS, forcing
// every new domain into a real subpackage from day one. It deliberately does
// NOT attempt the decomposition — that is a multi-sprint program (leaf domains
// first, one per PR, CI green at each step) and a half-migrated tree with
// imports pointing both ways is worse than either endpoint.
//
// HONEST LIMITATIONS (do not mistake this for the §2 rule being satisfied):
//   * existing root files can still grow without bound;
//   * a new subpackage can still import half of package main's behaviour by
//     having package main call INTO it, so coupling can still increase;
//   * it measures files, not dependencies.
// It buys time and stops the bleeding. The decomposition still has to happen.
//
// WORKFLOW WHEN THIS FAILS
//   * Adding a NEW domain? Put it in its own subpackage. That is the point.
//   * Genuinely extending an existing root file? Edit that file — the count is
//     unchanged and this guard stays quiet.
//   * MOVED files out of the root (the direction we want)? Lower the ceiling in
//     the same commit. It only ever goes down.

import (
	"os"
	"strings"
	"testing"
)

// rootPackageCeiling is the number of non-test .go files in the backend root
// package. THIS NUMBER MUST ONLY EVER DECREASE. Lowering it is the whole point;
// raising it defeats the ratchet.
//
//	2026-07-27  296  pinned
//	2026-07-27  290  internal/chschema extracted (6 ClickHouse schema/DDL files)
//	2026-07-27  289  internal/openapi (spec builder) + internal/totp (2FA primitive)
//	2026-07-27  284  internal/rca (5 pure analysis files: independence, observer registry,
//	                  path attribution, recovery, report icons)
//	2026-07-27  283  internal/vault (secret custody; storage+logging now INJECTED)
//	2026-07-27  283  internal/vuln + internal/compliance (~900 LOC of evaluation
//	                  moved; count unchanged because each left a thin *_http.go
//	                  handler behind — the ratchet measures files, not LOC)
//	2026-07-27  282  portintel gains the port store (pg plumbing INJECTED via
//	                  portintel.DB); handlers + backend selection stayed
//	2026-07-27  281  internal/ratelimit (the F-33 fixed-window limiter; callers
//	                  now pass their budget — the env read left the package)
//	2026-07-27  280  internal/metricval (the F-21 metric-value parse boundary;
//	                  counter exposed read-only via NonFinite())
//	2026-07-27  279  chISO folded into chschema.ISO (21 call sites qualified);
//	                  the zone-less-toString guard now walks subpackages too
//	2026-07-27  278  internal/noclabel (ai_labels.go + kindNoc — the NOC display-
//	                  language mirror of the frontend label library; rca wave-2
//	                  seam pre-step, ~15 consumers qualified)
//	2026-07-27  276  internal/ticketing (model + pure policy decision + the
//	                  CorrFacts type; the payload BUILDERS stayed — they read
//	                  rcaPathView, a domain that has not moved)
//	2026-07-27  263  rca wave 2: the 13-file report/analysis family (report
//	                  builder, semantics, wording, html, coverage, accounting,
//	                  consistency, actions, merge, postmortem, issue context,
//	                  impact provenance) — moved as ONE commit because the
//	                  family is one strongly-connected component. Six rca_*
//	                  handler/store files stayed and consume the exported
//	                  surface (rca.Report, rca.BuildReport, …).
//	2026-07-27  262  internal/gqlparse (the F-72 GraphQL subset parser — zero
//	                  external deps, one consumer; the handler and its RBAC
//	                  gate stayed)
//	2026-07-27  260  internal/verify (the Active Verification engine + its
//	                  prebuilt modules — closed command tables, deterministic
//	                  parsers, injected Dialers; the SSH runner, service,
//	                  trigger and HTTP stayed)
//	2026-07-27  259  internal/segclass (the ingest segment/device classifier
//	                  mirror + its embedded provider-CIDR snapshot; zero Go
//	                  consumers found — flagged in the plan for the owner)
//	2026-07-27  258  internal/seam (the canonical seam inventory: model,
//	                  lifecycle, validation + pg store with seam.DB INJECTED
//	                  via the portintel idiom; bootstrap rules, handlers and
//	                  backend selection stayed)
//	2026-07-28  257  internal/token (the auth-crypto boundary: Claims + HS256
//	                  sign/verify; jwtClaims stays as a type alias for the 90+
//	                  consumers; the actingTenant unmarshal-immunity is now the
//	                  json:"-" tag, pinned by TestCraftedTokenCannotSetActingTenant)
//	2026-07-28  256  internal/session (session lifecycle Store + rotating
//	                  RefreshStore; kv + error-log INJECTED via session.KV /
//	                  session.Errorf — the vault idiom, wired in
//	                  session_wiring.go; the CONC-HIGH-1/F-70 white-box suites
//	                  moved in and dropped the process-global backend swap)
//	2026-07-28  255  internal/jwks (OIDC discovery + JWKS RS256 verification,
//	                  pure stdlib; TTL now injected — the OIDC_JWKS_TTL_MIN env
//	                  read moved to oidc.go; main's token exchange got its own
//	                  http.Client instead of borrowing the cache's)
//	2026-07-28  254  internal/apikey (scoped tenant-bound API keys: store,
//	                  RFC 7591 validation, fixed-window limiter, multi-writer
//	                  reload; kv INJECTED via the shared platformKV adapter,
//	                  APIKEY_RATE_LIMIT_PER_MIN read + TenantGlobal default
//	                  moved to the composition root; roleFromScopes stayed —
//	                  it maps onto main's Role constants)
//	2026-07-28  253  internal/tenant (the tenant model + store + isolation-mode
//	                  router; cross-domain inputs INJECTED as tenant.Deps — kv,
//	                  DefaultOrg, id-mint/slug rules, region validation; the
//	                  75-file fan-in handled by tenant_wiring.go aliases, the
//	                  jwtClaims technique; tenantkv.go deliberately stayed for
//	                  its own step)
//	2026-07-28  252  tenantkv.go → tenant.Collection[T] (the §3a default-closed
//	                  per-tenant collection primitive joins internal/tenant; a
//	                  generic alias + wrapper in tenant_wiring.go keeps the
//	                  three consumers' call shape; Path() accessor added)
//	2026-07-28  251  internal/snmpcred (SNMP credential profiles: model,
//	                  validation, vault-enveloped store with kv INJECTED;
//	                  slugify duplicated per the no-utils rule; four consumer
//	                  files qualified directly — no alias needed)
//	2026-07-28  250  copilot_tools.go → ai/toolwire.go (the per-provider LLM
//	                  tool-calling wire codecs join the ai subpackage they were
//	                  built around; transport INJECTED as ai.DoFunc so main
//	                  keeps timeout/retry/redaction policy; the LLM04 output
//	                  cap hoisted to ai.MaxOutputTokens — one definition)
//	2026-07-28  249  wireless_store.go → wireless/store.go (the canonical
//	                  inventory store joins its domain package; pg plumbing
//	                  INJECTED via wireless.DB and the portintelPG adapter
//	                  generalized to rlsPG — one adapter for every RLS seam)
const rootPackageCeiling = 249

func TestFlatPackageMainDoesNotGrow(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read backend root: %v", err)
	}
	var files []string
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		files = append(files, name)
	}

	switch {
	case len(files) > rootPackageCeiling:
		t.Errorf("package main grew to %d non-test files (ceiling %d).\n"+
			"CLAUDE.md §2 forbids business logic in the entrypoint package, and this "+
			"package already holds ~98k lines of it. New code belongs in a SUBPACKAGE "+
			"(a real boundary the compiler can enforce), not in the root.\n"+
			"If you genuinely extended an existing file, this guard would not have "+
			"fired — it counts files, so a new file here is a new domain in the wrong "+
			"place. If you MOVED files out, lower rootPackageCeiling in the same commit.",
			len(files), rootPackageCeiling)
	case len(files) < rootPackageCeiling:
		t.Errorf("package main shrank to %d non-test files (ceiling %d) — good, that is "+
			"the direction the §2 decomposition goes. Lower rootPackageCeiling to %d in "+
			"this commit so the ratchet holds at the new position.",
			len(files), rootPackageCeiling, len(files))
	}

	// Anti-vacuity: if the scan stops seeing the package, the guard has broken
	// rather than the decomposition having succeeded overnight.
	if len(files) < 50 {
		t.Fatalf("only %d root .go files seen — the guard is not reading the package", len(files))
	}
}

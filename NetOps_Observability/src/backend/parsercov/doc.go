// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Package parsercov is the parser-coverage surface (parser programme A6,
// backend half): what the correlation engine's parser recognises today, and
// what it does NOT.
//
// Three routes, and nothing else:
//
//	GET  /api/admin/parser/stats                             platform admin
//	GET  /api/telemetry/unrecognized?days&limit&lane          infrastructure:read
//	POST /api/telemetry/unrecognized/{template_id}/propose    alerts:write
//
// WHY A PACKAGE. The root package is at its decomposition ceiling
// (package_growth_guard_test.go), and this is a new domain: a metrics/health
// aggregator over the correlation replicas, a pure template miner, a bounded
// cache and a deterministic YAML drafter. None of it needs ambient authority,
// so none of it gets any — every collaborator arrives through Deps (§5:
// interfaces for all external dependencies), exactly as secapi does.
//
// # THE THREE HONESTY RULES THIS SURFACE IS BUILT ON
//
//  1. NEVER GUESS AN ADMISSION VERDICT. "Unrecognized" means "the engine would
//     not admit this line". That verdict is the engine's, not ours, and it is
//     PUBLISHED per-document: the aggregator stamps `.cx_admission` on every
//     syslog record it forwards, from VRL that is GENERATED out of
//     `src/correlation/producers.syslog_promotable` by
//     `scripts/gen-syslog-admission.py` (see admission.go for the full
//     argument). We read that stamp. We do NOT re-implement the screen in Go —
//     a third, un-drift-guarded copy of a predicate that already exists twice
//     is precisely the failure §13 exists to prevent. When the stamp is absent
//     from the window, the route answers 503 with a note that says so.
//
//  2. NEVER INVENT RULE METADATA. `lane`/`kind`/`fidelity` per rule are catalog
//     facts owned by telemetry-catalog/events.yaml and baked into the engine.
//     The engine does not export them today (no `corr_parser_rule_info` series,
//     no `rules_meta` in the /healthz parser block), so this package returns
//     them EMPTY rather than deriving them from a rule_id's spelling. See
//     stats.go for the one-block engine change that fills them in; when it
//     lands, this package reads it with no change here.
//
//  3. NOTHING IS APPLIED. The propose route drafts a catalog row and a fixture
//     as TEXT. It writes nothing, reloads nothing, and touches no rule table.
//     A row is landed by a human, through a pull request against
//     telemetry-catalog/events.yaml, followed by `bake_rules.py`.
//
// # ISOLATION (§3a)
//
// The two /api/telemetry routes are per-tenant DATA: they read the caller's own
// syslog/snmptrap indices via oslog.TenantIndexPattern and carry
// oslog.TenantFilter as a per-doc clause — the same chokepoint pair every other
// log surface uses, so another tenant's document is unreachable even if a
// filter were dropped. The scope is derived ONCE, in scopeOf, so no handler can
// build a pattern by hand. /api/admin/parser/stats is platform-GLOBAL plumbing
// (engine counters for the whole process, not a tenant's rows) and therefore
// takes the platform-admin gate, per §3a rule 3.
package parsercov

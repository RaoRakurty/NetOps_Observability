package main

// silent_failure_guards_test.go — MECHANICAL enforcement of CLAUDE.md §10
// ("No silent failures allowed / All errors must be observable") as a CLASS.
//
// WHY THIS FILE EXISTS
// The 2026-07-27 audit found ~60 instances of one defect: an error routed to
// the same branch as a benign empty state, so a FAILURE renders as "nothing
// wrong". The seed was alerts/engine.go — `if err != nil || len(samples) == 0
// { continue }` — which made a VictoriaMetrics outage indistinguishable from
// "no rules firing" and therefore mass-RESOLVED live alerts, closing pages
// during the outage. Its sibling: an alert-engine `healthy` field set true at
// construction and never set false anywhere.
//
// WHY NOTHING CAUGHT IT
// The code is structurally perfect — the error IS checked, nothing is
// discarded with `_ =`, it compiles, vets, and passes errcheck/gosec/
// staticcheck (verified per-linter: errcheck flags UNCHECKED errors; this one
// is checked; staticcheck has no SA rule for branch-on-error). The defect is
// purely in WHICH BRANCH is taken. Every pre-existing guard in this repo asks a
// STRUCTURAL question (does a symbol exist, does a call go through a seam, does
// a field have a column); none asked a semantic one. §10 sat at PROSE tier with
// no gate behind it. These two guards move it to BUILD tier.
//
// THE REFERENCE IMPLEMENTATION already in this tree is cloud_monitor_eval.go
// (~:186-208): it distinguishes THREE states against the same VictoriaMetrics —
// the store did not answer / it answered with no samples / evaluated. New code
// reading a dependency should follow that shape, not invent another.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"
)

// ---- Guard 1: health flags must be falsifiable ----------------------------

// healthFlagNames are boolean fields whose whole purpose is to report that a
// subsystem is working. A flag that only ever receives `true` is not a health
// signal, it is a decoration — and it is worse than nothing, because operators
// and the /api/health surface believe it.
var healthFlagNames = map[string]bool{
	"healthy": true, "Healthy": true,
	"ok": true, "OK": true,
	"ready": true, "Ready": true,
	"alive": true, "Alive": true,
}

// TestHealthFlagsCanBeFalsified fails when a health-ish bool field is assigned
// the literal `true` somewhere but NEVER receives a false-or-derived value
// anywhere in the module.
//
// Measured when introduced: 1 real hit (alerts.Engine.healthy — set true at
// construction, never falsified, and reported by Health() forever) plus the
// Status.Healthy family across the collector pool, where 8 collectors could
// never report their own blindness while the shipped `CollectorDown` alert
// (collector_up == 0) could never fire.
func TestHealthFlagsCanBeFalsified(t *testing.T) {
	srcs := goSources(t)

	trueAssign := map[string][]string{} // field -> files assigning literal true
	falsifiable := map[string]bool{}    // field -> has a false/derived assignment
	fset := token.NewFileSet()

	for path, src := range srcs {
		f, err := parser.ParseFile(fset, path, src, 0)
		if err != nil {
			continue // stripComments can leave a fragment the parser dislikes; skip
		}
		ast.Inspect(f, func(n ast.Node) bool {
			switch v := n.(type) {
			case *ast.KeyValueExpr: // composite literal: Healthy: true
				key, ok := v.Key.(*ast.Ident)
				if !ok || !healthFlagNames[key.Name] {
					return true
				}
				if isTrueLit(v.Value) {
					trueAssign[key.Name] = append(trueAssign[key.Name], path)
				} else if !isFalseLit(v.Value) {
					falsifiable[key.Name] = true // derived from an expression
				} else {
					falsifiable[key.Name] = true // literal false
				}
			case *ast.AssignStmt: // x.Healthy = <expr>
				for i, lhs := range v.Lhs {
					name := fieldName(lhs)
					if name == "" || !healthFlagNames[name] || i >= len(v.Rhs) {
						continue
					}
					if isTrueLit(v.Rhs[i]) {
						trueAssign[name] = append(trueAssign[name], path)
					} else {
						falsifiable[name] = true
					}
				}
			}
			return true
		})
	}

	for field, files := range trueAssign {
		if falsifiable[field] {
			continue
		}
		t.Errorf("health flag %q is assigned literal true (%s) and NEVER set false or "+
			"derived anywhere in the module — it can only ever report healthy, so the "+
			"subsystem cannot report its own failure (CLAUDE.md §10). Give it a real "+
			"false transition, or stop calling it a health flag.",
			field, strings.Join(dedupe(files), ", "))
	}
}

// ---- Guard 2: an error must not be conflated with an empty state ----------

// TestErrorIsNotConflatedWithABenignState fails on the seed pattern:
//
//	if err != nil || <emptiness> { continue }   // or break / bare return
//
// An error and "there is genuinely nothing here" are different facts and must
// not share a branch: the first is a failure the operator must see, the second
// is normal. Splitting them is the whole fix.
//
// SCOPE: deliberately narrowed to control-flow bodies (continue/break/bare
// return) — the tightest, highest-severity form. Measured when introduced:
// 318 raw `err != nil ||` lines in the module, 91 matching the emptiness shape,
// 11 reaching a control-flow body, of which 5 were real defects (including two
// where a report spec whose JSON failed to parse was silently treated as
// DISABLED and never ran). The remainder are byte-level wire parsing where
// skipping a malformed record IS correct — those carry an allowlist entry with
// a stated reason rather than being silently exempted.
func TestErrorIsNotConflatedWithABenignState(t *testing.T) {
	// Allowlist: each entry is a place where skipping on error is genuinely
	// correct, with the reason. Parsing untrusted wire data record-by-record is
	// the honest case — one malformed TLV must not abort the batch. Anything
	// added here must say WHY, and must not be a dependency read.
	allow := map[string]string{
		"collectors/snmptrap.go":    "byte-level BER walk: a malformed varbind is skipped, the trap still lands",
		"collectors/redis.go":       "byte-level RESP parse: a malformed entry is skipped, the scan continues",
		"integration_reconciler.go": "documented dedup skip; the reconcile outcome is counted separately",
		"pgstore.go":                "file-import migration: ENOENT-shaped absence is genuinely 'nothing to import'",
	}

	// FROZEN BASELINE — the pre-existing backlog this guard found on the day it
	// was introduced (2026-07-27), recorded per-file so it survives line drift.
	// It exists so the guard is BLOCKING for new code immediately instead of
	// waiting for a 44-site cleanup. Same idiom as the isolation-coverage
	// baseline: THE SET ONLY SHRINKS. Deleting an entry after fixing the file is
	// the intended workflow; adding one is not permitted — a new file with this
	// pattern must be fixed, not baselined.
	//
	// Not every entry is a defect: some are optional-enrichment reads where
	// absence is genuinely benign. The obligation is to TRIAGE each one and
	// either fix it or move it to `allow` above with a stated reason.
	baseline := map[string]bool{
		"ai_datasource_ops.go": true, "ai_tenant_config.go": true, "appid_overrides.go": true,
		"auth_config.go": true, "cloud_handlers.go": true, "cloud_monitors.go": true,
		"cloud_slo.go": true, "collectors/bgpls.go": true,
		"collectors/unifi.go": true, "copilot_config.go": true,
		"device_persist.go": true, "discovery.go": true, "events_feed.go": true,
		"events.go": true, "export_policy.go": true, "integration/jira.go": true,
		"internalca/ca.go": true, "nms/auth.go": true, "oidc_config.go": true,
		"path_graph_api.go": true, "path_graph_enrichment.go": true,
		"probe_paths_enrichment.go": true, "rules_user.go": true, "safehttp/safehttp.go": true,
		"snmp_discovery.go": true, "svc_health.go": true, "tenant_display.go": true,
		"tenant_governance.go": true, "ticketing_http.go": true, "ticketing_jira.go": true,
		"ticketing_servicenow.go": true, "ticketing_worker.go": true, "timeintel_api.go": true,
		"timeintel_manual.go": true, "token_policy.go": true, "verify_service.go": true,
		"wireless_store.go": true,
	}

	srcs := goSources(t)
	fset := token.NewFileSet()
	stillDirty := map[string]bool{}

	for path, src := range srcs {
		if _, ok := allow[path]; ok {
			continue
		}
		f, err := parser.ParseFile(fset, path, src, 0)
		if err != nil {
			continue
		}
		ast.Inspect(f, func(n ast.Node) bool {
			ifs, ok := n.(*ast.IfStmt)
			if !ok {
				return true
			}
			bin, ok := ifs.Cond.(*ast.BinaryExpr)
			if !ok || bin.Op != token.LOR {
				return true
			}
			if !(isErrNotNil(bin.X) || isErrNotNil(bin.Y)) {
				return true
			}
			if !(isEmptinessTest(bin.X) || isEmptinessTest(bin.Y)) {
				return true
			}
			if !isBenignBody(ifs.Body) {
				return true
			}
			if baseline[path] {
				stillDirty[path] = true
				return true // known backlog; tracked, shrink-only (asserted below)
			}
			t.Errorf("%s:%d: `if err != nil || <empty> { %s }` conflates a FAILURE with "+
				"an empty state — the caller cannot tell a broken dependency from "+
				"'there is nothing here', so an outage renders as normal (CLAUDE.md §10). "+
				"Split the branches: handle the error (surface/count it and preserve prior "+
				"state), then handle empty separately. See cloud_monitor_eval.go for the "+
				"three-state shape this repo already uses.",
				path, fset.Position(ifs.Pos()).Line, bodyKind(ifs.Body))
			return true
		})
	}

	// Shrink-only: a baselined file that no longer trips the guard must be
	// REMOVED from the baseline, so the backlog can never silently grow back
	// under cover of a stale exemption.
	for path := range baseline {
		if !stillDirty[path] {
			t.Errorf("%s is in the frozen baseline but no longer conflates an error with an "+
				"empty state — delete its baseline entry. The baseline only shrinks.", path)
		}
	}
	// Anti-vacuity: if the scan stops matching anything at all, the guard has
	// broken rather than the tree having been cleaned.
	if len(stillDirty) == 0 && len(baseline) > 0 {
		t.Fatal("the conflation scan matched nothing anywhere — the guard is broken, not the tree clean")
	}
}

// ---- helpers --------------------------------------------------------------

func isTrueLit(e ast.Expr) bool  { id, ok := e.(*ast.Ident); return ok && id.Name == "true" }
func isFalseLit(e ast.Expr) bool { id, ok := e.(*ast.Ident); return ok && id.Name == "false" }

func fieldName(e ast.Expr) string {
	switch v := e.(type) {
	case *ast.SelectorExpr:
		return v.Sel.Name
	case *ast.Ident:
		return v.Name
	}
	return ""
}

// isErrNotNil matches `err != nil` (any identifier ending in "err"/"Err").
func isErrNotNil(e ast.Expr) bool {
	bin, ok := e.(*ast.BinaryExpr)
	if !ok || bin.Op != token.NEQ {
		return false
	}
	id, ok := bin.X.(*ast.Ident)
	if !ok {
		return false
	}
	nilID, ok := bin.Y.(*ast.Ident)
	if !ok || nilID.Name != "nil" {
		return false
	}
	n := id.Name
	return n == "err" || strings.HasSuffix(n, "Err") || strings.HasSuffix(n, "err")
}

// isEmptinessTest matches len(x) == 0, x == nil, x == "", !ok, !found.
func isEmptinessTest(e ast.Expr) bool {
	switch v := e.(type) {
	case *ast.UnaryExpr: // !ok / !found
		if v.Op != token.NOT {
			return false
		}
		id, ok := v.X.(*ast.Ident)
		return ok && (id.Name == "ok" || id.Name == "found" || id.Name == "exists")
	case *ast.BinaryExpr:
		if v.Op != token.EQL {
			return false
		}
		// len(x) == 0
		if call, ok := v.X.(*ast.CallExpr); ok {
			if id, ok := call.Fun.(*ast.Ident); ok && id.Name == "len" {
				if lit, ok := v.Y.(*ast.BasicLit); ok && lit.Value == "0" {
					return true
				}
			}
		}
		// x == nil / x == ""
		if id, ok := v.Y.(*ast.Ident); ok && id.Name == "nil" {
			return true
		}
		if lit, ok := v.Y.(*ast.BasicLit); ok && (lit.Value == `""` || lit.Value == "0") {
			return true
		}
	}
	return false
}

// isBenignBody reports whether the branch merely skips: continue, break, or a
// return that carries no error.
func isBenignBody(b *ast.BlockStmt) bool {
	if b == nil || len(b.List) != 1 {
		return false
	}
	switch st := b.List[0].(type) {
	case *ast.BranchStmt:
		return st.Tok == token.CONTINUE || st.Tok == token.BREAK
	case *ast.ReturnStmt:
		for _, r := range st.Results {
			if id, ok := r.(*ast.Ident); ok && (id.Name == "err" || strings.HasSuffix(id.Name, "Err")) {
				return false // returning the error is honest
			}
		}
		return true
	}
	return false
}

func bodyKind(b *ast.BlockStmt) string {
	if b == nil || len(b.List) == 0 {
		return "…"
	}
	switch st := b.List[0].(type) {
	case *ast.BranchStmt:
		return st.Tok.String()
	case *ast.ReturnStmt:
		return "return"
	}
	return "…"
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

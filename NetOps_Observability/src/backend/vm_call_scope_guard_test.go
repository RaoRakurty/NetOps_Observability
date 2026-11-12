// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// vm_call_scope_guard_test.go — a STRUCTURAL guard, not a per-lane one.
//
// A table of correct VictoriaMetrics lanes is a snapshot: it says the lanes
// that exist today are scoped, and says nothing about the one somebody adds
// next week. This test walks the package source instead, finds every call into
// a VictoriaMetrics read helper, and fails on any that cannot carry the
// caller's boundary — so a new lane cannot be added unscoped without either
// turning this red or writing itself into the allowlist below, in a diff a
// reviewer reads.
//
// It exists because the per-lane guard missed exactly this. /api/paths/health
// ran eight fleet-wide baseline queries while serving tenant-scoped callers,
// and TestMetricsRoutesCarryCallerScope was pointed at "/api/rca/path/health",
// a route this server does not register: it skipped, quietly, for a year.

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// vmUnscopedAllowlist names the ONLY files that may read VictoriaMetrics with
// no tenant boundary, and why. These are platform lanes with no HTTP caller:
// they read VictoriaMetrics' own self-metrics, which carry no tenant label and
// belong to no tenant. A file is not added here to make a test pass — it is
// added when the read genuinely has no principal to scope to.
var vmUnscopedAllowlist = map[string]string{
	"main.go":                  "the storage and telemetry meters: vm_data_size_bytes / vm_rows_inserted_total are VictoriaMetrics' own self-metrics, read on the platform path only",
	"path_health_baselines.go": "the precompute ticker: a background job with no caller, whose rows are written untagged and read back bounded to the caller's own paths",
}

// vmReadHelpers are the entry points that actually reach VictoriaMetrics.
var vmReadHelpers = []string{"vmInstantUnscoped", "vmInstantScoped", "vmRange", "vmQueryRangeByIf", "vmRangeByDst", "vmRangeSeries"}

// vmNilFilterExceptions are the exact expressions allowed to pass a literal nil
// filter set. Only the unscoped door's own body qualifies.
var vmNilFilterExceptions = map[string]bool{
	"return s.vmInstantScoped(ctx, query, nil)": true,
}

func packageGoSources(t *testing.T) map[string][]string {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	out := map[string][]string{}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		b, err := os.ReadFile(filepath.Clean(name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		out[name] = strings.Split(string(b), "\n")
	}
	if len(out) == 0 {
		t.Fatal("the sweep found no package sources — it would pass vacuously")
	}
	return out
}

// isVMCall reports whether the line CALLS helper (rather than declaring it),
// through ANY receiver expression. It used to name the receivers it knew
// (s, srv, d.srv, q.s, w), so a call through any other one — a renamed
// receiver, a struct field — was not a call as far as this guard could tell.
func isVMCall(line, helper string) bool {
	if regexp.MustCompile(`func \([^)]*\) ` + helper + `\(`).MatchString(line) {
		return false
	}
	return regexp.MustCompile(`[A-Za-z0-9_)\]]\.` + helper + `\(`).MatchString(line)
}

func TestEveryVictoriaMetricsReadCarriesACallerBoundary(t *testing.T) {
	sources := packageGoSources(t)
	seenHelper := map[string]bool{}

	for file, lines := range sources {
		for i, line := range lines {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "//") {
				continue
			}
			for _, helper := range vmReadHelpers {
				if !isVMCall(line, helper) {
					continue
				}
				seenHelper[helper] = true

				// The explicitly unscoped door: platform lanes only.
				if helper == "vmInstantUnscoped" || helper == "vmRangeByDst" {
					if _, ok := vmUnscopedAllowlist[file]; !ok {
						t.Errorf("%s:%d calls %s, which reads VictoriaMetrics with NO tenant boundary.\n"+
							"  %s\n"+
							"  A lane that serves an HTTP caller must use vmInstantScoped with that caller's\n"+
							"  filters (s.metricsScopeFiltersFor, or the metricsScopeFilters derivation).\n"+
							"  If this read genuinely has no principal, add %s to vmUnscopedAllowlist with the reason.",
							file, i+1, helper, trimmed, file)
					}
					continue
				}

				// The scoped helpers, handed a literal nil: same thing wearing a
				// better name.
				if strings.Contains(line, ", nil)") && !vmNilFilterExceptions[trimmed] {
					t.Errorf("%s:%d passes a literal nil filter set to %s — that is a fleet-wide read with extra steps.\n  %s",
						file, i+1, helper, trimmed)
				}
			}
		}
	}

	// A sweep that matches nothing passes for the wrong reason.
	for _, helper := range vmReadHelpers {
		if !seenHelper[helper] {
			t.Errorf("the sweep found no call site for %s — its regex has drifted away from the code and the guard proves nothing", helper)
		}
	}
}

// ---- the free-function doors (tracker 392) ---------------------------------
//
// The method sweep above only sees METHOD calls (receiver.helper(…)). Package
// FUNCTIONS that send PromQL to VictoriaMetrics — vmQuery / vmQueryBy (the
// cloud lane), vmQueryRangeBy, vmQueryMap, seamFetchBGPPeers — were invisible
// to it, which is how cloudLiveStates read the whole fleet's cloud series for
// every caller while this guard stayed green. They take raw PromQL, so the
// boundary lives in the query each CALLER builds; the guard therefore reviews
// call sites rather than helpers.
//
// Three rules, the second backed by a reviewed table:
//
//  1. Every function or method in the package whose body names a
//     VictoriaMetrics read endpoint (/api/v1/query, /query_range, /series,
//     /label, /export) must be a known door: a scoped method (vmReadHelpers),
//     a proxy route (vmProxyRoutes) or a free door (vmFreeDoors). A new door is
//     red until somebody classifies it.
//  2. Every reference to a free door — a call OR a function value handed to
//     something else — must be in vmFreeDoorUses, keyed by file, enclosing
//     function and door, with the reason its query is bounded. A stale entry
//     is red too, so the table cannot rot into a blanket pass.
//  3. A non-platform use may not hand a door a CONSTANT query: a PromQL string
//     with no caller-derived part in it has no boundary in it, which is
//     exactly the shape cloudLiveStates had.

// vmFreeDoors are the package functions that reach VictoriaMetrics with
// caller-built PromQL (or, for seamFetchBGPPeers, a fixed one).
var vmFreeDoors = []string{"vmQuery", "vmQueryBy", "vmQueryRangeBy", "vmQueryMap", "seamFetchBGPPeers"}

// vmProxyRoutes are the handlers that name a VictoriaMetrics path and hand it
// to proxyMetrics, which injects s.metricsScopeFiltersFor(caller).
var vmProxyRoutes = map[string]bool{"handleMetricsQuery": true, "handleMetricsQueryRange": true, "handleMetricsNames": true}

type vmFreeUse struct {
	// platform marks a use with no tenant principal (a background job, or a
	// platform-admin-only gate). Only these may pass a constant query.
	platform bool
	why      string
}

// vmFreeDoorUses is the reviewed list of every free-door reference, keyed
// "file:enclosingFunc:door". Adding a line here is a review decision: the
// reason must say where the query's boundary comes from.
var vmFreeDoorUses = map[string]vmFreeUse{
	"cloud_enrich.go:vmQuery:vmQueryBy":                              {why: "the resource_id-keyed wrapper; every use of vmQuery is reviewed below"},
	"cloud_enrich.go:readCloudLiveMetrics:vmQuery":                   {why: "selector built from the caller's own inventory ids (cloudResourceIDBatches → cloudLiveQuery)"},
	"cloud_ingestion.go:readCloudMetricProof:vmQueryBy":              {why: "fleet-wide only on the fleetWide branch (an unrestricted platform caller); otherwise per-batch selectors of the caller's own inventory ids"},
	"cloud_metrics_series.go:handleCloudMetricSeries:vmQueryRangeBy": {why: "selector built from resource ids validated against the caller's inventory (404 otherwise)"},
	"cloud_monitor_eval.go:newCloudMonitorEvaluator:vmQuery":         {why: "the evaluator selects only the monitor's tenant's own inventory ids (cloud/monitor_eval.go)"},
	"cloud_slo.go:handleCloudSLOs:vmQuery":                           {why: "cloud.MeasureSLO selects only the caller's own inventory ids for the app"},
	"main.go:parserCovDeps:vmQueryBy":                                {platform: true, why: "parser-coverage stats are requirePlatformAdmin; the router's vendor counters carry no tenant"},
	"report_scheduler.go:dataSource:vmQueryMap":                      {why: "reports post-filter every row by the run's device scope (reports scope.filterMap) before anything is rendered"},
	"seam_bootstrap.go:runSeamBootstrapOnce:seamFetchBGPPeers":       {platform: true, why: "the background seam bootstrap: no principal, platform-built seam table"},
}

// vmQueryArgIndex is where each free door takes its PromQL; -1 = a fixed query
// the door builds itself, which only a platform use may reach.
var vmQueryArgIndex = map[string]int{"vmQuery": 1, "vmQueryBy": 1, "vmQueryRangeBy": 1, "vmQueryMap": 0, "seamFetchBGPPeers": -1}

// vmEndpointRe recognises a VictoriaMetrics read path in a string literal.
var vmEndpointRe = regexp.MustCompile(`/api/v1/(?:query|query_range|series|label|export)\b`)

// vmDoorSweep is what freeDoorFindings saw, so the caller can also prove the
// sweep was not vacuous.
type vmDoorSweep struct {
	findings []string
	seenUse  map[string]bool // vmFreeDoorUses keys that matched a real use
	seenDoor map[string]bool // free doors that were referenced at all
}

// freeDoorFindings applies rules 1–3 to parsed sources. Split from the test so
// the rules are proven on synthetic sources too (TestFreeDoorGuardCatches…).
func freeDoorFindings(fset *token.FileSet, files map[string]*ast.File, uses map[string]vmFreeUse) vmDoorSweep {
	sw := vmDoorSweep{seenUse: map[string]bool{}, seenDoor: map[string]bool{}}
	report := func(pos token.Pos, format string, args ...any) {
		sw.findings = append(sw.findings, fset.Position(pos).String()+": "+fmt.Sprintf(format, args...))
	}

	// Package-level constants: a query built only from these is as constant as
	// a literal.
	consts := map[string]bool{}
	for _, f := range files {
		for _, decl := range f.Decls {
			if gd, ok := decl.(*ast.GenDecl); ok && gd.Tok == token.CONST {
				for _, spec := range gd.Specs {
					if vs, ok := spec.(*ast.ValueSpec); ok {
						for _, n := range vs.Names {
							consts[n.Name] = true
						}
					}
				}
			}
		}
	}
	var isConst func(e ast.Expr) bool
	isConst = func(e ast.Expr) bool {
		switch x := e.(type) {
		case *ast.BasicLit:
			return x.Kind == token.STRING
		case *ast.ParenExpr:
			return isConst(x.X)
		case *ast.BinaryExpr:
			return x.Op == token.ADD && isConst(x.X) && isConst(x.Y)
		case *ast.Ident:
			return consts[x.Name]
		}
		return false
	}

	freeDoor := map[string]bool{}
	for _, d := range vmFreeDoors {
		freeDoor[d] = true
	}
	methodDoor := map[string]bool{}
	for _, h := range vmReadHelpers {
		methodDoor[h] = true
	}

	checkUses := func(file, fn string, root ast.Node) {
		selectorNames := map[*ast.Ident]bool{}
		ast.Inspect(root, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.SelectorExpr:
				selectorNames[x.Sel] = true // x.vmQuery is somebody else's vmQuery
			case *ast.CallExpr:
				id, ok := x.Fun.(*ast.Ident)
				if !ok || !freeDoor[id.Name] {
					return true
				}
				use, reviewed := uses[file+":"+fn+":"+id.Name]
				if !reviewed || use.platform {
					return true // unreviewed: the identifier rule reports it
				}
				idx := vmQueryArgIndex[id.Name]
				if idx < 0 || (idx < len(x.Args) && isConst(x.Args[idx])) {
					report(x.Pos(), "%s hands %s a CONSTANT query on a tenant-serving path. A PromQL string with nothing "+
						"caller-derived in it has no boundary in it (the shape cloudLiveStates had, tracker 392). Build the "+
						"selector from the caller's own ids, or mark the use platform with the reason it has no principal.",
						fn, id.Name)
				}
			case *ast.Ident:
				if !freeDoor[x.Name] || selectorNames[x] {
					return true
				}
				key := file + ":" + fn + ":" + x.Name
				sw.seenDoor[x.Name] = true
				if _, ok := uses[key]; !ok {
					report(x.Pos(), "%s uses %s, a package function that sends PromQL straight to VictoriaMetrics. Its "+
						"boundary is whatever the query says, so the use must be reviewed: add %q to vmFreeDoorUses with "+
						"where the query's caller boundary comes from (or platform: true and why there is no principal).",
						fn, x.Name, key)
					return true
				}
				sw.seenUse[key] = true
			}
			return true
		})
	}

	for file, f := range files {
		for _, decl := range f.Decls {
			switch d := decl.(type) {
			case *ast.FuncDecl:
				if d.Body == nil {
					continue
				}
				fn := d.Name.Name
				// Rule 1: a function that names a VictoriaMetrics read path is a door.
				namesEndpoint := false
				ast.Inspect(d.Body, func(n ast.Node) bool {
					if lit, ok := n.(*ast.BasicLit); ok && lit.Kind == token.STRING {
						if v, err := strconv.Unquote(lit.Value); err == nil && vmEndpointRe.MatchString(v) {
							namesEndpoint = true
						}
					}
					return !namesEndpoint
				})
				if namesEndpoint {
					known := (d.Recv == nil && freeDoor[fn]) || (d.Recv != nil && (methodDoor[fn] || vmProxyRoutes[fn]))
					if !known {
						report(d.Pos(), "%s names a VictoriaMetrics read endpoint, so it is a new door into the metric store. "+
							"Classify it: a scoped server method goes in vmReadHelpers (and takes the caller's filters), a "+
							"package function in vmFreeDoors (and every use of it in vmFreeDoorUses).", fn)
					}
				}
				checkUses(file, fn, d.Body)
			case *ast.GenDecl:
				checkUses(file, "", d) // a package-level reference has no enclosing function
			}
		}
	}
	return sw
}

func TestEveryFreeVictoriaMetricsDoorUseIsReviewed(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	fset := token.NewFileSet()
	files := map[string]*ast.File{}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Clean(name), nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		files[name] = f
	}
	if len(files) == 0 {
		t.Fatal("the sweep parsed no package sources — it would pass vacuously")
	}
	sw := freeDoorFindings(fset, files, vmFreeDoorUses)
	for _, f := range sw.findings {
		t.Error(f)
	}
	for key, use := range vmFreeDoorUses {
		if strings.TrimSpace(use.why) == "" {
			t.Errorf("vmFreeDoorUses[%q] has no reason — an entry is a review decision and must say where the boundary comes from", key)
		}
		if !sw.seenUse[key] {
			t.Errorf("vmFreeDoorUses names %q, which no longer exists — drop the stale entry so the table stays a review, not a pass", key)
		}
	}
	for _, d := range vmFreeDoors {
		if !sw.seenDoor[d] {
			t.Errorf("the sweep found no use of %s — the parser has drifted away from the code and the guard proves nothing", d)
		}
	}
}

// The rules are proven on synthetic sources, so the guard cannot pass merely
// because the package happens to be clean today.
func TestFreeDoorGuardCatchesEachShape(t *testing.T) {
	parse := func(t *testing.T, src string) (*token.FileSet, map[string]*ast.File) {
		t.Helper()
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, "x.go", "package x\n"+src, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		return fset, map[string]*ast.File{"x.go": f}
	}
	cases := []struct {
		name, src string
		uses      map[string]vmFreeUse
		want      string // substring of the one expected finding; "" = clean
	}{
		{
			name: "the 392 shape: a constant cloud query on a reviewed tenant path",
			src:  "func (s *server) lane(ctx context.Context) { _ = vmQuery(ctx, `last_over_time(cloud_cpu_util[30m])`) }",
			uses: map[string]vmFreeUse{"x.go:lane:vmQuery": {why: "test"}},
			want: "CONSTANT query",
		},
		{
			name: "a constant built from package constants is still constant",
			src:  "const m = `cloud_cpu_util`\nfunc (s *server) lane(ctx context.Context) { _ = vmQueryBy(ctx, `last_over_time(` + m + `[5m])`, `provider`) }",
			uses: map[string]vmFreeUse{"x.go:lane:vmQueryBy": {why: "test"}},
			want: "CONSTANT query",
		},
		{
			name: "an unreviewed call",
			src:  "func newLane(ctx context.Context, q string) { _ = vmQuery(ctx, q) }",
			want: "must be reviewed",
		},
		{
			name: "an unreviewed function value handed elsewhere",
			src:  "func wire() Deps { return Deps{Query: vmQueryMap} }",
			want: "must be reviewed",
		},
		{
			name: "a package-level reference",
			src:  "var q = vmQuery",
			want: "must be reviewed",
		},
		{
			name: "a new free door",
			src:  "func vmNewDoor(base string) string { return base + `/api/v1/query_range?query=up` }",
			want: "new door",
		},
		{
			name: "a new method door",
			src:  "func (s *server) vmSneaky(base string) string { return base + `/api/v1/series` }",
			want: "new door",
		},
		{
			name: "a caller-built query on a reviewed path is clean",
			src:  "func (s *server) lane(ctx context.Context, ids string) { _ = vmQuery(ctx, cloudLiveQuery(`cloud_cpu_util`, ids)) }",
			uses: map[string]vmFreeUse{"x.go:lane:vmQuery": {why: "test"}},
		},
		{
			name: "a platform use may pass a constant",
			src:  "func (s *server) meter(ctx context.Context) { _ = vmQueryBy(ctx, `up`, `vendor`) }",
			uses: map[string]vmFreeUse{"x.go:meter:vmQueryBy": {platform: true, why: "test"}},
		},
		{
			name: "somebody else's method of the same name is not a door use",
			src:  "func (s *server) lane(c client) { _ = c.vmQuery(`up`) }",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fset, files := parse(t, c.src)
			got := freeDoorFindings(fset, files, c.uses).findings
			switch {
			case c.want == "" && len(got) != 0:
				t.Fatalf("expected no finding, got %q", got)
			case c.want != "" && (len(got) != 1 || !strings.Contains(got[0], c.want)):
				t.Fatalf("expected exactly one finding containing %q, got %q", c.want, got)
			}
		})
	}
}

// The widened method matcher sees a call through any receiver, and still not a
// declaration.
func TestIsVMCallSeesAnyReceiver(t *testing.T) {
	for _, line := range []string{
		"	rows, err := s.vmInstantScoped(ctx, q, f)",
		"	rows, err := api.srv.vmInstantScoped(ctx, q, f)",
		"	rows, err := deps().vmInstantScoped(ctx, q, f)",
		"	rows, err := lanes[i].vmInstantScoped(ctx, q, f)",
	} {
		if !isVMCall(line, "vmInstantScoped") {
			t.Errorf("not seen as a call: %q", line)
		}
	}
	for _, line := range []string{
		"func (s *server) vmInstantScoped(ctx context.Context, query string, filters []string) ([]vmSample, error) {",
		"func (srv *server) vmInstantScoped(ctx context.Context, query string, filters []string) ([]vmSample, error) {",
	} {
		if isVMCall(line, "vmInstantScoped") {
			t.Errorf("a declaration was taken for a call: %q", line)
		}
	}
}

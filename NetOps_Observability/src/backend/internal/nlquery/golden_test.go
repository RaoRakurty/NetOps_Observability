// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package nlquery_test

// golden_test.go — the golden NL query corpus (tracker 337 N-C6 seed; design:
// docs/architecture/iris-nl-query-design.md §7). The corpus under
// testdata/golden/ is what the N-C5 compiler will be measured against: each
// case pairs an operator question (and its paraphrases) with the ONE
// CorrelixQueryAST v1 it must compile to. This test does not compile anything
// — the compiler does not exist yet. It proves the corpus itself is honest:
//
//   - every expected AST (and every alternate, and every prior turn) decodes
//     strictly AND validates against the embedded catalog and a fixture Scope
//     built from testdata/golden/fixture.json;
//   - every unsupported question's AST is REJECTED with the closed code the
//     case names (or the case declines outright), so the compiler is pinned
//     to refuse rather than guess;
//   - the result semantics a case claims (rows that must appear, a minimum
//     row count) actually hold against the fixture inventory;
//   - tenant isolation: no tenant-B id appears in any tenant-A expectation,
//     and the fixture's same-site-slug trap device never leaks into a site
//     expansion.
//
// Gated metrics (circuit_*/probe_*, catalog scope "gated:N-B5") are valid only
// for a platform-operator (cross-tenant) principal until N-B5 lands; a case
// that uses one sets context.cross=true, and the test re-validates it as a
// workspace user to prove it is REFUSED (scope_unavailable), never answered
// with an empty result.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
	_ "time/tzdata" // context.tz must load on a host without zoneinfo

	"netops/backend/internal/nlquery/ast"
	"netops/backend/internal/nlquery/catalog"
	"netops/backend/internal/nlquery/validate"
)

const goldenDir = "testdata/golden"

// Part 2 §20/§21: the categories the corpus must cover.
var goldenCategories = []string{
	"metrics", "interfaces", "devices", "circuits", "sites", "applications", "flows", "bgp", "routes",
	"sdwan", "dns", "changes", "configuration", "incidents", "users", "cloud", "providers",
	"time_comparisons", "aggregation", "ranking", "grouping",
}

const (
	minCasesPerCategory = 5
	minCasesTotal       = 150
	minParaphrases      = 2
	maxParaphrases      = 5
)

// intent → the query type it compiles to.
var intentTypes = map[string][]ast.QueryType{
	"show_metric":      {ast.MetricSeries},
	"rank":             {ast.MetricTopK},
	"threshold":        {ast.MetricFilter},
	"compare":          {ast.CompareWindows},
	"list_changes":     {ast.ChangeList},
	"change_diff":      {ast.ChangeList},
	"list_incidents":   {ast.IncidentList},
	"explain_incident": {ast.IncidentExplain},
}

// result kind → the query types that can produce it.
var kindTypes = map[string][]ast.QueryType{
	"timeseries":      {ast.MetricSeries},
	"ranking":         {ast.MetricTopK, ast.CompareWindows},
	"entity_rows":     {ast.MetricFilter},
	"comparison":      {ast.CompareWindows},
	"change_rows":     {ast.ChangeList},
	"change_diff":     {ast.ChangeList},
	"group_counts":    {ast.ChangeList, ast.IncidentList},
	"incident_rows":   {ast.IncidentList},
	"incident_detail": {ast.IncidentExplain},
}

var declines = map[string]bool{
	"not_a_query":        true, // an action ("restart the router"): Iris NL reads, never writes
	"not_expressible_v1": true, // a real question the v1 AST has no shape for (a recorded gap)
}

// ---- corpus format -------------------------------------------------------------

type goldenFile struct {
	Schema   string       `json:"schema"`
	Category string       `json:"category"`
	Cases    []goldenCase `json:"cases"`
}

type goldenCase struct {
	ID          string      `json:"id"`
	Category    string      `json:"category"`
	Question    string      `json:"question"`
	Context     caseContext `json:"context"`
	Expect      caseExpect  `json:"expect"`
	Paraphrases []string    `json:"paraphrases"`
	file        string      // set by the loader
	raw         []byte      // the case as it appears on disk (re-encoded)
}

type caseContext struct {
	TZ         string          `json:"tz"`
	IncidentID string          `json:"incident_id,omitempty"`
	PriorAST   json.RawMessage `json:"prior_ast,omitempty"`
	Cross      bool            `json:"cross,omitempty"`
	Script     string          `json:"script,omitempty"`
	Turn       int             `json:"turn,omitempty"`
}

type caseExpect struct {
	Intent          string            `json:"intent"`
	Entities        []expectEntity    `json:"entities,omitempty"`
	AST             json.RawMessage   `json:"ast,omitempty"`
	Alternates      []json.RawMessage `json:"alternates,omitempty"`
	ResultSemantics *resultSemantics  `json:"result_semantics,omitempty"`
	RejectCode      string            `json:"reject_code,omitempty"`
	RejectedAST     json.RawMessage   `json:"rejected_ast,omitempty"`
	Decline         string            `json:"decline,omitempty"`
	ForeignProbe    bool              `json:"foreign_probe,omitempty"`
}

type expectEntity struct {
	Input  string `json:"input"`
	Type   string `json:"type"`
	ID     string `json:"id"`
	Method string `json:"method"`
}

type resultSemantics struct {
	Kind            string   `json:"kind"`
	MinRows         *int     `json:"min_rows,omitempty"`
	MustIncludeRefs []string `json:"must_include_refs"`
}

// ---- fixture inventory ---------------------------------------------------------

type fixtureFile struct {
	Schema      string    `json:"schema"`
	Description string    `json:"description"`
	Now         time.Time `json:"now"`
	TenantA     inventory `json:"tenant_a"`
	TenantB     inventory `json:"tenant_b"`
}

type inventory struct {
	Tenant string `json:"tenant"`
	Sites  []struct {
		ID      string   `json:"id"`
		Name    string   `json:"name"`
		Aliases []string `json:"aliases"`
	} `json:"sites"`
	Devices []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
		Site string `json:"site"` // the raw site LABEL slug, not an id
	} `json:"devices"`
	Interfaces []struct {
		ID     string `json:"id"`
		Device string `json:"device"`
	} `json:"interfaces"`
	Circuits []struct {
		ID             string `json:"id"`
		LocalDevice    string `json:"local_device"`
		LocalInterface string `json:"local_interface"`
		Provider       string `json:"provider"`
	} `json:"circuits"`
	Providers []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"providers"`
	BGPPeers []struct {
		ID     string `json:"id"`
		Device string `json:"device"`
	} `json:"bgp_peers"`
	Applications []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"applications"`
	ProbeTargets []struct {
		ID string `json:"id"`
	} `json:"probe_targets"`
	Incidents []fxIncident `json:"incidents"`
	Changes   []fxChange   `json:"changes"`
}

type fxIncident struct {
	ID            string    `json:"id"`
	CreatedAt     time.Time `json:"created_at"`
	State         string    `json:"state"`
	VerdictTier   string    `json:"verdict_tier"`
	SeamType      string    `json:"seam_type"`
	TopConfidence float64   `json:"top_confidence"`
	Owner         string    `json:"owner"`
	Sites         []string  `json:"sites"`
	Devices       []string  `json:"devices"`
	Apps          []string  `json:"apps"`
}

type fxChange struct {
	ID         string    `json:"id"`
	At         time.Time `json:"at"`
	Type       string    `json:"type"`
	Actor      string    `json:"actor,omitempty"`
	Source     string    `json:"source"`
	Site       string    `json:"site,omitempty"`
	Device     string    `json:"device,omitempty"`
	App        string    `json:"app,omitempty"`
	Object     string    `json:"object,omitempty"`
	ObjectKind string    `json:"object_kind,omitempty"`
	Seam       string    `json:"seam,omitempty"`
}

// world indexes both tenants. Relations are computed over the WHOLE world and
// then filtered by visibility — the same order the root uses (site expansion
// via the site label, then canSeeDevice) — so the trap device is really tested.
type world struct {
	now       time.Time
	a, b      *inventory
	owner     map[string]string          // id → tenant
	typeOf    map[string]string          // id → catalog entity type
	related   map[string]map[string]bool // metric-entity id → ids it relates to (incl. itself)
	incidents map[string]fxIncident
}

func strictDecode(raw []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if dec.More() {
		return fmt.Errorf("trailing data")
	}
	return nil
}

func loadWorld(t *testing.T) *world {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(goldenDir, "fixture.json"))
	if err != nil {
		t.Fatal(err)
	}
	var f fixtureFile
	if err := strictDecode(raw, &f); err != nil {
		t.Fatalf("fixture.json: %v", err)
	}
	if f.Now.IsZero() {
		t.Fatal("fixture.json: now is required")
	}
	w := &world{now: f.Now.UTC(), a: &f.TenantA, b: &f.TenantB, owner: map[string]string{},
		typeOf: map[string]string{}, related: map[string]map[string]bool{}, incidents: map[string]fxIncident{}}
	for _, inv := range []*inventory{w.a, w.b} {
		add := func(typ, id string) {
			if prev, dup := w.owner[id]; dup {
				t.Errorf("fixture: id %s appears in %s and %s — tenant ids must be disjoint", id, prev, inv.Tenant)
			}
			w.owner[id], w.typeOf[id] = inv.Tenant, typ
		}
		for _, x := range inv.Sites {
			add("site", x.ID)
		}
		for _, x := range inv.Devices {
			add("device", x.ID)
		}
		for _, x := range inv.Interfaces {
			add("interface", x.ID)
		}
		for _, x := range inv.Circuits {
			add("circuit", x.ID)
		}
		for _, x := range inv.Providers {
			add("provider", x.ID)
		}
		for _, x := range inv.BGPPeers {
			add("bgp_peer", x.ID)
		}
		for _, x := range inv.Applications {
			add("application", x.ID)
		}
		for _, x := range inv.ProbeTargets {
			add("probe_target", x.ID)
		}
		for _, x := range inv.Incidents {
			add("incident", x.ID)
			w.incidents[x.ID] = x
		}
		for _, x := range inv.Changes {
			add("change", x.ID)
		}
	}
	// Relations for metric targets (≤ 2 catalog hops, matching the catalog's
	// relationship graph): device↔site (label), device↔interface/bgp_peer,
	// circuit↔device/interface (local end), provider↔circuit.
	siteOf := map[string]string{}
	for _, inv := range []*inventory{w.a, w.b} {
		for _, d := range inv.Devices {
			siteOf[d.ID] = "site:" + d.Site
		}
	}
	set := func(id string, ids ...string) {
		if w.related[id] == nil {
			w.related[id] = map[string]bool{id: true}
		}
		for _, x := range ids {
			if x != "" {
				w.related[id][x] = true
			}
		}
	}
	for _, inv := range []*inventory{w.a, w.b} {
		byDevice := map[string][]string{} // device → circuit ids + providers
		byIf := map[string][]string{}
		for _, c := range inv.Circuits {
			set(c.ID, c.LocalDevice, c.LocalInterface, siteOf[c.LocalDevice], c.Provider)
			byDevice[c.LocalDevice] = append(byDevice[c.LocalDevice], c.ID, c.Provider)
			byIf[c.LocalInterface] = append(byIf[c.LocalInterface], c.ID, c.Provider)
		}
		for _, d := range inv.Devices {
			set(d.ID, append([]string{siteOf[d.ID]}, byDevice[d.ID]...)...)
		}
		for _, i := range inv.Interfaces {
			set(i.ID, append([]string{i.Device, siteOf[i.Device]}, byIf[i.ID]...)...)
		}
		for _, p := range inv.BGPPeers {
			set(p.ID, append([]string{p.Device, siteOf[p.Device]}, byDevice[p.Device]...)...)
		}
		for _, p := range inv.ProbeTargets {
			set(p.ID)
		}
	}
	return w
}

// fixtureScope implements validate.Scope for the asking tenant (A).
type fixtureScope struct {
	w     *world
	cross bool
	// hide removes ids from the world entirely (used to prove a foreign id is
	// refused exactly like one that never existed).
	hide map[string]bool
}

func (s fixtureScope) Visible(_ context.Context, r ast.EntityRef) (bool, error) {
	if s.hide[r.ID] {
		return false, nil
	}
	owner, ok := s.w.owner[r.ID]
	if !ok || s.w.typeOf[r.ID] != r.Type {
		return false, nil
	}
	return s.cross || owner == s.w.a.Tenant, nil
}

func (s fixtureScope) Count(ctx context.Context, target string, refs []ast.EntityRef) (int, error) {
	n := 0
	for id, typ := range s.w.typeOf {
		if typ != target {
			continue
		}
		if vis, _ := s.Visible(ctx, ast.EntityRef{Type: typ, ID: id}); !vis {
			continue
		}
		if s.w.matches(id, refs) {
			n++
		}
	}
	return n, nil
}

func (s fixtureScope) CrossTenant() bool { return s.cross }
func (s fixtureScope) Now() time.Time    { return s.w.now }

// matches: refs of one type are OR'd, different types AND'd (ast.EntityRef).
func (w *world) matches(id string, refs []ast.EntityRef) bool {
	byType := map[string][]string{}
	for _, r := range refs {
		byType[r.Type] = append(byType[r.Type], r.ID)
	}
	for _, ids := range byType {
		hit := false
		for _, r := range ids {
			if w.related[id][r] {
				hit = true
				break
			}
		}
		if !hit {
			return false
		}
	}
	return true
}

// ---- loading -------------------------------------------------------------------

func loadCases(t *testing.T) []*goldenCase {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join(goldenDir, "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	known := map[string]bool{}
	for _, c := range goldenCategories {
		known[c] = true
	}
	var out []*goldenCase
	for _, p := range paths {
		stem := strings.TrimSuffix(filepath.Base(p), ".json")
		if stem == "fixture" {
			continue
		}
		raw, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		var f goldenFile
		if err := strictDecode(raw, &f); err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		if f.Schema != "correlix.nlquery.golden/v1" {
			t.Errorf("%s: schema %q", p, f.Schema)
		}
		if f.Category != stem {
			t.Errorf("%s: file category %q must equal the file name", p, f.Category)
		}
		if stem != "unsupported" && !known[stem] {
			t.Errorf("%s: %q is not a corpus category", p, stem)
		}
		if len(f.Cases) == 0 {
			t.Errorf("%s: no cases", p)
		}
		for i := range f.Cases {
			c := &f.Cases[i]
			c.file = stem
			if stem != "unsupported" && c.Category != stem {
				t.Errorf("%s: case %s has category %q", p, c.ID, c.Category)
			}
			if !known[c.Category] {
				t.Errorf("%s: case %s category %q is not a corpus category", p, c.ID, c.Category)
			}
			b, err := json.Marshal(c)
			if err != nil {
				t.Fatal(err)
			}
			c.raw = b
			out = append(out, c)
		}
	}
	if len(out) == 0 {
		t.Fatal("no golden cases found — the test is not looking where the corpus is")
	}
	return out
}

func decodeAST(t *testing.T, where string, raw json.RawMessage) *ast.AST {
	t.Helper()
	if len(raw) == 0 {
		t.Errorf("%s: missing AST", where)
		return nil
	}
	a, err := ast.Decode(raw)
	if err != nil {
		t.Errorf("%s: %v", where, err)
		return nil
	}
	return a
}

func errCodes(r validate.Result) string {
	var s []string
	for _, e := range r.Errors {
		s = append(s, e.Path+":"+e.Code)
	}
	return strings.Join(s, " ")
}

// astRefIDs lists every entity the AST names, as catalog ids.
func astRefIDs(a *ast.AST) []string {
	var out []string
	for _, r := range a.Refs {
		out = append(out, r.ID)
	}
	if a.IncidentID != "" {
		out = append(out, "incident:"+a.IncidentID)
	}
	for _, tr := range []*ast.TimeRange{&a.Time, a.CompareTo} {
		if tr == nil || tr.Anchor == nil {
			continue
		}
		if tr.Anchor.IncidentID != "" {
			out = append(out, "incident:"+tr.Anchor.IncidentID)
		}
		if set := tr.Anchor.Incidents; set != nil {
			for _, r := range set.Refs {
				out = append(out, r.ID)
			}
		}
	}
	return out
}

func isGated(cat *catalog.Catalog, a *ast.AST) bool {
	if a == nil || a.Metric == "" {
		return false
	}
	m, ok := cat.Metric(a.Metric)
	return ok && m.Scope == "gated:N-B5"
}

// ---- the test ------------------------------------------------------------------

func TestGoldenCorpus(t *testing.T) {
	cat := catalog.MustLoad()
	w := loadWorld(t)
	cases := loadCases(t)
	ctx := context.Background()

	t.Run("fixture", func(t *testing.T) { checkFixture(t, cat, w) })

	ids := map[string]bool{}
	perCat := map[string][2]int{} // [supported, unsupported]
	for _, c := range cases {
		c := c
		if c.ID == "" || ids[c.ID] {
			t.Errorf("case id %q is empty or duplicated", c.ID)
		}
		ids[c.ID] = true
		n := perCat[c.Category]
		if c.file == "unsupported" {
			n[1]++
		} else {
			n[0]++
		}
		perCat[c.Category] = n
		t.Run(c.ID, func(t *testing.T) {
			checkCommon(t, c)
			checkIsolation(t, w, c)
			if c.file == "unsupported" {
				checkUnsupported(ctx, t, cat, w, c)
				return
			}
			checkSupported(ctx, t, cat, w, c)
		})
	}

	t.Run("scripts", func(t *testing.T) { checkScripts(t, cases) })

	total := 0
	var lines []string
	for _, name := range goldenCategories {
		n := perCat[name]
		total += n[0] + n[1]
		lines = append(lines, fmt.Sprintf("%-17s %3d (%d supported, %d must-refuse)", name, n[0]+n[1], n[0], n[1]))
		if n[0]+n[1] < minCasesPerCategory {
			t.Errorf("category %s has %d cases, want ≥ %d", name, n[0]+n[1], minCasesPerCategory)
		}
	}
	if total < minCasesTotal {
		t.Errorf("corpus has %d cases, want ≥ %d", total, minCasesTotal)
	}
	t.Logf("golden corpus: %d cases\n%s", total, strings.Join(lines, "\n"))
}

func checkFixture(t *testing.T, cat *catalog.Catalog, w *world) {
	for id, typ := range w.typeOf {
		et, ok := cat.Entity(typ)
		if !ok {
			t.Errorf("fixture %s: unknown entity type %s", id, typ)
			continue
		}
		if err := matchPattern(et.IDPattern, id); err != nil {
			t.Errorf("fixture %s: %v", id, err)
		}
	}
	// The isolation trap: a tenant-B device labelled with a tenant-A site slug,
	// where tenant B has no such site.
	aSites := map[string]bool{}
	for _, s := range w.a.Sites {
		aSites[s.ID] = true
	}
	trap := ""
	for _, d := range w.b.Devices {
		if aSites["site:"+d.Site] && w.owner["site:"+d.Site] != w.b.Tenant {
			trap = d.ID
			site := "site:" + d.Site
			ctx := context.Background()
			refs := []ast.EntityRef{{Type: "site", ID: site}}
			tenantN, _ := fixtureScope{w: w}.Count(ctx, "device", refs)
			crossN, _ := fixtureScope{w: w, cross: true}.Count(ctx, "device", refs)
			aN := 0
			for _, ad := range w.a.Devices {
				if "site:"+ad.Site == site {
					aN++
				}
			}
			if tenantN != aN {
				t.Errorf("site expansion of %s for tenant A counts %d devices, want %d (the trap %s must not leak)", site, tenantN, aN, d.ID)
			}
			if crossN != aN+1 {
				t.Errorf("cross-tenant expansion of %s counts %d, want %d — the trap is not wired", site, crossN, aN+1)
			}
		}
	}
	if trap == "" {
		t.Error("fixture has no tenant-B device labelled with a tenant-A site slug — the isolation trap is missing")
	}
}

func matchPattern(pat, id string) error {
	re, err := regexp.Compile(pat)
	if err != nil {
		return err
	}
	if !re.MatchString(id) {
		return fmt.Errorf("does not match %s", pat)
	}
	return nil
}

func checkCommon(t *testing.T, c *goldenCase) {
	if strings.TrimSpace(c.Question) == "" {
		t.Error("empty question")
	}
	if n := len(c.Paraphrases); n < minParaphrases || n > maxParaphrases {
		t.Errorf("%d paraphrases, want %d–%d", n, minParaphrases, maxParaphrases)
	}
	seen := map[string]bool{norm(c.Question): true}
	for _, p := range c.Paraphrases {
		k := norm(p)
		if k == "" || seen[k] {
			t.Errorf("paraphrase %q is empty or repeats the question/another paraphrase", p)
		}
		seen[k] = true
	}
	if c.Context.TZ == "" {
		t.Error("context.tz is required")
	} else if _, err := time.LoadLocation(c.Context.TZ); err != nil {
		t.Errorf("context.tz: %v", err)
	}
	if (c.Context.Script == "") != (c.Context.Turn == 0) {
		t.Error("context.script and context.turn go together")
	}
}

func norm(s string) string {
	return strings.Join(strings.Fields(strings.ToLower(strings.TrimRight(strings.TrimSpace(s), ".?!"))), " ")
}

// checkIsolation: nothing tenant B owns may appear in a tenant-A expectation.
// A foreign_probe case deliberately names a tenant-B id in its rejected AST
// (and question) to pin that it is refused; only those parts are exempt.
func checkIsolation(t *testing.T, w *world, c *goldenCase) {
	scan := c.raw
	if c.Expect.ForeignProbe {
		cc := *c
		cc.Question, cc.Paraphrases = "", nil
		cc.Expect.RejectedAST = nil
		b, err := json.Marshal(cc)
		if err != nil {
			t.Fatal(err)
		}
		scan = b
	}
	for id, owner := range w.owner {
		if owner != w.b.Tenant {
			continue
		}
		bare := id[strings.Index(id, ":")+1:]
		if bytes.Contains(scan, []byte(id)) || bytes.Contains(scan, []byte(bare)) {
			t.Errorf("tenant-B id %s appears in a tenant-A case", id)
		}
	}
}

func checkSupported(ctx context.Context, t *testing.T, cat *catalog.Catalog, w *world, c *goldenCase) {
	e := c.Expect
	if e.RejectCode != "" || len(e.RejectedAST) > 0 || e.Decline != "" || e.ForeignProbe {
		t.Error("a supported case carries no reject/decline fields")
	}
	sc := fixtureScope{w: w, cross: c.Context.Cross}
	a := decodeAST(t, "expect.ast", e.AST)
	if a == nil {
		return
	}
	out, res := validate.Validate(ctx, cat, sc, a)
	if !res.Valid {
		t.Fatalf("expect.ast does not validate: %s", errCodes(res))
	}
	if a.Time.Kind == "" && a.Type != ast.IncidentExplain {
		found := false
		for _, k := range res.Constraints {
			found = found || k.Reason == "default_window"
		}
		if !found {
			t.Error("a question without a time must be reported as default_window")
		}
	}
	for i, alt := range e.Alternates {
		b := decodeAST(t, fmt.Sprintf("alternates[%d]", i), alt)
		if b == nil {
			continue
		}
		if _, r := validate.Validate(ctx, cat, sc, b); !r.Valid {
			t.Errorf("alternates[%d] does not validate: %s", i, errCodes(r))
		}
		if b.Hash() == a.Hash() {
			t.Errorf("alternates[%d] is the expected AST itself", i)
		}
	}
	var prior *ast.AST
	if len(c.Context.PriorAST) > 0 {
		prior = decodeAST(t, "context.prior_ast", c.Context.PriorAST)
		if prior != nil {
			if _, r := validate.Validate(ctx, cat, sc, prior); !r.Valid {
				t.Errorf("context.prior_ast does not validate: %s", errCodes(r))
			}
		}
	}
	if c.Context.IncidentID != "" {
		if ok, _ := sc.Visible(ctx, ast.EntityRef{Type: "incident", ID: "incident:" + c.Context.IncidentID}); !ok {
			t.Errorf("context.incident_id %s is not a tenant-A incident", c.Context.IncidentID)
		}
	}

	// Gated metrics: honest only for a platform operator, refused for a tenant.
	gated := isGated(cat, a) || isGated(cat, prior)
	if c.Context.Cross && !gated {
		t.Error("context.cross is only for cases that need a gated metric (circuit_*/probe_*)")
	}
	if isGated(cat, a) {
		_, r := validate.Validate(ctx, cat, fixtureScope{w: w}, a)
		if r.Valid || !hasCode(r, validate.CodeScopeUnavailable) {
			t.Errorf("gated metric %s must be scope_unavailable for a workspace user, got valid=%v %s", a.Metric, r.Valid, errCodes(r))
		}
	}

	// Intent and result kind agree with the query type.
	if !typeIn(a.Type, intentTypes[e.Intent]) {
		t.Errorf("intent %q does not compile to %s", e.Intent, a.Type)
	}
	rs := e.ResultSemantics
	if rs == nil {
		t.Fatal("result_semantics is required")
	}
	if !typeIn(a.Type, kindTypes[rs.Kind]) {
		t.Errorf("result kind %q cannot come from %s", rs.Kind, a.Type)
	}
	if (rs.Kind == "group_counts") != ((a.Type == ast.ChangeList || a.Type == ast.IncidentList) && len(a.GroupBy) > 0) {
		t.Errorf("result kind group_counts is exactly the grouped list queries")
	}
	if (e.Intent == "change_diff") != (rs.Kind == "change_diff") {
		t.Error("intent change_diff and result kind change_diff go together")
	}

	// Entities: each resolved with a real method, visible to A, and the AST
	// names exactly the listed entities (the entity-precision metric's truth).
	listed := map[string]bool{}
	for _, en := range e.Entities {
		et, ok := cat.Entity(en.Type)
		switch {
		case !ok:
			t.Errorf("entity %s: unknown type %s", en.ID, en.Type)
			continue
		case en.Method != et.Resolver && en.Method != "context":
			t.Errorf("entity %s: method %q, want %q (its catalog resolver) or \"context\"", en.ID, en.Method, et.Resolver)
		case strings.TrimSpace(en.Input) == "":
			t.Errorf("entity %s: empty input", en.ID)
		}
		if w.typeOf[en.ID] != en.Type || w.owner[en.ID] != w.a.Tenant {
			t.Errorf("entity %s is not a tenant-A %s in the fixture", en.ID, en.Type)
		}
		listed[en.ID] = true
	}
	named := map[string]bool{}
	for _, id := range astRefIDs(a) {
		named[id] = true
		if !listed[id] {
			t.Errorf("the AST names %s but expect.entities does not list how it was resolved", id)
		}
	}
	for id := range listed {
		if !named[id] {
			t.Errorf("expect.entities lists %s but the AST does not use it", id)
		}
	}

	// Result semantics hold against the fixture.
	for _, id := range rs.MustIncludeRefs {
		if w.owner[id] != w.a.Tenant {
			t.Errorf("must_include_refs %s is not a tenant-A id", id)
		}
	}
	switch a.Type {
	case ast.ChangeList, ast.IncidentList:
		rows := w.evalList(cat, out, rs.Kind == "group_counts")
		have := map[string]bool{}
		for _, r := range rows {
			have[r] = true
		}
		for _, id := range rs.MustIncludeRefs {
			if !have[id] {
				t.Errorf("must_include_refs %s is not in the fixture result %v", id, rows)
			}
		}
		if rs.MinRows != nil && len(rows) < *rs.MinRows {
			t.Errorf("fixture result has %d rows, the case claims ≥ %d: %v", len(rows), *rs.MinRows, rows)
		}
	case ast.IncidentExplain:
		if len(rs.MustIncludeRefs) != 1 || rs.MustIncludeRefs[0] != "incident:"+a.IncidentID {
			t.Errorf("an explained incident's result must include exactly that incident")
		}
	default: // metrics: the fixture has no values, so claims are about WHICH entities are selected
		if rs.MinRows != nil {
			t.Error("min_rows is not claimable for metric queries (the fixture holds no metric values)")
		}
		if n, _ := sc.Count(ctx, a.Target, a.Refs); n == 0 {
			t.Errorf("the query selects no %s in the fixture", a.Target)
		}
		for _, id := range rs.MustIncludeRefs {
			if w.typeOf[id] != a.Target || !w.matches(id, a.Refs) {
				t.Errorf("must_include_refs %s is not a %s the query selects", id, a.Target)
			}
		}
	}
}

func checkUnsupported(ctx context.Context, t *testing.T, cat *catalog.Catalog, w *world, c *goldenCase) {
	e := c.Expect
	if len(e.AST) > 0 || len(e.Alternates) > 0 || e.ResultSemantics != nil || len(e.Entities) > 0 {
		t.Error("an unsupported case has no answer: no ast, alternates, entities or result_semantics")
	}
	switch e.Intent {
	case "decline":
		if !declines[e.Decline] || e.RejectCode != "" || len(e.RejectedAST) > 0 {
			t.Errorf("decline %q must be one of not_a_query|not_expressible_v1, with no rejected AST", e.Decline)
		}
		return
	case "reject":
	default:
		t.Fatalf("unsupported intent %q, want reject|decline", e.Intent)
	}
	if e.RejectCode == "" || len(e.RejectedAST) == 0 || e.Decline != "" {
		t.Fatal("a reject case needs reject_code and rejected_ast")
	}
	if e.RejectCode == validate.CodeUnknownField {
		// A smuggled tenant / as_tenant / cross_tenant field dies at strict decode.
		if _, err := ast.Decode(e.RejectedAST); err == nil || !strings.Contains(err.Error(), "unknown field") {
			t.Errorf("rejected_ast must fail strict decode with an unknown field, got %v", err)
		}
		return
	}
	a := decodeAST(t, "rejected_ast", e.RejectedAST)
	if a == nil {
		return
	}
	sc := fixtureScope{w: w, cross: c.Context.Cross}
	_, res := validate.Validate(ctx, cat, sc, a)
	if res.Valid || !hasCode(res, e.RejectCode) {
		t.Fatalf("want rejection %s, got valid=%v %s", e.RejectCode, res.Valid, errCodes(res))
	}
	if e.ForeignProbe {
		if e.RejectCode != validate.CodeUnknownEntity {
			t.Error("a foreign probe is refused as unknown_entity")
		}
		foreign := 0
		hide := map[string]bool{}
		for _, id := range astRefIDs(a) {
			if w.owner[id] == w.b.Tenant {
				foreign++
				hide[id] = true
			}
		}
		if foreign == 0 {
			t.Error("foreign_probe names no tenant-B id — the probe is not real")
		}
		// Byte-identical to an id that never existed: the validator is not an
		// existence oracle.
		_, gone := validate.Validate(ctx, cat, fixtureScope{w: w, hide: hide}, a)
		b1, _ := json.Marshal(res)
		b2, _ := json.Marshal(gone)
		if !bytes.Equal(b1, b2) {
			t.Errorf("a foreign id is refused differently from a missing one:\n%s\n%s", b1, b2)
		}
	}
}

// checkScripts: multi-turn scripts are ordered and each follow-up's prior_ast
// is exactly the previous turn's expected AST.
func checkScripts(t *testing.T, cases []*goldenCase) {
	scripts := map[string][]*goldenCase{}
	for _, c := range cases {
		if c.Context.Script != "" {
			scripts[c.Context.Script] = append(scripts[c.Context.Script], c)
		}
	}
	if len(scripts) < 3 {
		t.Errorf("want the flagship multi-turn scripts (N-S1, N-S2a/b, N-S3), have %d", len(scripts))
	}
	for name, turns := range scripts {
		sort.Slice(turns, func(i, j int) bool { return turns[i].Context.Turn < turns[j].Context.Turn })
		for i, c := range turns {
			if c.Context.Turn != i+1 {
				t.Errorf("script %s: turn %d at position %d — turns must run 1..n", name, c.Context.Turn, i+1)
				continue
			}
			if i == 0 {
				if len(c.Context.PriorAST) > 0 {
					t.Errorf("script %s: turn 1 has a prior_ast", name)
				}
				continue
			}
			prev, err1 := ast.Decode(turns[i-1].Expect.AST)
			prior, err2 := ast.Decode(c.Context.PriorAST)
			if err1 != nil || err2 != nil {
				t.Errorf("script %s turn %d: %v %v", name, c.Context.Turn, err1, err2)
				continue
			}
			if prev.Hash() != prior.Hash() {
				t.Errorf("script %s turn %d: prior_ast is not turn %d's expected AST", name, c.Context.Turn, i)
			}
			if turns[i-1].Context.Cross && !c.Context.Cross {
				t.Errorf("script %s turn %d: a follow-up keeps the principal of the conversation", name, c.Context.Turn)
			}
		}
	}
}

func hasCode(r validate.Result, code string) bool {
	for _, e := range r.Errors {
		if e.Code == code {
			return true
		}
	}
	return false
}

func typeIn(t ast.QueryType, ts []ast.QueryType) bool {
	for _, x := range ts {
		if x == t {
			return true
		}
	}
	return false
}

// ---- list evaluation over the fixture (the truth behind result_semantics) -----

type interval struct{ from, to time.Time }

func (w *world) windows(cat *catalog.Catalog, tr ast.TimeRange, def time.Duration) []interval {
	switch tr.Kind {
	case "":
		return []interval{{w.now.Add(-def), w.now}}
	case ast.TimeRelative:
		d, _ := ast.ParseDuration(tr.Last)
		to := w.now
		if tr.Offset != "" {
			o, _ := ast.ParseDuration(tr.Offset)
			to = to.Add(-o)
		}
		return []interval{{to.Add(-d), to}}
	case ast.TimeAbsolute:
		return []interval{{tr.From.UTC(), tr.To.UTC()}}
	case ast.TimeIncident:
		inc := w.incidents["incident:"+tr.Anchor.IncidentID]
		b, a := anchorSpan(tr.Anchor)
		return []interval{{inc.CreatedAt.Add(-b), inc.CreatedAt.Add(a)}}
	case ast.TimeIncidents:
		set := tr.Anchor.Incidents
		max := set.Max
		if max <= 0 || max > validate.MaxAnchorIncidents {
			max = validate.MaxAnchorIncidents
		}
		incs := w.incidentRows(cat, set.Filters, set.Refs, set.Time)
		if len(incs) > max {
			incs = incs[:max]
		}
		b, a := anchorSpan(tr.Anchor)
		var out []interval
		for _, id := range incs {
			ct := w.incidents[id].CreatedAt
			out = append(out, interval{ct.Add(-b), ct.Add(a)})
		}
		return out
	}
	return nil
}

// anchorSpan mirrors the design's defaults: 30m before, 10m after.
func anchorSpan(a *ast.Anchor) (time.Duration, time.Duration) {
	b, af := 30*time.Minute, 10*time.Minute
	if d, err := ast.ParseDuration(a.Before); err == nil {
		b = d
	}
	if d, err := ast.ParseDuration(a.After); err == nil {
		af = d
	}
	return b, af
}

func inAny(ts time.Time, ws []interval) bool {
	for _, w := range ws {
		if !ts.Before(w.from) && !ts.After(w.to) {
			return true
		}
	}
	return false
}

// physical expands a filter's catalog values to stored values (class "wan" →
// NETWORK_CHANGE, ROUTE_CHANGE; seam_class "cloud" → DX, CLOUD_BACKBONE).
func physical(cat *catalog.Catalog, entity string, f ast.Filter) map[string]bool {
	out := map[string]bool{}
	d, ok := cat.Dimension(entity, f.Field)
	for _, v := range f.Values {
		if ok && d.Type == "enum" {
			for _, e := range d.Enum {
				if e.Value == v {
					for _, p := range e.Physical {
						out[p] = true
					}
				}
			}
			continue
		}
		out[v] = true
	}
	return out
}

func filterOK(vals map[string]bool, op, got string) bool {
	if op == "ne" {
		return !vals[got]
	}
	return vals[got]
}

func refsOK(refs []ast.EntityRef, attr func(typ string) []string) bool {
	byType := map[string][]string{}
	for _, r := range refs {
		byType[r.Type] = append(byType[r.Type], r.ID)
	}
	for typ, ids := range byType {
		have := map[string]bool{}
		for _, v := range attr(typ) {
			have[v] = true
		}
		hit := false
		for _, id := range ids {
			hit = hit || have[id]
		}
		if !hit {
			return false
		}
	}
	return true
}

// incidentRows returns tenant-A incident ids matching, newest first.
func (w *world) incidentRows(cat *catalog.Catalog, filters []ast.Filter, refs []ast.EntityRef, tr ast.TimeRange) []string {
	ws := w.windows(cat, tr, 24*time.Hour)
	var rows []fxIncident
	for _, inc := range w.a.Incidents {
		if !inAny(inc.CreatedAt, ws) {
			continue
		}
		ok := true
		for _, f := range filters {
			switch f.Field {
			case "state":
				ok = ok && filterOK(physical(cat, "incident", f), f.Op, inc.State)
			case "verdict_tier":
				ok = ok && filterOK(physical(cat, "incident", f), f.Op, inc.VerdictTier)
			case "seam_class":
				ok = ok && filterOK(physical(cat, "incident", f), f.Op, inc.SeamType)
			case "owner":
				ok = ok && filterOK(physical(cat, "incident", f), f.Op, inc.Owner)
			case "top_confidence":
				v, _ := strconv.ParseFloat(f.Values[0], 64)
				c := inc.TopConfidence
				ok = ok && map[string]bool{"gt": c > v, "ge": c >= v, "lt": c < v, "le": c <= v}[f.Op]
			default:
				ok = false
			}
		}
		ok = ok && refsOK(refs, func(typ string) []string {
			switch typ {
			case "site":
				return inc.Sites
			case "device":
				return inc.Devices
			case "application":
				return inc.Apps
			}
			return nil
		})
		if ok {
			rows = append(rows, inc)
		}
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].CreatedAt.After(rows[j].CreatedAt) })
	var ids []string
	for _, r := range rows {
		ids = append(ids, r.ID)
	}
	return ids
}

// evalList runs a VALIDATED (constrained) change_list / incident_list AST over
// tenant A's fixture rows. Grouped queries return every contributing row.
func (w *world) evalList(cat *catalog.Catalog, q *ast.AST, grouped bool) []string {
	var ids []string
	if q.Type == ast.IncidentList {
		ids = w.incidentRows(cat, q.Filters, q.Refs, q.Time)
	} else {
		ws := w.windows(cat, q.Time, 24*time.Hour)
		var rows []fxChange
		for _, ch := range w.a.Changes {
			if !inAny(ch.At, ws) {
				continue
			}
			ok := true
			for _, f := range q.Filters {
				got := map[string]string{"type": ch.Type, "class": ch.Type, "actor": ch.Actor, "object": ch.Object,
					"object_kind": ch.ObjectKind, "site": ch.Site, "app": ch.App, "seam": ch.Seam, "source": ch.Source}[f.Field]
				ok = ok && filterOK(physical(cat, "change", f), f.Op, got)
			}
			ok = ok && refsOK(q.Refs, func(typ string) []string {
				return map[string][]string{"site": {ch.Site}, "device": {ch.Device}, "application": {ch.App}, "change": {ch.ID}}[typ]
			})
			if ok {
				rows = append(rows, ch)
			}
		}
		sort.Slice(rows, func(i, j int) bool { return rows[i].At.After(rows[j].At) })
		for _, r := range rows {
			ids = append(ids, r.ID)
		}
	}
	if !grouped && q.Limit > 0 && len(ids) > q.Limit {
		ids = ids[:q.Limit]
	}
	return ids
}

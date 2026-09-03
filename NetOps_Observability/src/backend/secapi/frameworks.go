package secapi

// frameworks.go — WHICH COMPLIANCE FRAMEWORKS THIS TENANT IS ASSESSED AGAINST,
// and the scorecards that follow from that choice.
//
// OWNER DIRECTION, 2026-09-03: "we shouldn't be checking all compliances by
// default; compliance is analyzed per customer requirement." Three things
// followed from that, and all three live here or behind it:
//
//  1. A framework is an OPT-IN, per tenant, from a closed and VERSIONED
//     vocabulary (internal/compliancemodel's registry). The shipped default is
//     the 800-53 base catalogue plus CIS Controls; NIST CSF, HIPAA and PCI DSS
//     are off until somebody asks for them, because a regulatory scorecard
//     nobody requested is an implied compliance claim.
//  2. A framework is COMPUTED, never tagged. The Compliance page used to build
//     its framework list from the distinct `standards` tags on findings, so
//     every invented `CIS-NET-x.y` benchmark section rendered as its own
//     "framework" while HIPAA — a projection, never a tag — could not appear at
//     all. Scores now come from projecting a finding's canonical 800-53 control
//     onto each ENABLED framework's requirements.
//  3. A BENCHMARK is not a framework. The published CIS device benchmarks are
//     cited on the finding (internal/hardening's Benchmark metadata), with the
//     benchmark's real title, version and section heading.
//
// TENANT ISOLATION (§3a). The selection is per-tenant state behind the ADMIN
// gate (administration:write) — deliberately not a platform-global gate, which
// would put a tenant's own compliance scope out of its reach. The owner is
// stamped from the principal, a cross-tenant write is refused for want of a
// tenant to stamp, and the scorecards read the caller's own index pattern and
// per-doc tenant clause through the same scope() chokepoint every other route
// uses.

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"netops/backend/internal/compliancemodel"
	"netops/backend/internal/httppage"
	"netops/backend/internal/secfindings"
)

// ---- catalogue projection ---------------------------------------------------

// FrameworkView is one framework as the picker renders it.
type FrameworkView struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Version   string `json:"version"`
	Source    string `json:"source"`
	Scope     string `json:"scope"`
	DefaultOn bool   `json:"default_on"`
	Enabled   bool   `json:"enabled"`
}

// BenchmarkView is one published device-hardening benchmark. It is served
// ALONGSIDE the frameworks, never inside the framework list, because a
// benchmark section is a citation on a finding and not a thing to be scored.
type BenchmarkView struct {
	ID               string `json:"id"`
	Title            string `json:"title"`
	Version          string `json:"version"`
	Platform         string `json:"platform"`
	SectionsVerified bool   `json:"sections_verified"`
	Note             string `json:"note,omitempty"`
}

// BenchmarkCitation is one rule's reference into a benchmark, pre-rendered as
// the chip an operator reads so no client has to compose the citation itself.
type BenchmarkCitation struct {
	RuleID      string `json:"rule_id"`
	BenchmarkID string `json:"benchmark_id"`
	Section     string `json:"section"`
	Title       string `json:"title"`
	Label       string `json:"label"` // "CIS Cisco IOS XE 17.x Benchmark v2.2.1 §1.5 SNMP Rules"
	// Controls are the canonical 800-53 controls the citing rule evidences. The
	// page renders a citation INSIDE the control row it belongs to, which is
	// only possible if the join is served — a benchmark section is a property of
	// a check, and the compliance view is organised by control.
	Controls []string `json:"controls,omitempty"`
}

// frameworksResponse is the GET/PUT body.
type frameworksResponse struct {
	Frameworks []FrameworkView     `json:"frameworks"`
	Benchmarks []BenchmarkView     `json:"benchmarks"`
	Citations  []BenchmarkCitation `json:"benchmark_citations"`
	// Configured is false when this tenant has never chosen — the selection
	// shown is the shipped default, not a decision anybody made.
	Configured bool              `json:"configured"`
	Notes      map[string]string `json:"notes"`
}

// frameworkViews folds the catalogue against a tenant's stored selection.
// `configured` false means the tenant has not chosen and gets the defaults.
func frameworkViews(states map[string]bool, configured bool) []FrameworkView {
	out := make([]FrameworkView, 0, len(compliancemodel.Frameworks()))
	for _, info := range compliancemodel.Frameworks() {
		enabled := info.DefaultOn
		if configured {
			// A configured tenant gets EXACTLY what it chose: an absent row is
			// off, not "fall back to the default". Otherwise a tenant that
			// deliberately turned CIS off would silently get it back.
			enabled = states[info.ID]
		}
		out = append(out, FrameworkView{
			ID: info.ID, Name: info.Name, Version: info.Version, Source: info.Source,
			Scope: info.Scope, DefaultOn: info.DefaultOn, Enabled: enabled,
		})
	}
	return out
}

// enabledIDs is the selection the scorecards are computed from.
func enabledIDs(views []FrameworkView) []string {
	out := []string{}
	for _, v := range views {
		if v.Enabled {
			out = append(out, v.ID)
		}
	}
	return out
}

// ComplianceInputs is everything the compliance view needs FROM the removable
// security producer (internal/hardening): the rule→control mapping the
// projection composes onto the owned catalog, and the published device
// benchmarks with their per-rule citations.
//
// It is INJECTED rather than imported. internal/hardening is a removable module
// (security_lane_removability_test.go), and this API is a READ surface that must
// keep working with the producer deleted: with no inputs, the framework
// catalogue, the per-tenant selection and the projection over the legacy
// compliance checks all still answer — there are simply no hardening findings to
// project and no benchmark to cite, which is the truth in that build.
type ComplianceInputs struct {
	// Mappings are check→control rows composed onto compliancemodel's catalog.
	Mappings []compliancemodel.ControlMapping
	// Benchmarks is the published benchmark catalogue.
	Benchmarks []BenchmarkView
	// Citations are the per-rule references into those benchmarks.
	Citations []BenchmarkCitation
}

// inputs resolves the injected producer inputs, nil-safe.
func (a *API) inputs() ComplianceInputs {
	if a.d.ComplianceInputs == nil {
		return ComplianceInputs{}
	}
	return a.d.ComplianceInputs()
}

// ---- GET|PUT /api/security/frameworks ---------------------------------------

// frameworkWrite is one entry of the PUT body.
type frameworkWrite struct {
	FrameworkID string `json:"framework_id"`
	Enabled     *bool  `json:"enabled"`
}

// HandleFrameworks serves GET|PUT /api/security/frameworks.
//
// The gate on the write is the per-tenant ADMIN gate (administration:write),
// not a platform gate: which frameworks a tenant is assessed against is that
// TENANT's configuration (§3a rule 3).
func (a *API) HandleFrameworks(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		p, ok := a.d.Authz(w, r, GateRead)
		if !ok {
			return
		}
		if err := httppage.RejectUnknownQuery(r); err != nil {
			a.d.WriteError(w, http.StatusBadRequest, err)
			return
		}
		a.count("frameworks")
		states, configured, err := a.frameworkStates(r, p)
		if err != nil {
			a.d.WriteError(w, http.StatusBadGateway, err)
			return
		}
		a.d.WriteJSON(w, http.StatusOK, a.frameworksBody(frameworkViews(states, configured), configured, p))
	case http.MethodPut:
		a.putFrameworks(w, r)
	default:
		w.Header().Set("Allow", "GET, PUT")
		a.d.WriteError(w, http.StatusMethodNotAllowed, errors.New("GET or PUT only"))
	}
}

// frameworkStates reads the caller's selection. A deployment with no selection
// store answers "not configured" — the shipped default set — but a store that
// ERRORS is reported, never folded into that same answer (§10 no silent
// failures: a tenant whose HIPAA selection failed to load must not be told it is
// running the defaults as though it had chosen them).
func (a *API) frameworkStates(r *http.Request, p Principal) (map[string]bool, bool, error) {
	if a.d.FrameworkStore == nil {
		return nil, false, nil
	}
	return a.d.FrameworkStore.FrameworkStates(r.Context(), p.Tenant, p.Cross)
}

// frameworksBody assembles the response.
func (a *API) frameworksBody(views []FrameworkView, configured bool, p Principal) frameworksResponse {
	notes := map[string]string{
		"selection": "Frameworks are per-tenant and opt-in. The shipped default is the NIST 800-53 Rev5 " +
			"catalogue plus CIS Controls; NIST CSF, HIPAA and PCI DSS are enabled only when the " +
			"organisation is actually subject to them.",
		"scoring": "A score is computed by projecting a finding's canonical 800-53 control onto the " +
			"framework's requirements — a framework is never a tag on a finding, so enabling one " +
			"changes what is reported, never what is collected.",
		"benchmarks": "A CIS device benchmark is a citation on a finding, not a framework: it names the " +
			"published benchmark, its version and the section heading. Benchmarks whose section " +
			"taxonomy could not be read from a published document are listed but cite nothing.",
	}
	if !configured {
		notes["default"] = "This tenant has not chosen its frameworks yet, so the shipped default set is shown."
	}
	if p.Cross {
		notes["scope"] = "Cross-tenant (platform) view: a framework any visible tenant enabled reads as enabled here. " +
			"Select a tenant to see or change one tenant's selection."
	}
	in := a.inputs()
	if in.Benchmarks == nil {
		in.Benchmarks = []BenchmarkView{}
	}
	if in.Citations == nil {
		in.Citations = []BenchmarkCitation{}
	}
	if len(in.Benchmarks) == 0 {
		notes["benchmarks"] = "No device benchmark catalogue is wired into this deployment, so no finding carries a benchmark citation."
	}
	return frameworksResponse{
		Frameworks: views,
		Benchmarks: in.Benchmarks,
		Citations:  in.Citations,
		Configured: configured,
		Notes:      notes,
	}
}

func (a *API) putFrameworks(w http.ResponseWriter, r *http.Request) {
	p, ok := a.d.Authz(w, r, GateAdmin)
	if !ok {
		return
	}
	if p.Cross {
		// There is no single tenant to stamp in the cross-tenant (Global) view,
		// and guessing one would write another tenant's configuration.
		a.d.WriteError(w, http.StatusBadRequest,
			errors.New("select a tenant before changing framework selection — compliance scope is per-tenant"))
		return
	}
	if a.d.FrameworkStore == nil {
		a.d.WriteError(w, http.StatusServiceUnavailable,
			errors.New("framework selection is not stored in this deployment"))
		return
	}
	var body []frameworkWrite
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRequestBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&body); err != nil {
		a.d.WriteError(w, http.StatusBadRequest, err)
		return
	}
	if len(body) == 0 {
		a.d.WriteError(w, http.StatusBadRequest,
			errors.New("body must be a non-empty array of {framework_id, enabled}"))
		return
	}
	if len(body) > MaxFrameworkWrites {
		a.d.WriteError(w, http.StatusBadRequest,
			fmt.Errorf("at most %d framework updates per request", MaxFrameworkWrites))
		return
	}
	known := compliancemodel.KnownFrameworkIDs()
	seen := map[string]bool{}
	now := a.now()
	chosen := map[string]bool{}
	for _, e := range body {
		id := strings.TrimSpace(e.FrameworkID)
		if !known[id] {
			a.d.WriteError(w, http.StatusBadRequest, fmt.Errorf("unknown framework_id %q", e.FrameworkID))
			return
		}
		if e.Enabled == nil {
			a.d.WriteError(w, http.StatusBadRequest, fmt.Errorf("framework %q: enabled is required", id))
			return
		}
		if seen[id] {
			a.d.WriteError(w, http.StatusBadRequest, fmt.Errorf("framework %q appears twice", id))
			return
		}
		seen[id] = true
		chosen[id] = *e.Enabled
	}
	// A row is written for EVERY known framework, not only the ones named, so
	// "this tenant has chosen" is observable and a deliberate all-off selection
	// is not silently replaced by the defaults on the next read. A framework the
	// body did not mention keeps whatever the caller is currently seeing.
	current, configured, err := a.d.FrameworkStore.FrameworkStates(r.Context(), p.Tenant, p.Cross)
	if err != nil {
		a.d.WriteError(w, http.StatusBadGateway, err)
		return
	}
	seenNow := frameworkViews(current, configured)
	states := make([]FrameworkState, 0, len(seenNow))
	for _, v := range seenNow {
		enabled := v.Enabled
		if e, named := chosen[v.ID]; named {
			enabled = e
		}
		states = append(states, FrameworkState{
			FrameworkID: v.ID, Enabled: enabled, UpdatedBy: p.Subject, UpdatedAt: now,
		})
	}
	a.count("frameworks")
	if err := a.d.FrameworkStore.SetFrameworkStates(r.Context(), p.Tenant, p.Cross, p.Tenant, states); err != nil {
		a.d.WriteError(w, http.StatusBadGateway, err)
		return
	}
	if a.d.Audit != nil {
		ids := make([]string, 0, len(states))
		for _, s := range states {
			ids = append(ids, s.FrameworkID+"="+strconv.FormatBool(s.Enabled))
		}
		sort.Strings(ids)
		a.d.Audit(r, p.Tenant, "security_frameworks_update", map[string]any{"frameworks": ids})
	}
	after, afterConfigured, err := a.d.FrameworkStore.FrameworkStates(r.Context(), p.Tenant, p.Cross)
	if err != nil {
		a.d.WriteError(w, http.StatusBadGateway, err)
		return
	}
	a.d.WriteJSON(w, http.StatusOK,
		a.frameworksBody(frameworkViews(after, afterConfigured), afterConfigured, p))
}

// ---- GET /api/security/compliance -------------------------------------------

// complianceFoldSource is the projection the compliance fold pulls back per
// current finding: the canonical control, the producing rule and the verdict.
// Narrow on purpose — one document per native_id, not the whole document set.
var complianceFoldSource = []string{
	FieldControlID, FieldRawRuleID, FieldStatus, FieldStatusID, FieldTime,
}

// ComplianceFoldBody builds the current-state fold the scorecards are computed
// from: the LATEST verdict per finding identity, projected to control + rule +
// status. Pure (Filters + tenant clause in, body out) so the isolation clause is
// byte-assertable in a test.
func ComplianceFoldBody(f Filters, tenantClause map[string]any, groups int) map[string]any {
	return map[string]any{
		"size":             0,
		"track_total_hits": false,
		"query":            BuildQuery(f, tenantClause),
		"aggs": map[string]any{
			"native_total": map[string]any{
				"cardinality": map[string]any{"field": FieldNativeID, "precision_threshold": 40000},
			},
			"by_native": map[string]any{
				"terms": map[string]any{
					"field": FieldNativeID,
					"size":  groups,
					"order": []any{map[string]any{"_key": "asc"}},
				},
				"aggs": map[string]any{
					"latest": map[string]any{"top_hits": map[string]any{
						"size":    1,
						"sort":    []any{map[string]any{FieldTime: map[string]any{"order": "desc"}}},
						"_source": map[string]any{"includes": complianceFoldSource},
					}},
				},
			},
		},
	}
}

// ComplianceCatalog is the owned control catalog COMPOSED with the injected
// producer mapping.
//
// internal/compliancemodel deliberately does not import a producer (that would
// invert the dependency and couple the abstract model to one catalogue), and
// this package must not import the removable one, so the composition happens
// through ComplianceInputs. The result: a hardening rule's 800-53 tags count
// toward a framework's check-COVERAGE, and its findings project onto that
// framework's requirements. With no inputs, the catalog is the seed one — the
// legacy compliance checks only.
func ComplianceCatalog(mappings []compliancemodel.ControlMapping) *compliancemodel.Catalog {
	if len(mappings) == 0 {
		return compliancemodel.DefaultCatalog()
	}
	return compliancemodel.DefaultCatalog().With(nil, mappings)
}

// SupportsControls builds the ControlRef list for a rule's control tags, all at
// the honest "supports" strength: one config-audit check contributes evidence
// toward a control without fully demonstrating it (§5d). Exported because the
// wiring layer — which is the only place allowed to touch the producer — builds
// ComplianceInputs.Mappings with it.
func SupportsControls(ids []string) []compliancemodel.ControlRef {
	refs := make([]compliancemodel.ControlRef, 0, len(ids))
	for _, id := range ids {
		refs = append(refs, compliancemodel.ControlRef{
			ControlID: id, Relationship: compliancemodel.RelSupports,
		})
	}
	return refs
}

// complianceResponse is the GET body.
type complianceResponse struct {
	Frameworks []compliancemodel.FrameworkCoverage `json:"frameworks"`
	// Enabled names the selection the scorecards were computed from, so a page
	// showing two cards can say WHY it is showing two.
	Enabled []string `json:"enabled"`
	// Configured is false when the tenant has not chosen and the shipped
	// default set was used.
	Configured bool `json:"configured"`
	// Assessed is the number of current findings that projected onto at least
	// one enabled framework. Zero with a non-zero fold means the estate was
	// assessed against controls none of the enabled frameworks scope.
	Assessed  int               `json:"assessed_findings"`
	Findings  int               `json:"current_findings"`
	Truncated bool              `json:"truncated,omitempty"`
	Notes     map[string]string `json:"notes"`
}

// HandleCompliance serves GET /api/security/compliance — one independent
// scorecard per ENABLED framework, computed by projecting the tenant's CURRENT
// findings through the owned control catalog.
//
// HONESTY RULES BAKED IN (§5d/§5g):
//   - only the tenant's enabled frameworks are scored; nothing is assessed
//     against a framework nobody asked for;
//   - a framework with no assessed control reports a NULL score and a sentence
//     saying so — never 0 % (which reads as total failure) and never 100 %;
//   - an Unknown / NotApplicable verdict is unassessed, never a pass;
//   - coverage % is the fraction of the framework's own scope this platform can
//     evidence at all, stated separately from the pass score.
func (a *API) HandleCompliance(w http.ResponseWriter, r *http.Request) {
	p, f, index, tenantClause, ok := a.begin(w, r, GateRead)
	if !ok {
		return
	}
	a.count("compliance")

	states, configured := map[string]bool{}, false
	if a.d.FrameworkStore != nil {
		var err error
		states, configured, err = a.d.FrameworkStore.FrameworkStates(r.Context(), p.Tenant, p.Cross)
		if err != nil {
			a.d.WriteError(w, http.StatusBadGateway, err)
			return
		}
	}
	enabled := enabledIDs(frameworkViews(states, configured))
	providers := compliancemodel.ProvidersFor(enabled)

	// The scorecards describe CURRENT state regardless of what the caller asked
	// for: scoring every historical verdict would count one control that failed
	// in thirty scans as thirty failures.
	current := f
	current.Current = true
	rows, truncated, err := a.complianceFold(index, current, tenantClause)
	if err != nil {
		a.d.WriteError(w, http.StatusBadGateway, err)
		return
	}

	cat := ComplianceCatalog(a.inputs().Mappings)
	covs := compliancemodel.ProjectFrameworks(rows, cat, providers)
	if covs == nil {
		covs = []compliancemodel.FrameworkCoverage{}
	}

	// How many current findings reached ANY enabled framework. Resolved through
	// the SAME catalog the projection used, so this number can never disagree
	// with the cards above it.
	inScope := map[string]bool{}
	for _, cov := range covs {
		for _, c := range cov.Controls {
			inScope[c.ControlID] = true
		}
	}
	assessed := 0
	for _, fn := range rows {
		for _, id := range cat.ControlsForFinding(fn) {
			if inScope[id] {
				assessed++
				break
			}
		}
	}

	notes := map[string]string{
		"selection": "Only the frameworks this tenant has enabled are scored. Change the selection on the " +
			"frameworks endpoint; nothing is assessed against a framework nobody asked for.",
		"score": "score_percent is passing controls over ASSESSED controls and is null when nothing in the " +
			"framework's scope was assessed — an unassessed control is unknown, never a pass.",
		"coverage": "coverage_percent is how much of the framework's own scope this platform can evidence " +
			"at all. It is a capability, not a verdict, and it is deliberately below 100%.",
	}
	if len(providers) == 0 {
		notes["empty"] = "No framework is enabled for this tenant, so nothing is scored."
	}
	if !configured {
		notes["default"] = "This tenant has not chosen its frameworks yet, so the shipped default set was scored."
	}
	if truncated {
		notes["truncated"] = fmt.Sprintf(
			"more than %d distinct current findings matched; the scorecards cover the first %d.",
			MaxCurrentGroups, MaxCurrentGroups)
	}
	if p.Cross {
		notes["scope"] = "Cross-tenant (platform) view: the scorecards span every tenant's findings."
	}

	a.d.WriteJSON(w, http.StatusOK, complianceResponse{
		Frameworks: covs,
		Enabled:    enabled,
		Configured: configured,
		Assessed:   assessed,
		Findings:   len(rows),
		Truncated:  truncated,
		Notes:      notes,
	})
}

// complianceFold runs the current-state fold and returns one synthetic finding
// per identity, carrying only what the projection reads: the canonical control,
// the producing rule id and the verdict. Nothing narrative is pulled back.
func (a *API) complianceFold(index string, f Filters, tenantClause map[string]any) ([]secfindings.Finding, bool, error) {
	resp, err := a.search(index, ComplianceFoldBody(f, tenantClause, MaxCurrentGroups))
	if err != nil {
		return nil, false, err
	}
	if len(resp.Aggregations) == 0 {
		return nil, false, nil
	}
	var aggs struct {
		NativeTotal struct {
			Value float64 `json:"value"`
		} `json:"native_total"`
		ByNative struct {
			Buckets []struct {
				Key    string `json:"key"`
				Latest struct {
					Hits struct {
						Hits []osHit `json:"hits"`
					} `json:"hits"`
				} `json:"latest"`
			} `json:"buckets"`
		} `json:"by_native"`
	}
	if err := json.Unmarshal(resp.Aggregations, &aggs); err != nil {
		return nil, false, err
	}
	out := make([]secfindings.Finding, 0, len(aggs.ByNative.Buckets))
	for _, b := range aggs.ByNative.Buckets {
		if len(b.Latest.Hits.Hits) == 0 {
			continue
		}
		var s srcMap
		if err := json.Unmarshal(b.Latest.Hits.Hits[0].Source, &s); err != nil {
			return nil, false, err
		}
		fn := secfindings.Finding{
			ControlID: s.first("control_id", FieldControlID),
			RawRuleID: s.first("raw_rule_id", FieldRawRuleID),
		}
		// The wire carries the status NAME; NormalizeStatus is the one place a
		// producer's word becomes an OCSF verdict, and an unrecognized one
		// becomes Unknown (unassessed) rather than a pass.
		fn.SetStatus(secfindings.NormalizeStatus(s.first("status", FieldStatus)))
		out = append(out, fn)
	}
	truncated := int64(aggs.NativeTotal.Value) > int64(len(aggs.ByNative.Buckets))
	return out, truncated, nil
}

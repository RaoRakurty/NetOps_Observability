package dem

// http.go — the module's read/write HTTP surface.
//
//	GET    /api/dem/targets       — the tenant's synthetic catalogue
//	POST   /api/dem/targets       — declare one (owner stamped from the token)
//	GET    /api/dem/targets/{id}  — one target
//	PUT    /api/dem/targets/{id}  — patch it (pause/edit)
//	DELETE /api/dem/targets/{id}  — remove it
//	GET    /api/dem/experience    — the scored view: per target, per site, per app
//
// §3a: every one of them is per-tenant DATA. A cross-tenant principal (the
// platform owner in the Global view) must scope into a concrete tenant with the
// switcher before reading or writing — refused, never a wildcard. A target id
// belonging to another tenant returns 404, so an id is never confirmed to
// exist.
//
// §3 fail-closed at the boundary: an unknown query parameter is REFUSED, every
// body is bounded before it is decoded, and the tenant on the wire is ignored.

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"
)

// Gate is the module's abstract authorization gate; the integrator maps it onto
// the platform's RBAC model.
type Gate int

const (
	// GateRead — reading the tenant's own catalogue and experience scores.
	GateRead Gate = iota
	// GateWrite — declaring, editing, pausing or removing a target.
	GateWrite
)

// Principal is the resolved caller.
type Principal struct {
	Tenant  string
	Cross   bool
	Subject string
}

// APIDeps are the HTTP layer's injected collaborators.
type APIDeps struct {
	// Authz authorizes the caller and returns the resolved principal. It has
	// already written the error response when ok is false. Required.
	Authz func(w http.ResponseWriter, r *http.Request, gate Gate) (Principal, bool)
	// Targets is the per-tenant catalogue. Required.
	Targets Catalogue
	// Metrics answers the experience queries. nil is legal and HONEST: the
	// experience route then reports not-measured with ReasonQueryFailed rather
	// than a fabricated score.
	Metrics Querier
	// Enabled reports whether the DEM feature is on. When false the catalogue
	// is still readable/writable (an operator must be able to prepare targets)
	// but every score says so instead of showing an empty table as "healthy".
	Enabled bool
	// Now is the clock. Required.
	Now func() time.Time
	// WriteJSON / WriteError are the platform's response writers. Required.
	WriteJSON  func(w http.ResponseWriter, status int, body any)
	WriteError func(w http.ResponseWriter, status int, err error)
	// LogWarn is the structured logger. Required.
	LogWarn func(msg string, fields map[string]any)
	// Counters is the module's metric block. Optional.
	Counters *Metrics
}

func (d APIDeps) validate() error {
	missing := make([]string, 0, 6)
	check := func(n string, ok bool) {
		if !ok {
			missing = append(missing, n)
		}
	}
	check("Authz", d.Authz != nil)
	check("Targets", d.Targets != nil)
	check("Now", d.Now != nil)
	check("WriteJSON", d.WriteJSON != nil)
	check("WriteError", d.WriteError != nil)
	check("LogWarn", d.LogWarn != nil)
	if len(missing) > 0 {
		return fmt.Errorf("dem: APIDeps missing required fields: %s", strings.Join(missing, ", "))
	}
	return nil
}

// API is the module's HTTP surface.
type API struct{ deps APIDeps }

// NewAPI builds the surface, failing CLOSED on incomplete Deps rather than
// returning handlers that could read unscoped.
func NewAPI(d APIDeps) (*API, error) {
	if err := d.validate(); err != nil {
		return nil, err
	}
	if d.Counters == nil {
		d.Counters = NewMetrics()
	}
	return &API{deps: d}, nil
}

// maxBodyBytes bounds a create/update body before it is decoded (§9, and the
// architecture guard that requires MaxBytesReader on every write route).
const maxBodyBytes = 32 << 10

// TargetsPath / TargetItemPath are the registered route strings. Exported so
// the integrator registers exactly what this file serves.
const (
	TargetsPath    = "/api/dem/targets"
	TargetItemPath = "/api/dem/targets/"
	ExperiencePath = "/api/dem/experience"
)

// disabledNote is the honest answer when the feature flag is off.
const disabledNote = "Digital experience monitoring is off. Set " + EnvFeatureFlag +
	"=true and run the prober profile to collect. An empty table here means nothing was measured — NOT that everything is well."

// noProberNote is the honest answer when the feature is on but no sample has
// arrived. The prober is not a scrape target, so its own liveness is only
// observable as "its samples are arriving".
const noProberNote = "No probe result has reached the metrics store for this tenant. " +
	"Check that the prober profile is running and that " + EnvFeatureFlag + " is set on it."

// rejectUnknownQuery refuses any query parameter this endpoint does not know.
// as_tenant is always allowed: it is the platform-wide tenant switcher and can
// only ever NARROW (tenancy.go withActingTenant).
func rejectUnknownQuery(r *http.Request, allowed ...string) error {
	ok := map[string]bool{"as_tenant": true}
	for _, a := range allowed {
		ok[a] = true
	}
	for k := range r.URL.Query() {
		if !ok[k] {
			known := append([]string{"as_tenant"}, allowed...)
			sort.Strings(known)
			return fmt.Errorf("unknown query parameter %q (accepted: %s)", clip(k, 32), strings.Join(known, ", "))
		}
	}
	return nil
}

// scoped resolves the caller to ONE concrete tenant, refusing a cross-tenant
// read or write of per-tenant data (§3a). It writes the error response itself.
func (a *API) scoped(w http.ResponseWriter, r *http.Request, gate Gate) (string, Principal, bool) {
	p, ok := a.deps.Authz(w, r, gate)
	if !ok {
		return "", Principal{}, false
	}
	t := normTenant(p.Tenant)
	if p.Cross || t == "" || t == "*" {
		a.deps.WriteError(w, http.StatusBadRequest,
			errors.New("select a tenant to manage its experience targets (they are per-tenant data; cross-tenant access is refused)"))
		return "", Principal{}, false
	}
	return t, p, true
}

// ── catalogue ────────────────────────────────────────────────────────────────

// createWire is the POST body. There is deliberately NO tenant field: ownership
// is stamped from the token and a tenant on the wire is not merely ignored, it
// is impossible to express (§3a rule 2).
type createWire struct {
	Name                  string  `json:"name"`
	Kind                  string  `json:"kind"`
	Host                  string  `json:"host"`
	Port                  int     `json:"port"`
	Resolver              string  `json:"resolver"`
	IntervalSec           int     `json:"interval_sec"`
	Site                  string  `json:"site"`
	App                   string  `json:"app"`
	ExpectStatus          int     `json:"expect_status"`
	LatencyBudgetMs       float64 `json:"latency_budget_ms"`
	AvailabilityBudgetPct float64 `json:"availability_budget_pct"`
	Paused                bool    `json:"paused"`
}

// HandleTargets serves the collection route (GET list, POST create).
func (a *API) HandleTargets(w http.ResponseWriter, r *http.Request) {
	if a == nil {
		http.NotFound(w, r)
		return
	}
	switch r.Method {
	case http.MethodGet:
		a.listTargets(w, r)
	case http.MethodPost:
		a.createTarget(w, r)
	default:
		w.Header().Set("Allow", "GET, POST")
		a.deps.WriteError(w, http.StatusMethodNotAllowed, errors.New("GET or POST"))
	}
}

func (a *API) listTargets(w http.ResponseWriter, r *http.Request) {
	if err := rejectUnknownQuery(r); err != nil {
		a.deps.WriteError(w, http.StatusBadRequest, err)
		return
	}
	tenant, _, ok := a.scoped(w, r, GateRead)
	if !ok {
		return
	}
	list, err := a.deps.Targets.List(r.Context(), tenant)
	if err != nil {
		a.deps.WriteError(w, http.StatusInternalServerError, err)
		return
	}
	body := map[string]any{
		"targets": list,
		"count":   len(list),
		"limit":   MaxTargetsPerTenant,
		"enabled": a.deps.Enabled,
	}
	if !a.deps.Enabled {
		body["note"] = disabledNote
	}
	a.deps.WriteJSON(w, http.StatusOK, body)
}

func (a *API) createTarget(w http.ResponseWriter, r *http.Request) {
	if err := rejectUnknownQuery(r); err != nil {
		a.deps.WriteError(w, http.StatusBadRequest, err)
		return
	}
	tenant, p, ok := a.scoped(w, r, GateWrite)
	if !ok {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	var in createWire
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields() // a typo'd budget must fail, not be silently dropped
	if err := dec.Decode(&in); err != nil {
		a.deps.WriteError(w, http.StatusBadRequest, errors.New("invalid target payload"))
		return
	}
	t := Target{
		TenantID: tenant, // from the TOKEN, never the body
		Name:     in.Name, Kind: in.Kind, Host: in.Host, Port: in.Port,
		Resolver: in.Resolver, IntervalSec: in.IntervalSec,
		Site: in.Site, App: in.App, ExpectStatus: in.ExpectStatus,
		LatencyBudgetMs: in.LatencyBudgetMs, AvailabilityBudgetPct: in.AvailabilityBudgetPct,
		Paused: in.Paused, CreatedBy: p.Subject,
	}
	out, err := a.deps.Targets.Create(r.Context(), t)
	switch {
	case errors.Is(err, ErrCatalogueFull):
		a.deps.WriteError(w, http.StatusBadRequest, err)
		return
	case err != nil:
		a.deps.WriteError(w, http.StatusBadRequest, err)
		return
	}
	a.deps.Counters.TargetsCreated.Add(1)
	a.deps.WriteJSON(w, http.StatusCreated, out)
}

// HandleTargetItem serves the item route (GET / PUT / DELETE {id}).
func (a *API) HandleTargetItem(w http.ResponseWriter, r *http.Request) {
	if a == nil {
		http.NotFound(w, r)
		return
	}
	id := strings.TrimPrefix(r.URL.Path, TargetItemPath)
	if !validTargetID(id) {
		// An unparseable id is a 404, not a 400: a 400 would confirm that a
		// well-formed id from another tenant is "the right shape".
		http.NotFound(w, r)
		return
	}
	if err := rejectUnknownQuery(r); err != nil {
		a.deps.WriteError(w, http.StatusBadRequest, err)
		return
	}
	switch r.Method {
	case http.MethodGet:
		tenant, _, ok := a.scoped(w, r, GateRead)
		if !ok {
			return
		}
		t, err := a.deps.Targets.Get(r.Context(), tenant, id)
		if err != nil {
			http.NotFound(w, r) // cross-tenant id is indistinguishable from absent
			return
		}
		a.deps.WriteJSON(w, http.StatusOK, t)
	case http.MethodPut:
		tenant, _, ok := a.scoped(w, r, GateWrite)
		if !ok {
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
		var patch Patch
		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()
		if err := dec.Decode(&patch); err != nil {
			a.deps.WriteError(w, http.StatusBadRequest, errors.New("invalid target patch"))
			return
		}
		out, err := a.deps.Targets.Update(r.Context(), tenant, id, patch)
		if errors.Is(err, ErrNotFound) {
			http.NotFound(w, r)
			return
		}
		if err != nil {
			a.deps.WriteError(w, http.StatusBadRequest, err)
			return
		}
		a.deps.Counters.TargetsUpdated.Add(1)
		a.deps.WriteJSON(w, http.StatusOK, out)
	case http.MethodDelete:
		tenant, _, ok := a.scoped(w, r, GateWrite)
		if !ok {
			return
		}
		if err := a.deps.Targets.Delete(r.Context(), tenant, id); err != nil {
			if errors.Is(err, ErrNotFound) {
				http.NotFound(w, r)
				return
			}
			a.deps.WriteError(w, http.StatusInternalServerError, err)
			return
		}
		a.deps.Counters.TargetsDeleted.Add(1)
		a.deps.WriteJSON(w, http.StatusOK, map[string]any{"deleted": id})
	default:
		w.Header().Set("Allow", "GET, PUT, DELETE")
		a.deps.WriteError(w, http.StatusMethodNotAllowed, errors.New("GET, PUT or DELETE"))
	}
}

// validTargetID accepts only ids this package mints. Checked before the store
// is touched so a path-traversal-shaped id never reaches a key lookup.
func validTargetID(id string) bool {
	if len(id) != 4+32 || !strings.HasPrefix(id, "dem-") {
		return false
	}
	for _, r := range id[4:] {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	return true
}

// ── experience ───────────────────────────────────────────────────────────────

// ExperienceResponse is the scored view.
type ExperienceResponse struct {
	Window   string `json:"window"`
	Enabled  bool   `json:"enabled"`
	Measured bool   `json:"measured"`
	// Reason/Note explain a wholly-unmeasured answer. They are the sentence the
	// UI must render instead of an empty table.
	Reason string `json:"reason,omitempty"`
	Note   string `json:"note,omitempty"`

	Targets []Result `json:"targets"`
	Sites   []Rollup `json:"sites"`
	Apps    []Rollup `json:"apps"`

	TargetCount int    `json:"target_count"`
	ScoredCount int    `json:"scored_count"`
	GeneratedAt string `json:"generated_at"`
}

// HandleExperience serves GET /api/dem/experience.
func (a *API) HandleExperience(w http.ResponseWriter, r *http.Request) {
	if a == nil {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		a.deps.WriteError(w, http.StatusMethodNotAllowed, errors.New("GET only"))
		return
	}
	if err := rejectUnknownQuery(r, "window"); err != nil {
		a.deps.WriteError(w, http.StatusBadRequest, err)
		return
	}
	window, _, werr := ParseWindow(r.URL.Query().Get("window"))
	if werr != nil {
		a.deps.WriteError(w, http.StatusBadRequest, werr)
		return
	}
	tenant, _, ok := a.scoped(w, r, GateRead)
	if !ok {
		return
	}
	targets, err := a.deps.Targets.List(r.Context(), tenant)
	if err != nil {
		a.deps.WriteError(w, http.StatusInternalServerError, err)
		return
	}
	resp := ExperienceResponse{
		Window: window, Enabled: a.deps.Enabled,
		Targets: []Result{}, Sites: []Rollup{}, Apps: []Rollup{},
		TargetCount: len(targets),
		GeneratedAt: a.deps.Now().UTC().Format(time.RFC3339),
	}
	if len(targets) > MaxScoredTargets {
		targets = targets[:MaxScoredTargets]
		resp.Note = fmt.Sprintf("showing the first %d targets", MaxScoredTargets)
	}

	// Four honest not-measured shapes, each with its own reason, BEFORE any
	// score is computed. None of them is an empty table that reads as "all
	// well" (the 2026-09-02 lesson: silence is not health).
	switch {
	case !a.deps.Enabled:
		resp.Reason, resp.Note = ReasonFeatureOff, disabledNote
		a.fillNotMeasured(&resp, targets)
		a.deps.WriteJSON(w, http.StatusOK, resp)
		return
	case len(targets) == 0:
		resp.Reason = ReasonNoTargets
		resp.Note = "No experience target is declared for this tenant, so nothing is being measured."
		a.deps.WriteJSON(w, http.StatusOK, resp)
		return
	case a.deps.Metrics == nil:
		resp.Reason = ReasonQueryFailed
		resp.Note = "The metrics store is not wired into this API, so no score can be computed."
		a.fillNotMeasured(&resp, targets)
		a.deps.WriteJSON(w, http.StatusOK, resp)
		return
	}

	stats, qerr := FetchWindow(r.Context(), a.deps.Metrics, tenant, false, window)
	if qerr != nil {
		a.deps.Counters.QueryErrors.Add(1)
		a.deps.LogWarn("the experience score could not be computed — the metrics store did not answer",
			map[string]any{"err": qerr.Error(), "window": window})
		resp.Reason = ReasonQueryFailed
		resp.Note = "The metrics store did not answer, so no score is shown. This is not a healthy result."
		a.fillNotMeasured(&resp, targets)
		a.deps.WriteJSON(w, http.StatusOK, resp)
		return
	}

	scored := 0
	for _, t := range targets {
		st, has := stats[t.ID]
		st.Identity = t.Identity()
		var res Result
		switch {
		case t.Paused:
			res = NotMeasured(t.Identity(), window, ReasonPaused,
				"this target is paused, so nothing was measured in this window")
		case !has || st.Samples == 0:
			res = NotMeasured(t.Identity(), window, ReasonNoSamples, noProberNote)
		default:
			res = Score(t, st, window)
		}
		if res.Measured {
			scored++
		}
		resp.Targets = append(resp.Targets, res)
	}
	resp.ScoredCount = scored
	resp.Measured = scored > 0
	if scored == 0 {
		resp.Reason, resp.Note = ReasonNoProber, noProberNote
	}
	resp.Sites = rollupBy(window, "site", targets, resp.Targets, func(t Target) string { return t.Site })
	resp.Apps = rollupBy(window, "app", targets, resp.Targets, func(t Target) string { return t.App })
	a.deps.Counters.ScoresServed.Add(1)
	a.deps.WriteJSON(w, http.StatusOK, resp)
}

// fillNotMeasured populates one honest row per target so the page can render
// the catalogue with its reason rather than an empty table.
func (a *API) fillNotMeasured(resp *ExperienceResponse, targets []Target) {
	for _, t := range targets {
		resp.Targets = append(resp.Targets, NotMeasured(t.Identity(), resp.Window, resp.Reason, resp.Note))
	}
}

// rollupBy groups per-target results by a label and aggregates each group.
// Targets carrying no label are grouped under "" and reported as unlabelled —
// they are not dropped, because a target nobody labelled is exactly the one
// most likely to be forgotten.
func rollupBy(window, scope string, targets []Target, results []Result, key func(Target) string) []Rollup {
	idx := make(map[string]int, len(targets))
	for i, t := range targets {
		idx[t.ID] = i
	}
	groups := map[string][]Result{}
	for _, res := range results {
		i, ok := idx[res.Subject]
		if !ok {
			continue
		}
		groups[key(targets[i])] = append(groups[key(targets[i])], res)
	}
	out := make([]Rollup, 0, len(groups))
	for k, list := range groups {
		out = append(out, Aggregate(k, scope, window, list))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
}

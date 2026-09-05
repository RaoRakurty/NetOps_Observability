package experience

// http.go — the Digital Experience aggregation surface.
//
//	GET    /api/dem/overview        the Experience overview (score, journeys, incidents, changes, telemetry confidence)
//	GET    /api/dem/incidents       experience incidents, newest/most severe first
//	GET    /api/dem/incidents/{id}  one incident; …/evidence, …/timeline, …/path
//	GET    /api/dem/journeys        the declared journeys with their measured health
//	POST   /api/dem/journeys        declare one (owner stamped from the token)
//	GET/PUT/DELETE /api/dem/journeys/{id}
//	GET    /api/dem/synthetics/coverage  the coverage model
//	GET    /api/dem/changes         the normalized change feed
//	POST   /api/dem/changes         record one (producers)
//	GET    /api/dem/data-health     per-source health, coverage and confidence influence
//
// §3a: every one of them is per-tenant DATA. A cross-tenant principal must
// scope into a concrete tenant with the switcher — refused, never a wildcard.
// A foreign id answers 404 so an id is never confirmed to exist. Ownership is
// stamped from the TOKEN: the create wire types carry no tenant field at all,
// and unknown fields are refused outright.

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"netops/backend/internal/dem"
	"netops/backend/internal/httppage"
)

// Route paths. Exported so the integrator registers exactly what this file
// serves and a test can pin the registered literals against them.
const (
	OverviewPath     = "/api/dem/overview"
	IncidentsPath    = "/api/dem/incidents"
	IncidentItemPath = "/api/dem/incidents/"
	JourneysPath     = "/api/dem/journeys"
	JourneyItemPath  = "/api/dem/journeys/"
	CoveragePath     = "/api/dem/synthetics/coverage"
	ChangesPath      = "/api/dem/changes"
	DataHealthPath   = "/api/dem/data-health"
)

// maxBodyBytes bounds a write body before it is decoded (§9, and the
// architecture guard that requires MaxBytesReader on every write route).
const maxBodyBytes = 64 << 10

// Page defaults. Both are modest: an experience view is a triage surface, and a
// caller that wants everything must ask for it a page at a time.
const (
	defaultPageLimit = 100
	maxPageLimit     = 500
)

// Deps are the surface's injected collaborators.
type Deps struct {
	// Authz authorizes the caller and returns the resolved principal. It has
	// already written the error response when ok is false. Required.
	Authz func(w http.ResponseWriter, r *http.Request, gate dem.Gate) (dem.Principal, bool)
	// Store holds the two persisted objects. Required.
	Store Store
	// Targets is internal/dem's per-tenant synthetic catalogue. Required: the
	// journeys bind to it and the coverage model is computed over it.
	Targets dem.Catalogue
	// Metrics answers the experience queries. nil is legal and HONEST: every
	// surface then reports not-measured with ReasonQueryFailed rather than a
	// fabricated score.
	Metrics dem.Querier
	// Policy is the versioned score policy. Required.
	Policy ScorePolicy
	// Enabled reports whether experience collection is on.
	Enabled bool
	// InvestigatorEnabled reports whether the AI investigator is available. It
	// is surfaced so the UI can render a disabled panel with the reason rather
	// than hiding a feature the operator paid for.
	InvestigatorEnabled bool

	Now        func() time.Time
	WriteJSON  func(w http.ResponseWriter, status int, body any)
	WriteError func(w http.ResponseWriter, status int, err error)
	LogWarn    func(msg string, fields map[string]any)
	Counters   *Counters
}

func (d Deps) validate() error {
	missing := make([]string, 0, 8)
	check := func(n string, ok bool) {
		if !ok {
			missing = append(missing, n)
		}
	}
	check("Authz", d.Authz != nil)
	check("Store", d.Store != nil)
	check("Targets", d.Targets != nil)
	check("Now", d.Now != nil)
	check("WriteJSON", d.WriteJSON != nil)
	check("WriteError", d.WriteError != nil)
	check("LogWarn", d.LogWarn != nil)
	check("Policy", d.Policy.Version > 0)
	if len(missing) > 0 {
		return fmt.Errorf("experience: Deps missing required fields: %s", strings.Join(missing, ", "))
	}
	return nil
}

// API is the module's HTTP surface.
type API struct{ deps Deps }

// NewAPI builds the surface, failing CLOSED on incomplete Deps rather than
// returning handlers that could read unscoped.
func NewAPI(d Deps) (*API, error) {
	if err := d.validate(); err != nil {
		return nil, err
	}
	if d.Counters == nil {
		d.Counters = NewCounters()
	}
	return &API{deps: d}, nil
}

// scoped resolves the caller to ONE concrete tenant, refusing a cross-tenant
// read or write of per-tenant data (§3a). It writes the error response itself.
func (a *API) scoped(w http.ResponseWriter, r *http.Request, gate dem.Gate) (string, dem.Principal, bool) {
	p, ok := a.deps.Authz(w, r, gate)
	if !ok {
		return "", dem.Principal{}, false
	}
	t := strings.ToLower(strings.TrimSpace(p.Tenant))
	if p.Cross || t == "" || t == "*" {
		a.deps.WriteError(w, http.StatusBadRequest,
			errors.New("select a tenant to see its digital experience (it is per-tenant data; cross-tenant access is refused)"))
		return "", dem.Principal{}, false
	}
	return t, p, true
}

// assemble collects the whole view for one tenant and one window.
func (a *API) assemble(r *http.Request, tenant, window string) (Assembly, error) {
	label, dur, err := dem.ParseWindow(window)
	if err != nil {
		return Assembly{}, err
	}
	in := AssembleInput{
		TenantID: tenant, Window: label, WindowDuration: dur, Now: a.deps.Now().UTC(),
		FeatureEnabled: a.deps.Enabled,
	}
	targets, terr := a.deps.Targets.List(r.Context(), tenant)
	if terr != nil {
		return Assembly{}, terr
	}
	in.Targets = targets

	if a.deps.Metrics != nil {
		stats, qerr := dem.FetchWindow(r.Context(), a.deps.Metrics, tenant, false, label)
		if qerr != nil {
			// A query failure is REPORTED, never treated as zero: the surfaces
			// render "not measured — the metrics store did not answer".
			a.deps.Counters.QueryErrors.Add(1)
			a.deps.LogWarn("the experience view could not be scored — the metrics store did not answer",
				map[string]any{"err": qerr.Error(), "window": label})
			in.QueryError = qerr
		} else {
			in.MetricsAvailable = true
			in.Stats = stats
		}
	}
	if in.Stats == nil {
		in.Stats = map[string]dem.WindowStats{}
	}
	for _, t := range targets {
		st, has := in.Stats[t.ID]
		st.Identity = t.Identity()
		switch {
		case t.Paused:
			in.Results = append(in.Results, dem.NotMeasured(t.Identity(), label, dem.ReasonPaused,
				"this target is paused, so nothing was measured in this window"))
		case !in.MetricsAvailable:
			in.Results = append(in.Results, dem.NotMeasured(t.Identity(), label, dem.ReasonQueryFailed,
				"the metrics store did not answer, so this target has no score"))
		case !has || st.Samples == 0:
			in.Results = append(in.Results, dem.NotMeasured(t.Identity(), label, dem.ReasonNoSamples,
				"no probe result was recorded for this target in this window"))
		default:
			in.Results = append(in.Results, dem.Score(t, st, label))
		}
	}

	journeys, jerr := a.deps.Store.ListJourneys(r.Context(), tenant)
	if jerr != nil {
		return Assembly{}, jerr
	}
	in.Journeys = journeys

	changes, cerr := a.deps.Store.ListChanges(r.Context(), tenant, ChangeQuery{
		Since: in.Now.Add(-changeLookbackFor(dur)), Limit: DefaultChangePageLimit,
	})
	if cerr != nil {
		return Assembly{}, cerr
	}
	in.Changes = changes

	a.deps.Counters.ViewsServed.Add(1)
	asm := Assemble(in, a.deps.Policy)
	a.deps.Counters.IncidentsDerived.Add(int64(len(asm.Incidents)))
	return asm, nil
}

// changeLookbackFor bounds how far back changes are read for a window. It is
// the window plus the change lookback, so a change just before the window
// opened is still a candidate cause and one from last week is not.
func changeLookbackFor(window time.Duration) time.Duration {
	return window + DefaultChangeLookback
}

// ── overview ────────────────────────────────────────────────────────────────

// OverviewResponse is the Experience overview's payload.
type OverviewResponse struct {
	Window   string `json:"window"`
	Enabled  bool   `json:"enabled"`
	Measured bool   `json:"measured"`
	Reason   string `json:"reason,omitempty"`
	Note     string `json:"note,omitempty"`

	Score                  ExperienceScore   `json:"score"`
	Journeys               []JourneyHealth   `json:"journeys"`
	Incidents              []IncidentSummary `json:"incidents"`
	Changes                []ChangeEvent     `json:"changes"`
	DataHealth             DataHealth        `json:"data_health"`
	Hotspots               []Hotspot         `json:"hotspots"`
	BusinessImpact         *float64          `json:"business_impact,omitempty"`
	BusinessImpactCurrency string            `json:"business_impact_currency,omitempty"`

	AIInvestigator AIAvailability `json:"ai_investigator"`
	GeneratedAt    string         `json:"generated_at"`
	PolicyVersion  int            `json:"policy_version"`
}

// AIAvailability tells the UI whether to render the investigator panel enabled
// or disabled-with-a-reason. A hidden feature is indistinguishable from a
// missing one, so it is never hidden.
type AIAvailability struct {
	Available bool   `json:"available"`
	Reason    string `json:"reason,omitempty"`
}

// Hotspot is one dimension of the "where is it worst" breakdown.
type Hotspot struct {
	Dimension string   `json:"dimension"` // site | app | isp | device | browser | version | network
	Key       string   `json:"key"`
	Band      string   `json:"band"`
	Measured  bool     `json:"measured"`
	Reason    string   `json:"reason,omitempty"`
	Score     *float64 `json:"score,omitempty"`
	Subjects  int      `json:"subjects"`
	Failing   int      `json:"failing"`
}

// IncidentSummary is the incident row the overview and the list render.
type IncidentSummary struct {
	ID       string `json:"id"`
	Title    string `json:"title"`
	Severity string `json:"severity"`
	Status   string `json:"status"`

	App     string `json:"app,omitempty"`
	Journey string `json:"journey,omitempty"`

	DetectedAt    time.Time `json:"detected_at"`
	FirstImpactAt time.Time `json:"first_impact_at"`
	DurationSec   int64     `json:"duration_sec"`

	LeadingCause      string  `json:"leading_cause,omitempty"`
	LeadingCauseClass string  `json:"leading_cause_class,omitempty"`
	LikelyLayer       string  `json:"likely_layer,omitempty"`
	Confidence        float64 `json:"confidence"`
	VerdictTier       string  `json:"verdict_tier"`
	Owner             string  `json:"owner,omitempty"`
	Seam              string  `json:"seam,omitempty"`

	JourneySuccessPct *float64 `json:"journey_success_pct,omitempty"`
	BusinessImpact    *float64 `json:"business_impact,omitempty"`
	Currency          string   `json:"currency,omitempty"`
	// ImpactNotMeasured is the honest list of impact dimensions nothing
	// produced. The UI renders it instead of a zero.
	ImpactNotMeasured  []string `json:"impact_not_measured,omitempty"`
	EvidenceCount      int      `json:"evidence_count"`
	ContradictionCount int      `json:"contradiction_count"`
	MissingCount       int      `json:"missing_evidence_count"`
}

// Summarize projects an incident onto its list row.
func Summarize(inc ExperienceIncident, now time.Time) IncidentSummary {
	s := IncidentSummary{
		ID: inc.ID, Title: inc.Title, Severity: inc.Severity, Status: inc.Status,
		DetectedAt: inc.DetectedAt, FirstImpactAt: inc.FirstImpactAt,
		Confidence: inc.Confidence, VerdictTier: inc.VerdictTier,
		Owner: inc.Owner, Seam: inc.Seam,
		JourneySuccessPct: inc.Impact.JourneySuccessPct,
		BusinessImpact:    inc.Impact.BusinessValueLost, Currency: inc.Impact.Currency,
		ImpactNotMeasured: inc.Impact.NotMeasured,
	}
	if len(inc.AffectedApps) > 0 {
		s.App = inc.AffectedApps[0]
	}
	if len(inc.AffectedJourneys) > 0 {
		s.Journey = inc.AffectedJourneys[0]
	}
	if !inc.FirstImpactAt.IsZero() {
		d := int64(now.Sub(inc.FirstImpactAt).Seconds())
		if d < 0 {
			d = 0
		}
		s.DurationSec = d
	}
	for _, h := range inc.Hypotheses {
		if h.ID == inc.LeadingHypothesisID {
			s.LeadingCause, s.LeadingCauseClass = h.Explanation, h.CauseClass
			s.LikelyLayer = LayerFor(h.CauseClass)
			break
		}
	}
	for _, e := range inc.Evidence {
		switch e.Stance {
		case StanceSupports:
			s.EvidenceCount++
		case StanceContradicts:
			s.ContradictionCount++
		}
	}
	s.MissingCount = len(inc.MissingEvidence)
	return s
}

// LayerFor names the layer a cause class sits at, in the vocabulary the seam
// ribbon uses. It is the "likely layer" column of the incident list.
func LayerFor(cause string) string {
	switch cause {
	case CauseClientEndpoint:
		return "device"
	case CauseLANAccess:
		return "LAN"
	case CauseWANOverlay:
		return "WAN"
	case CauseLastMile, CauseTransitDegradation, CauseRoutingChange:
		return "ISP"
	case CauseDNSResolution:
		return "DNS"
	case CauseTLSTermination, CauseCloudEdge, CauseCloudPolicy:
		return "cloud edge"
	case CauseApplicationRegress, CauseDependencyFailure, CauseCapacitySaturation:
		return "application"
	case CauseConfigChange:
		return "network"
	case CauseSyntheticArtifact:
		return "measurement"
	default:
		return ""
	}
}

// HandleOverview serves GET /api/dem/overview.
func (a *API) HandleOverview(w http.ResponseWriter, r *http.Request) {
	if a == nil {
		http.NotFound(w, r)
		return
	}
	if !a.methodIs(w, r, http.MethodGet) {
		return
	}
	if err := httppage.RejectUnknownQuery(r, "window"); err != nil {
		a.deps.WriteError(w, http.StatusBadRequest, err)
		return
	}
	tenant, _, ok := a.scoped(w, r, dem.GateRead)
	if !ok {
		return
	}
	asm, err := a.assemble(r, tenant, r.URL.Query().Get("window"))
	if err != nil {
		a.deps.WriteError(w, http.StatusBadRequest, err)
		return
	}
	now := a.deps.Now().UTC()
	resp := OverviewResponse{
		Window: asm.Window, Enabled: a.deps.Enabled, Measured: asm.Measured,
		Reason: asm.Reason, Note: asm.Detail,
		Score: asm.Score, Journeys: asm.JourneyHealth, DataHealth: asm.DataHealth,
		Changes: asm.Bundle.Changes, Incidents: []IncidentSummary{},
		Hotspots: hotspots(asm), GeneratedAt: now.Format(time.RFC3339),
		PolicyVersion:  a.deps.Policy.Version,
		AIInvestigator: a.aiAvailability(),
	}
	if resp.Journeys == nil {
		resp.Journeys = []JourneyHealth{}
	}
	if resp.Changes == nil {
		resp.Changes = []ChangeEvent{}
	}
	var impact float64
	currency := ""
	for _, inc := range asm.Incidents {
		resp.Incidents = append(resp.Incidents, Summarize(inc, now))
		if inc.Impact.BusinessValueLost != nil {
			impact += *inc.Impact.BusinessValueLost
			currency = inc.Impact.Currency
		}
	}
	if currency != "" {
		v := round2(impact)
		resp.BusinessImpact, resp.BusinessImpactCurrency = &v, currency
	}
	a.deps.WriteJSON(w, http.StatusOK, resp)
}

func (a *API) aiAvailability() AIAvailability {
	if a.deps.InvestigatorEnabled {
		return AIAvailability{Available: true}
	}
	return AIAvailability{Reason: "The AI investigator is switched off for this deployment. " +
		"It explains the evidence Correlix has already gathered; it never gathers its own, and it can never mark a cause confirmed."}
}

// hotspots breaks the window down by site and application. Dimensions Correlix
// cannot measure yet (ISP, device, browser, release, network type) are reported
// as NOT MEASURED rather than omitted, so the absence is visible.
func hotspots(asm Assembly) []Hotspot {
	out := []Hotspot{}
	bySite := map[string][]JourneyHealth{}
	byApp := map[string][]JourneyHealth{}
	for _, h := range asm.JourneyHealth {
		byApp[h.App] = append(byApp[h.App], h)
	}
	for _, inc := range asm.Incidents {
		for _, s := range inc.AffectedSites {
			bySite[s] = append(bySite[s], JourneyHealth{})
		}
	}
	for app, list := range byApp {
		if app == "" {
			continue
		}
		h := Hotspot{Dimension: "app", Key: app, Subjects: len(list), Band: BandNotMeasured}
		sum, n := 0.0, 0
		for _, j := range list {
			if !j.Measured {
				continue
			}
			sum += j.SuccessPct
			n++
			if !j.MeetsSLO {
				h.Failing++
			}
		}
		if n > 0 {
			v := round2(sum / float64(n))
			h.Measured, h.Score, h.Band = true, &v, Band(v)
		} else {
			h.Reason = ReasonJourneyNotMeasured
		}
		out = append(out, h)
	}
	for site, list := range bySite {
		out = append(out, Hotspot{Dimension: "site", Key: site, Subjects: len(list),
			Failing: len(list), Band: BandNotMeasured,
			Reason: "sites are ranked by open experience incidents; a per-site score needs a prober at the site"})
	}
	for _, dim := range []string{"isp", "device", "browser", "version", "network"} {
		out = append(out, Hotspot{Dimension: dim, Band: BandNotMeasured,
			Reason: "this breakdown needs first-party real-user telemetry, which is not collected yet"})
	}
	return out
}

// ── incidents ───────────────────────────────────────────────────────────────

// IncidentsResponse is the incident list.
type IncidentsResponse struct {
	Window    string            `json:"window"`
	Measured  bool              `json:"measured"`
	Reason    string            `json:"reason,omitempty"`
	Note      string            `json:"note,omitempty"`
	Incidents []IncidentSummary `json:"incidents"`
	Total     int               `json:"total"`
	Returned  int               `json:"returned"`
	Limit     int               `json:"limit"`
	Offset    int               `json:"offset"`
	Complete  bool              `json:"complete"`
}

// HandleIncidents serves GET /api/dem/incidents.
func (a *API) HandleIncidents(w http.ResponseWriter, r *http.Request) {
	if a == nil {
		http.NotFound(w, r)
		return
	}
	if !a.methodIs(w, r, http.MethodGet) {
		return
	}
	if err := httppage.RejectUnknownQuery(r, "window", "severity", "app", "journey"); err != nil {
		a.deps.WriteError(w, http.StatusBadRequest, err)
		return
	}
	page, perr := httppage.Parse(r, defaultPageLimit, maxPageLimit)
	if perr != nil {
		a.deps.WriteError(w, http.StatusBadRequest, perr)
		return
	}
	tenant, _, ok := a.scoped(w, r, dem.GateRead)
	if !ok {
		return
	}
	asm, err := a.assemble(r, tenant, r.URL.Query().Get("window"))
	if err != nil {
		a.deps.WriteError(w, http.StatusBadRequest, err)
		return
	}
	q := r.URL.Query()
	sev, app, journey := q.Get("severity"), q.Get("app"), q.Get("journey")
	if sev != "" && severityRank(sev) == 0 && sev != SeverityInfo {
		a.deps.WriteError(w, http.StatusBadRequest,
			errors.New("severity must be one of info, low, medium, high, critical"))
		return
	}
	now := a.deps.Now().UTC()
	all := make([]IncidentSummary, 0, len(asm.Incidents))
	for _, inc := range asm.Incidents {
		s := Summarize(inc, now)
		if sev != "" && s.Severity != sev {
			continue
		}
		if app != "" && s.App != app {
			continue
		}
		if journey != "" && s.Journey != journey {
			continue
		}
		all = append(all, s)
	}
	rows := httppage.SliceOf(all, page)
	httppage.LogTruncated(IncidentsPath, page, len(rows), len(all))
	httppage.WriteHeaders(w, page, len(rows), len(all))
	a.deps.WriteJSON(w, http.StatusOK, IncidentsResponse{
		Window: asm.Window, Measured: asm.Measured, Reason: asm.Reason, Note: asm.Detail,
		Incidents: rows, Total: len(all), Returned: len(rows),
		Limit: page.Limit, Offset: page.Offset, Complete: httppage.Complete(page, len(rows), len(all)),
	})
}

// IncidentResponse is one incident's full packet.
type IncidentResponse struct {
	Window   string             `json:"window"`
	Incident ExperienceIncident `json:"incident"`
	// AIInvestigator says whether the AI panel is available and, when it is
	// not, why. The panel renders disabled rather than absent.
	AIInvestigator AIAvailability `json:"ai_investigator"`
	// EvidencePacketAvailable reports whether a model briefing could be built
	// from this incident at all (it cannot when every item is above the class
	// that may leave the platform).
	EvidencePacketAvailable bool `json:"evidence_packet_available"`
}

// HandleIncidentItem serves the item route and its three sub-resources.
func (a *API) HandleIncidentItem(w http.ResponseWriter, r *http.Request) {
	if a == nil {
		http.NotFound(w, r)
		return
	}
	if !a.methodIs(w, r, http.MethodGet) {
		return
	}
	rest := strings.TrimPrefix(r.URL.Path, IncidentItemPath)
	id, sub, _ := strings.Cut(rest, "/")
	if !validIncidentID(id) {
		// An unparseable id is a 404, not a 400: a 400 would confirm that a
		// well-formed id from another tenant is "the right shape".
		http.NotFound(w, r)
		return
	}
	switch sub {
	case "", "evidence", "timeline", "path":
	default:
		http.NotFound(w, r)
		return
	}
	if err := httppage.RejectUnknownQuery(r, "window"); err != nil {
		a.deps.WriteError(w, http.StatusBadRequest, err)
		return
	}
	tenant, _, ok := a.scoped(w, r, dem.GateRead)
	if !ok {
		return
	}
	asm, err := a.assemble(r, tenant, r.URL.Query().Get("window"))
	if err != nil {
		a.deps.WriteError(w, http.StatusBadRequest, err)
		return
	}
	var found *ExperienceIncident
	for i := range asm.Incidents {
		if asm.Incidents[i].ID == id {
			found = &asm.Incidents[i]
			break
		}
	}
	if found == nil {
		http.NotFound(w, r) // a foreign or resolved id is indistinguishable from absent
		return
	}
	switch sub {
	case "evidence":
		a.deps.WriteJSON(w, http.StatusOK, map[string]any{
			"incident_id": found.ID, "evidence": found.Evidence,
			"missing_evidence": found.MissingEvidence, "hypotheses": found.Hypotheses,
		})
	case "timeline":
		a.deps.WriteJSON(w, http.StatusOK, map[string]any{
			"incident_id": found.ID, "timeline": found.Timeline, "changes": found.Changes,
		})
	case "path":
		// The ordered spine itself belongs to the frozen path contract and is
		// served by its own API. This route returns the REFERENCE plus the
		// honest reason when there is none, so the UI never renders a path it
		// invented from evidence.
		body := map[string]any{"incident_id": found.ID, "path_observation_id": found.PathObservationID}
		if found.PathObservationID == "" {
			body["measured"] = false
			body["reason"] = "no forward path was observed for this incident's subject in this window, so there is no path to render — this is an absent measurement, not a clean path"
		} else {
			body["measured"] = true
			body["note"] = "fetch the ordered spine from the service path graph API using this observation id; it is the single source of hop order"
		}
		a.deps.WriteJSON(w, http.StatusOK, body)
	default:
		packet := BuildPacket(*found, asm.DataHealth.Sources)
		a.deps.WriteJSON(w, http.StatusOK, IncidentResponse{
			Window: asm.Window, Incident: *found,
			AIInvestigator:          a.aiAvailability(),
			EvidencePacketAvailable: len(packet.EvidenceIDs) > 0,
		})
	}
}

func validIncidentID(id string) bool { return validPrefixedID(id, "exp-", 20) }

// ── journeys ────────────────────────────────────────────────────────────────

// journeyWire is the create/update body. There is deliberately NO tenant field:
// ownership is stamped from the token and a tenant on the wire is not merely
// ignored, it is impossible to express (§3a rule 2).
type journeyWire struct {
	Name                    string        `json:"name"`
	App                     string        `json:"app"`
	Description             string        `json:"description"`
	BusinessImportance      string        `json:"business_importance"`
	BusinessValuePerSuccess float64       `json:"business_value_per_success"`
	Currency                string        `json:"currency"`
	EntryStepID             string        `json:"entry_step_id"`
	Steps                   []JourneyStep `json:"steps"`
	SLO                     ExperienceSLO `json:"slo"`
}

func (jw journeyWire) toDefinition(tenant, actor string) JourneyDefinition {
	return JourneyDefinition{
		TenantID: tenant, // from the TOKEN, never the body
		Name:     jw.Name, App: jw.App, Description: jw.Description,
		BusinessImportance:      jw.BusinessImportance,
		BusinessValuePerSuccess: jw.BusinessValuePerSuccess, Currency: jw.Currency,
		EntryStepID: jw.EntryStepID, Steps: jw.Steps, SLO: jw.SLO,
		CreatedBy: actor,
	}
}

// JourneysResponse is the journeys list with their measured health.
type JourneysResponse struct {
	Window   string              `json:"window"`
	Measured bool                `json:"measured"`
	Reason   string              `json:"reason,omitempty"`
	Note     string              `json:"note,omitempty"`
	Journeys []JourneyDefinition `json:"journeys"`
	Health   []JourneyHealth     `json:"health"`
	Count    int                 `json:"count"`
	Limit    int                 `json:"limit"`
}

// HandleJourneys serves the collection route (GET list, POST create).
func (a *API) HandleJourneys(w http.ResponseWriter, r *http.Request) {
	if a == nil {
		http.NotFound(w, r)
		return
	}
	switch r.Method {
	case http.MethodGet:
		a.listJourneys(w, r)
	case http.MethodPost:
		a.createJourney(w, r)
	default:
		w.Header().Set("Allow", "GET, POST")
		a.deps.WriteError(w, http.StatusMethodNotAllowed, errors.New("GET or POST"))
	}
}

func (a *API) listJourneys(w http.ResponseWriter, r *http.Request) {
	if err := httppage.RejectUnknownQuery(r, "window"); err != nil {
		a.deps.WriteError(w, http.StatusBadRequest, err)
		return
	}
	tenant, _, ok := a.scoped(w, r, dem.GateRead)
	if !ok {
		return
	}
	asm, err := a.assemble(r, tenant, r.URL.Query().Get("window"))
	if err != nil {
		a.deps.WriteError(w, http.StatusBadRequest, err)
		return
	}
	resp := JourneysResponse{
		Window: asm.Window, Measured: asm.Measured, Reason: asm.Reason, Note: asm.Detail,
		Journeys: asm.Bundle.Journeys, Health: asm.JourneyHealth,
		Count: len(asm.Bundle.Journeys), Limit: MaxJourneysPerTenant,
	}
	if resp.Journeys == nil {
		resp.Journeys = []JourneyDefinition{}
	}
	if resp.Health == nil {
		resp.Health = []JourneyHealth{}
	}
	if len(resp.Journeys) == 0 {
		resp.Reason = ReasonNoJourneys
		resp.Note = "No journey is declared for this tenant. Correlix cannot report on a workflow nobody described, and it will not guess one."
	}
	a.deps.WriteJSON(w, http.StatusOK, resp)
}

func (a *API) createJourney(w http.ResponseWriter, r *http.Request) {
	if err := httppage.RejectUnknownQuery(r); err != nil {
		a.deps.WriteError(w, http.StatusBadRequest, err)
		return
	}
	tenant, p, ok := a.scoped(w, r, dem.GateWrite)
	if !ok {
		return
	}
	var jw journeyWire
	if !a.decode(w, r, &jw, "journey") {
		return
	}
	out, err := a.deps.Store.CreateJourney(r.Context(), jw.toDefinition(tenant, p.Subject))
	if err != nil {
		a.deps.WriteError(w, http.StatusBadRequest, err)
		return
	}
	a.deps.Counters.JourneysCreated.Add(1)
	a.deps.WriteJSON(w, http.StatusCreated, out)
}

// HandleJourneyItem serves the item route (GET / PUT / DELETE {id}).
func (a *API) HandleJourneyItem(w http.ResponseWriter, r *http.Request) {
	if a == nil {
		http.NotFound(w, r)
		return
	}
	id := strings.TrimPrefix(r.URL.Path, JourneyItemPath)
	if !ValidJourneyID(id) {
		http.NotFound(w, r)
		return
	}
	if err := httppage.RejectUnknownQuery(r, "window"); err != nil {
		a.deps.WriteError(w, http.StatusBadRequest, err)
		return
	}
	switch r.Method {
	case http.MethodGet:
		tenant, _, ok := a.scoped(w, r, dem.GateRead)
		if !ok {
			return
		}
		def, err := a.deps.Store.GetJourney(r.Context(), tenant, id)
		if err != nil {
			http.NotFound(w, r) // cross-tenant id is indistinguishable from absent
			return
		}
		asm, aerr := a.assemble(r, tenant, r.URL.Query().Get("window"))
		if aerr != nil {
			a.deps.WriteError(w, http.StatusBadRequest, aerr)
			return
		}
		body := map[string]any{"journey": def, "window": asm.Window}
		for _, h := range asm.JourneyHealth {
			if h.JourneyID == id {
				body["health"] = h
				break
			}
		}
		if _, has := body["health"]; !has {
			body["health"] = JourneyHealth{JourneyID: id, Name: def.Name, App: def.App,
				Window: asm.Window, Reason: ReasonJourneyNotMeasured,
				Detail: "no required step of this journey is measured in this window"}
		}
		a.deps.WriteJSON(w, http.StatusOK, body)
	case http.MethodPut:
		tenant, _, ok := a.scoped(w, r, dem.GateWrite)
		if !ok {
			return
		}
		var jw journeyWire
		if !a.decode(w, r, &jw, "journey") {
			return
		}
		out, err := a.deps.Store.UpdateJourney(r.Context(), tenant, id, jw.toDefinition(tenant, ""))
		if errors.Is(err, ErrNotFound) {
			http.NotFound(w, r)
			return
		}
		if err != nil {
			a.deps.WriteError(w, http.StatusBadRequest, err)
			return
		}
		a.deps.Counters.JourneysUpdated.Add(1)
		a.deps.WriteJSON(w, http.StatusOK, out)
	case http.MethodDelete:
		tenant, _, ok := a.scoped(w, r, dem.GateWrite)
		if !ok {
			return
		}
		if err := a.deps.Store.DeleteJourney(r.Context(), tenant, id); err != nil {
			if errors.Is(err, ErrNotFound) {
				http.NotFound(w, r)
				return
			}
			a.deps.WriteError(w, http.StatusInternalServerError, err)
			return
		}
		a.deps.Counters.JourneysDeleted.Add(1)
		a.deps.WriteJSON(w, http.StatusOK, map[string]any{"deleted": id})
	default:
		w.Header().Set("Allow", "GET, PUT, DELETE")
		a.deps.WriteError(w, http.StatusMethodNotAllowed, errors.New("GET, PUT or DELETE"))
	}
}

// ── coverage ────────────────────────────────────────────────────────────────

// HandleCoverage serves GET /api/dem/synthetics/coverage.
func (a *API) HandleCoverage(w http.ResponseWriter, r *http.Request) {
	if a == nil {
		http.NotFound(w, r)
		return
	}
	if !a.methodIs(w, r, http.MethodGet) {
		return
	}
	if err := httppage.RejectUnknownQuery(r, "window"); err != nil {
		a.deps.WriteError(w, http.StatusBadRequest, err)
		return
	}
	tenant, _, ok := a.scoped(w, r, dem.GateRead)
	if !ok {
		return
	}
	asm, err := a.assemble(r, tenant, r.URL.Query().Get("window"))
	if err != nil {
		a.deps.WriteError(w, http.StatusBadRequest, err)
		return
	}
	// Every catalogue target bound to a journey step IS a synthetic definition
	// of the kind that step is protected by. There is no second registry: a
	// parallel definition store would let a step be "covered" by a check the
	// prober never runs.
	defs := map[string][]SyntheticDefinition{}
	lastSuccess := map[string]time.Time{}
	targetByID := map[string]dem.Target{}
	for _, t := range asm.Targets {
		targetByID[t.ID] = t
	}
	for _, j := range asm.Bundle.Journeys {
		for _, s := range j.Steps {
			if s.TargetID == "" {
				continue
			}
			t, has := targetByID[s.TargetID]
			if !has {
				continue
			}
			vantage := "prober"
			if t.Site != "" {
				vantage = "prober@" + t.Site
			}
			defs[j.ID+"/"+s.ID] = append(defs[j.ID+"/"+s.ID], SyntheticDefinition{
				ID: t.ID, TenantID: tenant, Name: t.Name, Kind: kindForTarget(t.Kind),
				TargetID: t.ID, JourneyID: j.ID, StepID: s.ID,
				Vantages: []string{vantage}, App: t.App, Site: t.Site, Version: 1,
			})
		}
	}
	for _, res := range asm.Results {
		if res.Measured && res.LastProbe != nil && res.Availability.Measured && res.Availability.Met {
			lastSuccess[res.Subject] = res.LastProbe.UTC()
		}
	}
	rep := BuildCoverage(asm.Window, asm.Bundle.Journeys, defs, map[string]SyntheticReliability{}, lastSuccess)
	a.deps.WriteJSON(w, http.StatusOK, map[string]any{
		"window": asm.Window, "coverage": rep,
		"reliability_note": "Per-check reliability needs per-RUN records; the prober publishes aggregate series today, so every check's reliability reads as unknown rather than as trustworthy. A check nobody has graded is not a check that passed.",
	})
}

func kindForTarget(k string) string {
	switch k {
	case dem.KindHTTP:
		return SynHTTP
	case dem.KindDNS:
		return SynDNS
	case dem.KindTCP, dem.KindICMP:
		return SynNetwork
	default:
		return SynNetwork
	}
}

// ── changes ─────────────────────────────────────────────────────────────────

// changeWire is the POST body. No tenant field, by construction.
type changeWire struct {
	Type         string `json:"type"`
	Actor        string `json:"actor"`
	Object       string `json:"object"`
	ObjectKind   string `json:"object_kind"`
	Summary      string `json:"summary"`
	Before       string `json:"before"`
	After        string `json:"after"`
	ReleaseID    string `json:"release_id"`
	RollbackRef  string `json:"rollback_ref"`
	Site         string `json:"site"`
	App          string `json:"app"`
	Seam         string `json:"seam"`
	Cohort       Cohort `json:"cohort"`
	EventAt      string `json:"event_at"`
	Source       string `json:"source"`
	SourceObject string `json:"source_object"`
}

// HandleChanges serves GET (list) and POST (record) on /api/dem/changes.
func (a *API) HandleChanges(w http.ResponseWriter, r *http.Request) {
	if a == nil {
		http.NotFound(w, r)
		return
	}
	switch r.Method {
	case http.MethodGet:
		a.listChanges(w, r)
	case http.MethodPost:
		a.recordChange(w, r)
	default:
		w.Header().Set("Allow", "GET, POST")
		a.deps.WriteError(w, http.StatusMethodNotAllowed, errors.New("GET or POST"))
	}
}

func (a *API) listChanges(w http.ResponseWriter, r *http.Request) {
	if err := httppage.RejectUnknownQuery(r, "window", "type", "app", "site"); err != nil {
		a.deps.WriteError(w, http.StatusBadRequest, err)
		return
	}
	page, perr := httppage.Parse(r, defaultPageLimit, maxPageLimit)
	if perr != nil {
		a.deps.WriteError(w, http.StatusBadRequest, perr)
		return
	}
	tenant, _, ok := a.scoped(w, r, dem.GateRead)
	if !ok {
		return
	}
	label, dur, werr := dem.ParseWindow(r.URL.Query().Get("window"))
	if werr != nil {
		a.deps.WriteError(w, http.StatusBadRequest, werr)
		return
	}
	q := r.URL.Query()
	if t := strings.ToUpper(strings.TrimSpace(q.Get("type"))); t != "" && !ValidChangeType(t) {
		a.deps.WriteError(w, http.StatusBadRequest,
			fmt.Errorf("unknown change type %q", clip(t, 40)))
		return
	}
	cq := ChangeQuery{
		Since: a.deps.Now().UTC().Add(-changeLookbackFor(dur)),
		App:   strings.TrimSpace(q.Get("app")), Site: strings.TrimSpace(q.Get("site")),
		Limit: maxPageLimit,
	}
	if t := strings.ToUpper(strings.TrimSpace(q.Get("type"))); t != "" {
		cq.Types = []string{t}
	}
	all, err := a.deps.Store.ListChanges(r.Context(), tenant, cq)
	if err != nil {
		a.deps.WriteError(w, http.StatusInternalServerError, err)
		return
	}
	rows := httppage.SliceOf(all, page)
	httppage.LogTruncated(ChangesPath, page, len(rows), len(all))
	httppage.WriteHeaders(w, page, len(rows), len(all))
	note := ""
	if len(all) == 0 {
		note = "No change was recorded in this window. That may be correct — a quiet estate reports nothing — but it is not proof that nothing changed: only the producers that are wired report here."
	}
	a.deps.WriteJSON(w, http.StatusOK, map[string]any{
		"window": label, "changes": rows, "total": len(all), "returned": len(rows),
		"limit": page.Limit, "offset": page.Offset,
		"complete": httppage.Complete(page, len(rows), len(all)), "note": note,
	})
}

func (a *API) recordChange(w http.ResponseWriter, r *http.Request) {
	if err := httppage.RejectUnknownQuery(r); err != nil {
		a.deps.WriteError(w, http.StatusBadRequest, err)
		return
	}
	tenant, p, ok := a.scoped(w, r, dem.GateWrite)
	if !ok {
		return
	}
	var cw changeWire
	if !a.decode(w, r, &cw, "change") {
		return
	}
	at := a.deps.Now().UTC()
	if strings.TrimSpace(cw.EventAt) != "" {
		parsed, perr := time.Parse(time.RFC3339, cw.EventAt)
		if perr != nil {
			a.deps.WriteError(w, http.StatusBadRequest,
				errors.New("event_at must be an RFC3339 timestamp"))
			return
		}
		at = parsed.UTC()
	}
	src := strings.ToLower(strings.TrimSpace(cw.Source))
	if src == "" {
		src = SourceManual
	}
	actor := cw.Actor
	if actor == "" {
		actor = p.Subject
	}
	ch := ChangeEvent{
		TenantID: tenant, // from the TOKEN, never the body
		Type:     cw.Type, Actor: actor, Object: cw.Object, ObjectKind: cw.ObjectKind,
		Summary: cw.Summary, Before: cw.Before, After: cw.After,
		ReleaseID: cw.ReleaseID, RollbackRef: cw.RollbackRef,
		Site: cw.Site, App: cw.App, Seam: cw.Seam, Cohort: cw.Cohort,
		Provenance: Provenance{
			Source: src, SourceObject: cw.SourceObject, Producer: p.Subject,
			EventAt: at, ObservedAt: a.deps.Now().UTC(),
			Observation: ObservationObserved, DataClass: DataClassCustomerMetadata,
		},
	}
	out, err := a.deps.Store.RecordChange(r.Context(), ch)
	if err != nil {
		a.deps.WriteError(w, http.StatusBadRequest, err)
		return
	}
	a.deps.Counters.ChangesRecorded.Add(1)
	a.deps.WriteJSON(w, http.StatusCreated, out)
}

// ── data health ─────────────────────────────────────────────────────────────

// HandleDataHealth serves GET /api/dem/data-health.
func (a *API) HandleDataHealth(w http.ResponseWriter, r *http.Request) {
	if a == nil {
		http.NotFound(w, r)
		return
	}
	if !a.methodIs(w, r, http.MethodGet) {
		return
	}
	if err := httppage.RejectUnknownQuery(r, "window"); err != nil {
		a.deps.WriteError(w, http.StatusBadRequest, err)
		return
	}
	tenant, _, ok := a.scoped(w, r, dem.GateRead)
	if !ok {
		return
	}
	asm, err := a.assemble(r, tenant, r.URL.Query().Get("window"))
	if err != nil {
		a.deps.WriteError(w, http.StatusBadRequest, err)
		return
	}
	a.deps.WriteJSON(w, http.StatusOK, map[string]any{
		"window": asm.Window, "enabled": a.deps.Enabled,
		"data_health": asm.DataHealth, "policy_version": a.deps.Policy.Version,
	})
}

// ── shared plumbing ─────────────────────────────────────────────────────────

func (a *API) methodIs(w http.ResponseWriter, r *http.Request, method string) bool {
	if r.Method == method {
		return true
	}
	w.Header().Set("Allow", method)
	a.deps.WriteError(w, http.StatusMethodNotAllowed, errors.New(method+" only"))
	return false
}

// decode bounds and strictly decodes a write body. Unknown fields are REFUSED:
// a typo'd budget must fail loudly, not be silently dropped.
func (a *API) decode(w http.ResponseWriter, r *http.Request, into any, what string) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(into); err != nil {
		a.deps.WriteError(w, http.StatusBadRequest, errors.New("invalid "+what+" payload"))
		return false
	}
	return true
}

package bgpwatch

// http.go — the module's read/write HTTP surface. Three routes:
//
//	GET  /api/bgp/alerts         — the tenant's alert history + current incidents
//	GET  /api/bgp/alerts/config  — the tenant's declared alert policy
//	PUT  /api/bgp/alerts/config  — replace it (owner stamped from the token)
//	GET  /api/bgp/bogons         — bogon sightings + the set actually in force
//
// §3a: every one of them is per-tenant DATA. A cross-tenant principal (the
// platform owner in the Global view) must scope into a concrete tenant with the
// switcher before reading or writing — refused, never a wildcard (the
// /api/bgp/feed and /api/bgp/watchlist precedent in bgp_ops.go).
//
// §3 fail-closed at the boundary: an unknown query parameter is REFUSED. A
// silently-ignored "filter" that never filtered is how an unscoped answer
// ships looking like a scoped one.

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Gate is the module's abstract authorization gate; the integrator maps it onto
// the platform's RBAC model.
type Gate int

const (
	// GateRead — reading the tenant's own alerts, policy and sightings.
	GateRead Gate = iota
	// GateWrite — replacing the tenant's alert policy.
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
	// Policies is the per-tenant policy store. Required.
	Policies PolicyStore
	// Bogons is the compiled bogon table. Required.
	Bogons *BogonSet
	// BogonFeedEnabled reports whether the optional full-bogons fetch is on.
	BogonFeedEnabled bool
	// Eval is the running evaluator, or nil when FEATURE_BGP_ALERTS is off. A
	// nil evaluator answers 200 with enabled:false and an explanation — never a
	// fabricated empty incident list that reads as "all clear".
	Eval *Evaluator
	// Now is the clock. Required.
	Now func() time.Time
	// WriteJSON / WriteError are the platform's response writers. Required.
	WriteJSON  func(w http.ResponseWriter, status int, body any)
	WriteError func(w http.ResponseWriter, status int, err error)
	// LogWarn is the structured logger. Required.
	LogWarn func(msg string, fields map[string]any)
}

func (d APIDeps) validate() error {
	missing := make([]string, 0, 7)
	check := func(n string, ok bool) {
		if !ok {
			missing = append(missing, n)
		}
	}
	check("Authz", d.Authz != nil)
	check("Policies", d.Policies != nil)
	check("Bogons", d.Bogons != nil)
	check("Now", d.Now != nil)
	check("WriteJSON", d.WriteJSON != nil)
	check("WriteError", d.WriteError != nil)
	check("LogWarn", d.LogWarn != nil)
	if len(missing) > 0 {
		return fmt.Errorf("bgpwatch: APIDeps missing required fields: %s", strings.Join(missing, ", "))
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
	return &API{deps: d}, nil
}

// Bounds on a read (§9).
const (
	defaultAlertLimit = 100
	maxAlertLimit     = 500
	defaultBogonLimit = 100
	maxBogonLimit     = SightingMaxPerTenant
	// maxPolicyBodyBytes bounds the PUT body before it is even decoded.
	maxPolicyBodyBytes = 128 << 10
)

// rejectUnknownQuery refuses any query parameter this endpoint does not know.
func rejectUnknownQuery(r *http.Request, allowed ...string) error {
	ok := map[string]bool{"as_tenant": true} // the platform-wide tenant switcher
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
// read of per-tenant data (§3a). It writes the error response itself.
func (a *API) scoped(w http.ResponseWriter, r *http.Request, gate Gate) (string, Principal, bool) {
	p, ok := a.deps.Authz(w, r, gate)
	if !ok {
		return "", Principal{}, false
	}
	t := normTenant(p.Tenant)
	if p.Cross || t == "" {
		a.deps.WriteError(w, http.StatusBadRequest,
			errors.New("select a tenant to read its BGP alerts (they are per-tenant data; cross-tenant reads are refused)"))
		return "", Principal{}, false
	}
	return t, p, true
}

func parseLimit(raw string, def, max int) (int, error) {
	if strings.TrimSpace(raw) == "" {
		return def, nil
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 1 || n > max {
		return 0, fmt.Errorf("limit must be 1..%d", max)
	}
	return n, nil
}

// disabledNote is the honest answer when FEATURE_BGP_ALERTS is off.
const disabledNote = "BGP alerting is off. Set " + EnvFeatureFlag + "=true to run the watchlist evaluator. " +
	"An empty list here means the evaluator has not run — NOT that nothing is wrong."

// HandleAlerts serves GET /api/bgp/alerts.
func (a *API) HandleAlerts(w http.ResponseWriter, r *http.Request) {
	if a == nil {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet {
		a.deps.WriteError(w, http.StatusMethodNotAllowed, errors.New("GET only"))
		return
	}
	if err := rejectUnknownQuery(r, "limit"); err != nil {
		a.deps.WriteError(w, http.StatusBadRequest, err)
		return
	}
	tenant, _, ok := a.scoped(w, r, GateRead)
	if !ok {
		return
	}
	limit, err := parseLimit(r.URL.Query().Get("limit"), defaultAlertLimit, maxAlertLimit)
	if err != nil {
		a.deps.WriteError(w, http.StatusBadRequest, err)
		return
	}
	body := map[string]any{
		"alerts":    []Alert{},
		"incidents": []Incident{},
		"classes":   []string{string(ClassOriginChange), string(ClassRPKIInvalid), string(ClassBogon), string(ClassRouteLeak), string(ClassVisibilityLoss), string(ClassNone), string(ClassUnknown)},
	}
	if a.deps.Eval == nil {
		body["status"] = Status{Enabled: false, Note: disabledNote}
		a.deps.WriteJSON(w, http.StatusOK, body)
		return
	}
	alerts, aerr := a.deps.Eval.Alerts(tenant, limit)
	if aerr != nil {
		a.deps.WriteError(w, http.StatusInternalServerError, aerr)
		return
	}
	incidents, ierr := a.deps.Eval.Incidents(tenant)
	if ierr != nil {
		a.deps.WriteError(w, http.StatusInternalServerError, ierr)
		return
	}
	body["alerts"], body["incidents"] = alerts, incidents
	body["status"] = a.deps.Eval.Status(tenant)
	body["metrics"] = a.deps.Eval.Metrics().Snapshot()
	a.deps.WriteJSON(w, http.StatusOK, body)
}

// policyWire is the request/response shape for the config route. ASNs are
// accepted as STRINGS ("AS64500" or "64500") so a UI never has to guess the
// operator's notation, and every one is parsed at this boundary.
type policyWire struct {
	Default  configWire            `json:"default"`
	Prefixes map[string]configWire `json:"prefixes,omitempty"`
}

type configWire struct {
	ExpectedOrigins []string `json:"expected_origins,omitempty"`
	Upstreams       []string `json:"upstreams,omitempty"`
	MinVisibility   float64  `json:"min_visibility,omitempty"`
	MinVantages     int      `json:"min_vantages,omitempty"`
}

func (c configWire) toConfig() (PolicyConfig, error) {
	out := PolicyConfig{MinVisibility: c.MinVisibility, MinVantages: c.MinVantages}
	conv := func(in []string) ([]uint32, error) {
		if len(in) > MaxDeclaredASNs {
			return nil, fmt.Errorf("at most %d ASNs per set", MaxDeclaredASNs)
		}
		o := make([]uint32, 0, len(in))
		for _, s := range in {
			n, err := ParseASN(s)
			if err != nil {
				return nil, err
			}
			o = append(o, n)
		}
		return o, nil
	}
	var err error
	if out.ExpectedOrigins, err = conv(c.ExpectedOrigins); err != nil {
		return PolicyConfig{}, fmt.Errorf("expected_origins: %w", err)
	}
	if out.Upstreams, err = conv(c.Upstreams); err != nil {
		return PolicyConfig{}, fmt.Errorf("upstreams: %w", err)
	}
	return out, nil
}

func configToWire(c PolicyConfig) configWire {
	asns := func(in []uint32) []string {
		o := make([]string, 0, len(in))
		for _, a := range in {
			o = append(o, fmt.Sprintf("AS%d", a))
		}
		return o
	}
	return configWire{
		ExpectedOrigins: asns(c.ExpectedOrigins), Upstreams: asns(c.Upstreams),
		MinVisibility: c.MinVisibility, MinVantages: c.MinVantages,
	}
}

// HandleAlertConfig serves GET/PUT /api/bgp/alerts/config.
func (a *API) HandleAlertConfig(w http.ResponseWriter, r *http.Request) {
	if a == nil {
		http.NotFound(w, r)
		return
	}
	if err := rejectUnknownQuery(r); err != nil {
		a.deps.WriteError(w, http.StatusBadRequest, err)
		return
	}
	gate := GateRead
	if r.Method == http.MethodPut {
		gate = GateWrite
	}
	tenant, p, ok := a.scoped(w, r, gate)
	if !ok {
		return
	}
	defaults := map[string]any{
		"min_visibility":   DefaultMinVisibility,
		"min_vantages":     DefaultMinVantages,
		"max_prefixes":     MaxPolicyPrefixes,
		"max_asns_per_set": MaxDeclaredASNs,
	}
	switch r.Method {
	case http.MethodGet:
		pol, err := a.deps.Policies.Policy(r.Context(), tenant)
		if err != nil {
			a.deps.WriteError(w, http.StatusInternalServerError, err)
			return
		}
		out := policyWire{Default: configToWire(pol.Default), Prefixes: map[string]configWire{}}
		for k, v := range pol.Prefixes {
			out.Prefixes[k] = configToWire(v)
		}
		a.deps.WriteJSON(w, http.StatusOK, map[string]any{
			"config": out, "defaults": defaults,
			"updated_by": pol.UpdatedBy, "updated_at": pol.UpdatedAt,
			"note": "expected_origins empty ⇒ the origin baseline is LEARNED from the first observation and marked as such. " +
				"upstreams empty ⇒ the route-leak heuristic does not run (there is nothing to call unexpected).",
		})
	case http.MethodPut:
		var req policyWire
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxPolicyBodyBytes)).Decode(&req); err != nil {
			a.deps.WriteError(w, http.StatusBadRequest, fmt.Errorf("bad body: %w", err))
			return
		}
		pol := TenantPolicy{Prefixes: map[string]PolicyConfig{}}
		def, err := req.Default.toConfig()
		if err != nil {
			a.deps.WriteError(w, http.StatusBadRequest, fmt.Errorf("default: %w", err))
			return
		}
		pol.Default = def
		if len(req.Prefixes) > MaxPolicyPrefixes {
			a.deps.WriteError(w, http.StatusBadRequest, fmt.Errorf("at most %d per-prefix policies are allowed", MaxPolicyPrefixes))
			return
		}
		for k, v := range req.Prefixes {
			c, cerr := v.toConfig()
			if cerr != nil {
				a.deps.WriteError(w, http.StatusBadRequest, fmt.Errorf("%s: %w", clip(k, 64), cerr))
				return
			}
			pol.Prefixes[k] = c
		}
		norm, nerr := pol.Normalize()
		if nerr != nil {
			a.deps.WriteError(w, http.StatusBadRequest, nerr)
			return
		}
		// §3a rule 2: the owner is stamped from the AUTHENTICATED principal.
		// There is no tenant field on the wire to override it with.
		if err := a.deps.Policies.SetPolicy(r.Context(), tenant, p.Subject, norm); err != nil {
			a.deps.WriteError(w, http.StatusInternalServerError, err)
			return
		}
		out := policyWire{Default: configToWire(norm.Default), Prefixes: map[string]configWire{}}
		for k, v := range norm.Prefixes {
			out.Prefixes[k] = configToWire(v)
		}
		a.deps.WriteJSON(w, http.StatusOK, map[string]any{"ok": true, "config": out, "defaults": defaults})
	default:
		a.deps.WriteError(w, http.StatusMethodNotAllowed, errors.New("GET or PUT"))
	}
}

// HandleBogons serves GET /api/bgp/bogons.
func (a *API) HandleBogons(w http.ResponseWriter, r *http.Request) {
	if a == nil {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet {
		a.deps.WriteError(w, http.StatusMethodNotAllowed, errors.New("GET only"))
		return
	}
	if err := rejectUnknownQuery(r, "limit"); err != nil {
		a.deps.WriteError(w, http.StatusBadRequest, err)
		return
	}
	tenant, _, ok := a.scoped(w, r, GateRead)
	if !ok {
		return
	}
	limit, err := parseLimit(r.URL.Query().Get("limit"), defaultBogonLimit, maxBogonLimit)
	if err != nil {
		a.deps.WriteError(w, http.StatusBadRequest, err)
		return
	}
	sightings := []Sighting{}
	if a.deps.Eval != nil {
		s, serr := a.deps.Eval.Sightings(tenant, limit)
		if serr != nil {
			a.deps.WriteError(w, http.StatusInternalServerError, serr)
			return
		}
		sightings = s
	}
	body := map[string]any{
		"sightings": sightings,
		"set": map[string]any{
			"source": StaticSetSource,
			"date":   StaticSetDate,
			"blocks": a.deps.Bogons.StaticCount(),
			"note": "IPv4 has had no unallocated unicast /8 since the IANA free pool was exhausted on 2011-02-03, " +
				"so the embedded IPv4 set is the special-purpose registry only. IPv6 outside 2000::/3 is reported as unallocated by rule, not by a snapshot.",
		},
		"feed": a.deps.Bogons.FeedStatus(a.deps.BogonFeedEnabled),
	}
	if a.deps.Eval == nil {
		body["note"] = "The sighting register is fed by the watchlist evaluator, which is off. " + disabledNote
	}
	a.deps.WriteJSON(w, http.StatusOK, body)
}

// LookupPrefix is a helper for the integrator: it reports whether one prefix is
// a bogon under the set currently in force. Used by the watchlist surface so a
// watched bogon is flagged even before the evaluator's first pass.
func (a *API) LookupPrefix(prefix string) (BogonEntry, bool) {
	if a == nil {
		return BogonEntry{}, false
	}
	p, err := parsePrefix(prefix)
	if err != nil {
		return BogonEntry{}, false
	}
	return a.deps.Bogons.Lookup(p)
}

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Package changeapi serves the change ledger to people and tools (tracker 337
// N-D3):
//
//	GET /api/changes                 the caller's changes, every ledger filter,
//	                                 optionally anchored to an incident
//	GET /api/changes/{id}            one change
//	GET /api/changes/{id}/diff       what it changed: a configuration change
//	                                 as the REDACTED unified diff of its two
//	                                 captured versions; any other change as its
//	                                 redacted before/after
//
// HONESTY. A change listed around an incident is labelled by what is known:
// relation "temporal" — it happened in the incident's window — and whether it
// touched one of the incident's affected devices or sites. It is never labelled
// a cause: the engine's causal chain does not reference individual changes,
// and by the engine's own rule a change can at most corroborate a hypothesis.
//
// §3a. The tenant is the caller's, from Authorize — never a request field. A
// change id from another tenant, a malformed id and a missing one are the same
// 404. A cross-tenant (Global) caller has no single ledger and is told so.
package changeapi

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"netops/backend/internal/dem/experience"
)

// Bounds.
const (
	DefaultLimit   = 100
	MaxLimit       = 500
	DefaultWindow  = 24 * time.Hour
	MaxWindow      = experience.ChangeRetention
	MaxAnchorSpan  = 24 * time.Hour
	DefaultBefore  = 30 * time.Minute
	DefaultAfter   = 10 * time.Minute
	maxFilterItems = 20
	maxValueLen    = 256
)

// RelationTemporal is the only relation this API asserts (see package doc).
const RelationTemporal = "temporal"

// RelationNote is the sentence every incident-anchored row carries.
const RelationNote = "Happened in the incident's window — temporally correlated, not established as its cause."

// ErrNotFound: not visible to the caller (or does not exist).
var ErrNotFound = errors.New("changeapi: not found")

// Caller is the authenticated principal's scope.
type Caller struct {
	Tenant string
	Cross  bool // a Global (cross-tenant) view: no single ledger to read
}

// IncidentScope is what an incident anchors: when it began and what it
// affected (device ids / names and site slugs as the incident store holds them).
type IncidentScope struct {
	ID      string
	Start   time.Time
	Devices []string
	Sites   []string
}

// Diff is a rendered configuration comparison (already redacted upstream).
type Diff struct {
	DeviceID    string    `json:"device_id"`
	FromVersion string    `json:"from_version"`
	ToVersion   string    `json:"to_version"`
	FromAt      time.Time `json:"from_at"`
	ToAt        time.Time `json:"to_at"`
	Added       int       `json:"added"`
	Removed     int       `json:"removed"`
	Unified     string    `json:"unified"`
	Truncated   bool      `json:"truncated"`
	// Unavailable is the honest sentence when no comparison exists.
	Unavailable string `json:"unavailable,omitempty"`
}

// Deps are injected by the server.
type Deps struct {
	Store experience.Store
	// Authorize resolves the caller; ok=false means it has written the response.
	Authorize func(w http.ResponseWriter, r *http.Request) (Caller, bool)
	// Incident resolves an incident the caller can see (ErrNotFound otherwise).
	Incident func(ctx context.Context, r *http.Request, id string) (IncidentScope, error)
	// ConfigDiff compares two captured versions of a device (ErrNotFound when
	// the device is not the caller's). nil = configuration backup not wired.
	ConfigDiff func(ctx context.Context, r *http.Request, deviceID, fromVersion, toVersion string) (Diff, error)
	// Redact scrubs secrets from free text (before/after of non-config changes).
	Redact func(string) string
	// WriteJSON / WriteError are the server's response helpers.
	WriteJSON  func(w http.ResponseWriter, status int, v any)
	WriteError func(w http.ResponseWriter, status int, err error)
	Now        func() time.Time
}

// View is one change as the API returns it. Before/After are only on the
// by-id read, redacted.
type View struct {
	ID           string    `json:"id"`
	Type         string    `json:"type"`
	At           time.Time `json:"event_at"`
	DetectedAt   time.Time `json:"detected_at,omitempty"`
	Actor        string    `json:"actor,omitempty"`
	ActorType    string    `json:"actor_type,omitempty"`
	Automation   bool      `json:"automation,omitempty"`
	Object       string    `json:"object"`
	ObjectKind   string    `json:"object_kind,omitempty"`
	Site         string    `json:"site,omitempty"`
	App          string    `json:"app,omitempty"`
	Seam         string    `json:"seam,omitempty"`
	Summary      string    `json:"summary"`
	SourceSystem string    `json:"source_system"`
	TicketRef    string    `json:"ticket_ref,omitempty"`
	HasDiff      bool      `json:"has_diff"`
	Before       string    `json:"before,omitempty"`
	After        string    `json:"after,omitempty"`
	// Incident-anchored reads only.
	Relation        string `json:"relation,omitempty"`
	RelationNote    string `json:"relation_note,omitempty"`
	InIncidentScope *bool  `json:"in_incident_scope,omitempty"`
}

func viewOf(c experience.ChangeEvent) View {
	return View{ID: c.ID, Type: c.Type, At: c.EventAt, DetectedAt: c.ObservedAt,
		Actor: firstNonEmpty(c.ActorDisplay, c.ActorID, c.Actor), ActorType: c.ActorType, Automation: c.Automation,
		Object: c.Object, ObjectKind: c.ObjectKind, Site: c.Site, App: c.App, Seam: c.Seam, Summary: c.Summary,
		SourceSystem: c.SourceSystem, TicketRef: c.TicketRef, HasDiff: c.Before != "" || c.After != ""}
}

var (
	idRe      = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	uuidRe    = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	versionRe = regexp.MustCompile(`^sha256:([0-9a-f]{8,64})$`)
)

// Handler serves /api/changes and /api/changes/.
func (d Deps) Handler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		d.WriteError(w, http.StatusMethodNotAllowed, errors.New("GET"))
		return
	}
	caller, ok := d.Authorize(w, r)
	if !ok {
		return
	}
	rest := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/changes"), "/")
	if rest == "" {
		d.list(w, r, caller)
		return
	}
	id, sub, _ := strings.Cut(rest, "/")
	if !idRe.MatchString(id) || (sub != "" && sub != "diff") {
		d.WriteError(w, http.StatusNotFound, errors.New("not found"))
		return
	}
	c, err := d.one(r.Context(), caller, id)
	switch {
	case errors.Is(err, ErrNotFound):
		d.WriteError(w, http.StatusNotFound, errors.New("not found"))
		return
	case err != nil:
		d.WriteError(w, http.StatusInternalServerError, errors.New("the change could not be read"))
		return
	}
	if sub == "diff" {
		d.diff(w, r, c)
		return
	}
	v := viewOf(c)
	v.Before, v.After = d.redact(c.Before), d.redact(c.After)
	d.WriteJSON(w, http.StatusOK, v)
}

func (d Deps) redact(s string) string {
	if s == "" || d.Redact == nil {
		return s
	}
	return d.Redact(s)
}

func (d Deps) one(ctx context.Context, caller Caller, id string) (experience.ChangeEvent, error) {
	if caller.Cross {
		return experience.ChangeEvent{}, ErrNotFound
	}
	evs, err := d.Store.ListChanges(ctx, caller.Tenant, experience.ChangeQuery{IDs: []string{id}, Limit: 1})
	if err != nil {
		return experience.ChangeEvent{}, err
	}
	if len(evs) == 0 || evs[0].ID != id {
		return experience.ChangeEvent{}, ErrNotFound
	}
	return evs[0], nil
}

func (d Deps) diff(w http.ResponseWriter, r *http.Request, c experience.ChangeEvent) {
	from, fok := versionRe.FindStringSubmatch(c.Before), versionRe.FindStringSubmatch(c.After)
	if c.SourceSystem == experience.SourceSystemConfigCapture && c.ObjectKind == "device" && fok != nil && from != nil {
		if d.ConfigDiff == nil {
			d.WriteJSON(w, http.StatusOK, map[string]any{"change_id": c.ID, "kind": "config",
				"diff": Diff{DeviceID: c.Object, Unavailable: "configuration backup is not enabled on this deployment"}})
			return
		}
		df, err := d.ConfigDiff(r.Context(), r, c.Object, from[1], fok[1])
		switch {
		case errors.Is(err, ErrNotFound):
			d.WriteError(w, http.StatusNotFound, errors.New("not found"))
		case err != nil:
			d.WriteError(w, http.StatusInternalServerError, errors.New("the configuration diff could not be read"))
		default:
			d.WriteJSON(w, http.StatusOK, map[string]any{"change_id": c.ID, "kind": "config", "diff": df})
		}
		return
	}
	d.WriteJSON(w, http.StatusOK, map[string]any{"change_id": c.ID, "kind": "values",
		"before": d.redact(c.Before), "after": d.redact(c.After), "has_diff": c.Before != "" || c.After != ""})
}

// listParams is a parsed, bounded list request.
type listParams struct {
	q                     experience.ChangeQuery
	incident              string
	before, after, window time.Duration
}

func (d Deps) parseList(r *http.Request) (listParams, error) {
	v := r.URL.Query()
	now := time.Now().UTC()
	if d.Now != nil {
		now = d.Now()
	}
	p := listParams{q: experience.ChangeQuery{Limit: DefaultLimit}, before: DefaultBefore, after: DefaultAfter}
	multi := func(name string) ([]string, error) {
		var out []string
		for _, raw := range v[name] {
			for _, s := range strings.Split(raw, ",") {
				s = strings.TrimSpace(s)
				if s == "" {
					continue
				}
				if len(s) > maxValueLen {
					return nil, fmt.Errorf("%s value too long", name)
				}
				out = append(out, s)
			}
		}
		if len(out) > maxFilterItems {
			return nil, fmt.Errorf("at most %d %s values", maxFilterItems, name)
		}
		return out, nil
	}
	var err error
	for name, dst := range map[string]*[]string{"type": &p.q.Types, "actor": &p.q.Actors, "object": &p.q.Objects,
		"object_kind": &p.q.ObjectKinds, "source": &p.q.Sources, "site": &p.q.Sites, "app": &p.q.Apps, "seam": &p.q.Seams} {
		if *dst, err = multi(name); err != nil {
			return p, err
		}
	}
	if s := v.Get("limit"); s != "" {
		n, err := strconv.Atoi(s)
		if err != nil || n < 1 || n > MaxLimit {
			return p, fmt.Errorf("limit is 1 to %d", MaxLimit)
		}
		p.q.Limit = n
	}
	dur := func(name string, def, max time.Duration) (time.Duration, error) {
		s := v.Get(name)
		if s == "" {
			return def, nil
		}
		x, err := time.ParseDuration(s)
		if err != nil || x <= 0 || x > max {
			return 0, fmt.Errorf("%s is a duration up to %s", name, max)
		}
		return x, nil
	}
	if p.incident = strings.TrimSpace(v.Get("incident_id")); p.incident != "" {
		if !uuidRe.MatchString(p.incident) {
			return p, errors.New("incident_id is not an incident id")
		}
		if p.before, err = dur("before", DefaultBefore, MaxAnchorSpan); err != nil {
			return p, err
		}
		if p.after, err = dur("after", DefaultAfter, MaxAnchorSpan); err != nil {
			return p, err
		}
		return p, nil
	}
	if p.window, err = dur("window", DefaultWindow, MaxWindow); err != nil {
		return p, err
	}
	p.q.Since, p.q.Until = now.Add(-p.window), now
	for name, dst := range map[string]*time.Time{"since": &p.q.Since, "until": &p.q.Until} {
		if s := v.Get(name); s != "" {
			t, err := time.Parse(time.RFC3339, s)
			if err != nil {
				return p, fmt.Errorf("%s is an RFC 3339 time", name)
			}
			*dst = t
		}
	}
	if !p.q.Until.After(p.q.Since) || p.q.Until.Sub(p.q.Since) > MaxWindow {
		return p, fmt.Errorf("the window must be positive and at most %s", MaxWindow)
	}
	return p, nil
}

func (d Deps) list(w http.ResponseWriter, r *http.Request, caller Caller) {
	p, err := d.parseList(r)
	if err != nil {
		d.WriteError(w, http.StatusBadRequest, err)
		return
	}
	if caller.Cross {
		d.WriteJSON(w, http.StatusOK, map[string]any{"changes": []View{}, "returned": 0, "truncated": false,
			"note": "Choose a workspace: the change ledger belongs to one workspace, and the Global view has none of its own."})
		return
	}
	var inc *IncidentScope
	if p.incident != "" {
		sc, err := d.Incident(r.Context(), r, p.incident)
		switch {
		case errors.Is(err, ErrNotFound):
			d.WriteError(w, http.StatusNotFound, errors.New("not found"))
			return
		case err != nil:
			d.WriteError(w, http.StatusInternalServerError, errors.New("the incident could not be read"))
			return
		}
		inc = &sc
		p.q.Since, p.q.Until = sc.Start.Add(-p.before), sc.Start.Add(p.after)
	}
	limit := p.q.Limit
	p.q.Limit = limit + 1 // one past the limit tells "that is all" from "that is all we read"
	evs, err := d.Store.ListChanges(r.Context(), caller.Tenant, p.q)
	if err != nil {
		d.WriteError(w, http.StatusInternalServerError, errors.New("changes could not be read"))
		return
	}
	truncated := len(evs) > limit
	if truncated {
		evs = evs[:limit]
	}
	views := make([]View, 0, len(evs))
	for _, c := range evs {
		v := viewOf(c)
		if inc != nil {
			in := touches(c, inc)
			v.Relation, v.RelationNote, v.InIncidentScope = RelationTemporal, RelationNote, &in
		}
		views = append(views, v)
	}
	out := map[string]any{"changes": views, "returned": len(views), "truncated": truncated,
		"window": map[string]time.Time{"from": p.q.Since, "to": p.q.Until}}
	if inc != nil {
		out["incident"] = map[string]any{"id": inc.ID, "start": inc.Start,
			"rule": "A change is in the incident's scope when its object is one of the incident's affected devices or its site is one of the incident's sites. That is where it happened, not why the incident happened."}
	}
	d.WriteJSON(w, http.StatusOK, out)
}

// touches reports whether a change landed on something the incident affected.
func touches(c experience.ChangeEvent, inc *IncidentScope) bool {
	for _, dv := range inc.Devices {
		if dv != "" && strings.EqualFold(dv, c.Object) {
			return true
		}
	}
	for _, s := range inc.Sites {
		if s != "" && s == c.Site {
			return true
		}
	}
	return false
}

func firstNonEmpty(xs ...string) string {
	for _, x := range xs {
		if x != "" {
			return x
		}
	}
	return ""
}

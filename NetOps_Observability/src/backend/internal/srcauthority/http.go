// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package srcauthority

// http.go — /api/ai/source-authority (tracker 337 N-F6):
//
//	GET    /api/ai/source-authority   the workspace's order (or the platform default)
//	PUT    /api/ai/source-authority   {"order": ["controller","discovered","declared","manual"]}
//	DELETE /api/ai/source-authority   back to the platform default
//
// §3a: the tenant is the caller's (Authorize → principalTenant), never a
// request field — an unknown body field (a smuggled tenant_id) is refused. A
// Global (cross-tenant) view has no workspace and is told to choose one. There
// is no id in the path, so no other tenant's row can be named at all.

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"
)

// Level is the permission an action needs.
type Level int

const (
	LevelRead   Level = iota // see the order
	LevelChange              // change or reset the order
)

// Caller is the authenticated principal.
type Caller struct {
	Tenant string
	Cross  bool
	Sub    string
}

// Deps are the server seams.
type Deps struct {
	// Store is nil on a deployment without the platform database: reads
	// answer the platform default, changes answer 503.
	Store Store
	// Authorize checks the permission for level; ok=false means it has
	// written the response.
	Authorize func(w http.ResponseWriter, r *http.Request, level Level) (Caller, bool)
	// Audit records one change (old and new order; nothing else).
	Audit      func(r *http.Request, c Caller, detail map[string]any)
	WriteJSON  func(w http.ResponseWriter, status int, v any)
	WriteError func(w http.ResponseWriter, status int, err error)
	Log        func(msg string, err error)
}

// BodyCap bounds a request body.
const BodyCap = 4 << 10

// ClassInfo is one class as the UI shows it.
type ClassInfo struct {
	Class Class  `json:"class"`
	Label string `json:"label"`
}

// View is the GET/PUT/DELETE response.
type View struct {
	Order      []ClassInfo `json:"order"`
	Default    []ClassInfo `json:"default"`
	Customized bool        `json:"customized"`
	Editable   bool        `json:"editable"`
	UpdatedBy  string      `json:"updated_by,omitempty"`
	UpdatedAt  *time.Time  `json:"updated_at,omitempty"`
}

func infos(order []Class) []ClassInfo {
	out := make([]ClassInfo, 0, len(order))
	for _, c := range order {
		out = append(out, ClassInfo{Class: c, Label: Label(c)})
	}
	return out
}

func (d Deps) view(p Policy, has bool) View {
	v := View{Order: infos(DefaultOrder()), Default: infos(DefaultOrder()), Editable: d.Store != nil}
	if has && ValidateOrder(p.Order) == nil {
		v.Order = infos(p.Order)
		v.Customized = !IsDefault(p.Order)
		v.UpdatedBy = p.UpdatedBy
		if !p.UpdatedAt.IsZero() {
			t := p.UpdatedAt
			v.UpdatedAt = &t
		}
	}
	return v
}

// Handler serves /api/ai/source-authority.
func (d Deps) Handler(w http.ResponseWriter, r *http.Request) {
	if strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/ai/source-authority"), "/") != "" {
		d.WriteError(w, http.StatusNotFound, errors.New("not found"))
		return
	}
	switch r.Method {
	case http.MethodGet:
		d.get(w, r)
	case http.MethodPut:
		d.put(w, r)
	case http.MethodDelete:
		d.reset(w, r)
	default:
		d.WriteError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
	}
}

func (d Deps) caller(w http.ResponseWriter, r *http.Request, level Level) (Caller, bool) {
	c, ok := d.Authorize(w, r, level)
	if !ok {
		return Caller{}, false
	}
	if c.Cross || strings.TrimSpace(c.Tenant) == "" {
		d.WriteError(w, http.StatusBadRequest, errors.New("choose a workspace first — the source order belongs to one workspace"))
		return Caller{}, false
	}
	if level == LevelChange && d.Store == nil {
		d.WriteError(w, http.StatusServiceUnavailable, errors.New("changing the source order needs the Postgres platform store on this deployment; Iris uses the platform default"))
		return Caller{}, false
	}
	return c, true
}

func (d Deps) current(r *http.Request, tenant string) (Policy, bool, error) {
	if d.Store == nil {
		return Policy{}, false, nil
	}
	return d.Store.Get(r.Context(), tenant)
}

func (d Deps) get(w http.ResponseWriter, r *http.Request) {
	c, ok := d.caller(w, r, LevelRead)
	if !ok {
		return
	}
	p, has, err := d.current(r, c.Tenant)
	if err != nil {
		d.fail(w, "read", err)
		return
	}
	d.WriteJSON(w, http.StatusOK, d.view(p, has))
}

func (d Deps) put(w http.ResponseWriter, r *http.Request) {
	c, ok := d.caller(w, r, LevelChange)
	if !ok {
		return
	}
	var req struct {
		Order []string `json:"order"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, BodyCap)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields() // a smuggled tenant_id is an error, not a silent no-op
	if err := dec.Decode(&req); err != nil {
		d.WriteError(w, http.StatusBadRequest, errors.New("the request is not valid: "+err.Error()))
		return
	}
	if len(req.Order) > 16 {
		d.WriteError(w, http.StatusBadRequest, ErrInvalidOrder)
		return
	}
	order, err := ParseOrder(req.Order)
	if err != nil {
		d.WriteError(w, http.StatusBadRequest, err)
		return
	}
	before, had, err := d.Store.Get(r.Context(), c.Tenant)
	if err != nil {
		d.fail(w, "read", err)
		return
	}
	p, err := d.Store.Put(r.Context(), c.Tenant, c.Sub, order)
	if err != nil {
		d.fail(w, "save", err)
		return
	}
	d.audit(r, c, "set", before, had, order)
	d.WriteJSON(w, http.StatusOK, d.view(p, true))
}

func (d Deps) reset(w http.ResponseWriter, r *http.Request) {
	c, ok := d.caller(w, r, LevelChange)
	if !ok {
		return
	}
	before, had, err := d.Store.Get(r.Context(), c.Tenant)
	if err != nil {
		d.fail(w, "read", err)
		return
	}
	if err := d.Store.Delete(r.Context(), c.Tenant); err != nil {
		d.fail(w, "reset", err)
		return
	}
	d.audit(r, c, "reset", before, had, DefaultOrder())
	d.WriteJSON(w, http.StatusOK, d.view(Policy{}, false))
}

func orderStrings(order []Class) []string {
	out := make([]string, len(order))
	for i, c := range order {
		out[i] = string(c)
	}
	return out
}

func (d Deps) audit(r *http.Request, c Caller, action string, before Policy, had bool, after []Class) {
	if d.Audit == nil {
		return
	}
	from := DefaultOrder()
	if had && ValidateOrder(before.Order) == nil {
		from = before.Order
	}
	d.Audit(r, c, map[string]any{
		"action": action, "from": orderStrings(from), "to": orderStrings(after),
	})
}

func (d Deps) fail(w http.ResponseWriter, what string, err error) {
	if errors.Is(err, ErrInvalidOrder) {
		d.WriteError(w, http.StatusBadRequest, err)
		return
	}
	if d.Log != nil {
		d.Log("source authority "+what+" failed", err)
	}
	d.WriteError(w, http.StatusInternalServerError, errors.New("the source order could not be read or saved"))
}

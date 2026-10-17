// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package orgcontext

// http.go — /api/ai/context (tracker 337 N-F1):
//
//	GET    /api/ai/context                    the workspace's facts + history
//	POST   /api/ai/context                    new fact (version 1 = a draft)
//	GET    /api/ai/context/preview            exactly what Iris reads now
//	GET    /api/ai/context/{id}               one fact
//	PUT    /api/ai/context/{id}/draft         write / edit the open draft
//	DELETE /api/ai/context/{id}/draft         discard the open draft
//	POST   /api/ai/context/{id}/submit        send the draft for review
//	POST   /api/ai/context/{id}/withdraw      take it back to draft
//	POST   /api/ai/context/{id}/approve       {version, body_sha256} — not the author
//	POST   /api/ai/context/{id}/reject        {version, reason}       — not the author
//	POST   /api/ai/context/{id}/rollback      {to_version, reason}
//	POST   /api/ai/context/{id}/retire        {reason}
//
// §3a: the tenant is the caller's (Authorize), never a request field; a
// Global (cross-tenant) view has no workspace to read or write and is told to
// choose one. Unknown and foreign ids are the same 404. Approvals need a
// PERSON (an API key is not a second person).

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"
)

// Level is the permission an action needs.
type Level int

const (
	LevelRead   Level = iota // see facts and the preview
	LevelAuthor              // write, submit, withdraw, discard a draft
	LevelManage              // approve, reject, roll back, retire
)

// Caller is the authenticated principal.
type Caller struct {
	Tenant string
	Cross  bool
	Sub    string
	// Person is false for an API key: it may read, never author or approve.
	Person bool
}

// Deps are the server seams.
type Deps struct {
	Store Store
	// Authorize checks the permission for level (and the AI entitlement);
	// ok=false means it has written the response.
	Authorize func(w http.ResponseWriter, r *http.Request, level Level) (Caller, bool)
	// SiteVisible reports whether the caller can see the site (a fact may
	// only be scoped to a site the author can see).
	SiteVisible func(ctx context.Context, r *http.Request, site string) (bool, error)
	// ToolNames are the registered Iris tool names (a fact may not name one).
	ToolNames func() []string
	// Preview renders the block Iris reads for the tenant.
	Preview func(ctx context.Context, tenant string) (block string, facts, omitted int, err error)
	// Audit records one decision; detail never carries fact text.
	Audit func(r *http.Request, c Caller, decision string, detail map[string]any)
	// Changed is called after a committed change (cache invalidation).
	Changed    func(tenant string)
	WriteJSON  func(w http.ResponseWriter, status int, v any)
	WriteError func(w http.ResponseWriter, status int, err error)
	Log        func(msg string, err error)
}

// BodyCap bounds a request body.
const BodyCap = 8 << 10

// Handler serves /api/ai/context and /api/ai/context/.
func (d Deps) Handler(w http.ResponseWriter, r *http.Request) {
	rest := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/ai/context"), "/")
	parts := strings.Split(rest, "/")
	switch {
	case rest == "":
		switch r.Method {
		case http.MethodGet:
			d.list(w, r)
		case http.MethodPost:
			d.create(w, r)
		default:
			d.WriteError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		}
	case rest == "preview" && r.Method == http.MethodGet:
		d.preview(w, r)
	case len(parts) == 1 && r.Method == http.MethodGet:
		d.get(w, r, parts[0])
	case len(parts) == 2:
		d.action(w, r, parts[0], parts[1])
	default:
		d.WriteError(w, http.StatusNotFound, errors.New("not found"))
	}
}

func (d Deps) caller(w http.ResponseWriter, r *http.Request, level Level) (Caller, bool) {
	c, ok := d.Authorize(w, r, level)
	if !ok {
		return Caller{}, false
	}
	if c.Cross || c.Tenant == "" {
		d.WriteError(w, http.StatusBadRequest, errors.New("choose a workspace first — network context belongs to one workspace"))
		return Caller{}, false
	}
	if level > LevelRead && (!c.Person || strings.TrimSpace(c.Sub) == "") {
		d.WriteError(w, http.StatusForbidden, errors.New("network context is written and approved by people; an API key can only read it"))
		return Caller{}, false
	}
	return c, true
}

// KindInfo is the vocabulary the UI offers.
type KindInfo struct {
	Kind  Kind   `json:"kind"`
	Label string `json:"label"`
}

func (d Deps) list(w http.ResponseWriter, r *http.Request) {
	c, ok := d.caller(w, r, LevelRead)
	if !ok {
		return
	}
	docs, err := d.Store.List(r.Context(), c.Tenant)
	if err != nil {
		d.fail(w, "list", err)
		return
	}
	kinds := make([]KindInfo, 0, 9)
	for _, k := range Kinds() {
		kinds = append(kinds, KindInfo{k, Label(k)})
	}
	if docs == nil {
		docs = []Doc{}
	}
	d.WriteJSON(w, http.StatusOK, map[string]any{
		"facts": docs, "kinds": kinds, "you": c.Sub,
		"limits": map[string]int{"body_bytes": MaxBodyBytes, "key_bytes": MaxKeyBytes, "facts": MaxDocsPerTenant},
	})
}

func (d Deps) get(w http.ResponseWriter, r *http.Request, id string) {
	c, ok := d.caller(w, r, LevelRead)
	if !ok {
		return
	}
	doc, err := d.Store.Get(r.Context(), c.Tenant, id)
	if err != nil {
		d.fail(w, "get", err)
		return
	}
	d.WriteJSON(w, http.StatusOK, doc)
}

func (d Deps) preview(w http.ResponseWriter, r *http.Request) {
	c, ok := d.caller(w, r, LevelRead)
	if !ok {
		return
	}
	block, n, omitted, err := d.Preview(r.Context(), c.Tenant)
	if err != nil {
		d.fail(w, "preview", err)
		return
	}
	d.WriteJSON(w, http.StatusOK, map[string]any{"block": block, "facts": n, "omitted": omitted})
}

func decode(w http.ResponseWriter, r *http.Request, v any) error {
	r.Body = http.MaxBytesReader(w, r.Body, BodyCap)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields() // a smuggled tenant_id is an error, not a silent no-op
	if err := dec.Decode(v); err != nil {
		return errors.New("the request is not valid: " + err.Error())
	}
	return nil
}

func (d Deps) create(w http.ResponseWriter, r *http.Request) {
	c, ok := d.caller(w, r, LevelAuthor)
	if !ok {
		return
	}
	var req struct {
		Scope string `json:"scope"`
		Kind  Kind   `json:"kind"`
		Key   string `json:"key"`
		Body  string `json:"body"`
	}
	if err := decode(w, r, &req); err != nil {
		d.WriteError(w, http.StatusBadRequest, err)
		return
	}
	if req.Scope == "" {
		req.Scope = ScopeTenant
	}
	if !ValidKind(req.Kind) {
		d.WriteError(w, http.StatusBadRequest, errors.New("unknown type of fact"))
		return
	}
	if !ValidScope(req.Scope) {
		d.WriteError(w, http.StatusBadRequest, errors.New(`the place must be "tenant" or "site:<site>"`))
		return
	}
	if !d.checkContent(w, req.Kind, req.Key, req.Body) {
		return
	}
	if site := SiteOf(req.Scope); site != "" {
		vis, err := d.SiteVisible(r.Context(), r, site)
		if err != nil {
			d.fail(w, "site check", err)
			return
		}
		if !vis {
			d.WriteError(w, http.StatusNotFound, errors.New("no such site is visible to you"))
			return
		}
	}
	doc, err := d.Store.Create(r.Context(), c.Tenant, c.Sub, NewDoc{Scope: req.Scope, Kind: req.Kind, Key: req.Key, Body: req.Body})
	if err != nil {
		d.fail(w, "create", err)
		return
	}
	d.Audit(r, c, "allow", detail(doc, 1, "create"))
	d.WriteJSON(w, http.StatusCreated, doc)
}

func (d Deps) checkContent(w http.ResponseWriter, kind Kind, key, body string) bool {
	tools := d.ToolNames()
	for _, err := range []error{CheckKey(key), CheckBody(kind, body, tools)} {
		var p Problem
		if errors.As(err, &p) {
			d.WriteJSON(w, http.StatusBadRequest, map[string]any{"error": p.Say, "problem": p})
			return false
		}
	}
	return true
}

func (d Deps) action(w http.ResponseWriter, r *http.Request, id, verb string) {
	level := LevelAuthor
	switch verb {
	case "approve", "reject", "rollback", "retire":
		level = LevelManage
	case "draft", "submit", "withdraw":
	default:
		d.WriteError(w, http.StatusNotFound, errors.New("not found"))
		return
	}
	want := http.MethodPost
	if verb == "draft" && r.Method == http.MethodDelete {
		want = http.MethodDelete
	} else if verb == "draft" {
		want = http.MethodPut
	}
	if r.Method != want {
		d.WriteError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	c, ok := d.caller(w, r, level)
	if !ok {
		return
	}
	if !ValidID(id) {
		d.WriteError(w, http.StatusNotFound, errors.New("no such fact"))
		return
	}
	op := Op{Actor: c.Sub, Now: time.Now().UTC()}
	var req struct {
		Body       string `json:"body"`
		Version    int    `json:"version"`
		BodySHA256 string `json:"body_sha256"`
		ToVersion  int    `json:"to_version"`
		Reason     string `json:"reason"`
	}
	if r.Method != http.MethodDelete && r.ContentLength != 0 {
		if err := decode(w, r, &req); err != nil {
			d.WriteError(w, http.StatusBadRequest, err)
			return
		}
	}
	op.Body, op.Version, op.BodySHA256, op.ToVersion, op.Reason = req.Body, req.Version, req.BodySHA256, req.ToVersion, req.Reason
	switch {
	case verb == "draft" && r.Method == http.MethodDelete:
		op.Kind = OpDiscard
	case verb == "draft":
		op.Kind = OpDraft
		cur, err := d.Store.Get(r.Context(), c.Tenant, id)
		if err != nil {
			d.fail(w, "get", err)
			return
		}
		if !d.checkContent(w, cur.Kind, cur.Key, req.Body) {
			return
		}
	default:
		op.Kind = OpKind(verb)
	}
	if err := CheckReason(op.Reason, op.Kind == OpReject || op.Kind == OpRetire); err != nil {
		var p Problem
		if errors.As(err, &p) {
			d.WriteJSON(w, http.StatusBadRequest, map[string]any{"error": p.Say, "problem": p})
			return
		}
	}
	doc, err := d.Store.Do(r.Context(), c.Tenant, id, op)
	if err != nil {
		if errors.Is(err, ErrSelfApproval) || errors.Is(err, ErrNotAuthor) {
			d.Audit(r, c, "deny", map[string]any{"doc_id": id, "action": verb, "why": err.Error()})
		}
		d.fail(w, verb, err)
		return
	}
	v := doc.latest()
	if op.Kind == OpApprove || op.Kind == OpReject {
		v = op.Version
	}
	d.Audit(r, c, "allow", detail(doc, v, verb))
	if d.Changed != nil && (op.Kind == OpApprove || op.Kind == OpRollback || op.Kind == OpRetire) {
		d.Changed(c.Tenant)
	}
	if len(doc.Versions) == 0 {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	d.WriteJSON(w, http.StatusOK, doc)
}

// detail is the audit record of a change — ids, kind, scope, hash; never the text.
func detail(doc Doc, version int, action string) map[string]any {
	m := map[string]any{"doc_id": doc.ID, "action": action, "kind": string(doc.Kind), "scope": doc.Scope, "version": version}
	for _, v := range doc.Versions {
		if v.Version == version {
			m["body_sha256"] = v.BodySHA256
			m["state"] = string(v.State)
			if v.RestoredFrom > 0 {
				m["restored_from"] = v.RestoredFrom
			}
		}
	}
	return m
}

func (d Deps) fail(w http.ResponseWriter, what string, err error) {
	switch {
	case errors.Is(err, ErrNotFound):
		d.WriteError(w, http.StatusNotFound, errors.New("no such fact"))
	case errors.Is(err, ErrSelfApproval):
		d.WriteError(w, http.StatusForbidden, errors.New("you wrote this version, so another administrator has to approve it"))
	case errors.Is(err, ErrNotAuthor):
		d.WriteError(w, http.StatusForbidden, errors.New("only the person who wrote this draft can change it"))
	case errors.Is(err, ErrStale):
		d.WriteError(w, http.StatusConflict, errors.New("the text changed since you reviewed it — review it again"))
	case errors.Is(err, ErrWrongState):
		d.WriteError(w, http.StatusConflict, errors.New("that is not possible in the fact's current state — reload and try again"))
	case errors.Is(err, ErrExists):
		d.WriteError(w, http.StatusConflict, errors.New("a fact with this place, type and name already exists — edit that one"))
	case errors.Is(err, ErrFull):
		d.WriteError(w, http.StatusConflict, errors.New("the limit is reached (50 facts per workspace, 200 versions per fact)"))
	case errors.Is(err, ErrInvalid):
		d.WriteError(w, http.StatusBadRequest, errors.New("the request is not valid (a reason is required to reject or retire)"))
	default:
		if d.Log != nil {
			d.Log("org context "+what+" failed", err)
		}
		d.WriteError(w, http.StatusInternalServerError, errors.New("the network context could not be read or saved"))
	}
}

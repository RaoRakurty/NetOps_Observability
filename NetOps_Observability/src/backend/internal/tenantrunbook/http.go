// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package tenantrunbook

// http.go — /api/ai/runbooks (tracker 337 N-F2):
//
//	GET    /api/ai/runbooks                    the workspace's runbooks + history
//	GET    /api/ai/runbooks?q=                 search by name and when-to-use
//	GET    /api/ai/runbooks?link_type=&link_key=  what is linked to this
//	POST   /api/ai/runbooks                    new runbook (version 1 = a draft)
//	GET    /api/ai/runbooks/{id}               one runbook
//	PUT    /api/ai/runbooks/{id}/draft         write / edit the open draft
//	DELETE /api/ai/runbooks/{id}/draft         discard the open draft
//	POST   /api/ai/runbooks/{id}/check         run the cases; changes nothing
//	POST   /api/ai/runbooks/{id}/submit        run the cases, then send for review
//	POST   /api/ai/runbooks/{id}/withdraw      take it back to draft
//	POST   /api/ai/runbooks/{id}/approve       {version, body_sha256} — not the author
//	POST   /api/ai/runbooks/{id}/reject        {version, reason}      — not the author
//	POST   /api/ai/runbooks/{id}/rollback      {to_version, reason}
//	POST   /api/ai/runbooks/{id}/retire        {reason}
//	GET    /api/ai/runbooks/{id}/links         what the runbook is linked to
//	PUT    /api/ai/runbooks/{id}/links         {link_type, link_key}
//	DELETE /api/ai/runbooks/{id}/links         {link_type, link_key}
//
// §3a: the tenant is the caller's (Authorize), never a request field; a Global
// (cross-tenant) view has no workspace and is told to choose one. Unknown and
// foreign ids are the same 404. Writing and approving need a PERSON: an API key can
// only read.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"netops/backend/internal/orgcontext"
)

// BodyCap bounds a request body.
const BodyCap = 64 << 10

const apiPrefix = "/api/ai/runbooks"

// Deps are the server seams.
type Deps struct {
	Store Store
	// Authorize checks the permission for level (and the AI entitlement); ok=false
	// means it has written the response.
	Authorize func(w http.ResponseWriter, r *http.Request, level orgcontext.Level) (orgcontext.Caller, bool)
	// LinkTargetExists reports whether the caller's workspace has what a link
	// points at. Nil refuses every link: an unchecked link is not a link.
	LinkTargetExists func(ctx context.Context, c orgcontext.Caller, t LinkType, key string) (bool, error)
	// Audit records one decision; detail never carries runbook text.
	Audit func(r *http.Request, c orgcontext.Caller, decision string, detail map[string]any)
	// Changed is called after a committed change to what is active.
	Changed    func(tenant string)
	WriteJSON  func(w http.ResponseWriter, status int, v any)
	WriteError func(w http.ResponseWriter, status int, err error)
	Log        func(msg string, err error)
}

// Handler serves /api/ai/runbooks and /api/ai/runbooks/.
func (d Deps) Handler(w http.ResponseWriter, r *http.Request) {
	rest := strings.Trim(strings.TrimPrefix(r.URL.Path, apiPrefix), "/")
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
	case len(parts) == 1 && r.Method == http.MethodGet:
		d.get(w, r, parts[0])
	case len(parts) == 2 && parts[1] == "links":
		d.links(w, r, parts[0])
	case len(parts) == 2:
		d.action(w, r, parts[0], parts[1])
	default:
		d.WriteError(w, http.StatusNotFound, errors.New("not found"))
	}
}

func (d Deps) caller(w http.ResponseWriter, r *http.Request, level orgcontext.Level) (orgcontext.Caller, bool) {
	c, ok := d.Authorize(w, r, level)
	if !ok {
		return orgcontext.Caller{}, false
	}
	if c.Cross || c.Tenant == "" {
		d.WriteError(w, http.StatusBadRequest, errors.New("choose a workspace first — a runbook belongs to one workspace"))
		return orgcontext.Caller{}, false
	}
	if level > orgcontext.LevelRead && (!c.Person || strings.TrimSpace(c.Sub) == "") {
		d.WriteError(w, http.StatusForbidden, errors.New("runbooks are written and approved by people; an API key can only read them"))
		return orgcontext.Caller{}, false
	}
	return c, true
}

// VersionView is one version as the API shows it: the two texts an author wrote,
// and the hash an approval has to quote.
type VersionView struct {
	orgcontext.Version
	Source
	HarnessPassed      bool       `json:"harness_passed"`
	HarnessFingerprint string     `json:"harness_fingerprint,omitempty"`
	HarnessAt          *time.Time `json:"harness_at,omitempty"`
}

// MarshalJSON leaves out the canonical body: it is the two texts joined, and the
// hash is what binds them.
func (v VersionView) MarshalJSON() ([]byte, error) {
	type plain VersionView
	raw, err := json.Marshal(plain(v))
	if err != nil {
		return nil, err
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	delete(m, "body")
	return json.Marshal(m)
}

// RunbookView is a runbook as the API shows it.
type RunbookView struct {
	ID        string        `json:"id"`
	Name      string        `json:"name"`
	Kind      Kind          `json:"kind"`
	WhenToUse string        `json:"when_to_use"`
	CreatedBy string        `json:"created_by"`
	CreatedAt time.Time     `json:"created_at"`
	UpdatedAt time.Time     `json:"updated_at"`
	Versions  []VersionView `json:"versions"`
}

func viewOf(rb Runbook) RunbookView {
	out := RunbookView{ID: rb.ID, Name: rb.Name(), Kind: rb.RunbookKind, WhenToUse: rb.WhenToUse, CreatedBy: rb.CreatedBy,
		CreatedAt: rb.CreatedAt, UpdatedAt: rb.UpdatedAt, Versions: make([]VersionView, 0, len(rb.Versions))}
	for _, v := range rb.Versions {
		st := rb.Harness[v.Version]
		vv := VersionView{Version: v, HarnessPassed: st.Passed, HarnessFingerprint: st.Fingerprint, HarnessAt: st.At}
		// A body that does not split was never written by this package; the view
		// then shows no text rather than a guess at it.
		if src, err := SplitBody(v.Body); err == nil {
			vv.Source = src
		}
		out.Versions = append(out.Versions, vv)
	}
	return out
}

func (d Deps) list(w http.ResponseWriter, r *http.Request) {
	c, ok := d.caller(w, r, orgcontext.LevelRead)
	if !ok {
		return
	}
	q := r.URL.Query()
	search, linkType, linkKey := q.Get("q"), q.Get("link_type"), q.Get("link_key")
	switch {
	case q.Has("q") && (q.Has("link_type") || q.Has("link_key")):
		d.WriteError(w, http.StatusBadRequest, errors.New("search by text or by link, not both"))
	case q.Has("q"):
		if len(search) > MaxSearchQueryBytes {
			d.WriteError(w, http.StatusBadRequest, errors.New("the search text is too long"))
			return
		}
		limit, err := parseLimit(q.Get("limit"))
		if err != nil {
			d.WriteError(w, http.StatusBadRequest, err)
			return
		}
		docs, err := d.Store.Search(r.Context(), c.Tenant, search, limit)
		if err != nil {
			d.fail(w, r, c, "search", "", err)
			return
		}
		d.WriteJSON(w, http.StatusOK, map[string]any{"results": docs})
	case q.Has("link_type") || q.Has("link_key"):
		if err := checkLink(LinkType(linkType), linkKey); err != nil {
			d.fail(w, r, c, "list by link", "", err)
			return
		}
		docs, err := d.Store.ListByLink(r.Context(), c.Tenant, LinkType(linkType), linkKey)
		if err != nil {
			d.fail(w, r, c, "list by link", "", err)
			return
		}
		d.WriteJSON(w, http.StatusOK, map[string]any{"results": docs})
	default:
		rows, err := d.Store.List(r.Context(), c.Tenant)
		if err != nil {
			d.fail(w, r, c, "list", "", err)
			return
		}
		views := make([]RunbookView, 0, len(rows))
		for _, rb := range rows {
			views = append(views, viewOf(rb))
		}
		d.WriteJSON(w, http.StatusOK, map[string]any{
			"runbooks": views, "you": c.Sub,
			"limits": map[string]int{"runbooks": MaxRunbooksPerTenant, "versions": MaxVersionsPerRunbook, "cases": MaxCasesPerRunbook, "links": MaxLinksPerRunbook},
		})
	}
}

func parseLimit(s string) (int, error) {
	if s == "" {
		return 0, nil
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 1 {
		return 0, errors.New("limit must be a positive number")
	}
	return n, nil
}

func (d Deps) get(w http.ResponseWriter, r *http.Request, id string) {
	c, ok := d.caller(w, r, orgcontext.LevelRead)
	if !ok {
		return
	}
	rb, err := d.Store.Get(r.Context(), c.Tenant, id)
	if err != nil {
		d.fail(w, r, c, "get", id, err)
		return
	}
	d.WriteJSON(w, http.StatusOK, viewOf(rb))
}

// decode reads one bounded JSON object. A smuggled tenant_id is an error, not a
// silent no-op. It answers the request itself when it fails.
func (d Deps) decode(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, BodyCap)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			d.WriteError(w, http.StatusRequestEntityTooLarge, errors.New("the request is too large"))
			return false
		}
		d.WriteError(w, http.StatusBadRequest, errors.New("the request is not valid: "+err.Error()))
		return false
	}
	return true
}

func (d Deps) create(w http.ResponseWriter, r *http.Request) {
	c, ok := d.caller(w, r, orgcontext.LevelAuthor)
	if !ok {
		return
	}
	var req struct {
		Name string `json:"name"`
		Kind Kind   `json:"kind"`
		Source
	}
	if !d.decode(w, r, &req) {
		return
	}
	rb, err := d.Store.Create(r.Context(), c.Tenant, c.Sub, NewRunbook{Name: req.Name, Kind: req.Kind, Source: req.Source})
	if err != nil {
		d.fail(w, r, c, "create", "", err)
		return
	}
	d.Audit(r, c, "allow", detail(rb, 1, "create"))
	d.WriteJSON(w, http.StatusCreated, viewOf(rb))
}

func (d Deps) action(w http.ResponseWriter, r *http.Request, id, verb string) {
	level := orgcontext.LevelAuthor
	switch verb {
	case "approve", "reject", "rollback", "retire":
		level = orgcontext.LevelManage
	case "draft", "check", "submit", "withdraw":
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
		d.WriteError(w, http.StatusNotFound, errors.New("no such runbook"))
		return
	}
	var req struct {
		Source
		Version    int    `json:"version"`
		BodySHA256 string `json:"body_sha256"`
		ToVersion  int    `json:"to_version"`
		Reason     string `json:"reason"`
	}
	if r.Method != http.MethodDelete && r.ContentLength != 0 && !d.decode(w, r, &req) {
		return
	}
	if verb == "check" {
		d.check(w, r, c, id)
		return
	}
	op := orgcontext.Op{Actor: c.Sub, Now: time.Now().UTC(), Version: req.Version, BodySHA256: req.BodySHA256, ToVersion: req.ToVersion, Reason: req.Reason}
	switch {
	case verb == "draft" && r.Method == http.MethodDelete:
		op.Kind = orgcontext.OpDiscard
	case verb == "draft":
		op.Kind = orgcontext.OpDraft
		body, err := CanonicalBody(req.Source)
		if err != nil {
			d.fail(w, r, c, verb, id, err)
			return
		}
		op.Body = body
	default:
		op.Kind = orgcontext.OpKind(verb)
	}
	if err := orgcontext.CheckReason(op.Reason, op.Kind == orgcontext.OpReject || op.Kind == orgcontext.OpRetire); err != nil {
		d.fail(w, r, c, verb, id, err)
		return
	}
	rb, err := d.Store.Do(r.Context(), c.Tenant, id, op)
	if err != nil {
		d.fail(w, r, c, verb, id, err)
		return
	}
	v := rb.latest()
	if op.Kind == orgcontext.OpApprove || op.Kind == orgcontext.OpReject {
		v = op.Version
	}
	d.Audit(r, c, "allow", detail(rb, v, verb))
	if d.Changed != nil && (op.Kind == orgcontext.OpApprove || op.Kind == orgcontext.OpRollback || op.Kind == orgcontext.OpRetire) {
		d.Changed(c.Tenant)
	}
	if len(rb.Versions) == 0 {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	d.WriteJSON(w, http.StatusOK, viewOf(rb))
}

func (d Deps) check(w http.ResponseWriter, r *http.Request, c orgcontext.Caller, id string) {
	res, err := d.Store.Check(r.Context(), c.Tenant, id)
	if err != nil {
		d.fail(w, r, c, "check", id, err)
		return
	}
	if !res.Passed {
		d.fail(w, r, c, "check", id, &HarnessError{Problems: res.Problems})
		return
	}
	d.WriteJSON(w, http.StatusOK, map[string]any{"passed": true, "cases": res.Cases, "fingerprint": res.Fingerprint})
}

func (d Deps) links(w http.ResponseWriter, r *http.Request, id string) {
	level := orgcontext.LevelAuthor
	switch r.Method {
	case http.MethodGet:
		level = orgcontext.LevelRead
	case http.MethodPut, http.MethodDelete:
	default:
		d.WriteError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	c, ok := d.caller(w, r, level)
	if !ok {
		return
	}
	if !ValidID(id) {
		d.WriteError(w, http.StatusNotFound, errors.New("no such runbook"))
		return
	}
	if r.Method == http.MethodGet {
		ls, err := d.Store.Links(r.Context(), c.Tenant, id)
		if err != nil {
			d.fail(w, r, c, "links", id, err)
			return
		}
		d.WriteJSON(w, http.StatusOK, map[string]any{"links": ls})
		return
	}
	var req struct {
		Type LinkType `json:"link_type"`
		Key  string   `json:"link_key"`
	}
	if !d.decode(w, r, &req) {
		return
	}
	var ls []Link
	var err error
	action := "link"
	if r.Method == http.MethodDelete {
		action = "unlink"
		ls, err = d.Store.DeleteLink(r.Context(), c.Tenant, id, req.Type, req.Key)
	} else {
		ls, err = d.putLink(r, c, id, req.Type, req.Key)
	}
	if err != nil {
		d.fail(w, r, c, action, id, err)
		return
	}
	d.Audit(r, c, "allow", map[string]any{"runbook_id": id, "action": action, "link_type": string(req.Type)})
	d.WriteJSON(w, http.StatusOK, map[string]any{"links": ls})
}

// putLink refuses a link to something the caller's workspace does not have. It
// first proves the runbook is the caller's, so a foreign id is a 404 and the
// validator is never an oracle about another workspace's runbook.
func (d Deps) putLink(r *http.Request, c orgcontext.Caller, id string, t LinkType, key string) ([]Link, error) {
	if _, err := d.Store.Links(r.Context(), c.Tenant, id); err != nil {
		return nil, err
	}
	if err := checkLink(t, key); err != nil {
		return nil, err
	}
	if d.LinkTargetExists == nil {
		return nil, errLinkTarget
	}
	ok, err := d.LinkTargetExists(r.Context(), c, t, key)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, errLinkTarget
	}
	return d.Store.PutLink(r.Context(), c.Tenant, id, c.Sub, t, key)
}

var errLinkTarget = orgcontext.Problem{Field: "link_key", Rule: "unknown_target", Say: "nothing with that name exists in this workspace"}

// detail is the audit record of a change — ids, kind, hash; never the text.
func detail(rb Runbook, version int, action string) map[string]any {
	m := map[string]any{"runbook_id": rb.ID, "action": action, "kind": string(rb.RunbookKind), "name": rb.Name(), "version": version}
	if v, ok := rb.version(version); ok {
		m["body_sha256"] = v.BodySHA256
		m["state"] = string(v.State)
		if v.RestoredFrom > 0 {
			m["restored_from"] = v.RestoredFrom
		}
	}
	if st, ok := rb.Harness[version]; ok {
		m["harness_fingerprint"] = st.Fingerprint
	}
	return m
}

func (d Deps) fail(w http.ResponseWriter, r *http.Request, c orgcontext.Caller, what, id string, err error) {
	var problem orgcontext.Problem
	var harness *HarnessError
	switch {
	case errors.As(err, &harness):
		d.Audit(r, c, "deny", map[string]any{"runbook_id": id, "action": what, "why": "cases did not pass", "problems": len(harness.Problems)})
		problems := harness.Problems
		if problems == nil {
			problems = []CaseProblem{}
		}
		d.WriteJSON(w, http.StatusUnprocessableEntity, map[string]any{"error": "the runbook's cases did not pass", "problems": problems})
	case errors.As(err, &problem):
		d.WriteJSON(w, http.StatusBadRequest, map[string]any{"error": problem.Say, "problem": problem})
	case errors.Is(err, orgcontext.ErrNotFound):
		d.WriteError(w, http.StatusNotFound, errors.New("no such runbook"))
	case errors.Is(err, orgcontext.ErrSelfApproval):
		d.Audit(r, c, "deny", map[string]any{"runbook_id": id, "action": what, "why": err.Error()})
		d.WriteError(w, http.StatusForbidden, errors.New("you wrote this version, so another administrator has to approve it"))
	case errors.Is(err, orgcontext.ErrNotAuthor):
		d.Audit(r, c, "deny", map[string]any{"runbook_id": id, "action": what, "why": err.Error()})
		d.WriteError(w, http.StatusForbidden, errors.New("only the person who wrote this draft can change it"))
	case errors.Is(err, orgcontext.ErrStale):
		d.WriteError(w, http.StatusConflict, errors.New("the text changed since you reviewed it — review it again"))
	case errors.Is(err, ErrHarnessStale):
		d.Audit(r, c, "deny", map[string]any{"runbook_id": id, "action": what, "why": err.Error()})
		d.WriteError(w, http.StatusConflict, errors.New("the platform changed since this version's cases passed — its author has to withdraw and submit it again"))
	case errors.Is(err, orgcontext.ErrWrongState):
		d.WriteError(w, http.StatusConflict, errors.New("that is not possible in the runbook's current state — reload and try again"))
	case errors.Is(err, orgcontext.ErrExists):
		d.WriteError(w, http.StatusConflict, errors.New("a runbook with this name already exists — edit that one"))
	case errors.Is(err, orgcontext.ErrFull):
		d.WriteError(w, http.StatusConflict, errors.New("the limit is reached (30 runbooks per workspace, 50 versions per runbook, 20 links per runbook)"))
	case errors.Is(err, orgcontext.ErrInvalid):
		d.WriteError(w, http.StatusBadRequest, errors.New("the request is not valid"))
	case errors.Is(err, ErrHarnessBusy):
		d.WriteError(w, http.StatusServiceUnavailable, errors.New("too many runbook checks are running — try again in a moment"))
	default:
		if d.Log != nil {
			d.Log("runbook "+what+" failed", err)
		}
		d.WriteError(w, http.StatusInternalServerError, errors.New("the runbook could not be read or saved"))
	}
}

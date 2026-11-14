// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package irislearning

// http.go — /api/ai/learning (tracker 337 N-F5):
//
//	GET  /api/ai/learning               the workspace's proposals (+ where each went)
//	POST /api/ai/learning/refresh       look for new proposals now
//	GET  /api/ai/learning/{id}          one proposal
//	POST /api/ai/learning/{id}/adopt    {edit}    hand it to its target's review, as you
//	POST /api/ai/learning/{id}/approve  {}        second person (fact / alias)
//	POST /api/ai/learning/{id}/dismiss  {reason}  decline it
//
// §3a: the tenant is the caller's (Authorize), never a request field; a Global
// view has no workspace and is told to choose one. Unknown and foreign ids are
// the same 404. Adopting and approving need a PERSON (an API key is neither an
// author nor a second person). Every step is audited, without draft text.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"netops/backend/internal/entityalias"
	"netops/backend/internal/orgcontext"
	"netops/backend/internal/tenantrunbook"
)

// Deps are the server seams.
type Deps struct {
	Store   Store
	Targets Targets
	// Authorize checks the permission for level (and the AI entitlement);
	// ok=false means it has written the response.
	Authorize func(w http.ResponseWriter, r *http.Request, level orgcontext.Level) (orgcontext.Caller, bool)
	// Entitled reports whether the caller may adopt into target (each target
	// keeps its own AI entitlement); ok=false means it has written the response.
	Entitled func(w http.ResponseWriter, r *http.Request, target Target) bool
	// Inputs reads the generators' inputs for the caller's tenant.
	Inputs func(ctx context.Context, r *http.Request, tenant string) (Inputs, error)
	// Visible reports whether the requesting person can see an entity.
	Visible    func(r *http.Request) Visible
	Audit      func(r *http.Request, c orgcontext.Caller, decision string, detail map[string]any)
	Now        func() time.Time
	WriteJSON  func(w http.ResponseWriter, status int, v any)
	WriteError func(w http.ResponseWriter, status int, err error)
	Log        func(msg string, err error)
}

// BodyCap bounds a request body (a runbook edit is the largest).
const BodyCap = 64 << 10

const apiPrefix = "/api/ai/learning"

// View is a proposal as the API shows it.
type View struct {
	Proposal
	TargetState string `json:"target_state,omitempty"`
}

func (d Deps) now() time.Time {
	if d.Now != nil {
		return d.Now().UTC()
	}
	return time.Now().UTC()
}

// Handler serves /api/ai/learning and /api/ai/learning/.
func (d Deps) Handler(w http.ResponseWriter, r *http.Request) {
	rest := strings.Trim(strings.TrimPrefix(r.URL.Path, apiPrefix), "/")
	parts := strings.Split(rest, "/")
	switch {
	case rest == "" && r.Method == http.MethodGet:
		d.list(w, r)
	case rest == "refresh" && r.Method == http.MethodPost:
		d.refresh(w, r)
	case len(parts) == 1 && rest != "" && r.Method == http.MethodGet:
		d.get(w, r, parts[0])
	case len(parts) == 2 && r.Method == http.MethodPost:
		d.action(w, r, parts[0], parts[1])
	case rest == "" || rest == "refresh" || len(parts) <= 2:
		d.WriteError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
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
		d.WriteError(w, http.StatusBadRequest, errors.New("choose a workspace first — what Iris learns belongs to one workspace"))
		return orgcontext.Caller{}, false
	}
	if level > orgcontext.LevelRead && (!c.Person || strings.TrimSpace(c.Sub) == "") {
		d.WriteError(w, http.StatusForbidden, errors.New("proposals are adopted and approved by people; an API key can only read them"))
		return orgcontext.Caller{}, false
	}
	return c, true
}

func (d Deps) view(ctx context.Context, tenant string, p Proposal) View {
	return View{Proposal: p, TargetState: d.Targets.TargetState(ctx, tenant, p)}
}

func (d Deps) list(w http.ResponseWriter, r *http.Request) {
	c, ok := d.caller(w, r, orgcontext.LevelRead)
	if !ok {
		return
	}
	ps, err := d.Store.List(r.Context(), c.Tenant)
	if err != nil {
		d.fail(w, "list", err)
		return
	}
	out := make([]View, 0, len(ps))
	for _, p := range ps {
		out = append(out, d.view(r.Context(), c.Tenant, p))
	}
	d.WriteJSON(w, http.StatusOK, map[string]any{
		"proposals": out,
		"you":       c.Sub, // the page hides Approve on what you adopted; the server refuses it anyway
		"limits":    map[string]int{"proposals": MaxProposalsPerTenant, "open": MaxOpenPerTenant},
		"thresholds": map[string]int{"resolutions": MinResolutions, "alias_people": MinAliasPeople,
			"misses": MinMisses},
	})
}

func (d Deps) get(w http.ResponseWriter, r *http.Request, id string) {
	c, ok := d.caller(w, r, orgcontext.LevelRead)
	if !ok {
		return
	}
	if !ValidID(id) {
		d.WriteError(w, http.StatusNotFound, errors.New("not found"))
		return
	}
	p, err := d.Store.Get(r.Context(), c.Tenant, id)
	if err != nil {
		d.fail(w, "get", err)
		return
	}
	d.WriteJSON(w, http.StatusOK, d.view(r.Context(), c.Tenant, p))
}

func (d Deps) refresh(w http.ResponseWriter, r *http.Request) {
	c, ok := d.caller(w, r, orgcontext.LevelManage)
	if !ok {
		return
	}
	in, err := d.Inputs(r.Context(), r, c.Tenant)
	if err != nil {
		d.fail(w, "refresh", err)
		return
	}
	now := d.now()
	in.Now = now
	added, refreshed, err := d.Store.Offer(r.Context(), c.Tenant, Generate(in), now)
	if err != nil {
		d.fail(w, "refresh", err)
		return
	}
	d.audit(r, c, "allow", map[string]any{"action": "ai.learning.refresh", "added": added, "refreshed": refreshed})
	d.WriteJSON(w, http.StatusOK, map[string]int{"added": added, "refreshed": refreshed})
}

func decode(w http.ResponseWriter, r *http.Request, v any) error {
	r.Body = http.MaxBytesReader(w, r.Body, BodyCap)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields() // a smuggled tenant_id is an error, not a silent no-op
	if err := dec.Decode(v); err != nil {
		return err
	}
	return nil
}

func (d Deps) action(w http.ResponseWriter, r *http.Request, id, verb string) {
	level := orgcontext.LevelManage
	if verb == "adopt" {
		level = orgcontext.LevelAuthor
	}
	switch verb {
	case "adopt", "approve", "dismiss":
	default:
		d.WriteError(w, http.StatusNotFound, errors.New("not found"))
		return
	}
	c, ok := d.caller(w, r, level)
	if !ok {
		return
	}
	if !ValidID(id) {
		d.WriteError(w, http.StatusNotFound, errors.New("not found"))
		return
	}
	cur, err := d.Store.Get(r.Context(), c.Tenant, id)
	if err != nil {
		d.fail(w, verb, err)
		return
	}
	if verb != "dismiss" && d.Entitled != nil && !d.Entitled(w, r, cur.Target) {
		return
	}
	var visible Visible
	if d.Visible != nil {
		visible = d.Visible(r)
	}
	now := d.now()
	var out Proposal
	switch verb {
	case "adopt":
		var e Edit
		if err = decode(w, r, &e); err != nil {
			d.WriteError(w, http.StatusBadRequest, errors.New("send the proposal's fields to change, or {}"))
			return
		}
		out, err = Adopt(r.Context(), d.Store, d.Targets, c.Tenant, c.Sub, id, e, visible, now)
	case "approve":
		var none struct{}
		if err = decode(w, r, &none); err != nil {
			d.WriteError(w, http.StatusBadRequest, errors.New("approve takes an empty body"))
			return
		}
		out, err = Approve(r.Context(), d.Store, d.Targets, c.Tenant, c.Sub, id, visible, now)
	case "dismiss":
		var req struct {
			Reason string `json:"reason"`
		}
		if err = decode(w, r, &req); err != nil {
			d.WriteError(w, http.StatusBadRequest, errors.New("send {\"reason\": \"…\"}"))
			return
		}
		out, err = Dismiss(r.Context(), d.Store, c.Tenant, c.Sub, id, req.Reason, now)
	}
	if err != nil {
		d.audit(r, c, "deny", map[string]any{"action": "ai.learning." + verb, "proposal": id, "target": string(cur.Target),
			"generator": string(cur.Generator), "reason": reasonCode(err)})
		d.fail(w, verb, err)
		return
	}
	d.audit(r, c, "allow", map[string]any{"action": "ai.learning." + verb, "proposal": id, "target": string(out.Target),
		"generator": string(out.Generator), "target_id": out.TargetID, "target_version": out.TargetVersion})
	d.WriteJSON(w, http.StatusOK, d.view(r.Context(), c.Tenant, out))
}

func (d Deps) audit(r *http.Request, c orgcontext.Caller, decision string, detail map[string]any) {
	if d.Audit != nil {
		d.Audit(r, c, decision, detail)
	}
}

// reasonCode is a refusal's stable name for the audit trail (never text).
func reasonCode(err error) string {
	var p orgcontext.Problem
	switch {
	case errors.As(err, &p):
		return "invalid:" + p.Field + ":" + p.Rule
	case errors.Is(err, ErrSelfApproval), errors.Is(err, orgcontext.ErrSelfApproval):
		return "self_approval"
	case errors.Is(err, ErrWrongState), errors.Is(err, orgcontext.ErrWrongState):
		return "wrong_state"
	case errors.Is(err, ErrUnfinished):
		return "unfinished"
	case errors.Is(err, ErrConflict):
		return "alias_conflict"
	case errors.Is(err, ErrNotFound), errors.Is(err, orgcontext.ErrNotFound), errors.Is(err, entityalias.ErrNotFound):
		return "not_found"
	}
	return "error"
}

// fail maps an error onto a status and a plain-language message.
func (d Deps) fail(w http.ResponseWriter, what string, err error) {
	var p orgcontext.Problem
	var he *tenantrunbook.HarnessError
	switch {
	case errors.As(err, &p):
		d.WriteJSON(w, http.StatusUnprocessableEntity, map[string]any{"error": p.Say, "field": p.Field, "rule": p.Rule})
	case errors.As(err, &he):
		d.WriteJSON(w, http.StatusUnprocessableEntity, map[string]any{"error": he.Error()})
	case errors.Is(err, ErrNotFound), errors.Is(err, orgcontext.ErrNotFound), errors.Is(err, entityalias.ErrNotFound):
		d.WriteError(w, http.StatusNotFound, errors.New("not found"))
	case errors.Is(err, ErrSelfApproval), errors.Is(err, orgcontext.ErrSelfApproval):
		d.WriteError(w, http.StatusForbidden, errors.New("a second person must approve: you adopted or wrote this one"))
	case errors.Is(err, ErrUnfinished):
		d.WriteError(w, http.StatusUnprocessableEntity, errors.New("fill in every part marked {{…}} before adopting"))
	case errors.Is(err, ErrConflict):
		d.WriteError(w, http.StatusConflict, errors.New("that alias already means something else in this workspace"))
	case errors.Is(err, ErrReviewElse):
		d.WriteError(w, http.StatusConflict, errors.New("a runbook is approved on the Runbooks page, where its checks run"))
	case errors.Is(err, ErrWrongState), errors.Is(err, orgcontext.ErrWrongState), errors.Is(err, orgcontext.ErrStale):
		d.WriteError(w, http.StatusConflict, errors.New("not possible now — it changed, or someone already acted on it"))
	case errors.Is(err, orgcontext.ErrExists):
		d.WriteError(w, http.StatusConflict, errors.New("one with that name already exists — change the name and adopt again"))
	case errors.Is(err, ErrFull), errors.Is(err, orgcontext.ErrFull), errors.Is(err, entityalias.ErrFull):
		d.WriteError(w, http.StatusConflict, errors.New("the workspace is at its limit"))
	case errors.Is(err, ErrInvalid), errors.Is(err, orgcontext.ErrInvalid), errors.Is(err, entityalias.ErrInvalid):
		d.WriteError(w, http.StatusBadRequest, errors.New("that is not a valid change for this proposal"))
	default:
		if d.Log != nil {
			d.Log("learning "+what+" failed", err)
		}
		d.WriteError(w, http.StatusInternalServerError, errors.New("the proposal could not be "+pastTense(what)))
	}
}

func pastTense(verb string) string {
	switch verb {
	case "adopt":
		return "adopted"
	case "approve":
		return "approved"
	case "dismiss":
		return "dismissed"
	case "refresh":
		return "refreshed"
	}
	return "read"
}

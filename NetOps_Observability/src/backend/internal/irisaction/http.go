// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package irisaction

// http.go — /api/ai/actions (tracker 337 N-I4):
//
//	GET  /api/ai/actions                the workspace's settings, whether the
//	                                    installation offers actions, its requests
//	PUT  /api/ai/actions/settings       {enabled, kinds, dry_run_only, acknowledged}  workspace admin
//	GET  /api/ai/actions/{id}           one request
//	POST /api/ai/actions/{id}/approve   {reason}  a DIFFERENT person: runs it once
//	POST /api/ai/actions/{id}/reject    {reason}  decline (or withdraw your own)
//
// There is no route that proposes: a proposal is made by the server at the end
// of a concluded investigation (gate 1), never by a client. The server injects
// every check that needs its state (who may read/decide, the platform switch,
// the workspace's settings, audit, the decision ledger).

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
)

const apiPrefix = "/api/ai/actions"

// maxBody bounds a request body.
const maxBody = 8 << 10

// Caller is the authenticated principal, resolved by the server.
type Caller struct {
	Tenant string
	Sub    string
	// Person is false for an API key: a key may read, never decide.
	Person bool
}

// Level is what a route needs.
type Level int

const (
	LevelRead   Level = iota // see the requests
	LevelDecide              // approve / reject
	LevelManage              // change the workspace's settings
)

// Deps are the server's injected seams.
type Deps struct {
	Service *Service
	// Authorize resolves the caller for one route level and writes the refusal
	// itself (false). It must refuse a caller with no single workspace.
	Authorize func(w http.ResponseWriter, r *http.Request, level Level) (Caller, bool)
	// Env is the policy environment for the caller's workspace, read NOW.
	Env func(r *http.Request, tenant string) Env
	// Settings / SaveSettings read and persist the workspace's own settings.
	Settings     func(tenant string) Settings
	SaveSettings func(r *http.Request, c Caller, s Settings) error
	// Audit records one transition (never the payload text).
	Audit func(r *http.Request, c Caller, action, decision string, req *Request, detail map[string]any)
	// Ledger records a decision (approval/execution) in the decision ledger.
	Ledger func(r *http.Request, c Caller, req Request)
}

// errAckRequired refuses turning actions on without the acknowledgement.
var errAckRequired = errors.New("turning Iris actions on needs acknowledged: Iris will propose notes for the incident's ITSM ticket and its investigation memory, and anything approved is sent to that system")

// requestView is a request plus what THIS caller may do with it.
type requestView struct {
	Request
	KindLabel  string `json:"kind_label"`
	Tool       string `json:"tool"`
	CanApprove bool   `json:"can_approve"`
	CanReject  bool   `json:"can_reject"`
	Mine       bool   `json:"mine"`
}

func view(c Caller, r Request) requestView {
	open := r.Status == StatusProposed
	mine := r.ProposedBy == c.Sub
	return requestView{
		Request: r, KindLabel: KindLabel(r.Kind), Tool: ToolName(r.Kind), Mine: mine,
		CanApprove: open && c.Person && !mine,
		CanReject:  open && c.Person,
	}
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		// The status is already written; a broken client connection is all
		// this can mean, and there is nothing left to tell it.
		return
	}
}

func writeErr(w http.ResponseWriter, code int, err error) {
	writeJSON(w, code, map[string]string{"error": err.Error()})
}

// Handler serves every /api/ai/actions route.
func (d Deps) Handler(w http.ResponseWriter, r *http.Request) {
	if d.Service == nil || d.Authorize == nil || d.Env == nil || d.Settings == nil {
		writeErr(w, http.StatusServiceUnavailable, errors.New("Iris actions are not available on this deployment"))
		return
	}
	rest := strings.Trim(strings.TrimPrefix(r.URL.Path, apiPrefix), "/")
	parts := []string{}
	if rest != "" {
		parts = strings.Split(rest, "/")
	}
	switch {
	case len(parts) == 0:
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			writeErr(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
			return
		}
		d.list(w, r)
	case len(parts) == 1 && parts[0] == "settings":
		if r.Method != http.MethodPut {
			w.Header().Set("Allow", http.MethodPut)
			writeErr(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
			return
		}
		d.putSettings(w, r)
	case len(parts) == 1:
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			writeErr(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
			return
		}
		d.get(w, r, parts[0])
	case len(parts) == 2 && (parts[1] == "approve" || parts[1] == "reject"):
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			writeErr(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
			return
		}
		d.decide(w, r, parts[0], parts[1] == "approve")
	default:
		writeErr(w, http.StatusNotFound, ErrNotFound)
	}
}

func (d Deps) list(w http.ResponseWriter, r *http.Request) {
	c, ok := d.Authorize(w, r, LevelRead)
	if !ok {
		return
	}
	rs, err := d.Service.List(r.Context(), c.Tenant, Filter{Status: Status(r.URL.Query().Get("status"))})
	if err != nil {
		writeErr(w, http.StatusInternalServerError, errors.New("the actions could not be read"))
		return
	}
	views := make([]requestView, 0, len(rs))
	open := 0
	for _, x := range rs {
		if x.Status == StatusProposed {
			open++
		}
		views = append(views, view(c, x))
	}
	env := d.Env(r, c.Tenant)
	kinds := make([]map[string]string, 0, len(Kinds))
	for _, k := range Kinds {
		kinds = append(kinds, map[string]string{"kind": string(k), "label": KindLabel(k), "tool": ToolName(k)})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"settings":           d.Settings(c.Tenant).Normalized(),
		"available":          env.Platform,
		"unavailable_reason": unavailableReason(env),
		"kinds":              kinds,
		"requests":           views,
		"open":               open,
	})
}

func unavailableReason(env Env) string {
	if env.Platform {
		return ""
	}
	if env.PlatformReason != "" {
		return env.PlatformReason
	}
	return "Iris actions are turned off on this installation"
}

func (d Deps) get(w http.ResponseWriter, r *http.Request, id string) {
	c, ok := d.Authorize(w, r, LevelRead)
	if !ok {
		return
	}
	x, err := d.Service.Get(r.Context(), c.Tenant, id)
	if err != nil {
		d.fail(w, err, nil)
		return
	}
	writeJSON(w, http.StatusOK, view(c, x))
}

func decodeBody(r *http.Request, v any) error {
	b, err := io.ReadAll(http.MaxBytesReader(nil, r.Body, maxBody))
	if err != nil {
		return err
	}
	if len(strings.TrimSpace(string(b))) == 0 {
		return nil
	}
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

func (d Deps) decide(w http.ResponseWriter, r *http.Request, id string, approve bool) {
	c, ok := d.Authorize(w, r, LevelDecide)
	if !ok {
		return
	}
	if !c.Person {
		writeErr(w, http.StatusForbidden, errors.New("an API key cannot approve or decline an action — a person decides"))
		return
	}
	var body struct {
		Reason string `json:"reason"`
	}
	if err := decodeBody(r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, errors.New("the request body is not valid"))
		return
	}
	var (
		x   Request
		err error
	)
	action := "reject"
	if approve {
		action = "approve"
		x, err = d.Service.Approve(r.Context(), c.Tenant, c.Sub, d.Env(r, c.Tenant), id, body.Reason)
	} else {
		x, err = d.Service.Reject(r.Context(), c.Tenant, c.Sub, id, body.Reason)
	}
	ran := x.Status == StatusExecuted || x.Status == StatusFailed
	switch {
	case err == nil:
	case approve && ran && x.DecidedBy == c.Sub && !IsConflict(err):
		// This approval ran it and sending failed: recorded, shown as such.
	default:
		if d.Audit != nil && x.ID != "" {
			d.Audit(r, c, action, "deny", &x, map[string]any{"error": errorClass(err)})
		}
		d.fail(w, err, &x)
		return
	}
	if d.Audit != nil {
		d.Audit(r, c, action, "allow", &x, map[string]any{"status": string(x.Status)})
	}
	if approve && ran && d.Ledger != nil {
		d.Ledger(r, c, x)
	}
	code := http.StatusOK
	if x.Status == StatusFailed {
		code = http.StatusBadGateway
	}
	writeJSON(w, code, view(c, x))
}

func errorClass(err error) string {
	switch {
	case errors.Is(err, ErrSelfApproval):
		return "self_approval"
	case errors.Is(err, ErrExpired):
		return "expired"
	case errors.Is(err, ErrNotPending):
		return "not_pending"
	case errors.Is(err, ErrDryRunOnly):
		return "dry_run_only"
	case errors.Is(err, ErrDenied):
		return "denied"
	case errors.Is(err, ErrReasonMissing):
		return "reason_missing"
	case errors.Is(err, ErrNotFound):
		return "not_found"
	}
	return "error"
}

func (d Deps) fail(w http.ResponseWriter, err error, x *Request) {
	switch {
	case errors.Is(err, ErrNotFound):
		writeErr(w, http.StatusNotFound, ErrNotFound)
	case errors.Is(err, ErrSelfApproval):
		writeErr(w, http.StatusForbidden, err)
	case errors.Is(err, ErrDenied), errors.Is(err, ErrDryRunOnly):
		writeErr(w, http.StatusForbidden, err)
	case IsConflict(err):
		body := map[string]any{"error": err.Error()}
		if x != nil && x.ID != "" {
			body["request"] = x
		}
		writeJSON(w, http.StatusConflict, body)
	case errors.Is(err, ErrReasonMissing), errors.Is(err, ErrInvalid):
		writeErr(w, http.StatusBadRequest, err)
	default:
		writeErr(w, http.StatusInternalServerError, errors.New("the action could not be decided"))
	}
}

func (d Deps) putSettings(w http.ResponseWriter, r *http.Request) {
	c, ok := d.Authorize(w, r, LevelManage)
	if !ok {
		return
	}
	if !c.Person {
		writeErr(w, http.StatusForbidden, errors.New("an API key cannot change Iris action settings"))
		return
	}
	var body struct {
		Enabled      bool     `json:"enabled"`
		Kinds        []string `json:"kinds"`
		DryRunOnly   bool     `json:"dry_run_only"`
		Acknowledged bool     `json:"acknowledged"`
	}
	if err := decodeBody(r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, errors.New("the request body is not valid"))
		return
	}
	s := Settings{Enabled: body.Enabled, DryRunOnly: body.DryRunOnly}
	for _, k := range body.Kinds {
		if !ValidKind(Kind(k)) {
			writeErr(w, http.StatusBadRequest, errors.New("unknown action kind: "+k))
			return
		}
		s.Kinds = append(s.Kinds, Kind(k))
	}
	s = s.Normalized()
	prev := d.Settings(c.Tenant).Normalized()
	if s.Enabled && !prev.Enabled && !body.Acknowledged {
		writeErr(w, http.StatusBadRequest, errAckRequired)
		return
	}
	if d.SaveSettings == nil {
		writeErr(w, http.StatusServiceUnavailable, errors.New("Iris action settings cannot be saved on this deployment"))
		return
	}
	if err := d.SaveSettings(r, c, s); err != nil {
		writeErr(w, http.StatusInternalServerError, errors.New("the Iris action settings were not saved"))
		return
	}
	if d.Audit != nil {
		kinds := make([]string, 0, len(s.Kinds))
		for _, k := range s.Kinds {
			kinds = append(kinds, string(k))
		}
		d.Audit(r, c, "settings", "allow", nil, map[string]any{
			"enabled": s.Enabled, "kinds": kinds, "dry_run_only": s.DryRunOnly, "acknowledged": body.Acknowledged,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"settings": s})
}

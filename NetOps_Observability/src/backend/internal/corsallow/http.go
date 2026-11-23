// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package corsallow

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"
)

// Caller is the authorized principal.
type Caller struct {
	Subject string
	APIKey  bool // an API-key principal: refused for changes
}

// AuditEntry is one audit record the handler asks the integrator to write.
type AuditEntry struct {
	Subject string
	Method  string
	Path    string
	Status  int
	Outcome string // allow | error
	Detail  map[string]any
}

// Deps are the injected collaborators. All are required.
type Deps struct {
	// Authz authorizes the caller as the PLATFORM administrator
	// (requirePlatformAdmin — never a tenant admin) and has written the error
	// response when ok is false.
	Authz func(w http.ResponseWriter, r *http.Request) (Caller, bool)
	// AuditStrict writes a durable audit record; an error means the record was
	// NOT written, and the change it describes must not happen.
	AuditStrict func(e AuditEntry) error
	// Audit writes a best-effort record (the failure of a change already audited).
	Audit     func(e AuditEntry)
	WriteJSON func(w http.ResponseWriter, status int, v any)
	WriteErr  func(w http.ResponseWriter, status int, err error)
	LogInfo   func(msg string, fields map[string]any)
	Now       func() time.Time
}

// API serves GET/PUT /api/platform/cors-origins.
type API struct {
	list *Allowlist
	d    Deps
}

// NewAPI binds the handler.
func NewAPI(list *Allowlist, d Deps) *API { return &API{list: list, d: d} }

// maxBody bounds a PUT: MaxOrigins × MaxOriginLen plus JSON framing.
const maxBody = 64 << 10

// putBody is the PUT request: either a list, or reset to the install value.
type putBody struct {
	Origins *[]string `json:"origins"`
	Reset   bool      `json:"reset"`
}

// Handle serves the route.
//
//	GET  → View
//	PUT  {"origins": [...]}  save this list (empty = none allowed)
//	PUT  {"reset": true}     return to the install value
//
// Reset is a PUT, not a DELETE, on purpose: returning to the install value can
// WIDEN access, and the route's DELETE would skip the elevation step-up that
// guards a grant.
func (a *API) Handle(w http.ResponseWriter, r *http.Request) {
	caller, ok := a.d.Authz(w, r)
	if !ok {
		return
	}
	switch r.Method {
	case http.MethodGet:
		a.d.WriteJSON(w, http.StatusOK, a.list.View())
	case http.MethodPut:
		a.put(w, r, caller)
	default:
		w.Header().Set("Allow", "GET, PUT")
		a.d.WriteErr(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
	}
}

func (a *API) put(w http.ResponseWriter, r *http.Request, caller Caller) {
	if caller.APIKey {
		a.d.WriteErr(w, http.StatusForbidden, errors.New("an API key cannot change the cross-origin allowlist; sign in as the platform administrator"))
		return
	}
	var body putBody
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&body); err != nil {
		a.d.WriteErr(w, http.StatusBadRequest, errors.New("the request is not valid: send {\"origins\": [...]} or {\"reset\": true}"))
		return
	}
	if body.Reset == (body.Origins != nil) {
		a.d.WriteErr(w, http.StatusBadRequest, errors.New("send either {\"origins\": [...]} or {\"reset\": true}, not both or neither"))
		return
	}
	before := a.list.View()
	action, to := "cors_origins_reset", before.EnvOrigins
	if !body.Reset {
		clean, err := ValidateList(*body.Origins)
		if err != nil {
			a.d.WriteErr(w, http.StatusBadRequest, err)
			return
		}
		action, to = "cors_origins_set", clean
	}
	// The trail is written BEFORE the change: a change the audit cannot record
	// does not happen.
	entry := AuditEntry{
		Subject: caller.Subject, Method: r.Method, Path: r.URL.Path, Status: http.StatusOK, Outcome: "allow",
		Detail: map[string]any{"action": action, "from": before.Origins, "from_source": string(before.Source), "to": to},
	}
	if err := a.d.AuditStrict(entry); err != nil {
		a.d.WriteErr(w, http.StatusInternalServerError, errors.New("the change was not made: the audit trail could not record it"))
		return
	}
	var err error
	if body.Reset {
		_, _, err = a.list.Reset(caller.Subject, a.d.Now())
	} else {
		_, _, err = a.list.Set(to, caller.Subject, a.d.Now())
	}
	if err != nil {
		fail := entry
		fail.Status, fail.Outcome = http.StatusInternalServerError, "error"
		fail.Detail = map[string]any{"action": action, "error": err.Error()}
		a.d.Audit(fail)
		a.d.WriteErr(w, http.StatusInternalServerError, errors.New("the change was not saved, and the list in force is unchanged"))
		return
	}
	after := a.list.View()
	a.d.LogInfo("cross-origin allowlist changed", map[string]any{
		"action": action, "by": caller.Subject, "count": len(after.Origins), "source": string(after.Source),
	})
	a.d.WriteJSON(w, http.StatusOK, after)
}

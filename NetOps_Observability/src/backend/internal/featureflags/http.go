// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package featureflags

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"
)

// http.go — GET/PUT /api/platform/features and POST /api/platform/restart.
// Platform-global (CLAUDE.md §3a.3): the integrator's Authz is
// requirePlatformAdmin — never a tenant admin. Every collaborator is injected
// (§5); this package holds no ambient authority.

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
	// Authz authorizes the caller as the platform administrator and has
	// written the error response when ok is false.
	Authz func(w http.ResponseWriter, r *http.Request) (Caller, bool)
	// AuditStrict writes a durable audit record; an error means the record
	// was NOT written, and the change it describes must not happen.
	AuditStrict func(e AuditEntry) error
	// Audit writes a best-effort record (failures of a change already audited).
	Audit     func(e AuditEntry)
	WriteJSON func(w http.ResponseWriter, status int, v any)
	WriteErr  func(w http.ResponseWriter, status int, err error)
	LogInfo   func(msg string, fields map[string]any)
	// Supervised: something will start the process again after it exits
	// (compose restart policy, a Kubernetes Deployment).
	Supervised func() bool
	Now        func() time.Time
}

// RestartGate carries a restart request to the process's run loop and
// allows one request per Interval.
type RestartGate struct {
	C        chan struct{}
	Interval time.Duration

	mu   sync.Mutex
	last time.Time
}

// NewRestartGate returns a gate with a one-slot channel.
func NewRestartGate(interval time.Duration) *RestartGate {
	return &RestartGate{C: make(chan struct{}, 1), Interval: interval}
}

// API serves the Features page.
type API struct {
	reg  *Registry
	gate *RestartGate
	d    Deps
}

// NewAPI wires the handlers. reg or gate may be nil (the routes then answer
// 503 / 409 rather than panic).
func NewAPI(reg *Registry, gate *RestartGate, d Deps) *API {
	return &API{reg: reg, gate: gate, d: d}
}

// Row is one flag on the wire.
type Row struct {
	Env            string    `json:"env"`
	Label          string    `json:"label"`
	Group          string    `json:"group"`
	Help           string    `json:"help"`
	Apply          string    `json:"apply"`
	Risky          bool      `json:"risky"`
	Running        bool      `json:"running"`
	Desired        bool      `json:"desired"`
	RestartPending bool      `json:"restart_pending"`
	Source         string    `json:"source"`
	InstallValue   *bool     `json:"install_value"`
	UpdatedBy      string    `json:"updated_by,omitempty"`
	UpdatedAt      time.Time `json:"updated_at,omitempty"`
}

// ToRow renders a State for the wire.
func ToRow(st State) Row {
	return Row{
		Env: st.Env, Label: st.Label, Group: st.Group, Help: st.Help, Apply: string(st.Apply), Risky: st.Risky,
		Running: st.Running, Desired: st.Desired, RestartPending: st.RestartPending, Source: string(st.Source),
		InstallValue: st.InstallValue, UpdatedBy: st.UpdatedBy, UpdatedAt: st.UpdatedAt,
	}
}

func (a *API) anyRestartPending() bool {
	for _, st := range a.reg.List() {
		if st.RestartPending {
			return true
		}
	}
	return false
}

func (a *API) payload() map[string]any {
	states := a.reg.List()
	rows := make([]Row, 0, len(states))
	pending := false
	for _, st := range states {
		rows = append(rows, ToRow(st))
		pending = pending || st.RestartPending
	}
	out := map[string]any{
		"features":         rows,
		"restart_pending":  pending,
		"can_restart":      a.d.Supervised() && a.gate != nil,
		"store_load_error": "",
	}
	if a.reg.LoadError() != nil {
		out["store_load_error"] = "The saved feature settings could not be read when Correlix started. Install values are in force and risky features are off."
	}
	return out
}

// HandleFeatures: GET the switchable set; PUT {env, value, acknowledge}.
func (a *API) HandleFeatures(w http.ResponseWriter, r *http.Request) {
	caller, ok := a.d.Authz(w, r)
	if !ok {
		return
	}
	if a.reg == nil {
		a.d.WriteErr(w, http.StatusServiceUnavailable, errors.New("feature settings are not available on this server"))
		return
	}
	switch r.Method {
	case http.MethodGet:
		a.d.WriteJSON(w, http.StatusOK, a.payload())
	case http.MethodPut:
		a.put(w, r, caller)
	default:
		w.Header().Set("Allow", "GET, PUT")
		a.d.WriteErr(w, http.StatusMethodNotAllowed, errors.New("GET or PUT"))
	}
}

func (a *API) put(w http.ResponseWriter, r *http.Request, caller Caller) {
	if caller.APIKey {
		a.d.WriteErr(w, http.StatusForbidden, errors.New("feature settings can only be changed from a signed-in session"))
		return
	}
	var body struct {
		Env         string `json:"env"`
		Value       *bool  `json:"value"`
		Acknowledge string `json:"acknowledge"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&body); err != nil || body.Value == nil {
		a.d.WriteErr(w, http.StatusBadRequest, errors.New(`send {"env": <feature>, "value": true|false}`))
		return
	}
	before, known := a.reg.Get(body.Env)
	if !known {
		a.d.WriteErr(w, http.StatusBadRequest, ErrUnknownFlag)
		return
	}
	if before.Risky && *body.Value && body.Acknowledge != before.Env {
		a.d.WriteErr(w, http.StatusBadRequest, ErrAckRequired)
		return
	}
	// The trail is written BEFORE the change: a change the audit cannot
	// record does not happen.
	entry := AuditEntry{
		Subject: caller.Subject, Method: r.Method, Path: r.URL.Path, Status: http.StatusOK, Outcome: "allow",
		Detail: map[string]any{"action": "feature_flag_set", "flag": before.Env, "from": before.Desired, "to": *body.Value, "apply": string(before.Apply)},
	}
	if err := a.d.AuditStrict(entry); err != nil {
		a.d.WriteErr(w, http.StatusInternalServerError, errors.New("the change was not made: the audit trail could not record it"))
		return
	}
	_, after, err := a.reg.Set(body.Env, *body.Value, body.Acknowledge, caller.Subject, a.d.Now())
	if err != nil {
		fail := entry
		fail.Status, fail.Outcome = http.StatusInternalServerError, "error"
		fail.Detail = map[string]any{"action": "feature_flag_set", "flag": before.Env, "error": err.Error()}
		a.d.Audit(fail)
		status := http.StatusInternalServerError
		if errors.Is(err, ErrAckRequired) || errors.Is(err, ErrUnknownFlag) {
			status = http.StatusBadRequest
		}
		a.d.WriteErr(w, status, err)
		return
	}
	a.d.LogInfo("feature setting changed", map[string]any{"flag": after.Env, "to": *body.Value, "apply": string(after.Apply), "by": caller.Subject})
	a.d.WriteJSON(w, http.StatusOK, map[string]any{"feature": ToRow(after), "restart_pending": a.anyRestartPending()})
}

// HandleRestart restarts the process so restart-class settings take effect:
// the integrator's run loop receives on gate.C and runs its graceful shutdown;
// the process exits 0 and its supervisor starts it again. Refused when nothing
// supervises the process; one request per gate interval; audited first.
func (a *API) HandleRestart(w http.ResponseWriter, r *http.Request) {
	caller, ok := a.d.Authz(w, r)
	if !ok {
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		a.d.WriteErr(w, http.StatusMethodNotAllowed, errors.New("POST only"))
		return
	}
	if caller.APIKey {
		a.d.WriteErr(w, http.StatusForbidden, errors.New("a restart can only be requested from a signed-in session"))
		return
	}
	if a.gate == nil || !a.d.Supervised() {
		a.d.WriteErr(w, http.StatusConflict, errors.New("this installation is not set up to restart itself; restart the Correlix service from the host"))
		return
	}
	g := a.gate
	g.mu.Lock()
	defer g.mu.Unlock()
	now := a.d.Now()
	if !g.last.IsZero() && now.Sub(g.last) < g.Interval {
		a.d.WriteErr(w, http.StatusTooManyRequests, errors.New("a restart was requested a moment ago; wait a few minutes"))
		return
	}
	entry := AuditEntry{Subject: caller.Subject, Method: r.Method, Path: r.URL.Path, Status: http.StatusAccepted, Outcome: "allow",
		Detail: map[string]any{"action": "platform_restart", "reason": "apply feature settings"}}
	if err := a.d.AuditStrict(entry); err != nil {
		a.d.WriteErr(w, http.StatusInternalServerError, errors.New("the restart was not requested: the audit trail could not record it"))
		return
	}
	g.last = now
	a.d.LogInfo("restart requested to apply feature settings", map[string]any{"by": caller.Subject})
	a.d.WriteJSON(w, http.StatusAccepted, map[string]any{"status": "restarting"})
	select {
	case g.C <- struct{}{}:
	default: // a restart is already under way
	}
}

// Supervised reads the deployment's statement that it restarts the process
// (CORRELIX_SUPERVISED=true, set by compose and the chart).
func Supervised(lookup func(string) (string, bool)) bool {
	v, _ := lookup("CORRELIX_SUPERVISED") // discard: unset reads as not supervised
	return strings.TrimSpace(v) == "true"
}

// KVStore adapts a key-value backend to Store.
type KVStore struct {
	Key    string
	LoadFn func(key string) ([]byte, error)
	SaveFn func(key string, b []byte) error
}

func (k KVStore) Load() ([]byte, error) { return k.LoadFn(k.Key) }
func (k KVStore) Save(b []byte) error   { return k.SaveFn(k.Key, b) }

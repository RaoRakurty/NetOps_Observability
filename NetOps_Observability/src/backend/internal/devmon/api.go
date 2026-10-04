// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package devmon

// api.go — GET /api/devices/{id}/monitoring: READ-ONLY monitoring status.
//
// There is no switch to flip (owner decision 2026-10-03): every addressable
// inventory device is monitored up to the licence ceiling. This surface answers
// the operator's question about ONE device — is Correlix collecting from it,
// and if not, why — and it answers it honestly:
//
//   - monitored, over the licence limit, or without an address, with the
//     sentence behind it;
//   - the telemetry methods configured for it;
//   - whether a collector for ANY of those methods is actually running on this
//     installation. A device can be monitored (counted by the licence) while
//     every collector it needs is switched off; reporting "monitored" there
//     would claim data that is not flowing.
//
// The order every request follows, and the order IS the guarantee:
//
//  1. GATE FIRST: infrastructure:read, the gate the device routes take.
//  2. RESOLVE AND SCOPE: a device in another tenant answers 404, never 403 —
//     revealing that an id exists elsewhere is what §3a rule 1 forbids.
//  3. ANSWER from the registry's stamped state; nothing is re-derived here.

import (
	"errors"
	"net/http"
	"strings"

	"netops/backend/models"
)

// Principal is the authenticated caller as the gate resolved them. The module
// never derives identity or scope itself.
type Principal struct {
	Subject string
	// Tenant is the caller's tenant scope, from principalTenant.
	Tenant string
	// CrossTenant is true only for a caller who may reach every tenant.
	CrossTenant bool
}

// ErrUnknownDevice is the sentinel for an id the device registry does not hold.
var ErrUnknownDevice = errors.New("no such device")

// Registry is the device registry seam.
type Registry interface {
	// Get returns the device stored under id, with its monitoring state
	// stamped. ok is false when no such device exists.
	Get(id string) (models.Device, bool)
}

// Deps are the injected collaborators. No ambient authority.
type Deps struct {
	Registry Registry
	// ReadGate authenticates and authorizes the caller and reports their scope.
	// It has already written the 401/403 when ok is false. Nil is fail-closed.
	ReadGate func(w http.ResponseWriter, r *http.Request) (Principal, bool)
	// CanSee reports whether the (tenant, cross) principal may see this device.
	// The platform's own device-visibility rule, injected rather than copied.
	// Nil is fail-closed (nothing visible).
	CanSee func(d models.Device, tenant string, cross bool) bool
	// CollectorEnabled reports whether a collector for a telemetry method
	// (MethodSNMP, MethodGNMI, …) is running on this installation. Required:
	// without it the module cannot tell "monitored" from "monitored and
	// collecting", and it refuses to guess.
	CollectorEnabled func(method string) bool
	// WriteJSON / WriteError are the platform's response helpers. Required.
	WriteJSON  func(w http.ResponseWriter, status int, body any)
	WriteError func(w http.ResponseWriter, status int, err error)
}

// API is the route handler.
type API struct{ d Deps }

// New builds the API.
func New(d Deps) *API { return &API{d: d} }

// View is the wire body: what is being collected from this device, and why.
type View struct {
	DeviceID string `json:"device_id"`
	// Monitored is the licensed state — addressable and within the ceiling.
	Monitored bool `json:"monitored"`
	// State is the machine token (StateMonitored, StateOverLimit, …).
	State string `json:"state"`
	// Reason is the operator sentence behind it. Never empty.
	Reason string `json:"reason"`
	// Methods is the telemetry configured for the device. Several methods are
	// still ONE monitored device; this is display, never a count.
	Methods []string `json:"methods,omitempty"`
	// Collecting is true only when the device is monitored AND a collector
	// for at least one of its methods is running.
	Collecting bool `json:"collecting"`
	// CollectingMethods are the configured methods whose collector is on.
	CollectingMethods []string `json:"collecting_methods,omitempty"`
	// Limit is the licence ceiling an over-limit device is past.
	Limit int `json:"limit,omitempty"`
}

// Path returns the device id for a /api/devices/{id}/monitoring request, and
// whether the path is one.
func Path(p string) (string, bool) {
	const prefix, suffix = "/api/devices/", "/monitoring"
	if !strings.HasPrefix(p, prefix) {
		return "", false
	}
	// CutSuffix, not TrimSuffix: "/api/devices/monitoring" trims to the
	// non-empty "monitoring" and would otherwise read as a device called
	// "monitoring" — a route that answers about a device nobody named.
	id, ok := strings.CutSuffix(strings.TrimPrefix(p, prefix), suffix)
	if !ok || id == "" || strings.Contains(id, "/") {
		return "", false
	}
	return id, true
}

// Handle serves GET on /api/devices/{id}/monitoring. Every other verb is 405:
// the monitoring state is derived, not set.
func (a *API) Handle(w http.ResponseWriter, r *http.Request) {
	if a == nil || a.d.Registry == nil || a.d.WriteJSON == nil || a.d.WriteError == nil ||
		a.d.ReadGate == nil || a.d.CanSee == nil || a.d.CollectorEnabled == nil {
		// A surface that cannot answer must not serve. 503, never a silent
		// open door and never a guess.
		http.Error(w, "device monitoring unavailable", http.StatusServiceUnavailable)
		return
	}
	id, ok := Path(r.URL.Path)
	if !ok {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		a.d.WriteError(w, http.StatusMethodNotAllowed,
			errors.New("monitoring is read-only: every device with an address is monitored, up to the licence limit"))
		return
	}
	caller, ok := a.d.ReadGate(w, r)
	if !ok {
		return
	}
	d, found := a.d.Registry.Get(id)
	if !found || !a.d.CanSee(d, caller.Tenant, caller.CrossTenant) {
		// 404, not 403: another tenant's device must be indistinguishable from
		// one that does not exist.
		http.NotFound(w, r)
		return
	}
	a.d.WriteJSON(w, http.StatusOK, a.view(d))
}

func (a *API) view(d models.Device) View {
	v := View{
		DeviceID:  d.ID,
		Monitored: d.Monitored,
		State:     d.MonitorState,
		Reason:    d.MonitorReason,
		Methods:   Methods(d),
		Limit:     d.MonitorLimit,
	}
	if v.State == "" || v.Reason == "" {
		// The registry stamps every device it returns; an unstamped row is a
		// wiring fault. Say so rather than inventing a state.
		v.Monitored, v.State = false, ""
		v.Reason = "monitoring state is not available for this device"
		return v
	}
	if !v.Monitored {
		return v
	}
	v.CollectingMethods = Collecting(v.Methods, a.d.CollectorEnabled)
	v.Collecting = len(v.CollectingMethods) > 0
	if !v.Collecting {
		v.Reason += " — but no collector for " + strings.Join(v.Methods, " or ") +
			" is enabled on this installation, so nothing is being collected from it; " +
			"enable that collector to start receiving its telemetry"
	}
	return v
}

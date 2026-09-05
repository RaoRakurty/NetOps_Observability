package devmon

// api.go — the monitoring switch: GET|PUT /api/devices/{id}/monitoring.
//
// This is the operator's first-class answer to "is Correlix collecting from
// this device?", and it is the ONLY interactive path that turns monitoring on.
// Before it existed the only way to stop collecting from a device was to delete
// it, which threw the inventory row away with the telemetry.
//
// The order every handler follows, and the order IS the guarantee (the
// dataprotect/licence precedent):
//
//  1. GATE FIRST, per verb, before the body is read. A read needs
//     infrastructure:read, a write infrastructure:write — the same gates the
//     device routes themselves take, because this IS device state.
//  2. RESOLVE AND SCOPE. The device must be visible to the caller; a device in
//     another tenant answers 404, never 403 — revealing that an id exists
//     elsewhere is the disclosure §3a rule 1 forbids.
//  3. BOUND the body, then delegate to the registry, which owns the ceiling
//     check and the write under one lock.
//  4. AUDIT BOTH OUTCOMES. A refused activation that nobody recorded is
//     indistinguishable from one that never happened.
//
// Nothing here reads the environment, derives a tenant, or knows what a licence
// is: the gates hand it a principal, and a ceiling refusal arrives as an opaque
// error which the injected Refusal renderer turns into the platform's 402. That
// is deliberate — this module must stay usable by a build with no licence
// subsystem at all.

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"netops/backend/models"
)

// MaxBodyBytes bounds a PUT. The body is one boolean; 4 KiB is three orders of
// magnitude of headroom and still a hard stop (CLAUDE.md §9).
const MaxBodyBytes = 4 << 10

// Principal is the authenticated caller as the gate resolved them. The module
// never derives identity or scope itself.
type Principal struct {
	Subject string
	// Tenant is the caller's tenant scope, from principalTenant.
	Tenant string
	// CrossTenant is true only for a caller who may reach every tenant.
	CrossTenant bool
}

// AuditRecord is what the module asks the platform to record.
type AuditRecord struct {
	Actor    string
	Status   int
	Decision string
	Detail   map[string]any
}

// ErrUnknownDevice is the sentinel for an id the device registry does not hold.
// It is declared HERE, in the leaf, and used by the registry itself, so there is
// exactly one value: errors.Is compares by identity, and a second sentinel for
// the same fact would turn a 404 into a 500.
var ErrUnknownDevice = errors.New("no such device")

// Registry is the device registry seam: resolve a device, and change its
// monitoring state. The implementation (internal/discovery) owns the ceiling
// check and performs it in the same lock hold as the write, which is what makes
// concurrent activations at the ceiling safe.
type Registry interface {
	// Get returns the device stored under id, with its monitoring state
	// stamped. ok is false when no such device exists.
	Get(id string) (models.Device, bool)
	// Decision returns the stored operator decision for id, if one was ever
	// made. Absence means "never decided", which is not the same as "off".
	MonitoringDecision(id string) (Record, bool)
	// SetMonitoring turns monitoring on or off and returns the device as it now
	// stands. It returns a licence refusal when the ceiling refuses the
	// transition, and ErrUnknownDevice for an id it does not hold.
	SetMonitoring(id string, enabled bool, by string) (models.Device, error)
}

// Deps are the injected collaborators. No ambient authority.
type Deps struct {
	Registry Registry
	// ReadGate / WriteGate authenticate and authorize the caller and report
	// their scope. They have already written the 401/403 when ok is false. Nil
	// is fail-closed: the handler refuses rather than serving ungated.
	ReadGate  func(w http.ResponseWriter, r *http.Request) (Principal, bool)
	WriteGate func(w http.ResponseWriter, r *http.Request) (Principal, bool)
	// CanSee reports whether the (tenant, cross) principal may see this device.
	// The platform's own device-visibility rule, injected rather than copied so
	// this module cannot drift from it. Nil is fail-closed (nothing visible).
	CanSee func(d models.Device, tenant string, cross bool) bool
	// Audit records both outcomes of every write. Optional.
	Audit func(r *http.Request, ev AuditRecord)
	// Refusal renders a licence refusal (the platform's structured 402) and
	// reports whether it did. A non-licence error is left alone. Optional: with
	// no renderer a refusal falls through to the module's own 4xx, which still
	// carries the reason rather than a generic failure.
	Refusal func(w http.ResponseWriter, err error) bool
	// WriteJSON / WriteError are the platform's response helpers, so this
	// surface answers like every other route. Required.
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
	// Monitored is the state in force — the thing the licence counts.
	Monitored bool `json:"monitored"`
	// Reason is the operator sentence behind it. Never empty.
	Reason string `json:"reason"`
	// Methods is the telemetry configured for the device. Several methods are
	// still ONE monitored device; this is display, never a count.
	Methods []string `json:"methods,omitempty"`
	// Decided says whether an operator has ever made this call explicitly. When
	// false the state is the default for how the device entered the inventory,
	// and DecidedBy/DecidedAt are absent.
	Decided   bool      `json:"decided"`
	DecidedBy string    `json:"decided_by,omitempty"`
	DecidedAt time.Time `json:"decided_at,omitzero"`
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

// Handle serves GET (read) and PUT (set) on /api/devices/{id}/monitoring.
func (a *API) Handle(w http.ResponseWriter, r *http.Request) {
	if a == nil || a.d.Registry == nil || a.d.WriteJSON == nil || a.d.WriteError == nil {
		// A surface that cannot answer must not serve. 503, never a silent
		// open door.
		http.Error(w, "device monitoring unavailable", http.StatusServiceUnavailable)
		return
	}
	id, ok := Path(r.URL.Path)
	if !ok {
		http.NotFound(w, r)
		return
	}
	switch r.Method {
	case http.MethodGet:
		a.read(w, r, id)
	case http.MethodPut:
		a.set(w, r, id)
	default:
		w.Header().Set("Allow", "GET, PUT")
		a.d.WriteError(w, http.StatusMethodNotAllowed, errors.New("GET or PUT"))
	}
}

// resolve runs the gate and the visibility rule, answering the device or having
// already written the response.
func (a *API) resolve(w http.ResponseWriter, r *http.Request, id string, gate func(http.ResponseWriter, *http.Request) (Principal, bool)) (models.Device, Principal, bool) {
	if gate == nil || a.d.CanSee == nil {
		// Fail closed: an unwired gate or visibility rule serves nothing.
		http.Error(w, "device monitoring unavailable", http.StatusServiceUnavailable)
		return models.Device{}, Principal{}, false
	}
	caller, ok := gate(w, r)
	if !ok {
		return models.Device{}, Principal{}, false
	}
	d, found := a.d.Registry.Get(id)
	if !found || !a.d.CanSee(d, caller.Tenant, caller.CrossTenant) {
		// 404, not 403: another tenant's device must be indistinguishable from
		// one that does not exist.
		http.NotFound(w, r)
		return models.Device{}, Principal{}, false
	}
	return d, caller, true
}

func (a *API) read(w http.ResponseWriter, r *http.Request, id string) {
	d, _, ok := a.resolve(w, r, id, a.d.ReadGate)
	if !ok {
		return
	}
	a.d.WriteJSON(w, http.StatusOK, a.view(d))
}

func (a *API) set(w http.ResponseWriter, r *http.Request, id string) {
	d, caller, ok := a.resolve(w, r, id, a.d.WriteGate)
	if !ok {
		return
	}
	var req struct {
		Enabled *bool `json:"enabled"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, MaxBodyBytes)).Decode(&req); err != nil {
		a.d.WriteError(w, http.StatusBadRequest, errors.New(`body must be {"enabled": true|false}`))
		return
	}
	if req.Enabled == nil {
		// A missing field is not "false": guessing would silently stop
		// collecting from a device nobody asked to stop collecting from.
		a.d.WriteError(w, http.StatusBadRequest, errors.New(`"enabled" is required and must be true or false`))
		return
	}
	after, err := a.d.Registry.SetMonitoring(d.ID, *req.Enabled, caller.Subject)
	if err != nil {
		a.audit(r, caller, http.StatusPaymentRequired, "deny", map[string]any{
			"action": "device_monitoring_set", "device": d.ID,
			"enabled": *req.Enabled, "reason": err.Error(),
		})
		if a.d.Refusal != nil && a.d.Refusal(w, err) {
			return
		}
		if errors.Is(err, ErrUnknownDevice) {
			http.NotFound(w, r)
			return
		}
		a.d.WriteError(w, http.StatusConflict, err)
		return
	}
	a.audit(r, caller, http.StatusOK, "allow", map[string]any{
		"action": "device_monitoring_set", "device": d.ID,
		"enabled": *req.Enabled, "monitored": after.Monitored,
	})
	a.d.WriteJSON(w, http.StatusOK, a.view(after))
}

func (a *API) view(d models.Device) View {
	v := View{
		DeviceID:  d.ID,
		Monitored: d.Monitored,
		Reason:    d.MonitorReason,
		Methods:   d.MonitorMethods,
	}
	if v.Reason == "" {
		// Never silent: every state says why it is the state.
		on, why := Default(d)
		v.Monitored, v.Reason = on, why
	}
	if rec, ok := a.d.Registry.MonitoringDecision(d.ID); ok {
		v.Decided, v.DecidedBy, v.DecidedAt = true, rec.UpdatedBy, rec.UpdatedAt
	}
	return v
}

func (a *API) audit(r *http.Request, caller Principal, status int, decision string, detail map[string]any) {
	if a.d.Audit == nil {
		return
	}
	a.d.Audit(r, AuditRecord{Actor: caller.Subject, Status: status, Decision: decision, Detail: detail})
}

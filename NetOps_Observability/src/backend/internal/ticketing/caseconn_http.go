// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ticketing

// caseconn_http.go — the HTTP surface a customer brings its own TAC credentials
// through.
//
//	GET    /api/tac/connectors/{id}       — one connector's stored settings, redacted
//	PUT    /api/tac/connectors/{id}       — save them (owner stamped from the token)
//	DELETE /api/tac/connectors/{id}       — remove them
//	POST   /api/tac/connectors/{id}/test  — the vendor's read-only probe
//
// WHAT WAS MISSING. GET /api/tac/connectors has always been able to say whether
// a tenant has credentials for a vendor path. Nothing could ever GIVE it any:
// TACConnectorStore had a Set the adapters read from and no route reached it, so
// "Not configured" was a permanent condition of the product rather than a state
// a customer could leave. These four routes are the way out of it.
//
// §3a, in the order the rules are numbered:
//  1. The tenant is the CALLER's, derived by the integrator's Authz from the
//     token. This subtree accepts no tenant selector of any kind — not a query
//     parameter, not a body field — so there is nothing to widen. A cross-tenant
//     principal must scope into one concrete tenant first and is refused
//     otherwise, exactly as the template surface refuses it.
//  2. The owner is stamped from the principal. A tenant in the body is not
//     ignored, it is a 400: the forms reject unknown fields, so a body carrying
//     one is a client that believes something untrue.
//  3. The gate is requirePerm(infrastructure, read|write) plus the tenant
//     filter — per-tenant operator data, not platform plumbing.
//  4. The store itself refuses another tenant's key; every call here passes
//     cross=false with the resolved tenant as the target, so even a
//     cross-tenant principal acts as exactly one tenant.
//
// §8: a stored secret is never serialized out. The response carries a `secrets`
// map of NAME → stored?, so the form can render "stored" and offer replace or
// clear without the value ever leaving the process. A save that omits a secret
// keeps the stored one; a save that sends "" removes it (caseconn_form.go).
//
// §10: every write and every probe is audited on BOTH outcomes. A credential
// change that failed is exactly as interesting as one that worked.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// The registered route patterns. Exported so the integrator registers exactly
// what this file documents rather than a string that drifted from it.
const (
	TACConnectorItemPath = "/api/tac/connectors/{id}"
	TACConnectorTestPath = "/api/tac/connectors/{id}/test"
)

// tacConnectorMaxBody bounds a settings save. The largest legitimate form is
// Cisco's, with its field map; 64 KiB is far above it and far below a DoS (§9).
const tacConnectorMaxBody = 64 << 10

// ConnectorGate is the abstract authorization gate; the integrator maps it onto
// the platform's RBAC model.
type ConnectorGate int

const (
	// ConnectorGateRead — reading a connector's stored settings.
	ConnectorGateRead ConnectorGate = iota
	// ConnectorGateWrite — saving, removing, or testing them. A TEST is a write
	// gate on purpose: it spends the tenant's credential against a vendor.
	ConnectorGateWrite
)

// ConnectorPrincipal is the resolved caller.
type ConnectorPrincipal struct {
	Tenant  string
	Cross   bool
	Subject string
}

// TACConnectorAPIDeps are the surface's injected collaborators. Every one is
// required: a surface built from incomplete deps could read or write unscoped,
// so the constructor fails closed rather than defaulting a gap.
type TACConnectorAPIDeps struct {
	// Authz authorizes the caller and returns the resolved principal. It has
	// already written the error response when ok is false.
	Authz func(w http.ResponseWriter, r *http.Request, gate ConnectorGate) (ConnectorPrincipal, bool)
	// Store resolves the per-tenant connector store at REQUEST time. A function
	// rather than a value because the store is built after the routes are
	// registered, and a nil captured at registration would read as "no store"
	// forever.
	Store func() *TACConnectorStore
	// Registry is the closed connector catalogue — the same one the escalation
	// path uses, so a connector cannot be configurable here and unknown there.
	Registry *CaseConnectorRegistry
	// Resolve returns one tenant's configuration WITH the ITSM connection folded
	// in, which is what ValidateConfig and the ITSM probes need. Injected
	// because ITSMConfigStore lives outside this surface's reach.
	Resolve func(ctx context.Context, tenantID, connectorID string) (TACConnectorConfig, error)
	// Audit records every write and every probe, on both outcomes.
	Audit CaseAuditSink
	// WriteJSON / WriteError are the platform's response writers.
	WriteJSON  func(w http.ResponseWriter, status int, body any)
	WriteError func(w http.ResponseWriter, status int, err error)
	// Now is the clock.
	Now func() time.Time
	// ProbeTimeout bounds one connection test; zero means DefaultProbeTimeout.
	ProbeTimeout time.Duration
}

func (d TACConnectorAPIDeps) validate() error {
	missing := make([]string, 0, 8)
	check := func(n string, ok bool) {
		if !ok {
			missing = append(missing, n)
		}
	}
	check("Authz", d.Authz != nil)
	check("Store", d.Store != nil)
	check("Registry", d.Registry != nil)
	check("Resolve", d.Resolve != nil)
	check("Audit", d.Audit != nil)
	check("WriteJSON", d.WriteJSON != nil)
	check("WriteError", d.WriteError != nil)
	check("Now", d.Now != nil)
	if len(missing) > 0 {
		return fmt.Errorf("ticketing: TACConnectorAPIDeps missing required fields: %s", strings.Join(missing, ", "))
	}
	return nil
}

// TACConnectorAPI is the settings surface.
type TACConnectorAPI struct{ deps TACConnectorAPIDeps }

// NewTACConnectorAPI builds it, failing CLOSED on incomplete deps.
func NewTACConnectorAPI(d TACConnectorAPIDeps) (*TACConnectorAPI, error) {
	if err := d.validate(); err != nil {
		return nil, err
	}
	return &TACConnectorAPI{deps: d}, nil
}

// ConnectorConfigView is one connector's settings as a client may see them.
// Exactly one settings block is populated — the one this connector edits — and
// every write-only secret has been cleared out of it.
type ConnectorConfigView struct {
	ID      string           `json:"id"`
	Display string           `json:"display"`
	Vendor  string           `json:"vendor,omitempty"`
	Section ConnectorSection `json:"section,omitempty"`
	// Editable is false for the portal-only paths: they store no credential, so
	// there is no form. Saying so is the honest state, not an omission.
	Editable bool `json:"editable"`
	// Configured / StatusNote are the same two values the connector list carries,
	// recomputed here so a save's response tells the operator what changed.
	Configured bool   `json:"configured"`
	StatusNote string `json:"status_note,omitempty"`
	// Secrets names each write-only secret this section holds and whether one is
	// stored. The VALUE never appears anywhere in this type.
	Secrets map[string]bool `json:"secrets"`

	ServiceNow *ServiceNowAttachConfig `json:"servicenow,omitempty"`
	Jira       *JiraAttachConfig       `json:"jira,omitempty"`
	Email      *EmailConnectorConfig   `json:"email,omitempty"`
	Cisco      *CiscoConnectorConfig   `json:"cisco,omitempty"`
	Juniper    *JuniperConnectorConfig `json:"juniper,omitempty"`
}

// HandleConnectorItem serves GET/PUT/DELETE on one connector's settings.
func (a *TACConnectorAPI) HandleConnectorItem(w http.ResponseWriter, r *http.Request) {
	if a == nil {
		http.NotFound(w, r)
		return
	}
	switch r.Method {
	case http.MethodGet:
		a.get(w, r)
	case http.MethodPut:
		a.put(w, r)
	case http.MethodDelete:
		a.remove(w, r)
	default:
		a.deps.WriteError(w, http.StatusMethodNotAllowed, errors.New("GET, PUT or DELETE only"))
	}
}

// HandleConnectorTest serves the read-only probe.
func (a *TACConnectorAPI) HandleConnectorTest(w http.ResponseWriter, r *http.Request) {
	if a == nil {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodPost {
		a.deps.WriteError(w, http.StatusMethodNotAllowed, errors.New("POST only"))
		return
	}
	a.test(w, r)
}

// ── the four handlers ───────────────────────────────────────────────────────

func (a *TACConnectorAPI) get(w http.ResponseWriter, r *http.Request) {
	entry, p, ok := a.begin(w, r, ConnectorGateRead)
	if !ok {
		return
	}
	stored, err := a.stored(p.Tenant)
	if err != nil {
		a.deps.WriteError(w, http.StatusServiceUnavailable, err)
		return
	}
	a.deps.WriteJSON(w, http.StatusOK, a.view(r, entry, p.Tenant, stored))
}

func (a *TACConnectorAPI) put(w http.ResponseWriter, r *http.Request) {
	entry, p, ok := a.begin(w, r, ConnectorGateWrite)
	if !ok {
		return
	}
	tenant := p.Tenant
	section := SectionForConnector(entry.ID)
	if section == SectionNone {
		a.refuse(w, r, entry, p, "save", http.StatusConflict, ErrNoSettings)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, tacConnectorMaxBody))
	if err != nil {
		a.refuse(w, r, entry, p, "save", http.StatusRequestEntityTooLarge,
			errors.New("that form is larger than this endpoint accepts"))
		return
	}
	if len(strings.TrimSpace(string(body))) == 0 {
		a.refuse(w, r, entry, p, "save", http.StatusBadRequest,
			errors.New("the request carried no settings to save"))
		return
	}
	store := a.deps.Store()
	if store == nil {
		a.deps.WriteError(w, http.StatusServiceUnavailable, errNoConnectorStore)
		return
	}
	// The change is applied INSIDE the store's lock, so a save to one connector
	// can never carry another connector's block back to an older value.
	saved, err := store.Update(tenant, false, tenant, func(prev TACConnectorConfig) (TACConnectorConfig, error) {
		return ApplyConnectorWrite(section, body, prev)
	})
	if err != nil {
		// A refused save is the operator's own field to fix; the store's
		// cross-tenant answer is a 404 that reveals nothing.
		status := http.StatusBadRequest
		if errors.Is(err, ErrTenantNotFound) {
			status = http.StatusNotFound
		}
		a.refuse(w, r, entry, p, "save", status, err)
		return
	}
	a.record(entry, p, "save", "ok", nil)
	a.deps.WriteJSON(w, http.StatusOK, a.view(r, entry, tenant, saved))
}

func (a *TACConnectorAPI) remove(w http.ResponseWriter, r *http.Request) {
	entry, p, ok := a.begin(w, r, ConnectorGateWrite)
	if !ok {
		return
	}
	tenant := p.Tenant
	section := SectionForConnector(entry.ID)
	if section == SectionNone {
		a.refuse(w, r, entry, p, "remove", http.StatusConflict, ErrNoSettings)
		return
	}
	store := a.deps.Store()
	if store == nil {
		a.deps.WriteError(w, http.StatusServiceUnavailable, errNoConnectorStore)
		return
	}
	left, err := store.Update(tenant, false, tenant, func(prev TACConnectorConfig) (TACConnectorConfig, error) {
		return ClearConnectorSection(section, prev)
	})
	if err != nil {
		status := http.StatusBadRequest
		if errors.Is(err, ErrTenantNotFound) {
			status = http.StatusNotFound
		}
		a.refuse(w, r, entry, p, "remove", status, err)
		return
	}
	a.record(entry, p, "remove", "ok", nil)
	a.deps.WriteJSON(w, http.StatusOK, a.view(r, entry, tenant, left))
}

func (a *TACConnectorAPI) test(w http.ResponseWriter, r *http.Request) {
	entry, p, ok := a.begin(w, r, ConnectorGateWrite)
	if !ok {
		return
	}
	cfg, err := a.deps.Resolve(r.Context(), p.Tenant, entry.ID)
	switch {
	case errors.Is(err, ErrTenantNotFound), errors.Is(err, ErrNotConfigured):
		cfg = TACConnectorConfig{} // no row yet: the probe reports not_configured
	case err != nil:
		a.refuse(w, r, entry, p, "test", http.StatusServiceUnavailable, err)
		return
	}
	res := ProbeConnector(r.Context(), entry.Connector, cfg, a.deps.ProbeTimeout, a.deps.Now)
	res.ConnectorID = entry.ID
	result := "ok"
	if res.Outcome != ProbeOK {
		result = "error"
	}
	a.record(entry, p, "test:"+string(res.Outcome), result, nil)
	a.deps.WriteJSON(w, http.StatusOK, res)
}

// ── the shared preamble ─────────────────────────────────────────────────────

var (
	errNoConnectorStore = errors.New("the connector settings store is not available on this deployment")
	// errMustScope is the cross-tenant principal's refusal. A platform owner in
	// the Global view is not a customer and has no connector settings of its
	// own; it must pick a tenant before it can read or change one's credentials.
	errMustScope = errors.New("choose a tenant before reading or changing its connector settings")
)

// begin runs the gate, resolves the tenant, and finds the connector. Every
// handler starts here so no path can skip one of the three.
func (a *TACConnectorAPI) begin(w http.ResponseWriter, r *http.Request, gate ConnectorGate) (ConnectorEntry, ConnectorPrincipal, bool) {
	p, ok := a.deps.Authz(w, r, gate)
	if !ok {
		return ConnectorEntry{}, ConnectorPrincipal{}, false
	}
	p.Tenant = ITSMKey(p.Tenant)
	if p.Tenant == "" {
		a.deps.WriteError(w, http.StatusConflict, errMustScope)
		return ConnectorEntry{}, ConnectorPrincipal{}, false
	}
	id := strings.TrimSpace(r.PathValue("id"))
	entry, found := a.deps.Registry.Get(id)
	if !found {
		// An unknown id and a connector this deployment does not carry answer
		// the same 404 — the catalogue is not an oracle either.
		a.deps.WriteError(w, http.StatusNotFound, errors.New("no such case connector"))
		return ConnectorEntry{}, ConnectorPrincipal{}, false
	}
	return entry, p, true
}

// stored reads the tenant's OWN record. An absent row is not an error: it is a
// fresh tenant, and the form must open on it.
func (a *TACConnectorAPI) stored(tenant string) (TACConnectorConfig, error) {
	store := a.deps.Store()
	if store == nil {
		return TACConnectorConfig{}, errNoConnectorStore
	}
	cfg, err := store.Get(tenant, false, tenant)
	if errors.Is(err, ErrTenantNotFound) {
		return TACConnectorConfig{}, nil
	}
	if err != nil {
		return TACConnectorConfig{}, err
	}
	return cfg, nil
}

// view renders one connector's settings, redacted, with its current state.
func (a *TACConnectorAPI) view(r *http.Request, entry ConnectorEntry, tenant string, stored TACConnectorConfig) ConnectorConfigView {
	section := SectionForConnector(entry.ID)
	out := ConnectorConfigView{
		ID:       entry.ID,
		Display:  connectorDisplayName(entry),
		Vendor:   entry.Vendor,
		Section:  section,
		Editable: section != SectionNone,
		Secrets:  SectionSecretsPresent(section, stored),
	}
	red := stored.Redacted()
	switch section {
	case SectionServiceNow:
		out.ServiceNow = &red.ServiceNow
	case SectionJira:
		out.Jira = &red.Jira
	case SectionEmail:
		out.Email = &red.Email
	case SectionCisco:
		out.Cisco = &red.Cisco
	case SectionJuniper:
		out.Juniper = &red.Juniper
	}
	out.Configured, out.StatusNote = a.state(r, entry, tenant)
	return out
}

// state recomputes Configured/StatusNote through the SAME resolver and the SAME
// validator the connector list uses, so the form and the list can never disagree
// about whether a tenant is ready.
func (a *TACConnectorAPI) state(r *http.Request, entry ConnectorEntry, tenant string) (bool, string) {
	cfg, err := a.deps.Resolve(r.Context(), tenant, entry.ID)
	switch {
	case errors.Is(err, ErrTenantNotFound), errors.Is(err, ErrNotConfigured):
		return false, NotConfiguredStatusNote
	case err != nil:
		return false, "the stored connector configuration could not be read: " + Truncate(err.Error(), 160)
	}
	if verr := entry.Connector.ValidateConfig(cfg); verr != nil {
		return false, verr.Error()
	}
	return true, ""
}

// refuse writes the error AND audits it. A credential change that was refused is
// as much a security event as one that landed (§10).
func (a *TACConnectorAPI) refuse(w http.ResponseWriter, _ *http.Request, entry ConnectorEntry, p ConnectorPrincipal, action string, status int, err error) {
	a.record(entry, p, action, "error", err)
	a.deps.WriteError(w, status, err)
}

// record writes one audit row. It carries identifiers, the act and its outcome —
// never a field value, and therefore never a credential (§8).
func (a *TACConnectorAPI) record(entry ConnectorEntry, p ConnectorPrincipal, action, result string, err error) {
	e := CaseAuditEvent{
		At:        a.deps.Now(),
		TenantID:  p.Tenant,
		Actor:     p.Subject,
		Action:    "config_change",
		Detail:    action,
		Connector: entry.ID,
		Vendor:    entry.Vendor,
		Result:    result,
	}
	if err != nil {
		e.Error = Truncate(err.Error(), 400)
	}
	a.deps.Audit.RecordCaseAction(e)
}

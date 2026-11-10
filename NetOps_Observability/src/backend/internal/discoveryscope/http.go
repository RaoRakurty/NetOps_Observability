// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package discoveryscope

// http.go — /api/discovery/scopes:
//
//	GET    /api/discovery/scopes        the caller's customers' scans (+ the platform scan, platform owner only)
//	POST   /api/discovery/scopes        new scan for a customer          — platform owner only
//	GET    /api/discovery/scopes/{id}   one scan
//	PUT    /api/discovery/scopes/{id}   change a scan                    — platform owner only
//	DELETE /api/discovery/scopes/{id}   remove a scan                    — platform owner only
//
// §3a. Reads need infrastructure:read and are filtered by the caller's tenant
// (principalTenant): a customer sees only its own scans, and a scan of another
// customer is the same 404 as one that does not exist — on reads AND on writes,
// so a customer cannot probe ids with a PUT either (the 403 "platform
// administrator required" is answered only about a scan the caller can see).
// Writes are the platform owner's (owner decision D1): requirePlatformAdmin,
// with the customer chosen EXPLICITLY. The owning tenant is never taken from the
// body for a caller narrowed to one tenant ("view as" a customer): it is that
// tenant. A scan's customer never changes — moving a scan is delete + create.

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strings"
	"time"

	"netops/backend/internal/discovery"
	"netops/backend/internal/owner"
	"netops/backend/models"
)

const (
	apiPrefix = "/api/discovery/scopes"
	bodyCap   = 16 << 10
	// maxFoundListed bounds the found list of one scan in one response (§9).
	maxFoundListed = 500
)

// Caller is the authenticated principal as the gates resolved it.
type Caller struct {
	Subject string
	// Tenant and Cross are principalTenant's answer.
	Tenant string
	Cross  bool
	// PlatformOwner is the identity question (isPlatformOwner), independent of
	// any "view as" narrowing.
	PlatformOwner bool
}

// Deps are the server seams (§2: every dependency injected).
type Deps struct {
	Registry *Registry
	// Reader authorizes a read (infrastructure:read); ok=false means it has
	// written the response.
	Reader func(w http.ResponseWriter, r *http.Request) (Caller, bool)
	// Writer authorizes a write: the platform owner only (requirePlatformAdmin).
	Writer func(w http.ResponseWriter, r *http.Request) (Caller, bool)
	// ResolveTenant maps an UNTRUSTED tenant id-or-slug to the canonical id.
	ResolveTenant func(ref string) (string, bool)
	// TenantName is the display name of a tenant id ("" when unknown).
	TenantName func(id string) string
	// CredentialOwner is the owning tenant of an SNMP profile id; ok=false when
	// there is no such profile.
	CredentialOwner func(id string) (tenant string, ok bool)
	// PlatformScan is the platform scan's config: its ranges, whether it is on,
	// and how many addresses it charges against the shared sweep budget.
	PlatformScan func() (ranges []string, enabled bool, hosts int)
	// Status is the scanner's per-scope view (discovery.SNMPSource.ScopeStatuses).
	Status func() []discovery.ScopeStatus
	// Devices is the merged inventory (discovery.DiscoveryAggregator.Devices).
	Devices func() []models.Device
	// Refresh asks the scanner to sweep now (its cooldown still applies).
	Refresh func()
	// Audit records a committed change; detail never carries a secret.
	Audit      func(r *http.Request, c Caller, action string, sc Scope)
	NewID      func() (string, error)
	Now        func() time.Time
	WriteJSON  func(w http.ResponseWriter, status int, v any)
	WriteError func(w http.ResponseWriter, status int, err error)
	Log        func(msg string, err error)
}

var errNotFound = errors.New("no such scan")

// Handler serves /api/discovery/scopes and /api/discovery/scopes/.
func (d Deps) Handler(w http.ResponseWriter, r *http.Request) {
	rest := strings.Trim(strings.TrimPrefix(r.URL.Path, apiPrefix), "/")
	switch {
	case rest == "" && r.Method == http.MethodGet:
		d.list(w, r)
	case rest == "" && r.Method == http.MethodPost:
		d.create(w, r)
	case rest == "":
		w.Header().Set("Allow", "GET, POST")
		d.WriteError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
	case strings.Contains(rest, "/"):
		d.WriteError(w, http.StatusNotFound, errNotFound)
	case r.Method == http.MethodGet:
		d.get(w, r, rest)
	case r.Method == http.MethodPut:
		d.update(w, r, rest)
	case r.Method == http.MethodDelete:
		d.remove(w, r, rest)
	default:
		w.Header().Set("Allow", "GET, PUT, DELETE")
		d.WriteError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
	}
}

// scopeInput is the POST/PUT body. TenantID is honoured only for a
// cross-tenant platform owner creating a scan.
type scopeInput struct {
	TenantID        string   `json:"tenant_id"`
	Name            string   `json:"name"`
	Ranges          []string `json:"ranges"`
	AllowNonPrivate bool     `json:"allow_non_private"`
	CredentialRefs  []string `json:"credential_refs"`
	Enabled         bool     `json:"enabled"`
}

func (d Deps) decode(w http.ResponseWriter, r *http.Request) (scopeInput, bool) {
	var in scopeInput
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, bodyCap))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		d.WriteError(w, http.StatusBadRequest, fmt.Errorf("invalid body: %w", err))
		return in, false
	}
	return in, true
}

// visible is the read rule: cross sees every scan, a narrowed caller its own
// tenant's only. A scan never belongs to the platform, so the Provider view
// sees none.
func visible(c Caller, sc Scope) bool {
	return c.Cross || owner.ScopeReads(c.Tenant, sc.TenantID)
}

func (d Deps) list(w http.ResponseWriter, r *http.Request) {
	c, ok := d.Reader(w, r)
	if !ok {
		return
	}
	scopes, err := d.Registry.Store().List(r.Context(), c.Tenant, c.Cross)
	if err != nil {
		d.Log("discovery scopes: list failed", err)
		d.WriteError(w, http.StatusServiceUnavailable, errors.New("the discovery scans could not be read"))
		return
	}
	v := d.newViewer(c)
	out := make([]scopeView, 0, len(scopes))
	for _, sc := range scopes {
		if visible(c, sc) { // the store already scoped it; belt-and-braces
			out = append(out, v.view(sc))
		}
	}
	body := map[string]any{
		"scopes": out,
		"limits": map[string]int{"max_hosts": discovery.MaxScanHosts, "per_customer": MaxPerTenant, "max_credential_refs": MaxCredentialRefs},
	}
	// The platform's own scan, for the platform owner in the All-tenants or
	// Provider view only: it is platform configuration, never a customer's.
	if c.PlatformOwner && (c.Cross || owner.IsPlatform(c.Tenant)) {
		body["platform"] = v.platformView()
	}
	if err := d.Registry.LoadError(); err != nil && c.PlatformOwner {
		body["scanner_view_stale"] = true
	}
	d.WriteJSON(w, http.StatusOK, body)
}

func (d Deps) get(w http.ResponseWriter, r *http.Request, id string) {
	c, ok := d.Reader(w, r)
	if !ok {
		return
	}
	sc, found := d.lookup(w, r, c, id)
	if !found {
		return
	}
	d.WriteJSON(w, http.StatusOK, d.newViewer(c).view(sc))
}

// lookup finds a scan the caller can see; anything else is the one 404.
func (d Deps) lookup(w http.ResponseWriter, r *http.Request, c Caller, id string) (Scope, bool) {
	if !ValidID(id) {
		d.WriteError(w, http.StatusNotFound, errNotFound)
		return Scope{}, false
	}
	sc, found, err := d.Registry.Store().Get(r.Context(), c.Tenant, c.Cross, id)
	if err != nil {
		d.Log("discovery scopes: read failed", err)
		d.WriteError(w, http.StatusServiceUnavailable, errors.New("the discovery scans could not be read"))
		return Scope{}, false
	}
	if !found || !visible(c, sc) {
		d.WriteError(w, http.StatusNotFound, errNotFound)
		return Scope{}, false
	}
	return sc, true
}

func (d Deps) create(w http.ResponseWriter, r *http.Request) {
	c, ok := d.Writer(w, r)
	if !ok {
		return
	}
	in, ok := d.decode(w, r)
	if !ok {
		return
	}
	// THE OWNER. A caller narrowed to one tenant creates for THAT tenant — the
	// body cannot name another. Only the cross-tenant owner names the customer,
	// and the name is resolved against the tenant registry, never used raw.
	tenant := NormTenant(c.Tenant)
	if c.Cross {
		id, found := d.ResolveTenant(in.TenantID)
		if !found {
			d.WriteError(w, http.StatusBadRequest, errors.New("choose the customer this scan is for"))
			return
		}
		tenant = NormTenant(id)
	}
	if owner.IsPlatform(tenant) {
		d.WriteError(w, http.StatusBadRequest, errors.New("a customer scan needs a customer — the platform's own scan is set under Network Scan"))
		return
	}
	if len(d.Registry.Snapshot()) >= MaxTotal {
		d.WriteError(w, http.StatusBadRequest, fmt.Errorf("at most %d customer scans in all", MaxTotal))
		return
	}
	id, err := d.NewID()
	if err != nil {
		d.Log("discovery scopes: id generation failed", err)
		d.WriteError(w, http.StatusInternalServerError, errors.New("could not create the scan"))
		return
	}
	now := d.Now().UTC()
	sc := Scope{
		ID: id, TenantID: tenant, Name: in.Name, Ranges: in.Ranges, AllowNonPrivate: in.AllowNonPrivate,
		CredentialRefs: in.CredentialRefs, Enabled: in.Enabled, CreatedBy: c.Subject, CreatedAt: now, UpdatedAt: now,
	}
	if !d.admit(w, &sc) {
		return
	}
	if !d.save(w, r, c, "create", sc) {
		return
	}
	d.WriteJSON(w, http.StatusCreated, d.newViewer(c).view(sc))
}

func (d Deps) update(w http.ResponseWriter, r *http.Request, id string) {
	rc, ok := d.Reader(w, r)
	if !ok {
		return
	}
	existing, found := d.lookup(w, r, rc, id)
	if !found {
		return
	}
	c, ok := d.Writer(w, r)
	if !ok {
		return
	}
	in, ok := d.decode(w, r)
	if !ok {
		return
	}
	if c.Cross && strings.TrimSpace(in.TenantID) != "" {
		if want, ok := d.ResolveTenant(in.TenantID); !ok || NormTenant(want) != existing.TenantID {
			d.WriteError(w, http.StatusBadRequest, errors.New("a scan's customer cannot be changed — remove it and create one for the other customer"))
			return
		}
	}
	sc := existing // the owner, id and creation stamp are the stored ones
	sc.Name, sc.Ranges, sc.AllowNonPrivate = in.Name, in.Ranges, in.AllowNonPrivate
	sc.CredentialRefs, sc.Enabled, sc.UpdatedAt = in.CredentialRefs, in.Enabled, d.Now().UTC()
	if !d.admit(w, &sc) {
		return
	}
	if !d.save(w, r, c, "update", sc) {
		return
	}
	d.WriteJSON(w, http.StatusOK, d.newViewer(c).view(sc))
}

func (d Deps) remove(w http.ResponseWriter, r *http.Request, id string) {
	rc, ok := d.Reader(w, r)
	if !ok {
		return
	}
	existing, found := d.lookup(w, r, rc, id)
	if !found {
		return
	}
	c, ok := d.Writer(w, r)
	if !ok {
		return
	}
	removed, err := d.Registry.Store().Delete(r.Context(), existing.TenantID, existing.ID)
	if err != nil {
		d.Log("discovery scopes: delete failed", err)
		d.WriteError(w, http.StatusServiceUnavailable, errors.New("the scan could not be removed"))
		return
	}
	if !removed {
		d.WriteError(w, http.StatusNotFound, errNotFound)
		return
	}
	d.committed(r, c, "delete", existing)
	w.WriteHeader(http.StatusNoContent)
}

// admit validates sc and checks what the store cannot: the profiles are the
// customer's own, and the shared sweep budget holds.
func (d Deps) admit(w http.ResponseWriter, sc *Scope) bool {
	if err := Validate(sc); err != nil {
		d.WriteError(w, http.StatusBadRequest, err)
		return false
	}
	for _, ref := range sc.CredentialRefs {
		// One message for "no such profile" and "another owner's profile", so
		// the check cannot be used to learn which profile ids exist (§3a).
		if t, ok := d.CredentialOwner(ref); !ok || NormTenant(t) != sc.TenantID || owner.IsPlatform(t) {
			d.WriteError(w, http.StatusBadRequest, fmt.Errorf("SNMP profile %q is not one of this customer's own profiles — a customer's scan uses only the customer's profiles", ref))
			return false
		}
	}
	if sc.Enabled {
		_, platOn, platHosts := d.PlatformScan()
		used := Hosts(*sc)
		if platOn {
			used += platHosts
		}
		used += EnabledHosts(d.Registry.Snapshot(), sc.ID)
		if used > discovery.MaxScanHosts {
			d.WriteError(w, http.StatusBadRequest, BudgetError(used))
			return false
		}
	}
	return true
}

// save persists sc and runs the after-commit steps.
func (d Deps) save(w http.ResponseWriter, r *http.Request, c Caller, action string, sc Scope) bool {
	if err := d.Registry.Store().Put(r.Context(), sc); err != nil {
		if errors.Is(err, ErrInvalid) {
			d.WriteError(w, http.StatusBadRequest, err)
			return false
		}
		d.Log("discovery scopes: write failed", err)
		d.WriteError(w, http.StatusServiceUnavailable, errors.New("the scan could not be saved"))
		return false
	}
	d.committed(r, c, action, sc)
	return true
}

// committed reloads the scanner's view, records the audit row and asks for a
// sweep. A reload failure does not undo the committed write: it is logged, the
// API reports the scanner's view as stale, and RetryLoop catches up.
func (d Deps) committed(r *http.Request, c Caller, action string, sc Scope) {
	if err := d.Registry.Reload(r.Context()); err != nil {
		d.Log("discovery scopes: the scanner's view was not refreshed after a committed change", err)
	}
	d.Audit(r, c, action, sc)
	d.Refresh()
}

// ── views ──────────────────────────────────────────────────────────────────

type foundView struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	Address       string `json:"address"`
	Vendor        string `json:"vendor,omitempty"`
	CredentialRef string `json:"credential_ref,omitempty"`
	Stale         bool   `json:"stale,omitempty"`
	// AlsoFoundByPlatform: the platform scan holds a copy of this address. Its
	// telemetry is attributed to nobody until one copy is removed (the
	// registry leaves out an identity two owners hold).
	AlsoFoundByPlatform bool `json:"also_found_by_platform"`
	// AlsoFoundByOtherCustomers counts other customers' devices at the same
	// address — reported to a cross-tenant caller only (§3a).
	AlsoFoundByOtherCustomers int `json:"also_found_by_other_customers,omitempty"`
}

type statusView struct {
	LastSweep *time.Time `json:"last_sweep,omitempty"`
	LastError string     `json:"last_error,omitempty"`
	Answering int        `json:"answering"`
	Stale     int        `json:"stale"`
}

type scopeView struct {
	Scope
	TenantName string      `json:"tenant_name,omitempty"`
	Status     *statusView `json:"status,omitempty"`
	Found      []foundView `json:"found"`
	FoundTotal int         `json:"found_total"`
}

type platformView struct {
	ID         string      `json:"id"`
	Platform   bool        `json:"platform"`
	Ranges     []string    `json:"ranges"`
	Enabled    bool        `json:"enabled"`
	Status     *statusView `json:"status,omitempty"`
	FoundTotal int         `json:"found_total"`
}

// viewer computes views for one request against one inventory read.
type viewer struct {
	d        Deps
	c        Caller
	devices  []models.Device
	statuses map[string]discovery.ScopeStatus
	platAt   map[string]bool
	ownersAt map[string]map[string]bool
}

func (d Deps) newViewer(c Caller) *viewer {
	v := &viewer{d: d, c: c, devices: d.Devices(), statuses: map[string]discovery.ScopeStatus{},
		platAt: map[string]bool{}, ownersAt: map[string]map[string]bool{}}
	for _, st := range d.Status() {
		v.statuses[st.ScopeID] = st
	}
	for _, dev := range v.devices {
		if dev.Address == "" {
			continue
		}
		t := NormTenant(dev.TenantID)
		if owner.IsPlatform(t) {
			v.platAt[dev.Address] = true
			continue
		}
		if v.ownersAt[dev.Address] == nil {
			v.ownersAt[dev.Address] = map[string]bool{}
		}
		v.ownersAt[dev.Address][t] = true
	}
	return v
}

// budgetRefusedForCustomer is what a non-cross reader sees for a scope the
// shared sweep budget refused: the scanner's own text measures OTHER scans'
// load (and the platform scan's), which is not this customer's to read.
const budgetRefusedForCustomer = "Not scanned: the appliance's scan limit is reached. Your platform operator can see why."

func toStatus(st discovery.ScopeStatus, ok, cross bool) *statusView {
	if !ok {
		return nil
	}
	sv := &statusView{LastError: st.LastError, Answering: st.Answering, Stale: st.Stale}
	if st.BudgetRefused && !cross {
		sv.LastError = budgetRefusedForCustomer
	}
	if !st.LastSweep.IsZero() {
		at := st.LastSweep.UTC()
		sv.LastSweep = &at
	}
	return sv
}

func parseNets(ranges []string) []*net.IPNet {
	out := make([]*net.IPNet, 0, len(ranges))
	for _, r := range ranges {
		if _, n, err := net.ParseCIDR(r); err == nil {
			out = append(out, n)
		}
	}
	return out
}

func inNets(nets []*net.IPNet, addr string) bool {
	ip := net.ParseIP(addr)
	if ip == nil {
		return false
	}
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func (v *viewer) view(sc Scope) scopeView {
	st, ok := v.statuses[sc.ID]
	out := scopeView{Scope: sc, Status: toStatus(st, ok, v.c.Cross), Found: []foundView{}}
	if !v.c.Cross {
		// Who on the platform side created it is the platform's record (it
		// stays in the audit trail); a customer-facing read leaves it out.
		out.CreatedBy = ""
	}
	if v.d.TenantName != nil {
		out.TenantName = v.d.TenantName(sc.TenantID)
	}
	nets := parseNets(sc.Ranges)
	for _, dev := range v.devices {
		if dev.Source != "snmp" || NormTenant(dev.TenantID) != sc.TenantID || !inNets(nets, dev.Address) {
			continue
		}
		out.FoundTotal++
		if len(out.Found) >= maxFoundListed {
			continue
		}
		fv := foundView{ID: dev.ID, Name: dev.Name, Address: dev.Address, Vendor: dev.Vendor,
			CredentialRef: dev.CredentialRef, Stale: dev.DiscoveryStale, AlsoFoundByPlatform: v.platAt[dev.Address]}
		if v.c.Cross {
			for t := range v.ownersAt[dev.Address] {
				if t != sc.TenantID {
					fv.AlsoFoundByOtherCustomers++
				}
			}
		}
		out.Found = append(out.Found, fv)
	}
	sort.Slice(out.Found, func(i, j int) bool { return out.Found[i].Address < out.Found[j].Address })
	return out
}

func (v *viewer) platformView() platformView {
	ranges, enabled, _ := v.d.PlatformScan()
	st, ok := v.statuses[discovery.PlatformScopeID]
	pv := platformView{ID: discovery.PlatformScopeID, Platform: true, Ranges: append([]string{}, ranges...), Enabled: enabled, Status: toStatus(st, ok, v.c.Cross)}
	for _, dev := range v.devices {
		if dev.Source == "snmp" && owner.IsPlatform(dev.TenantID) {
			pv.FoundTotal++
		}
	}
	return pv
}

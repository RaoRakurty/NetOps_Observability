// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package licence

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"netops/backend/internal/entitlement"
)

// api.go — the Licence route: a provider-only WRITE and a tenant-readable VIEW.
//
// Every handler follows the same order, and the order IS the guarantee
// (the Data Protection precedent, internal/dataprotect/http.go):
//
//  1. GATE FIRST, before the body is looked at, and gate EVERY verb. The method
//     selects WHICH gate runs and nothing else is read before it:
//
//     PUT / DELETE / anything else — Gate (requirePlatformAdmin). Installing or
//     replacing a licence is platform-GLOBAL: there is one licence file per
//     installation and it covers every tenant on it, so a scope-blind
//     requireAdmin here would let any tenant license the whole platform
//     (CLAUDE.md §3a rule 3).
//
//     GET — ReadGate (requireAdmin + the caller's tenant). A tenant admin may
//     see what the installation's licence puts in force FOR THEM, so the read
//     answers a TENANT PROJECTION: tier, entitled features, the ceilings with
//     THIS TENANT'S usage beside them (§3a rule 1 — scoped by the principal,
//     default-closed), expiry state and who manages the licence. It carries no
//     customer name, no licence id, no key material and no install controls —
//     those are the provider's commercial terms, not the tenant's (§3a rule 3
//     applied to the payload, not only to the gate). A CROSS-TENANT caller (the
//     platform owner) gets the full provider view; narrowing with the tenant
//     switcher (`as_tenant`) drops them to that tenant's projection, because
//     the override may only ever NARROW.
//
//  2. BOUND the body and validate it — here, by verifying the signature. A
//     document that does not verify never reaches the disk.
//  3. AUDIT BOTH OUTCOMES. A refused platform-global write that was never
//     recorded is indistinguishable from one that never happened.
//
// Nothing in this file imports package backend and nothing reads the process
// environment: every seam is injected (the dataprotect rule). In particular the
// module never derives a tenant itself — the ReadGate hands it one.

// MaxDocumentBytes bounds an uploaded licence. A licence is ~1 KB; 64 KiB is
// four orders of magnitude of headroom and still a hard stop (CLAUDE.md §9:
// all IO bounded).
const MaxDocumentBytes = 64 << 10

// Principal is the authenticated caller, as the gate resolved them. The module
// never derives identity or scope itself: both arrive here already decided.
//
// Tenant/CrossTenant are meaningful for the READ gate only — the write gate
// resolves the platform owner, who is cross-tenant by construction. The zero
// value is a tenant-scoped principal with an EMPTY tenant, which is the
// fail-closed direction: it matches no tenant's rows.
type Principal struct {
	Subject string
	// Tenant is the caller's tenant scope, as principalTenant resolved it.
	Tenant string
	// CrossTenant is true only for a caller who may read across every tenant —
	// the platform owner with no active "view as tenant" narrowing.
	CrossTenant bool
}

// AuditRecord is what the module asks the platform to record. The request
// envelope (method, path, client IP) is filled by the adapter, so the module
// never has to know how this platform derives a client address behind its proxy.
type AuditRecord struct {
	Actor    string
	Status   int
	Decision string
	Detail   map[string]any
}

// Deps are the injected collaborators. No ambient authority: everything the
// module can do, it was handed.
type Deps struct {
	// Store is the licence's durable home.
	Store Store
	// Service is the entitlement projection shown on the page.
	Service *Service
	// Gate authenticates and authorizes the caller as a PLATFORM admin. It has
	// already written the 401/403 when it returns ok=false. It gates every
	// WRITE (and any unknown verb).
	Gate func(w http.ResponseWriter, r *http.Request) (Principal, bool)
	// ReadGate authenticates and authorizes a GET. It admits a tenant/org admin
	// and reports the scope its projection must be built for (Tenant,
	// CrossTenant). It has already written the 401/403 when it returns
	// ok=false.
	//
	// Nil is fail-closed and NOT an open door: the read falls back to Gate, so
	// a build that forgets to wire the tenant view serves the provider-only
	// route it served before, never an unscoped one.
	ReadGate func(w http.ResponseWriter, r *http.Request) (Principal, bool)
	// Audit records both outcomes of every write.
	Audit interface {
		Record(r *http.Request, ev AuditRecord)
	}
	// Usage measures the current value of each enforced ceiling. A ceiling this
	// function omits is NOT MEASURED and the page says so — it is never shown as
	// a reassuring zero.
	Usage func(ctx context.Context) Usage
	// UsageNotes explains, per ceiling, why a value is not measured. Optional.
	UsageNotes func(ctx context.Context) map[string]string
	// TenantUsage measures the ceilings for ONE tenant — the numbers beside the
	// ceilings in the tenant projection — and the per-ceiling reason for every
	// one it does not measure. It MUST count only rows that tenant owns; a
	// ceiling it omits is NOT MEASURED and is shown as such, never as a
	// reassuring zero and never as the platform-wide number, which would leak
	// another tenant's fleet size (§3a rule 1).
	//
	// Nil means nothing is measured for a tenant caller: every ceiling reads
	// "not measured", which is the fail-closed direction.
	TenantUsage func(ctx context.Context, tenant string) (Usage, map[string]string)
	// OverCeilingDevices lists the monitored devices beyond the licensed
	// allowance — the "over-ceiling state is LISTED" half of the owner's
	// 2026-09-05 decision, at device granularity rather than a bare count.
	//
	// PROVIDER VIEW ONLY. The ordering that decides which devices are "beyond"
	// is platform-wide, so the list is not a tenant's to read; the tenant
	// projection omits it entirely rather than showing a filtered slice of an
	// ordering that was never per-tenant.
	//
	// Nil means the platform does not compute one, and the page says so instead
	// of showing an empty list as if it had looked.
	OverCeilingDevices func(ctx context.Context) []OverCeilingDevice
	// Now is the clock. Injected so expiry and grace are testable.
	Now func() time.Time
	// WriteJSON and WriteError are the platform's response helpers, so a licence
	// error looks like every other error in this API.
	WriteJSON  func(w http.ResponseWriter, status int, body any)
	WriteError func(w http.ResponseWriter, status int, err error)
}

// API is the route handler.
type API struct{ d Deps }

// New builds the API. A nil Store or Gate is a wiring bug and the handlers
// refuse rather than serving an unguarded surface.
func New(d Deps) *API {
	if d.Now == nil {
		d.Now = time.Now
	}
	return &API{d: d}
}

// ─────────────────────────────────────────────────────────────────────────────
// Wire types — what the frontend mirrors
// ─────────────────────────────────────────────────────────────────────────────

// CeilingView is one row of the page's usage table.
//
// Current is a POINTER on purpose: a ceiling we do not measure is `null` with a
// sibling CurrentReason, never a fabricated 0. A zero that means "none in use"
// and a blank that means "we never looked" are different facts and the page
// renders them differently.
type CeilingView struct {
	Name  string `json:"name"`
	Label string `json:"label"`
	// Unit is the machine token for WHAT the number counts
	// (entitlement.CeilingUnit) — "monitored_devices" for the devices ceiling,
	// which is not the same thing as inventory rows. A client renders the
	// label, but keys any behaviour off this.
	Unit    string `json:"unit,omitempty"`
	Limit   int    `json:"limit"`
	Current *int   `json:"current"`
	Reason  string `json:"current_reason,omitempty"`
	// Note qualifies a MEASURED number — a fact the bar cannot show on its own,
	// such as devices the ceiling is holding back. Distinct from Reason, which
	// exists only when there is no number at all: "we counted, and here is
	// something else you need to know" and "we never counted" are different
	// statements and a page that conflated them would be lying in one of the
	// two cases.
	Note     string `json:"note,omitempty"`
	Enforced bool   `json:"enforced"`
	Over     bool   `json:"over"`
	// Soft is true where going over this ceiling is ALLOWED and recorded rather
	// than refused (entitlement.SoftCeiling — monitored devices on a paid
	// tier). The page renders a soft ceiling's overage as a true-up banner and a
	// hard one's as a block, which are different things and must not look alike.
	Soft     bool             `json:"soft"`
	LiftedBy entitlement.Tier `json:"lifted_by,omitempty"`
}

// OverCeilingDevice is one monitored device beyond the licensed allowance.
//
// Listing them is honesty, not enforcement: none of these is disabled, hidden
// or deleted, and NOTHING in the product picks which devices "lose" — the
// ordering below is presentational and says so.
type OverCeilingDevice struct {
	DeviceID string `json:"device_id"`
	TenantID string `json:"tenant_id,omitempty"`
	Name     string `json:"name,omitempty"`
	// Reason is the operator sentence for this device's state.
	Reason string `json:"reason"`
}

// FeatureView is one row of the page's feature table.
type FeatureView struct {
	Name     entitlement.Feature `json:"name"`
	Label    string              `json:"label"`
	Entitled bool                `json:"entitled"`
	// IncludedIn is the lowest tier that grants the feature, so the page can say
	// "Enterprise" beside a feature the customer does not have.
	IncludedIn entitlement.Tier `json:"included_in"`
}

// KeyView is a trusted public key as the page displays it (and offers for
// download, for the offline verification recipe).
type KeyView struct {
	ID     string `json:"id"`
	Role   string `json:"role"`
	Note   string `json:"note,omitempty"`
	Base64 string `json:"base64"`
}

// Scope names which of the two views a payload is, so the page renders the
// right one instead of inferring it from a missing field.
const (
	// ScopePlatform — the provider view: the whole licence, the keys, the
	// offline recipe, platform-wide usage, and the install/remove controls.
	ScopePlatform = "platform"
	// ScopeTenant — the tenant projection: what the installation's licence puts
	// in force for ONE tenant, with that tenant's own usage and no commercial
	// or key material.
	ScopeTenant = "tenant"
)

// ManagedBy is the closed vocabulary for who may install or replace the licence
// this deployment runs on. There is exactly one value today and it is stated
// explicitly rather than left to be inferred from a missing button.
const (
	ManagedByProvider = "provider"
)

// ManagedByProviderDetail is the sentence beside it. It answers the question a
// tenant admin actually has when the install controls are not there.
const ManagedByProviderDetail = "There is one licence file per installation and it covers every tenant on it, " +
	"so installing or replacing it is the provider's action. Everything shown here is what that single file puts in force for you."

// TenantScopeNote states, on the page, exactly what the numbers mean in the
// tenant projection: a shared ceiling with one tenant's slice beside it. Saying
// it is the honest-states rule — a tenant reading "7 of 25" must not conclude
// the installation has 18 devices spare.
const TenantScopeNote = "The ceilings are the whole installation's and are shared with every tenant on it. " +
	"The usage beside them counts only your tenant, so it is not the platform's total."

// View is the GET body. ONE shape serves both scopes: the tenant projection is
// the same document with Scope=tenant, the commercial and key material absent,
// and the usage counted under the caller's tenant.
type View struct {
	// Scope is ScopePlatform or ScopeTenant. Always present.
	Scope string `json:"scope"`
	// Tenant is the tenant the usage was counted for. Empty in the platform
	// view, where the counts are platform-wide.
	Tenant string `json:"tenant,omitempty"`
	// ManagedBy / ManagedByDetail — who may install or replace this licence.
	ManagedBy       string `json:"managed_by"`
	ManagedByDetail string `json:"managed_by_detail"`
	// ScopeNote qualifies the usage numbers. Set in the tenant projection.
	ScopeNote string        `json:"scope_note,omitempty"`
	State     State         `json:"state"`
	Ceilings  []CeilingView `json:"ceilings"`
	Features  []FeatureView `json:"features"`
	Overages  []Overage     `json:"overages"`
	// Keys, Path and VerifyHint are PROVIDER-ONLY: key material and the
	// operator's file path are not a tenant's business. Omitted, not blanked,
	// so the page can tell "not for you" from "empty".
	Keys []KeyView `json:"keys,omitempty"`
	// Path is where an operator may drop a licence by hand.
	Path string `json:"path,omitempty"`
	// VerifyHint is the offline verification recipe, shown verbatim on the page
	// so a customer can check what we sent them without trusting this UI.
	VerifyHint string `json:"verify_hint,omitempty"`
	// ExpirySemantics states the expiry, grace and overage policy in the
	// product itself, so an operator reads the same rules on the page they
	// would read in the design doc.
	ExpirySemantics string `json:"expiry_semantics"`
	// DaysToExpiry mirrors the metric. Null when there is nothing to expire.
	DaysToExpiry *int `json:"days_to_expiry"`
	// GraceDaysLeft is whole days until the grace window closes. Null unless
	// the licence is IN GRACE — "0 days left" and "grace does not apply" are
	// different facts and the page must not merge them.
	GraceDaysLeft *int `json:"grace_days_left"`
	// OverCeilingDevices are the monitored devices beyond the allowance.
	// PROVIDER VIEW ONLY (see Deps.OverCeilingDevices); absent, not empty, in
	// the tenant projection.
	OverCeilingDevices []OverCeilingDevice `json:"over_ceiling_devices,omitempty"`
	// OverCeilingNote explains what the list above is and — just as important —
	// what it is not. Present whenever the list is.
	OverCeilingNote string `json:"over_ceiling_note,omitempty"`
}

// OverCeilingNoteText is the sentence beside the over-ceiling device list.
//
// It exists because a list of "the devices that are over" invites exactly one
// wrong conclusion — that Correlix picked them and is doing something to them.
// It picked nothing and is doing nothing.
const OverCeilingNoteText = "These are the monitored devices beyond the licensed allowance. " +
	"Correlix does not choose which devices a licence covers: they are listed most-recently-enabled first purely so the size and shape of the overage are visible. " +
	"Every one of them is still being collected from — nothing here has been disabled, hidden or deleted."

// ExpirySemanticsNote is the expiry, grace and overage policy, stated in the
// product (owner decision, 2026-09-05 — docs/design/TIERING_PLAN_2026-09-03.md
// §9, and the LICENSING_MODEL addendum "Expiry, grace and overage").
//
// It says what happens AND what does not, because the second half is the part
// an operator reading this page at 2am actually needs.
const ExpirySemanticsNote = "A paid licence carries a grace period after its expiry date — 30 days as issued, 7 for an evaluation licence — " +
	"and during grace nothing changes at all. " +
	"After grace, creating and configuring paid capability is refused: no new monitored devices beyond the Community allowance, " +
	"no new tenants or organisations, no new configuration of licensed features. " +
	"Everything already here stays visible and exportable, everything over a ceiling is listed, and nothing is disabled or deleted. " +
	"On Team and Enterprise the monitored-device allowance is a SOFT limit: going over it is allowed and recorded for true-up, never blocked mid-incident. " +
	"No licence state can affect tenant isolation, data separation, permissions or sign-in — those are not licensed capabilities."

// VerifyHintText is the offline recipe. It names the command and the key so a
// customer can verify a file we issued without contacting us.
//
// The flag comes BEFORE the file: the command uses the stdlib flag package,
// which stops parsing at the first non-flag argument, so `verify <file>
// --pubkey <key>` is refused as two positional arguments. A hint the operator
// copies must be a line that actually runs.
const VerifyHintText = "Verify a licence offline with: correlix-licence verify <file> — " +
	"or with the published public key: correlix-licence verify --pubkey <key> <file>"

// ─────────────────────────────────────────────────────────────────────────────
// Handler
// ─────────────────────────────────────────────────────────────────────────────

// Handle serves GET (read), PUT (install) and DELETE (remove) on
// /api/system/licence.
//
// The METHOD picks the gate and nothing else is read before that gate runs. An
// unknown verb takes the PLATFORM gate deliberately: a 405 is a fact about this
// surface, and an unauthenticated caller must not be able to learn it.
func (a *API) Handle(w http.ResponseWriter, r *http.Request) {
	if a == nil || a.d.Store == nil || a.d.Gate == nil {
		// A surface that cannot gate must not serve. 503, not a silent open door.
		http.Error(w, "licence service unavailable", http.StatusServiceUnavailable)
		return
	}
	if r.Method == http.MethodGet {
		a.read(w, r)
		return
	}
	// 1. GATE FIRST — before the body. Every write is the platform owner's.
	caller, ok := a.d.Gate(w, r)
	if !ok {
		return
	}
	switch r.Method {
	case http.MethodPut:
		a.install(w, r, caller)
	case http.MethodDelete:
		a.remove(w, r, caller)
	default:
		w.Header().Set("Allow", "GET, PUT, DELETE")
		a.writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
	}
}

// read serves the GET. The gate decides the SCOPE and the scope decides the
// payload: a cross-tenant caller gets the provider view, everyone else gets
// their own tenant's projection. There is no third branch and no way to ask for
// someone else's — the tenant comes from the token, never from the request
// (§3a rule 2).
func (a *API) read(w http.ResponseWriter, r *http.Request) {
	if a.d.ReadGate == nil {
		// Fail closed: with no tenant read wired, the route is exactly what it
		// was before the split — the PLATFORM gate and the provider view. It
		// does not fall through to a tenant projection built from a principal
		// whose scope nobody resolved.
		if _, ok := a.d.Gate(w, r); !ok {
			return
		}
		a.writeJSON(w, http.StatusOK, a.view(r.Context()))
		return
	}
	caller, ok := a.d.ReadGate(w, r)
	if !ok {
		return
	}
	if caller.CrossTenant {
		a.writeJSON(w, http.StatusOK, a.view(r.Context()))
		return
	}
	a.writeJSON(w, http.StatusOK, a.tenantView(r.Context(), caller.Tenant))
}

func (a *API) install(w http.ResponseWriter, r *http.Request, caller Principal) {
	// 2. BOUND the body.
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, MaxDocumentBytes))
	if err != nil {
		a.audit(r, caller, http.StatusBadRequest, "deny", map[string]any{
			"action": "licence_install", "reason": "unreadable or oversize body",
		})
		a.writeError(w, http.StatusBadRequest, fmt.Errorf("licence document could not be read (limit %d bytes): %w", MaxDocumentBytes, err))
		return
	}
	if len(strings.TrimSpace(string(body))) == 0 {
		a.audit(r, caller, http.StatusBadRequest, "deny", map[string]any{
			"action": "licence_install", "reason": "empty body",
		})
		a.writeError(w, http.StatusBadRequest, errors.New("no licence document in the request"))
		return
	}

	// The store verifies BEFORE writing, so a refused document never displaces
	// a working licence.
	st, err := a.d.Store.Install(body, a.d.Now())
	if err != nil {
		// 3. AUDIT BOTH OUTCOMES. The refusal reason is recorded and returned
		// verbatim: an operator holding a licence we will not accept needs to
		// know exactly why, not "invalid".
		a.audit(r, caller, http.StatusBadRequest, "deny", map[string]any{
			"action": "licence_install", "reason": err.Error(),
		})
		a.writeError(w, http.StatusBadRequest, err)
		return
	}
	a.audit(r, caller, http.StatusOK, "allow", map[string]any{
		"action": "licence_install", "licence_id": st.LicenceID, "customer": st.Customer,
		"tier": string(st.LicensedTier), "expires_at": st.ExpiresAt.UTC().Format(time.RFC3339),
		"key_id": st.KeyID,
	})
	a.writeJSON(w, http.StatusOK, a.view(r.Context()))
}

func (a *API) remove(w http.ResponseWriter, r *http.Request, caller Principal) {
	before := a.d.Store.State()
	st, err := a.d.Store.Remove()
	if err != nil {
		a.audit(r, caller, http.StatusInternalServerError, "deny", map[string]any{
			"action": "licence_remove", "reason": err.Error(),
		})
		a.writeError(w, http.StatusInternalServerError, err)
		return
	}
	a.audit(r, caller, http.StatusOK, "allow", map[string]any{
		"action": "licence_remove", "licence_id": before.LicenceID,
		"tier_before": string(before.LicensedTier), "tier_after": string(st.Tier),
	})
	a.writeJSON(w, http.StatusOK, a.view(r.Context()))
}

// view assembles the PROVIDER payload from one State read, so every panel on
// the page describes the same instant.
func (a *API) view(ctx context.Context) View {
	usage := Usage{}
	if a.d.Usage != nil {
		usage = a.d.Usage(ctx)
	}
	notes := map[string]string{}
	if a.d.UsageNotes != nil {
		notes = a.d.UsageNotes(ctx)
	}
	v := a.compose(a.d.Store.State(), usage, notes, true)
	v.Scope = ScopePlatform
	keys := make([]KeyView, 0, 2)
	for _, k := range EmbeddedKeys() {
		keys = append(keys, KeyView{ID: k.ID, Role: k.Role, Note: k.Note, Base64: k.Base64})
	}
	v.Keys = keys
	v.Path = a.d.Store.Path()
	v.VerifyHint = VerifyHintText
	if a.d.OverCeilingDevices != nil {
		if rows := a.d.OverCeilingDevices(ctx); len(rows) > 0 {
			v.OverCeilingDevices = rows
			v.OverCeilingNote = OverCeilingNoteText
		}
	}
	return v
}

// tenantView assembles the TENANT PROJECTION: the same licence, seen from one
// tenant.
//
// Two things are deliberately different from the provider view, and both are
// isolation rules rather than presentation choices:
//
//   - the usage beside each ceiling is measured for THIS TENANT ONLY, so a
//     tenant can never learn another tenant's fleet size from a platform-wide
//     total (§3a rule 1);
//   - the commercial identity of the licence (customer, licence id, issue date,
//     support terms, signing key) and the operator's file path, keys and
//     offline recipe are simply not in the payload. Absent, not blanked.
//
// What IS kept is everything the tenant needs to understand what they may do:
// tier, entitled features, ceilings, expiry/grace/degraded state, and who
// manages the licence.
func (a *API) tenantView(ctx context.Context, tenant string) View {
	usage := Usage{}
	notes := map[string]string{}
	if a.d.TenantUsage != nil {
		usage, notes = a.d.TenantUsage(ctx, tenant)
	}
	v := a.compose(tenantState(a.d.Store.State()), usage, notes, false)
	v.Scope = ScopeTenant
	v.Tenant = tenant
	v.ScopeNote = TenantScopeNote
	return v
}

// tenantState strips a State down to what a tenant may see. It is a
// value-to-value function with no IO, so what leaves it is auditable by reading
// it: every field the projection keeps is named here, and everything else is
// dropped by construction (the zero value), not by remembering to blank it.
func tenantState(st State) State {
	out := State{
		Source:       st.Source,
		Tier:         st.Tier,
		Ceilings:     st.Ceilings,
		Features:     st.Features,
		ExpiresAt:    st.ExpiresAt,
		InGrace:      st.InGrace,
		Degraded:     st.Degraded,
		Reason:       st.Reason,
		LicensedTier: st.LicensedTier,
		// GraceDays is part of the EXPIRY STATE, not of the commercial identity:
		// "expired 3 days ago, inside a 30-day grace" is the sentence a tenant
		// needs, and without the number the page would have to invent one. The
		// phase, the grace end and the trial flag are the same kind of fact:
		// what a tenant may do right now and for how long.
		GraceDays:   st.GraceDays,
		Phase:       st.Phase,
		GraceEndsAt: st.GraceEndsAt,
		Trial:       st.Trial,
		// LapsedFeatures is what keeps a tenant's own history readable after a
		// lapse; a tenant who cannot see it cannot understand why a page they
		// use still loads while a button on it refuses.
		LapsedFeatures: st.LapsedFeatures,
	}
	// A REFUSED licence is a fact the tenant must have — their ceilings fell
	// back to Community and they need to know why their tier vanished — but the
	// verbatim reason names a file path, a key id or a signature failure, which
	// is provider detail. State the fact, not the forensics.
	if st.LoadError != "" {
		out.LoadError = "the licence installed on this platform was refused, so the Community ceilings are the ones in force — ask your provider"
	}
	return out
}

// compose builds the shared body of both views from one state and one usage
// reading, so the provider view and the tenant projection can never disagree
// about how a ceiling, a feature or an overage is rendered.
func (a *API) compose(st State, usage Usage, notes map[string]string, record bool) View {
	if notes == nil {
		notes = map[string]string{}
	}

	ceilings := make([]CeilingView, 0, len(entitlement.CeilingNames()))
	for _, n := range entitlement.CeilingNames() {
		limit, _ := st.Ceilings.Get(n)
		row := CeilingView{
			Name:     n,
			Label:    entitlement.CeilingLabel(n),
			Unit:     entitlement.CeilingUnit(n),
			Limit:    limit,
			Enforced: entitlement.Enforced(n),
			Soft:     entitlement.Enforced(n) && entitlement.SoftCeiling(n, st.Tier),
			LiftedBy: entitlement.LiftedBy(n, limit, st.Tier),
		}
		if cur, measured := usage[n]; measured {
			v := cur
			row.Current = &v
			row.Over = entitlement.Enforced(n) && entitlement.Exceeds(cur, limit)
			row.Note = notes[n]
		} else {
			row.Reason = notes[n]
			if row.Reason == "" {
				row.Reason = "not measured on this platform"
			}
		}
		ceilings = append(ceilings, row)
	}

	features := make([]FeatureView, 0, len(entitlement.Features()))
	for _, f := range entitlement.Features() {
		features = append(features, FeatureView{
			Name:       f,
			Label:      entitlement.FeatureLabel(f),
			Entitled:   st.Has(f),
			IncludedIn: entitlement.FeatureTier(f),
		})
	}

	v := View{
		ManagedBy: ManagedByProvider, ManagedByDetail: ManagedByProviderDetail,
		State: st, Ceilings: ceilings, Features: features,
		Overages:        a.overages(st, usage, record),
		ExpirySemantics: ExpirySemanticsNote,
	}
	now := a.d.Now()
	if d, ok := st.DaysToExpiry(now); ok {
		v.DaysToExpiry = &d
	}
	if d, ok := st.GraceDaysLeft(now); ok {
		v.GraceDaysLeft = &d
	}
	return v
}

// overages lists the ceilings the usage exceeds, stamped with when each
// episode began where the entitlement service keeps a register.
//
// Going through the Service rather than the State is what makes the page's
// `since` and the metric's `since` the same observation. With no Service wired
// the list is still correct, it simply carries no start time — a fact the page
// renders as an absent field rather than as "just now".
func (a *API) overages(st State, usage Usage, record bool) []Overage {
	// `record` is FALSE for the tenant projection, and that is load-bearing:
	// the register answers "since when is this INSTALLATION over its ceiling",
	// and feeding it one tenant's slice of the fleet would restart the episode
	// at a smaller number every time a tenant admin opened the page. The tenant
	// still sees its own over-ceiling rows; only the platform reading writes.
	if record && a.d.Service != nil {
		return a.d.Service.ObserveUsage(usage, a.d.Now())
	}
	return st.Overages(usage)
}

func (a *API) audit(r *http.Request, caller Principal, status int, decision string, detail map[string]any) {
	if a.d.Audit == nil {
		return
	}
	a.d.Audit.Record(r, AuditRecord{Actor: caller.Subject, Status: status, Decision: decision, Detail: detail})
}

func (a *API) writeJSON(w http.ResponseWriter, status int, body any) {
	if a.d.WriteJSON != nil {
		a.d.WriteJSON(w, status, body)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	// The fallback writer only runs when no platform helper was injected (tests);
	// the status line is already written by then.
	_ = json.NewEncoder(w).Encode(body) // best-effort: nothing can act on a write failure after the status line
}

func (a *API) writeError(w http.ResponseWriter, status int, err error) {
	if a.d.WriteError != nil {
		a.d.WriteError(w, status, err)
		return
	}
	a.writeJSON(w, status, map[string]string{"error": err.Error()})
}

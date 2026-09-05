package metering

// api.go — the two Usage routes.
//
//	GET /api/system/licence/usage           the roll-up, as the Licence page renders it
//	GET /api/system/licence/usage/report    the same period as a SIGNED document
//
// Both are READS of per-tenant data, and both follow the same order, which IS
// the guarantee (the internal/licence and internal/dataprotect precedent):
//
//  1. GATE FIRST, before anything else is read. The gate resolves the caller's
//     scope; this module never derives a tenant itself.
//  2. RESOLVE THE SCOPE FROM THE PRINCIPAL, not from the request (§3a rule 1
//     and rule 2). A cross-tenant caller may narrow with `?tenant=`; a
//     tenant-scoped caller naming ANY tenant but their own gets 404 — never a
//     403, which would confirm that the other tenant exists.
//  3. BOUND the period and validate it, so a malformed range is a refusal
//     rather than a quietly empty answer.
//  4. AUDIT the report download, both outcomes. A signed statement of what a
//     customer consumed leaving the building is an event, not a page view.
//
// Nothing here imports package backend and nothing reads the process
// environment: every seam is injected.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"
)

// DefaultWindowDays is the period a request with no bounds gets: the last 30
// days including today. Thirty because that is the billing period every
// comparable conversation uses, and because it is the window the Licence page
// charts.
const DefaultWindowDays = 30

// Principal is the authenticated caller as the gate resolved them. The module
// never derives identity or scope itself.
//
// The zero value is a tenant-scoped principal with an EMPTY tenant, which is
// the fail-closed direction: the store returns nothing for it.
type Principal struct {
	Subject string
	Tenant  string
	// CrossTenant is true only for a caller who may read every tenant — the
	// platform owner with no active "view as tenant" narrowing.
	CrossTenant bool
}

// AuditRecord is what the module asks the platform to record. The request
// envelope (method, path, client IP) is filled by the adapter.
type AuditRecord struct {
	Actor    string
	Status   int
	Decision string
	Detail   map[string]any
}

// Deps are the injected collaborators. No ambient authority.
type Deps struct {
	// Store is the durable home of the daily rows.
	Store Store
	// Key is the installation's report signing identity. Nil means this build
	// cannot sign, and the report route says so rather than serving an unsigned
	// document that looks signed.
	Key *ReportKey
	// Recorder supplies the last-snapshot time, so a page can say the numbers
	// are as of an hour ago instead of implying they are live.
	Recorder *Recorder
	// ReadGate authenticates and authorizes the caller and reports the scope the
	// answer must be built for. It has already written the 401/403 when it
	// returns ok=false. NIL IS FAIL-CLOSED: the handlers refuse to serve.
	ReadGate func(w http.ResponseWriter, r *http.Request) (Principal, bool)
	// Audit records both outcomes of a report download.
	Audit interface {
		Record(r *http.Request, ev AuditRecord)
	}
	// Licence supplies the entitlement context a report is read against. The
	// module asks for it per scope so the commercial identity (customer,
	// licence id) can be dropped from a tenant's document.
	Licence func(ctx context.Context, cross bool) ReportLicence
	// Now is the clock.
	Now func() time.Time
	// WriteJSON and WriteError are the platform's response helpers.
	WriteJSON  func(w http.ResponseWriter, status int, body any)
	WriteError func(w http.ResponseWriter, status int, err error)
}

// API is the route handler.
type API struct{ d Deps }

// New builds the API.
func New(d Deps) *API {
	if d.Now == nil {
		d.Now = func() time.Time { return time.Now().UTC() }
	}
	return &API{d: d}
}

// ─────────────────────────────────────────────────────────────────────────────
// Wire types
// ─────────────────────────────────────────────────────────────────────────────

// TenantUsage is one tenant's line in the platform breakdown.
type TenantUsage struct {
	TenantID string `json:"tenant_id"`
	// Label is "the installation" for the installation row, so a reader is
	// never shown a blank tenant id and left to guess.
	Label  string       `json:"label"`
	Days   int          `json:"days"`
	Meters []MeterValue `json:"meters"`
}

// InstallationLabel names the installation row wherever it is shown.
const InstallationLabel = "the installation"

// UsageView is the GET body. ONE shape serves both scopes: a tenant's answer is
// the same document with Scope=tenant, the commercial identity absent, and no
// per-tenant breakdown.
type UsageView struct {
	Scope  string `json:"scope"`
	Tenant string `json:"tenant,omitempty"`
	From   string `json:"from"`
	To     string `json:"to"`
	// Meters is the vocabulary as this build declares it, so a client renders
	// labels and units without hard-coding them.
	Meters []ReportMeter `json:"meter_definitions"`
	// Days are the daily rows in the period.
	Days []DailyRecord `json:"days"`
	// Totals is the period roll-up.
	Totals Totals `json:"totals"`
	// Tenants is the per-tenant breakdown. PLATFORM SCOPE ONLY: absent, not
	// empty, in a tenant's answer.
	Tenants []TenantUsage `json:"tenants,omitempty"`
	// Licence is the entitlement context the numbers are read against.
	Licence ReportLicence `json:"licence"`
	// LastSnapshot is when the numbers were last refreshed. Null when no
	// snapshot has been taken yet — which is a different fact from "the epoch".
	LastSnapshot *time.Time `json:"last_snapshot"`
	// SnapshotNote explains the sampling, so nobody reads the number as live.
	SnapshotNote string `json:"snapshot_note"`
	// Notes are the standing honesty statements.
	Notes []string `json:"notes"`
	// Key is the installation's report signing identity, so the page can show
	// the public key the downloaded report will carry. Absent when this build
	// cannot produce one, with KeyNote saying why.
	Key     *ReportKeyView `json:"key,omitempty"`
	KeyNote string         `json:"key_note,omitempty"`
	// ScopeNote qualifies the numbers in a tenant's answer.
	ScopeNote string `json:"scope_note,omitempty"`
	// ReportHint is the offline verification recipe, shown verbatim.
	ReportHint string `json:"report_hint"`
	// StoreError says the usage history could not be read, if it could not. A
	// blank history and an unreadable one look identical on a page, and they
	// are not the same fact.
	StoreError string `json:"store_error,omitempty"`
}

// SnapshotNoteText states the sampling shape wherever the numbers are shown.
const SnapshotNoteText = "Usage is sampled hourly and rolled up by UTC day, so today's row grows through the day and the last hour may not be in it yet. " +
	"Monitored devices are counted from configuration — a device with at least one collector enabled — never from recent telemetry."

// TenantScopeNoteText is the sentence beside a tenant's own numbers.
const TenantScopeNoteText = "These are your tenant's numbers only. The installation's totals, the other tenants on it, and the platform-wide diagnostic meters are the provider's and are not shown here."

// ReportHintText is the offline verification recipe. It names the command so a
// customer can check a report we both hold without trusting either UI.
const ReportHintText = "Verify a downloaded usage report offline with: correlix-licence usage-verify <file> — " +
	"it re-derives the totals from the daily rows and checks the signature against the key embedded in the document."

// KeyUnavailableNote is what a page shows when no signing identity could be
// produced. It says the consequence, which is the part an operator needs.
const KeyUnavailableNote = "This installation has no usage-report signing key, so a report cannot be signed. The usage numbers above are unaffected."

// ─────────────────────────────────────────────────────────────────────────────
// Handlers
// ─────────────────────────────────────────────────────────────────────────────

// HandleUsage serves GET /api/system/licence/usage.
func (a *API) HandleUsage(w http.ResponseWriter, r *http.Request) {
	if a == nil || a.d.Store == nil || a.d.ReadGate == nil {
		// A surface that cannot gate or cannot read must not serve.
		http.Error(w, "usage metering unavailable", http.StatusServiceUnavailable)
		return
	}
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		a.writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	caller, ok := a.d.ReadGate(w, r)
	if !ok {
		return
	}
	tenant, cross, ok := a.scope(w, caller, r)
	if !ok {
		return
	}
	from, to, err := a.period(r)
	if err != nil {
		a.writeError(w, http.StatusBadRequest, err)
		return
	}
	view := a.view(r.Context(), tenant, cross, from, to)
	a.writeJSON(w, http.StatusOK, view)
}

// HandleReport serves GET /api/system/licence/usage/report — the same period,
// as a signed document.
func (a *API) HandleReport(w http.ResponseWriter, r *http.Request) {
	if a == nil || a.d.Store == nil || a.d.ReadGate == nil {
		http.Error(w, "usage metering unavailable", http.StatusServiceUnavailable)
		return
	}
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		a.writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	caller, ok := a.d.ReadGate(w, r)
	if !ok {
		return
	}
	tenant, cross, ok := a.scope(w, caller, r)
	if !ok {
		return
	}
	from, to, err := a.period(r)
	if err != nil {
		a.writeError(w, http.StatusBadRequest, err)
		return
	}

	rows, readErr := a.d.Store.List(r.Context(), tenant, cross, from, to)
	if readErr != nil {
		a.audit(r, caller, http.StatusInternalServerError, "deny", map[string]any{
			"action": "usage_report", "reason": readErr.Error(), "from": from, "to": to,
		})
		a.writeError(w, http.StatusInternalServerError, fmt.Errorf("the usage history could not be read: %w", readErr))
		return
	}
	priv, created, keyErr := a.d.Key.Private()
	if keyErr != nil {
		// An unsigned document offered as a signed one is worse than none.
		a.audit(r, caller, http.StatusServiceUnavailable, "deny", map[string]any{
			"action": "usage_report", "reason": keyErr.Error(),
		})
		a.writeError(w, http.StatusServiceUnavailable, keyErr)
		return
	}

	rep := Report{
		Version: ReportVersion, Scope: scopeName(cross), Tenant: displayTenant(cross, tenant),
		GeneratedAt: a.d.Now().UTC(), From: from, To: to,
		Licence: a.licence(r.Context(), cross),
		Meters:  ReportMeters(), Days: rows,
		Totals: Totals{From: from, To: to, Days: len(rows), Meters: RollUp(rows)},
		Notes:  StandingNotes(),
	}
	signed, err := SignReport(rep, priv, created)
	if err != nil {
		a.audit(r, caller, http.StatusInternalServerError, "deny", map[string]any{
			"action": "usage_report", "reason": err.Error(),
		})
		a.writeError(w, http.StatusInternalServerError, err)
		return
	}
	// Indented on purpose: the document is meant to be read, diffed and checked
	// by a human. The SIGNATURE covers the canonical bytes, not these, so an
	// operator may re-format the file freely and it still verifies.
	body, err := json.MarshalIndent(signed, "", "  ")
	if err != nil {
		a.audit(r, caller, http.StatusInternalServerError, "deny", map[string]any{
			"action": "usage_report", "reason": err.Error(),
		})
		a.writeError(w, http.StatusInternalServerError, err)
		return
	}
	a.audit(r, caller, http.StatusOK, "allow", map[string]any{
		"action": "usage_report", "scope": signed.Scope, "tenant": signed.Tenant,
		"from": from, "to": to, "days": len(rows), "key_id": signed.Key.ID,
	})
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", "attachment; filename=\""+ReportFileName(signed)+"\"")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(append(body, '\n')); err != nil {
		return // the status line is already written; nothing can act on this
	}
}

// ReportFileName is the download's name. Deterministic and self-describing, so
// a folder of reports sorts by period and says which tenant each is for.
func ReportFileName(r Report) string {
	name := "correlix-usage-" + r.From + "_" + r.To
	if r.Scope == ReportScopeTenant && r.Tenant != "" {
		name += "-" + safeSegment(r.Tenant)
	}
	return name + ".json"
}

func safeSegment(s string) string {
	var b strings.Builder
	for _, c := range s {
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '_':
			b.WriteRune(c)
		case c >= 'A' && c <= 'Z':
			b.WriteRune(c + 32)
		default:
			b.WriteByte('-')
		}
	}
	return b.String()
}

// ─────────────────────────────────────────────────────────────────────────────
// Scope and period
// ─────────────────────────────────────────────────────────────────────────────

// scope resolves which rows this caller may read.
//
// THE TENANT COMES FROM THE TOKEN (§3a rule 2). `?tenant=` may only NARROW, and
// only for a caller who already reads across tenants. A tenant-scoped caller
// naming another tenant gets 404 — the same answer they would get for a tenant
// that does not exist, because telling them apart is itself a disclosure
// (§3a rule 1).
func (a *API) scope(w http.ResponseWriter, caller Principal, r *http.Request) (tenant string, cross bool, ok bool) {
	want := NormaliseTenant(r.URL.Query().Get("tenant"))
	own := NormaliseTenant(caller.Tenant)
	if !caller.CrossTenant {
		if own == "" {
			// Fail closed: an admitted caller with no resolved tenant reads
			// nothing rather than falling through to the installation row.
			a.writeError(w, http.StatusNotFound, errors.New("no usage is recorded for this scope"))
			return "", false, false
		}
		if want != "" && want != own {
			a.writeError(w, http.StatusNotFound, errors.New("no usage is recorded for that tenant"))
			return "", false, false
		}
		return own, false, true
	}
	if want != "" {
		return want, false, true
	}
	return "", true, true
}

func scopeName(cross bool) string {
	if cross {
		return ReportScopePlatform
	}
	return ReportScopeTenant
}

func displayTenant(cross bool, tenant string) string {
	if cross {
		return ""
	}
	return tenant
}

// period resolves the requested window, defaulting to the last
// DefaultWindowDays and refusing anything longer than the retention bound.
func (a *API) period(r *http.Request) (from, to string, err error) {
	now := a.d.Now().UTC()
	q := r.URL.Query()
	to = strings.TrimSpace(q.Get("to"))
	from = strings.TrimSpace(q.Get("from"))
	if to == "" {
		to = now.Format(DayFormat)
	}
	if from == "" {
		from = now.AddDate(0, 0, -(DefaultWindowDays - 1)).Format(DayFormat)
	}
	if err := checkRange(from, to); err != nil {
		return "", "", err
	}
	f, ferr := time.Parse(DayFormat, from)
	t, terr := time.Parse(DayFormat, to)
	if ferr != nil || terr != nil {
		return "", "", fmt.Errorf("from and to must both be UTC days (%s)", DayFormat)
	}
	if days := int(t.Sub(f).Hours()/24) + 1; days > RetentionDays {
		return "", "", fmt.Errorf("the period is %d days; usage history is kept for %d", days, RetentionDays)
	}
	return from, to, nil
}

// ─────────────────────────────────────────────────────────────────────────────
// The view
// ─────────────────────────────────────────────────────────────────────────────

func (a *API) view(ctx context.Context, tenant string, cross bool, from, to string) UsageView {
	v := UsageView{
		Scope: scopeName(cross), Tenant: displayTenant(cross, tenant),
		From: from, To: to,
		Meters: ReportMeters(), Days: []DailyRecord{},
		SnapshotNote: SnapshotNoteText, Notes: StandingNotes(),
		ReportHint: ReportHintText,
		Licence:    a.licence(ctx, cross),
	}
	if !cross {
		v.ScopeNote = TenantScopeNoteText
	}
	rows, err := a.d.Store.List(ctx, tenant, cross, from, to)
	if err != nil {
		// The page still renders, and says the history could not be read rather
		// than showing an empty chart as if there were nothing to show.
		v.StoreError = "the usage history could not be read, so the period below is not the full picture"
		v.Totals = Totals{From: from, To: to}
		return v
	}
	v.Days = rows
	v.Totals = Totals{From: from, To: to, Days: len(rows), Meters: RollUp(rows)}
	if cross {
		v.Tenants = breakdown(rows)
	}
	if ts := a.d.Recorder.LastSnapshot(); !ts.IsZero() {
		stamp := ts
		v.LastSnapshot = &stamp
	}
	if kv, ok := a.d.Key.View(); ok {
		v.Key = &kv
	} else {
		v.KeyNote = KeyUnavailableNote
	}
	return v
}

// breakdown groups the period's rows by tenant. The installation row keeps its
// own line rather than being folded into a total, because its meters are
// different meters.
func breakdown(rows []DailyRecord) []TenantUsage {
	byTenant := map[string][]DailyRecord{}
	for _, r := range rows {
		byTenant[r.TenantID] = append(byTenant[r.TenantID], r)
	}
	out := make([]TenantUsage, 0, len(byTenant))
	for t, rs := range byTenant {
		label := t
		if t == ScopeInstallation {
			label = InstallationLabel
		}
		out = append(out, TenantUsage{TenantID: t, Label: label, Days: len(rs), Meters: RollUp(rs)})
	}
	sort.Slice(out, func(i, j int) bool {
		// The installation line first, then tenants alphabetically.
		if (out[i].TenantID == ScopeInstallation) != (out[j].TenantID == ScopeInstallation) {
			return out[i].TenantID == ScopeInstallation
		}
		return out[i].TenantID < out[j].TenantID
	})
	return out
}

func (a *API) licence(ctx context.Context, cross bool) ReportLicence {
	if a.d.Licence == nil {
		return ReportLicence{Devices: -1}
	}
	l := a.d.Licence(ctx, cross)
	if !cross {
		// The customer's name and their licence id are the provider's
		// commercial terms, not the tenant's. Dropped here as well as at the
		// source, so a future wiring mistake cannot leak them.
		l.Customer, l.LicenceID = "", ""
	}
	return l
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
	_ = json.NewEncoder(w).Encode(body) // best-effort: nothing can act on a write failure after the status line
}

func (a *API) writeError(w http.ResponseWriter, status int, err error) {
	if a.d.WriteError != nil {
		a.d.WriteError(w, status, err)
		return
	}
	a.writeJSON(w, status, map[string]string{"error": err.Error()})
}

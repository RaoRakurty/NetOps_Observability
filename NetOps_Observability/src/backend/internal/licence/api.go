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

// api.go — the platform-admin Licence route.
//
// Every handler follows the same order, and the order IS the guarantee
// (the Data Protection precedent, internal/dataprotect/http.go):
//
//  1. GATE FIRST, before the verb or the body is looked at. The licence is
//     platform-GLOBAL plumbing, so the gate is requirePlatformAdmin, NOT
//     requireAdmin: a tenant/org admin holds full administration:admin, and a
//     scope-blind gate here would let any tenant read the customer's commercial
//     terms and install a licence for the whole platform (CLAUDE.md §3a rule 3).
//  2. BOUND the body and validate it — here, by verifying the signature. A
//     document that does not verify never reaches the disk.
//  3. AUDIT BOTH OUTCOMES. A refused platform-global write that was never
//     recorded is indistinguishable from one that never happened.
//
// Nothing in this file imports package backend and nothing reads the process
// environment: every seam is injected (the dataprotect rule).

// MaxDocumentBytes bounds an uploaded licence. A licence is ~1 KB; 64 KiB is
// four orders of magnitude of headroom and still a hard stop (CLAUDE.md §9:
// all IO bounded).
const MaxDocumentBytes = 64 << 10

// Principal is the authenticated platform administrator, as the gate resolved
// them. The module never derives identity itself.
type Principal struct{ Subject string }

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
	// already written the 401/403 when it returns ok=false.
	Gate func(w http.ResponseWriter, r *http.Request) (Principal, bool)
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
	Name     string           `json:"name"`
	Label    string           `json:"label"`
	Limit    int              `json:"limit"`
	Current  *int             `json:"current"`
	Reason   string           `json:"current_reason,omitempty"`
	Enforced bool             `json:"enforced"`
	Over     bool             `json:"over"`
	LiftedBy entitlement.Tier `json:"lifted_by,omitempty"`
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

// View is the GET body.
type View struct {
	State    State         `json:"state"`
	Ceilings []CeilingView `json:"ceilings"`
	Features []FeatureView `json:"features"`
	Overages []Overage     `json:"overages"`
	Keys     []KeyView     `json:"keys"`
	// Path is where an operator may drop a licence by hand.
	Path string `json:"path"`
	// VerifyHint is the offline verification recipe, shown verbatim on the page
	// so a customer can check what we sent them without trusting this UI.
	VerifyHint string `json:"verify_hint"`
	// ExpirySemantics states, in the product itself, that the commercial policy
	// for expiry is not yet decided. Saying it here rather than only in a design
	// doc is the honest-states rule applied to our own roadmap.
	ExpirySemantics string `json:"expiry_semantics"`
	// DaysToExpiry mirrors the metric. Null when there is nothing to expire.
	DaysToExpiry *int `json:"days_to_expiry"`
}

// ExpirySemanticsNote is the standing statement that expiry policy is pending.
const ExpirySemanticsNote = "Expiry semantics are an owner decision that is still open. " +
	"The mechanism is in place: a licence carries an expiry and an issuer-set grace period, and after grace the " +
	"commercial ceilings fall back to Community with everything over a ceiling listed here. " +
	"Nothing is ever deleted, and no licence state can affect tenant isolation, data separation, " +
	"permissions or sign-in — those are not licensed capabilities."

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
func (a *API) Handle(w http.ResponseWriter, r *http.Request) {
	if a == nil || a.d.Store == nil || a.d.Gate == nil {
		// A surface that cannot gate must not serve. 503, not a silent open door.
		http.Error(w, "licence service unavailable", http.StatusServiceUnavailable)
		return
	}
	// 1. GATE FIRST — before the verb, before the body.
	caller, ok := a.d.Gate(w, r)
	if !ok {
		return
	}
	switch r.Method {
	case http.MethodGet:
		a.writeJSON(w, http.StatusOK, a.view(r.Context()))
	case http.MethodPut:
		a.install(w, r, caller)
	case http.MethodDelete:
		a.remove(w, r, caller)
	default:
		w.Header().Set("Allow", "GET, PUT, DELETE")
		a.writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
	}
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

// view assembles the page's whole payload from one State read, so every panel
// on the page describes the same instant.
func (a *API) view(ctx context.Context) View {
	st := a.d.Store.State()
	usage := Usage{}
	if a.d.Usage != nil {
		usage = a.d.Usage(ctx)
	}
	notes := map[string]string{}
	if a.d.UsageNotes != nil {
		notes = a.d.UsageNotes(ctx)
	}

	ceilings := make([]CeilingView, 0, len(entitlement.CeilingNames()))
	for _, n := range entitlement.CeilingNames() {
		limit, _ := st.Ceilings.Get(n)
		row := CeilingView{
			Name:     n,
			Label:    entitlement.CeilingLabel(n),
			Limit:    limit,
			Enforced: entitlement.Enforced(n),
			LiftedBy: entitlement.LiftedBy(n, limit, st.Tier),
		}
		if cur, measured := usage[n]; measured {
			v := cur
			row.Current = &v
			row.Over = entitlement.Enforced(n) && entitlement.Exceeds(cur, limit)
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

	keys := make([]KeyView, 0, 2)
	for _, k := range EmbeddedKeys() {
		keys = append(keys, KeyView{ID: k.ID, Role: k.Role, Note: k.Note, Base64: k.Base64})
	}

	v := View{
		State: st, Ceilings: ceilings, Features: features,
		Overages: st.Overages(usage), Keys: keys,
		Path: a.d.Store.Path(), VerifyHint: VerifyHintText,
		ExpirySemantics: ExpirySemanticsNote,
	}
	if d, ok := st.DaysToExpiry(a.d.Now()); ok {
		v.DaysToExpiry = &d
	}
	return v
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

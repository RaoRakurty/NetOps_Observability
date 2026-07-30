package cloud

// source_status.go — the poller-reported per-source ERROR store (Wave 2 #4,
// extracted P2 RA.8). The readiness model has always DEFINED
// permission_denied / misconfigured, but no producer emitted them; this store
// closes the loop: the cloud-ingest poller PUTs its CURRENT error set (full-
// set replace), the connector wizard's live permission check upserts per
// connector, and reads are default-closed per tenant.
//
// Storage is in-memory by design (the ingest-inventory precedent): the poller
// re-PUTs its full error set every flush, so a restart converges within one
// cycle; records not refreshed within the stale horizon expire on read — an
// error can never outlive the poller that observed it by more than the
// matrix's own honesty window. Owner stamping and boundary validation stay
// with the entrypoint's handler (§3a.2 — connector-scoped records derive
// tenant+provider from the row, never the payload).

import (
	"sort"
	"strings"
	"sync"
	"time"
)

// SourceStatusAllowed are the ONLY poller-reportable statuses. flowing/stale/
// off stay measured from landed data — a poller may report why a source is
// failing, never that it is healthy.
var SourceStatusAllowed = map[string]bool{
	"permission_denied": true,
	"misconfigured":     true,
}

// SourceStatusRecord is one (tenant, provider, account, region, source) error
// state as observed by a poller. Since/Reported are server-resolved times
// (never serialized); origin is store-managed.
type SourceStatusRecord struct {
	Tenant      string    `json:"tenant,omitempty"`       // ambient lanes only; connector rows override it
	ConnectorID string    `json:"connector_id,omitempty"` // when set: tenant+provider come from the row
	Provider    string    `json:"provider"`
	AccountID   string    `json:"account_id,omitempty"`
	Region      string    `json:"region,omitempty"`
	SourceType  string    `json:"source_type"`
	Status      string    `json:"status"` // permission_denied | misconfigured
	Detail      string    `json:"detail,omitempty"`
	SinceISO    string    `json:"since_iso,omitempty"` // poller-observed first failure
	Since       time.Time `json:"-"`                   // resolved server-side
	Reported    time.Time `json:"-"`
	// origin separates the two producers writing into this store: "poller"
	// (full-set replace semantics per flush) and "validate" (the connector
	// wizard's live permission check, upserted per connector). Replace only
	// swaps the poller's records so a validate result survives poller flushes.
	origin string
}

const (
	sourceStatusOriginPoller   = "poller"
	sourceStatusOriginValidate = "validate"
)

func (r SourceStatusRecord) key() string {
	return strings.Join([]string{r.Tenant, r.Provider, r.AccountID, r.Region, r.SourceType}, "|")
}

// SourceStatusStore holds the poller-reported error set, tenant-keyed. The
// stale horizon is injected at construction (the ingest window stays with the
// caller).
type SourceStatusStore struct {
	mu    sync.Mutex
	recs  map[string]SourceStatusRecord // key() → record
	stale time.Duration
}

// NewSourceStatusStore builds the store with the given stale-expiry horizon.
func NewSourceStatusStore(staleWindow time.Duration) *SourceStatusStore {
	return &SourceStatusStore{recs: map[string]SourceStatusRecord{}, stale: staleWindow}
}

// Replace swaps in the poller's CURRENT error set (full-set semantics: a lane
// that recovered simply stops being reported and its record disappears). The
// first-failure time is preserved across re-reports so "since Tuesday" stays
// Tuesday — the earliest of the stored and incoming Since wins. Records the
// VALIDATE surface upserted are retained (a poller flush must not erase a live
// permission-check result); a poller record for the same key overrides it —
// the poller's runtime observation is fresher truth than a wizard snapshot.
func (st *SourceStatusStore) Replace(records []SourceStatusRecord, now time.Time) {
	st.mu.Lock()
	defer st.mu.Unlock()
	next := make(map[string]SourceStatusRecord, len(records))
	for k, prev := range st.recs {
		if prev.origin == sourceStatusOriginValidate {
			next[k] = prev
		}
	}
	for _, r := range records {
		r.origin = sourceStatusOriginPoller
		r.Reported = now
		if r.Since.IsZero() {
			r.Since = now
		}
		k := r.key()
		if prev, ok := st.recs[k]; ok && !prev.Since.IsZero() && prev.Since.Before(r.Since) {
			r.Since = prev.Since
		}
		next[k] = r
	}
	st.recs = next
}

// UpsertValidate merges the live permission-check results for one connector's
// scope into the store (origin "validate"), preserving first-seen times.
func (st *SourceStatusStore) UpsertValidate(records []SourceStatusRecord, now time.Time) {
	st.mu.Lock()
	defer st.mu.Unlock()
	for _, r := range records {
		r.origin = sourceStatusOriginValidate
		r.Reported = now
		if r.Since.IsZero() {
			r.Since = now
		}
		k := r.key()
		if prev, ok := st.recs[k]; ok && !prev.Since.IsZero() && prev.Since.Before(r.Since) {
			r.Since = prev.Since
		}
		st.recs[k] = r
	}
}

// ClearValidate drops a validate-origin record (the permission is granted
// again). Poller-origin records are never touched here.
func (st *SourceStatusStore) ClearValidate(rec SourceStatusRecord) {
	st.mu.Lock()
	defer st.mu.Unlock()
	k := rec.key()
	if prev, ok := st.recs[k]; ok && prev.origin == sourceStatusOriginValidate {
		delete(st.recs, k)
	}
}

// ForTenant returns the caller-visible records, default-closed (§3a.1): a
// non-cross caller only ever sees its own tenant's rows. Records that were not
// refreshed within the stale horizon have expired — the poller that observed
// them is gone or the lane state is unknown, and unknown ≠ broken.
func (st *SourceStatusStore) ForTenant(tenant string, cross bool, now time.Time) []SourceStatusRecord {
	t := strings.ToLower(strings.TrimSpace(tenant))
	st.mu.Lock()
	defer st.mu.Unlock()
	out := make([]SourceStatusRecord, 0, len(st.recs))
	for _, r := range st.recs {
		if now.Sub(r.Reported) > st.stale {
			continue
		}
		if !cross && r.Tenant != t {
			continue
		}
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].key() < out[j].key() })
	return out
}

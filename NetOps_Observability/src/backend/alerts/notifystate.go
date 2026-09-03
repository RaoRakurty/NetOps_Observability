package alerts

// notifystate.go — the DURABLE "already notified" set.
//
// THE DEFECT. The engine's firing state (`active`), its `for`-gating clocks
// (`pending`) and its "the fire notification actually went out" record
// (`dispatched`) lived in memory ONLY. A restart therefore wiped the memory of
// every notification the platform had ever sent, and the very next evaluation
// tick saw every still-firing alert as NEWLY firing and paged for all of them
// again. Observed live 2026-09-03: the api restarted twice inside an hour
// (deploys) and produced a burst of pages — CollectorDown, DeviceUnreachable,
// CollectorAllTargetsUnreachable — for conditions that had already been paged,
// which then hammered the push server into `429` and starved the pages that
// mattered. Every deploy was an alert storm of its own making.
//
// THE FIX. The notified set is persisted here, tenant-keyed, on the same file
// backend as the rest of the alerts-adjacent state (platformdb: FileKV's
// atomic CreateTemp+rename on the file build, the RLS-protected row store under
// STORE_BACKEND=postgres). On boot the engine re-seeds `active`, `pending` and
// `dispatched` from it, so:
//
//   - an alert that is STILL firing is not "newly firing" and is NOT re-sent;
//   - an alert that CLEARED while the process was down is still in the restored
//     active set, so the first tick after boot resolves it and the resolution
//     notification goes out exactly once — a restart must not swallow the "it
//     is over" either;
//   - the `for` clock is restored from the alert's FiredAt, so a restored alert
//     is not spuriously resolved and re-fired one `for` later.
//
// TENANCY (§3a). Records are keyed by tenant and every read/write takes the
// tenant explicitly — there is no unscoped "list everything" on this type. The
// tenant is derived by the CALLER from the alert's device (Engine.TenantOf →
// server.alertTenant), never from anything in a payload, exactly as the episode
// fold derives it. Device-less/stack alerts are platform-owned (tenant "").
//
// BOUNDS (§9). Per-tenant cap with oldest-first eviction, plus an age-out: a
// record whose alert has not been seen firing for notifyStateMaxAge is dropped,
// so a rule that is deleted while firing cannot pin a record forever. A record
// still firing is refreshed at most once per notifyStateRefreshEvery, so a
// chronic alert neither ages out nor rewrites the blob every tick.

import (
	"encoding/json"
	"errors"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"netops/backend/internal/platformdb"
	"netops/backend/models"
)

const (
	// notifyStateMaxPerTenant caps one tenant's notified set. A tenant at the
	// cap evicts its own OLDEST record — never another tenant's (§3a: one
	// tenant must not be able to displace another's state).
	notifyStateMaxPerTenant = 1000
	// notifyStateMaxAge drops a record whose alert has not been observed firing
	// for this long. It is the backstop for a rule deleted (or renamed) while
	// firing: without it that record would suppress a notification forever.
	notifyStateMaxAge = 7 * 24 * time.Hour
	// notifyStateRefreshEvery bounds how often a still-firing record's
	// last-seen stamp is rewritten. The engine ticks twice a minute; without
	// this the blob would be re-marshalled on every tick for no new information.
	notifyStateRefreshEvery = time.Hour
)

// NotifiedAlert is one durable record: an alert whose FIRE notification
// actually went out, and which has not yet resolved.
type NotifiedAlert struct {
	// TenantID owns the record. Derived from the alert's device by the caller;
	// "" is platform-owned (stack-level alerts), matching the episode fold.
	TenantID string `json:"tenant_id,omitempty"`
	// Alert is the firing alert as the engine published it. Kept whole so the
	// restored active set can serve the API and, more importantly, so the
	// RESOLUTION dispatched after a restart carries the same id and labels the
	// destination opened its incident under.
	Alert models.Alert `json:"alert"`
	// NotifiedAt is when the fire notification went out.
	NotifiedAt time.Time `json:"notified_at"`
	// LastSeen is the most recent tick that observed this alert still firing.
	// The age-out is measured from here, not from NotifiedAt, so a chronic
	// alert stays suppressed for as long as it is genuinely still firing.
	LastSeen time.Time `json:"last_seen"`
}

// NotifyStateStore is the tenant-keyed, bounded, file-backed notified set.
//
// Writes are BATCHED: MarkNotified/Clear/Touch mutate memory and set a dirty
// flag; the engine calls Flush once per evaluation tick. A storm that fires
// 5,000 alerts in one tick therefore costs ONE blob write, not 5,000 — the
// whole-collection write is O(N), so per-record flushing would be O(N²).
type NotifyStateStore struct {
	mu       sync.Mutex
	path     string
	byTenant map[string]map[string]NotifiedAlert // tenant → alert id → record
	dirty    bool

	maxAge time.Duration
	now    func() time.Time
}

// NewNotifyStateStore loads the persisted set, dropping records that aged out
// while the process was down. A missing or unreadable file is NOT fatal: the
// worst case is the pre-existing behaviour (one duplicate notification per
// still-firing alert), and refusing to start the alert engine over it would be
// a far worse trade. The error is returned so the caller can log it (§10).
func NewNotifyStateStore(path string) (*NotifyStateStore, error) {
	s := &NotifyStateStore{
		path:     path,
		byTenant: map[string]map[string]NotifiedAlert{},
		maxAge:   notifyStateMaxAge,
		now:      time.Now,
	}
	if path == "" {
		return s, nil
	}
	b, err := platformdb.Load(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return s, nil // first run — an absent file is an empty set, not a fault
		}
		return s, err
	}
	var list []NotifiedAlert
	if err := json.Unmarshal(b, &list); err != nil {
		return s, err
	}
	now := s.now().UTC()
	for _, rec := range list {
		if rec.Alert.ID == "" {
			continue
		}
		if rec.LastSeen.IsZero() {
			rec.LastSeen = rec.NotifiedAt
		}
		if !rec.LastSeen.IsZero() && now.Sub(rec.LastSeen) > s.maxAge {
			continue // aged out while we were down
		}
		s.put(rec)
	}
	for tenant := range s.byTenant {
		s.evictLocked(tenant)
	}
	return s, nil
}

// SetNowForTest injects a deterministic clock. Tests only.
func (s *NotifyStateStore) SetNowForTest(now func() time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.now = now
}

// SetMaxAgeForTest overrides the age-out window. Tests only.
func (s *NotifyStateStore) SetMaxAgeForTest(d time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.maxAge = d
}

// normTenant folds a tenant id the way every other tenant-keyed store here
// does, so "Acme", " acme" and "acme" are one namespace and never three.
func normTenant(t string) string { return strings.ToLower(strings.TrimSpace(t)) }

// put inserts a record. Caller holds the lock (or is the constructor).
func (s *NotifyStateStore) put(rec NotifiedAlert) {
	t := normTenant(rec.TenantID)
	rec.TenantID = t
	m := s.byTenant[t]
	if m == nil {
		m = map[string]NotifiedAlert{}
		s.byTenant[t] = m
	}
	m[rec.Alert.ID] = rec
}

// evictLocked keeps ONE tenant's set inside the cap, dropping its own oldest
// records first. Scoped deliberately: a noisy tenant must not be able to evict
// a quiet one's state and cause a duplicate page in another namespace.
func (s *NotifyStateStore) evictLocked(tenant string) {
	m := s.byTenant[tenant]
	if len(m) <= notifyStateMaxPerTenant {
		return
	}
	ids := make([]string, 0, len(m))
	for id := range m {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool {
		a, b := m[ids[i]].LastSeen, m[ids[j]].LastSeen
		if a.Equal(b) {
			return ids[i] < ids[j] // deterministic on a tie
		}
		return a.Before(b)
	})
	for _, id := range ids[:len(m)-notifyStateMaxPerTenant] {
		delete(m, id)
	}
}

// Notified reports whether this tenant has an outstanding notified record for
// the alert id. Scoped: another tenant's record for the same id is invisible
// here, so it can never suppress this tenant's notification.
func (s *NotifyStateStore) Notified(tenant, id string) (NotifiedAlert, bool) {
	if s == nil {
		return NotifiedAlert{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.byTenant[normTenant(tenant)][id]
	return rec, ok
}

// MarkNotified records that the fire notification for this alert went out.
// The owner is the TENANT ARGUMENT, derived by the caller from the alert's
// device — never anything carried in the alert's own labels (§3a rule 2).
func (s *NotifyStateStore) MarkNotified(tenant string, a models.Alert) {
	if s == nil || a.ID == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now().UTC()
	t := normTenant(tenant)
	s.put(NotifiedAlert{TenantID: t, Alert: a, NotifiedAt: now, LastSeen: now})
	s.evictLocked(t)
	s.dirty = true
}

// Touch refreshes a still-firing record's last-seen stamp, at most once per
// notifyStateRefreshEvery. It returns without dirtying the store the rest of
// the time, which is what keeps a chronic alert from rewriting the blob twice a
// minute forever.
func (s *NotifyStateStore) Touch(tenant, id string) {
	if s == nil || id == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	t := normTenant(tenant)
	rec, ok := s.byTenant[t][id]
	if !ok {
		return
	}
	now := s.now().UTC()
	if now.Sub(rec.LastSeen) < notifyStateRefreshEvery {
		return
	}
	rec.LastSeen = now
	s.byTenant[t][id] = rec
	s.dirty = true
}

// Clear forgets a record — the alert resolved, so the next firing is a genuinely
// new one and must notify again. Idempotent, and strictly own-tenant: clearing
// under the wrong tenant is a no-op rather than a cross-tenant delete.
func (s *NotifyStateStore) Clear(tenant, id string) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	t := normTenant(tenant)
	if _, ok := s.byTenant[t][id]; !ok {
		return
	}
	delete(s.byTenant[t], id)
	if len(s.byTenant[t]) == 0 {
		delete(s.byTenant, t)
	}
	s.dirty = true
}

// Tenants lists the tenants holding state. It exists ONLY so the engine can
// re-seed itself at boot (a process-internal operation, not an API surface);
// every actual record read still goes through the tenant-scoped List below.
func (s *NotifyStateStore) Tenants() []string {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, 0, len(s.byTenant))
	for t := range s.byTenant {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

// List returns ONE tenant's records, sorted by alert id for determinism. There
// is deliberately no cross-tenant variant: a caller that wants everything must
// ask tenant by tenant, which is what makes the isolation testable.
func (s *NotifyStateStore) List(tenant string) []NotifiedAlert {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	m := s.byTenant[normTenant(tenant)]
	out := make([]NotifiedAlert, 0, len(m))
	for _, rec := range m {
		out = append(out, rec)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Alert.ID < out[j].Alert.ID })
	return out
}

// Flush persists the set if anything changed, sweeping aged-out records first.
// Returns nil when there was nothing to write. The caller logs the error and
// keeps evaluating: an unwritable disk must never stop alerts from firing — it
// only costs the duplicate-suppression this file provides (§10, and the same
// explicit "best effort is the CALLER's decision" contract the episode store
// uses).
func (s *NotifyStateStore) Flush() error {
	if s == nil || s.path == "" {
		return nil
	}
	s.mu.Lock()
	s.sweepLocked()
	if !s.dirty {
		s.mu.Unlock()
		return nil
	}
	list := make([]NotifiedAlert, 0, 64)
	for _, m := range s.byTenant {
		for _, rec := range m {
			list = append(list, rec)
		}
	}
	s.dirty = false
	s.mu.Unlock()

	sort.Slice(list, func(i, j int) bool {
		if list[i].TenantID != list[j].TenantID {
			return list[i].TenantID < list[j].TenantID
		}
		return list[i].Alert.ID < list[j].Alert.ID
	})
	b, err := json.Marshal(list)
	if err != nil {
		s.mu.Lock()
		s.dirty = true // unwritten: do not pretend it was persisted
		s.mu.Unlock()
		return err
	}
	if err := platformdb.Save(s.path, b); err != nil {
		s.mu.Lock()
		s.dirty = true
		s.mu.Unlock()
		return err
	}
	return nil
}

// sweepLocked drops records whose alert has not been seen firing within the
// age-out window.
func (s *NotifyStateStore) sweepLocked() {
	now := s.now().UTC()
	for t, m := range s.byTenant {
		for id, rec := range m {
			if !rec.LastSeen.IsZero() && now.Sub(rec.LastSeen) > s.maxAge {
				delete(m, id)
				s.dirty = true
			}
		}
		if len(m) == 0 {
			delete(s.byTenant, t)
		}
	}
}

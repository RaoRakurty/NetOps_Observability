package session

import "time"

// RewindForTest backdates a session's timestamps to simulate elapsed time in
// tests (idle/absolute-expiry scenarios). TEST SUPPORT ONLY: production code
// must never rewrite lifecycle timestamps — the store is server-time-only by
// design (no client clock trust), and every non-test write path goes through
// Create/Touch/Validate. It lives in the package because the fields are
// deliberately unexported.
func (s *Store) RewindForTest(id string, lastActivity, created time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	x := s.byID[id]
	if !lastActivity.IsZero() {
		x.LastActivityAt = lastActivity
	}
	if !created.IsZero() {
		x.CreatedAt = created
	}
	s.byID[id] = x
}

// SetKVForTest swaps the persistence backend mid-test to inject write faults
// (full disk, wrong-UID container, Postgres down). TEST SUPPORT ONLY: in
// production the backend is fixed at construction for the store's lifetime.
func (s *Store) SetKVForTest(kv KV) {
	s.flushMu.Lock()
	defer s.flushMu.Unlock()
	s.kv = kv
}

// SetKVForTest is the RefreshStore counterpart — same contract as Store's.
func (s *RefreshStore) SetKVForTest(kv KV) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.kv = kv
}

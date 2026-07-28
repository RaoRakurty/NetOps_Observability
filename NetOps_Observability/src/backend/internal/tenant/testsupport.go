package tenant

// SetKVForTest swaps the persistence backend mid-test to inject write faults
// (full disk, wrong-UID container, Postgres down). TEST SUPPORT ONLY: in
// production the backend is fixed at construction for the store's lifetime.
func (s *Store) SetKVForTest(kv KV) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.deps.KV = kv
}

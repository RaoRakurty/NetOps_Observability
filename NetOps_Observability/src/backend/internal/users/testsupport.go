package users

import (
	"errors"
	"strings"
)

// MutateForTest applies mod to a stored account directly and persists the
// result — the injected-era replacement for tests that used to reach into the
// map to backdate lifecycle timestamps (account-policy rules must be provable
// without sleeping). TEST SUPPORT ONLY: every production write path goes
// through the exported methods and their invariants.
func (s *FileStore) MutateForTest(username string, mod func(*User)) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := strings.ToLower(username)
	u, ok := s.users[key]
	if !ok {
		return errors.New("no such user: " + username)
	}
	mod(&u)
	s.users[key] = u
	return s.flushLocked()
}

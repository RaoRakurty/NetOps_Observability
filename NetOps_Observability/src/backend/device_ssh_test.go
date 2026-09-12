// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

import (
	"path/filepath"
	"testing"
)

// TestSSHRoleAllowed: only operator/admin human roles may open a device shell;
// read-only is refused (API-key principals are blocked separately by sub prefix).
func TestSSHRoleAllowed(t *testing.T) {
	cases := map[string]bool{
		RoleSuperAdmin: true,
		RoleOperator:   true,
		"admin":        true, // legacy alias
		RoleReadOnly:   false,
		RoleAPIClient:  false,
		"":             false,
	}
	for role, want := range cases {
		if got := sshRoleAllowed(role); got != want {
			t.Errorf("sshRoleAllowed(%q) = %v, want %v", role, got, want)
		}
	}
}

// TestSSHHostTOFU: first key for an address is recorded and accepted; the same
// key reconnects ok; a DIFFERENT key for that address is refused (MITM guard).
func TestSSHHostTOFU(t *testing.T) {
	s := newSSHHostStore(filepath.Join(t.TempDir(), "known_hosts.json"))

	first, ok := s.check("10.0.0.1", "SHA256:aaa")
	if !first || !ok {
		t.Fatalf("first key: firstSeen=%v ok=%v, want true/true", first, ok)
	}
	// Same key again — known, not first, accepted.
	if first, ok := s.check("10.0.0.1", "SHA256:aaa"); first || !ok {
		t.Fatalf("repeat key: firstSeen=%v ok=%v, want false/true", first, ok)
	}
	// Changed key for the same address — refuse.
	if _, ok := s.check("10.0.0.1", "SHA256:bbb"); ok {
		t.Fatalf("changed host key must be refused (possible MITM)")
	}
	// A different address is independent.
	if first, ok := s.check("10.0.0.2", "SHA256:ccc"); !first || !ok {
		t.Fatalf("new address: firstSeen=%v ok=%v, want true/true", first, ok)
	}
}

// TestSSHHostTOFUPersists: a recorded fingerprint survives a store reload (so a
// restart doesn't silently re-trust a changed key).
func TestSSHHostTOFUPersists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "known_hosts.json")
	s1 := newSSHHostStore(path)
	s1.check("10.0.0.9", "SHA256:zzz")

	s2 := newSSHHostStore(path) // reload from disk
	if _, ok := s2.check("10.0.0.9", "SHA256:different"); ok {
		t.Fatalf("a changed key after reload must still be refused")
	}
	if first, ok := s2.check("10.0.0.9", "SHA256:zzz"); first || !ok {
		t.Fatalf("the persisted key must be recognized after reload: first=%v ok=%v", first, ok)
	}
}

func TestClampDim(t *testing.T) {
	cases := []struct{ in, def, want int }{
		{0, 24, 24}, {-5, 80, 80}, {100, 24, 100}, {5000, 24, 1000},
	}
	for _, c := range cases {
		if got := clampDim(c.in, c.def); got != c.want {
			t.Errorf("clampDim(%d,%d) = %d, want %d", c.in, c.def, got, c.want)
		}
	}
}

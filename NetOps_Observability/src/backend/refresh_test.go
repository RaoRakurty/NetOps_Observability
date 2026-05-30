package main

import (
	"path/filepath"
	"testing"
	"time"
)

func TestRefreshRotateAndReuseDetection(t *testing.T) {
	rs, err := newRefreshStore(filepath.Join(t.TempDir(), "r.json"), time.Hour)
	if err != nil {
		t.Fatalf("newRefreshStore: %v", err)
	}
	s1, err := rs.Issue("alice")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	// Normal rotation yields a new token for the same user.
	s2, user, err := rs.Rotate(s1)
	if err != nil || user != "alice" || s2 == s1 {
		t.Fatalf("Rotate: s2=%q user=%q err=%v", s2, user, err)
	}
	// Replaying the OLD token is a theft signal → whole family revoked.
	if _, _, err := rs.Rotate(s1); err == nil {
		t.Error("expected reuse of rotated token to fail")
	}
	// ...and that revokes the currently-valid token too.
	if _, _, err := rs.Rotate(s2); err == nil {
		t.Error("expected family revocation to invalidate the live token")
	}
}

func TestRefreshExpired(t *testing.T) {
	rs, err := newRefreshStore(filepath.Join(t.TempDir(), "r.json"), time.Hour)
	if err != nil {
		t.Fatalf("newRefreshStore: %v", err)
	}
	s1, _ := rs.Issue("bob")
	id, _ := parseSecret(s1)
	tok := rs.toks[id]
	tok.ExpiresAt = time.Now().Add(-time.Minute) // backdate
	rs.toks[id] = tok
	if _, _, err := rs.Rotate(s1); err == nil {
		t.Error("expected expired refresh token to fail")
	}
}

func TestRefreshRevokeAndMalformed(t *testing.T) {
	rs, err := newRefreshStore(filepath.Join(t.TempDir(), "r.json"), time.Hour)
	if err != nil {
		t.Fatalf("newRefreshStore: %v", err)
	}
	s1, _ := rs.Issue("carol")
	rs.Revoke(s1)
	if _, _, err := rs.Rotate(s1); err == nil {
		t.Error("expected revoked token to fail rotation")
	}
	if _, _, err := rs.Rotate("no-dot-here"); err == nil {
		t.Error("expected malformed token to fail")
	}
	if _, _, err := rs.Rotate("deadbeef.unknown"); err == nil {
		t.Error("expected unknown token id to fail")
	}
}

func TestRefreshPersistAcrossReload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "r.json")
	rs, _ := newRefreshStore(path, time.Hour)
	s1, _ := rs.Issue("dave")
	// Reopen the store from disk; the token should still rotate.
	rs2, err := newRefreshStore(path, time.Hour)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if _, user, err := rs2.Rotate(s1); err != nil || user != "dave" {
		t.Errorf("rotate after reload: user=%q err=%v", user, err)
	}
}

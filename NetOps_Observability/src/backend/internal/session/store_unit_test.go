// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package session

import (
	"errors"
	"testing"
	"time"
)

// Direct unit tests of the session store lifecycle contract (moved from the
// integrator's session_flow_test.go with the store's extraction).
func TestSessionStoreUnit(t *testing.T) {
	ss, err := NewStore(t.TempDir()+"/s.json", fileTestKV{}, nopErrf)
	if err != nil {
		t.Fatal(err)
	}
	sess, ev, err := ss.Create("u", "1.2.3.4", "agent", 30*time.Minute, 12*time.Hour)
	if err != nil || len(ev) != 0 {
		t.Fatalf("create: %v evicted=%v", err, ev)
	}
	if _, err := ss.Validate(sess.ID, true, true); err != nil {
		t.Fatalf("fresh session should validate: %v", err)
	}
	// Idle.
	ss.RewindForTest(sess.ID, time.Now().Add(-31*time.Minute), time.Time{})
	if _, err := ss.Validate(sess.ID, true, true); !errors.Is(err, ErrIdle) {
		t.Errorf("idle validate: %v, want ErrIdle", err)
	}
	// Absolute (new session; backdate creation).
	s2, _, _ := ss.Create("u2", "", "", 30*time.Minute, 12*time.Hour)
	ss.RewindForTest(s2.ID, time.Now(), time.Now().Add(-13*time.Hour))
	if _, err := ss.Validate(s2.ID, true, true); !errors.Is(err, ErrAbsolute) {
		t.Errorf("absolute validate: %v, want ErrAbsolute", err)
	}
	// Revoke.
	s3, _, _ := ss.Create("u3", "", "", time.Minute, time.Hour)
	if _, err := ss.Revoke(s3.ID); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if _, err := ss.Validate(s3.ID, true, true); !errors.Is(err, ErrRevoked) {
		t.Errorf("revoked validate: %v, want ErrRevoked", err)
	}
	// RevokeAllForUser.
	ss.Create("multi", "", "", time.Minute, time.Hour)
	ss.Create("multi", "", "", time.Minute, time.Hour)
	n, err := ss.RevokeAllForUser("multi")
	if err != nil {
		t.Fatalf("RevokeAllForUser: %v", err)
	}
	if n != 2 {
		t.Errorf("RevokeAllForUser = %d, want 2", n)
	}
	// Cap eviction.
	for i := 0; i < MaxSessionsPerUser+1; i++ {
		ss.Create("capped", "", "", time.Minute, time.Hour)
	}
	active := 0
	for _, x := range ss.ListForUser("capped") {
		if x.Status == StatusActive {
			active++
		}
	}
	if active != MaxSessionsPerUser {
		t.Errorf("capped active = %d, want %d", active, MaxSessionsPerUser)
	}
}

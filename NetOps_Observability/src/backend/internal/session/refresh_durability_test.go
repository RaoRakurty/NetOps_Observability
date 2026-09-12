// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package session

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func hashOf(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

// seedRefreshFile writes a register straight to disk so a test can start from a
// known set of rows, including ones the garbage collector wants to drop.
func seedRefreshFile(t *testing.T, path string, toks ...refreshToken) {
	t.Helper()
	b, err := json.MarshalIndent(toks, "", "  ")
	if err != nil {
		t.Fatalf("marshalling seed: %v", err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatalf("writing seed: %v", err)
	}
}

// TestIssueThatCannotPersistChangesNothing pins the persist-then-adopt contract
// on the refresh register. Issuing a token also garbage-collects rows that
// expired more than a day ago. That collection used to be applied to the live
// map BEFORE the write, so an issue that failed to persist still dropped those
// rows from memory: the register silently disagreed with the file, and the next
// unrelated write serialised the disagreement and made it durable.
func TestIssueThatCannotPersistChangesNothing(t *testing.T) {
	now := time.Now().UTC()
	dir := t.TempDir()
	path := filepath.Join(dir, "refresh_tokens.json")
	seedRefreshFile(t, path,
		refreshToken{ID: "expired1", Hash: hashOf("expired1.aaaa"), Username: "alice", Family: "f1",
			CreatedAt: now.Add(-72 * time.Hour), ExpiresAt: now.Add(-48 * time.Hour)},
		refreshToken{ID: "live1", Hash: hashOf("live1.bbbb"), Username: "bob", Family: "f2",
			CreatedAt: now.Add(-time.Hour), ExpiresAt: now.Add(time.Hour)},
	)

	kv := &switchKV{inner: fileTestKV{}}
	rs, err := NewRefreshStore(path, time.Hour, kv)
	if err != nil {
		t.Fatalf("new refresh store: %v", err)
	}
	if len(rs.toks) != 2 {
		t.Fatalf("seed loaded %d tokens, want 2", len(rs.toks))
	}

	kv.setFailing(true)
	if _, err := rs.IssueForSession("carol", "sess-1"); err == nil {
		t.Fatal("IssueForSession reported success with the write path broken")
	}
	if _, ok := rs.toks["expired1"]; !ok {
		t.Fatal("in memory: the long-expired row was collected by an issue that never persisted")
	}
	if len(rs.toks) != 2 {
		t.Fatalf("in memory: register holds %d tokens after a failed issue, want the 2 it started with", len(rs.toks))
	}
	kv.setFailing(false)

	// An unrelated write serialises the register as it now stands. This is
	// where a collection that was never persisted used to become durable.
	revoked, err := rs.Revoke("live1.bbbb")
	if err != nil || !revoked {
		t.Fatalf("Revoke(live1) = (%v, %v), want (true, nil)", revoked, err)
	}

	reloaded, err := NewRefreshStore(path, time.Hour, fileTestKV{})
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if _, ok := reloaded.toks["expired1"]; !ok {
		t.Fatal("on disk: the long-expired row is gone, so a failed issue changed the file after all")
	}
}

// TestIssueCollectsLongExpiredRowsWhenItDoesPersist keeps the collection itself
// honest: the fix must not turn the garbage collector off.
func TestIssueCollectsLongExpiredRowsWhenItDoesPersist(t *testing.T) {
	now := time.Now().UTC()
	path := filepath.Join(t.TempDir(), "refresh_tokens.json")
	seedRefreshFile(t, path,
		refreshToken{ID: "expired1", Hash: hashOf("expired1.aaaa"), Username: "alice", Family: "f1",
			CreatedAt: now.Add(-72 * time.Hour), ExpiresAt: now.Add(-48 * time.Hour)},
	)
	rs, err := NewRefreshStore(path, time.Hour, fileTestKV{})
	if err != nil {
		t.Fatalf("new refresh store: %v", err)
	}
	if _, err := rs.IssueForSession("carol", "sess-1"); err != nil {
		t.Fatalf("IssueForSession: %v", err)
	}
	if _, ok := rs.toks["expired1"]; ok {
		t.Fatal("in memory: the long-expired row survived a successful issue")
	}
	reloaded, err := NewRefreshStore(path, time.Hour, fileTestKV{})
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if _, ok := reloaded.toks["expired1"]; ok {
		t.Fatal("on disk: the long-expired row survived a successful issue")
	}
	if len(reloaded.toks) != 1 {
		t.Fatalf("on disk: %d tokens, want just the newly issued one", len(reloaded.toks))
	}
}

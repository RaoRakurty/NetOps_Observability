// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"netops/backend/internal/platformdb"
	"os"
	"path/filepath"
	"sort"
	"testing"
)

// kvconformance_test.go — a shared contract suite every platformdb.Backend must satisfy,
// run identically against fileKV, memKV, and (gated) pgStore. This is the
// backend-conformance layer that guards against behavioral drift between the
// file and Postgres backends — the divergence risk called out in design review:
// without it, edge cases (round-trip fidelity, deletions, absent-key signalling)
// can diverge silently and surface only in production.
//
// The contract deliberately pins what MUST match across backends (collection
// round-trip as a SET of entities; verbatim blob round-trip; deletions
// reflected) and documents the ONE tolerated difference (an absent collection
// signals empty either as os.ErrNotExist — file/mem — or as "[]" — pgStore,
// which has rows not files). Stores absorb both, so both are conformant.

// keyMaker yields a backend-appropriate key for a logical store name. fileKV
// needs a writable path; pgStore/memKV only care about the basename (pgStore
// routes on it). Using the same basename everywhere keeps the registry routing
// identical across backends.
type keyMaker func(name string) string

func assertBackendConformance(t *testing.T, b platformdb.Backend, key keyMaker) {
	t.Helper()

	// 1. Collection round-trip — Save a multi-tenant set, Load it back. pgStore
	//    explodes→reassembles (re-serialized, id-ordered), file/mem return bytes
	//    verbatim, so we compare as a SET of entities, never byte-for-byte.
	users := []map[string]any{
		{"username": "alice", "tenant_id": "acme", "role": "admin"},
		{"username": "bob", "tenant_id": "globex", "role": "viewer"},
	}
	blob, err := json.Marshal(users)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := b.Save(key("users"), blob); err != nil {
		t.Fatalf("Save collection: %v", err)
	}
	got, err := b.Load(key("users"))
	if err != nil {
		t.Fatalf("Load collection: %v", err)
	}
	if names := usernames(t, got); !equalSet(names, []string{"alice", "bob"}) {
		t.Errorf("collection round-trip = %v, want [alice bob]", names)
	}

	// 2. Deletions are reflected — re-Save a smaller set; the dropped entity must
	//    not survive (pgStore's delete-all+insert sync; file/mem overwrite).
	smaller, _ := json.Marshal(users[:1])
	if err := b.Save(key("users"), smaller); err != nil {
		t.Fatalf("Save shrink: %v", err)
	}
	got, err = b.Load(key("users"))
	if err != nil {
		t.Fatalf("Load after shrink: %v", err)
	}
	if names := usernames(t, got); !equalSet(names, []string{"alice"}) {
		t.Errorf("after shrink = %v, want [alice] (bob must be gone)", names)
	}

	// 3. Blob round-trip — a non-normalized singleton config is stored VERBATIM
	//    (byte-for-byte) on every backend.
	raw := []byte(`{"enabled":true,"host":"ldap.example.com","port":636}`)
	if err := b.Save(key("ldap_config"), raw); err != nil {
		t.Fatalf("Save blob: %v", err)
	}
	rawGot, err := b.Load(key("ldap_config"))
	if err != nil {
		t.Fatalf("Load blob: %v", err)
	}
	if !bytes.Equal(raw, rawGot) {
		t.Errorf("blob not verbatim: got %s, want %s", rawGot, raw)
	}

	// 4. Absent blob key → os.ErrNotExist on every backend (the platformdb.Backend
	//    contract the store constructors rely on).
	if _, err := b.Load(key("never_written_blob")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("absent blob key: got %v, want os.ErrNotExist", err)
	}

	// 5. Absent collection key → the one tolerated divergence: empty signalled as
	//    ErrNotExist (file/mem) OR "[]" (pgStore). Both yield an empty store.
	if data, err := b.Load(key("roles")); err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			t.Errorf("absent collection: got %v, want ErrNotExist or empty array", err)
		}
	} else if !isEmptyJSONArray(data) {
		t.Errorf("absent collection returned %s, want \"[]\" or ErrNotExist", data)
	}
}

func TestBackendConformance_File(t *testing.T) {
	dir := t.TempDir()
	assertBackendConformance(t, platformdb.FileKV{}, func(name string) string {
		return filepath.Join(dir, name+".json")
	})
}

func TestBackendConformance_Mem(t *testing.T) {
	assertBackendConformance(t, newMemKV(), func(name string) string {
		return "/data/" + name + ".json"
	})
}

func TestBackendConformance_Postgres(t *testing.T) {
	adminDSN := os.Getenv("DATABASE_URL_TEST")
	if adminDSN == "" {
		t.Skip("set DATABASE_URL_TEST to run the Postgres backend conformance test")
	}
	ctx := context.Background()
	ps, err := platformdb.NewPGStore(ctx, provisionAppRole(ctx, t, adminDSN))
	if err != nil {
		t.Fatalf("newPgStore: %v", err)
	}
	defer ps.DB().Close()
	assertBackendConformance(t, ps, func(name string) string {
		return "/data/" + name + ".json"
	})
}

// usernames extracts the "username" field from a collection blob.
func usernames(t *testing.T, blob []byte) []string {
	t.Helper()
	var list []map[string]any
	if err := json.Unmarshal(blob, &list); err != nil {
		t.Fatalf("unmarshal collection %s: %v", blob, err)
	}
	out := make([]string, 0, len(list))
	for _, m := range list {
		s, _ := m["username"].(string)
		out = append(out, s)
	}
	return out
}

func equalSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	ac := append([]string(nil), a...)
	bc := append([]string(nil), b...)
	sort.Strings(ac)
	sort.Strings(bc)
	for i := range ac {
		if ac[i] != bc[i] {
			return false
		}
	}
	return true
}

func isEmptyJSONArray(b []byte) bool {
	var list []json.RawMessage
	return json.Unmarshal(b, &list) == nil && len(list) == 0
}

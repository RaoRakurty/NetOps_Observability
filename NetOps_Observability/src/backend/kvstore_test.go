package backend

import (
	"encoding/json"
	"netops/backend/internal/platformdb"
	"netops/backend/internal/users"
	"os"
	"testing"
)

// memKV is an in-memory platformdb.Backend standing in for Postgres in tests: it proves
// the stores are genuinely backend-pluggable (no file I/O) and that the
// os.ErrNotExist contract holds for a missing key, exactly as pgKV guarantees.
type memKV struct{ m map[string][]byte }

func newMemKV() *memKV { return &memKV{m: map[string][]byte{}} }

func (k *memKV) Load(key string) ([]byte, error) {
	b, ok := k.m[key]
	if !ok {
		return nil, os.ErrNotExist
	}
	return b, nil
}
func (k *memKV) Save(key string, data []byte) error {
	k.m[key] = append([]byte(nil), data...)
	return nil
}

// withBackend swaps the process-wide backend for the duration of a test.
func withBackend(t *testing.T, b platformdb.Backend) {
	t.Helper()
	t.Cleanup(platformdb.SwapBackendForTest(b))
}

func TestFileKVMissingKeyIsNotExist(t *testing.T) {
	_, err := platformdb.FileKV{}.Load(t.TempDir() + "/does-not-exist.json")
	if !os.IsNotExist(err) {
		t.Errorf("missing file should report os.ErrNotExist, got %v", err)
	}
}

func TestSavedStoreRoundTripsThroughBackend(t *testing.T) {
	mem := newMemKV()
	withBackend(t, mem)

	// Create an object — it must land in the (non-file) backend, not on disk.
	s1, err := newSavedStore("kv://saved")
	if err != nil {
		t.Fatalf("newSavedStore: %v", err)
	}
	obj, err := s1.Create("saved_search", "my search", "alice", "acme", json.RawMessage(`{"q":"*"}`))
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if len(mem.m["kv://saved"]) == 0 {
		t.Fatal("expected the saved object to be written through the backend")
	}

	// A fresh store over the SAME key reloads it through the backend — this is
	// the "swap to Postgres with no API change" guarantee in miniature.
	s2, err := newSavedStore("kv://saved")
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	got, ok := s2.Get(obj.ID)
	if !ok {
		t.Fatal("reloaded store should see the object persisted via the backend")
	}
	if got.Name != "my search" || got.TenantID != "acme" {
		t.Errorf("round-tripped object mismatch: %+v", got)
	}
}

func TestUserStoreRoundTripsThroughBackend(t *testing.T) {
	withBackend(t, newMemKV())
	us, err := users.NewFileStore("kv://users", userDeps())
	if err != nil {
		t.Fatalf("newUserStore: %v", err)
	}
	if _, err := us.CreateFull(User{Username: "bob", Role: RoleReadOnly}, "hunter2hunter2"); err != nil {
		t.Fatalf("CreateFull: %v", err)
	}
	// Reload through the same in-memory backend.
	us2, err := users.NewFileStore("kv://users", userDeps())
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if _, ok := us2.Get("bob"); !ok {
		t.Error("reloaded user store should see bob via the backend")
	}
}

package snmpcred

import (
	"os"
	"path/filepath"
	"testing"
)

// fileKV is a plain file backend for tests.
type fileKV struct{}

func (fileKV) Load(key string) ([]byte, error)    { return os.ReadFile(key) }
func (fileKV) Save(key string, data []byte) error { return os.WriteFile(key, data, 0o600) }

func TestSNMPCredV2cAndRedaction(t *testing.T) {
	cs, err := NewStore(filepath.Join(t.TempDir(), "snmp.json"), nil, fileKV{})
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	pub, err := cs.Upsert(Credential{Name: "Core Switches", Version: "v2c", Community: "s3cr3t"})
	if err != nil {
		t.Fatalf("Upsert v2c: %v", err)
	}
	if pub.ID != "core-switches" || !pub.HasCommunity || pub.Port != 161 {
		t.Errorf("unexpected public cred: %+v", pub)
	}
	// List must never leak the secret.
	for _, c := range cs.List() {
		// Public has no Community field at all — compile-time proof.
		if !c.HasCommunity {
			t.Error("expected has_community true")
		}
	}
	// Resolve (poller path) returns the real secret.
	full, ok := cs.Resolve("core-switches")
	if !ok || full.Community != "s3cr3t" {
		t.Errorf("Resolve secret wrong: %+v ok=%v", full, ok)
	}
	// Resolve by name (case-insensitive) too.
	if _, ok := cs.Resolve("CORE SWITCHES"); !ok {
		t.Error("Resolve by name should work")
	}
}

func TestSNMPCredV3Validation(t *testing.T) {
	cs, _ := NewStore(filepath.Join(t.TempDir(), "snmp.json"), nil, fileKV{})
	// authPriv requires auth + priv protocols and keys.
	if _, err := cs.Upsert(Credential{Name: "v3bad", Version: "v3", SecurityName: "noc", SecurityLevel: "authPriv"}); err == nil {
		t.Error("expected validation error for authPriv without keys")
	}
	good := Credential{
		Name: "v3 good", Version: "v3", SecurityName: "noc", SecurityLevel: "authPriv",
		AuthProtocol: "SHA256", AuthKey: "authpass123", PrivProtocol: "AES256", PrivKey: "privpass123",
	}
	pub, err := cs.Upsert(good)
	if err != nil {
		t.Fatalf("Upsert v3: %v", err)
	}
	if !pub.HasAuthKey || !pub.HasPrivKey || pub.AuthProtocol != "SHA256" {
		t.Errorf("v3 public cred wrong: %+v", pub)
	}
	// Bad enum is rejected.
	if _, err := cs.Upsert(Credential{Name: "x", Version: "v9", Community: "c"}); err == nil {
		t.Error("expected invalid version to fail")
	}
}

func TestSNMPCredUpdatePreservesSecrets(t *testing.T) {
	cs, _ := NewStore(filepath.Join(t.TempDir(), "snmp.json"), nil, fileKV{})
	cs.Upsert(Credential{Name: "grp", Version: "v2c", Community: "orig"})
	// Update without re-sending the community keeps the stored one.
	if _, err := cs.Upsert(Credential{ID: "grp", Name: "grp", Version: "v2c", Retries: 3}); err != nil {
		t.Fatalf("update: %v", err)
	}
	full, _ := cs.Resolve("grp")
	if full.Community != "orig" {
		t.Errorf("secret not preserved on update: %q", full.Community)
	}
	if full.Retries != 3 {
		t.Errorf("retries not updated: %d", full.Retries)
	}
}

// TestSNMPCredDeleteBlocksResolve is the cache-invalidation guarantee for the
// poller path: a deleted credential must stop resolving immediately (write-
// through, no stale window).
func TestSNMPCredDeleteBlocksResolve(t *testing.T) {
	cs, _ := NewStore(filepath.Join(t.TempDir(), "snmp.json"), nil, fileKV{})
	if _, err := cs.Upsert(Credential{Name: "edge", Version: "v2c", Community: "c1"}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	if _, ok := cs.Resolve("edge"); !ok {
		t.Fatalf("Resolve should succeed before delete")
	}
	if err := cs.Delete("edge"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, ok := cs.Resolve("edge"); ok {
		t.Fatalf("Resolve must fail immediately after delete (cache-invalidation gap)")
	}
}

// TestSNMPCredRotationTakesEffect verifies a rotated secret is what the poller
// resolves next — the new community fully replaces the old one in the cache.
func TestSNMPCredRotationTakesEffect(t *testing.T) {
	cs, _ := NewStore(filepath.Join(t.TempDir(), "snmp.json"), nil, fileKV{})
	cs.Upsert(Credential{Name: "rot", Version: "v2c", Community: "old-secret"})
	if c, _ := cs.Resolve("rot"); c.Community != "old-secret" {
		t.Fatalf("pre-rotation community = %q", c.Community)
	}
	// Rotate: same id, new community.
	if _, err := cs.Upsert(Credential{ID: "rot", Name: "rot", Version: "v2c", Community: "new-secret"}); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if c, _ := cs.Resolve("rot"); c.Community != "new-secret" {
		t.Fatalf("rotation did not take effect: Resolve community = %q", c.Community)
	}
}

// TestSNMPCredReloadPropagatesChange simulates two replicas sharing one backend:
// a credential deleted on instance A stops resolving on instance B after B
// reloads (multi-instance convergence).
func TestSNMPCredReloadPropagatesChange(t *testing.T) {
	path := filepath.Join(t.TempDir(), "shared-snmp.json")
	a, err := NewStore(path, nil, fileKV{})
	if err != nil {
		t.Fatalf("instance A: %v", err)
	}
	a.Upsert(Credential{Name: "shared", Version: "v2c", Community: "live"})
	b, err := NewStore(path, nil, fileKV{})
	if err != nil {
		t.Fatalf("instance B: %v", err)
	}
	if _, ok := b.Resolve("shared"); !ok {
		t.Fatalf("B should resolve the credential it loaded")
	}
	if err := a.Delete("shared"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	// B is stale until it reloads.
	if _, ok := b.Resolve("shared"); !ok {
		t.Fatalf("precondition: B's cache should still be stale before reload")
	}
	if err := b.Reload(); err != nil {
		t.Fatalf("reload: %v", err)
	}
	if _, ok := b.Resolve("shared"); ok {
		t.Fatalf("after reload, B must not resolve the deleted credential")
	}
}

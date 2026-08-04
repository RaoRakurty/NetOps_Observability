package backend

// vault_testdeps_test.go — an active vault for package-main tests.
//
// The custody implementation moved to internal/vault, which exports the
// SealingProvider interface and the Store/Warnf seams. Package main therefore
// supplies its own in-memory provider and store rather than importing test
// helpers across a package boundary (test helpers are not API).
//
// The duplication is small and deliberate: what these tests need is "a vault
// that is ACTIVE", so encryption paths are exercised rather than the dormant
// passthrough. internal/vault's own tests cover the custody mechanics.

import (
	"context"
	"os"
	"sync"
	"testing"

	"netops/backend/internal/vault"
)

type memSealing struct{ kek []byte }

func (m *memSealing) Unseal(context.Context) ([]byte, error) {
	if len(m.kek) == 0 {
		// The explicit first-run sentinel: any OTHER error now refuses
		// activation instead of minting a new KEK (the 2026-08-04 fix).
		return nil, vault.ErrNoKEK
	}
	return m.kek, nil
}
func (m *memSealing) Seal(_ context.Context, kek []byte) error { m.kek = kek; return nil }

type memVaultStore struct {
	mu   sync.Mutex
	data map[string][]byte
}

func (m *memVaultStore) Load(key string) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	b, ok := m.data[key]
	if !ok {
		// os.ErrNotExist-shaped: the vault reads that specific sentinel as
		// "first run", and anything else as a corrupt store.
		return nil, os.ErrNotExist
	}
	return b, nil
}

func (m *memVaultStore) Save(key string, b []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.data[key] = append([]byte(nil), b...)
	return nil
}

// newTestVault returns an ACTIVE vault backed by in-memory custody and storage.
func newTestVault(t *testing.T) *vault.Vault {
	t.Helper()
	v, err := vault.NewWithProvider(context.Background(), &memSealing{},
		&memVaultStore{data: map[string][]byte{}}, func(string, string, map[string]any) {})
	if err != nil {
		t.Fatalf("test vault: %v", err)
	}
	return v
}

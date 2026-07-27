package main

import (
	"context"
	"netops/backend/internal/vault"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestSNMPCredsEncryptedAtRest proves that with an active Vault the SNMP secret
// fields are ciphertext on disk (not the plaintext community/keys), yet Resolve
// still returns the plaintext in memory and a reopened store decrypts them back.
func TestSNMPCredsEncryptedAtRest(t *testing.T) {
	v, err := vault.NewWithProvider(context.Background(), &memSealing{}, &memVaultStore{data: map[string][]byte{}}, func(string, string, map[string]any) {})
	if err != nil {
		t.Fatalf("vault: %v", err)
	}
	path := filepath.Join(t.TempDir(), "snmp.json")

	cs, err := newSNMPCredStore(path, v)
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	if _, err := cs.Upsert(SNMPCredential{
		Name: "core-v3", TenantID: "acme", Version: "v3",
		SecurityName: "noc", SecurityLevel: "authPriv",
		AuthProtocol: "SHA", AuthKey: "auth-secret-123",
		PrivProtocol: "AES128", PrivKey: "priv-secret-456",
	}); err != nil {
		t.Fatalf("upsert: %v", err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read file: %v", err)
	}
	if strings.Contains(string(raw), "auth-secret-123") || strings.Contains(string(raw), "priv-secret-456") {
		t.Fatalf("secret stored in plaintext on disk:\n%s", raw)
	}
	if !strings.Contains(string(raw), vault.VersionPrefix) {
		t.Fatal("expected versioned ciphertext on disk")
	}

	// Reopen with the same Vault → secrets decrypt back for the poller (Resolve).
	cs2, err := newSNMPCredStore(path, v)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	got, ok := cs2.Resolve("core-v3")
	if !ok {
		t.Fatal("resolve: not found")
	}
	if got.AuthKey != "auth-secret-123" || got.PrivKey != "priv-secret-456" {
		t.Fatalf("decrypt round-trip mismatch: auth=%q priv=%q", got.AuthKey, got.PrivKey)
	}
}

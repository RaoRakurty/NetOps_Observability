package main

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

// SR-027: tampering with the wrapped-DEK store (here, deleting a tenant's entry
// while keeping the old MAC) must be DETECTED on load — fail closed rather than
// silently minting a fresh DEK that orphans existing ciphertext.
func TestVaultWrappedStoreIntegrity(t *testing.T) {
	withTempKV(t)
	prov := &memSealing{}
	v1, err := newVaultWithProvider(context.Background(), prov)
	if err != nil {
		t.Fatalf("vault: %v", err)
	}
	if _, err := v1.Encrypt("acme", "f1", "secret"); err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	// Tamper: drop the tenant entry but leave the MAC (covering the original map).
	raw, err := kvLoad(wrappedKeysKey)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	var s wrappedStore
	if err := json.Unmarshal(raw, &s); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	delete(s.Keys, "acme")
	b, _ := json.Marshal(s)
	if err := kvSave(wrappedKeysKey, b); err != nil {
		t.Fatalf("save: %v", err)
	}
	if _, err := newVaultWithProvider(context.Background(), prov); err == nil {
		t.Fatal("tampered wrapped-DEK store must fail the integrity check")
	}
}

// memSealing is an in-memory SealingProvider for unit tests — it holds the KEK in
// a field instead of a TPM, so the Vault's envelope logic is exercised without
// swtpm. (The real swtpm path is gated behind SEAL_SWTPM_TEST, like DATABASE_URL_TEST.)
type memSealing struct{ kek []byte }

func (m *memSealing) Unseal(context.Context) ([]byte, error) {
	if len(m.kek) == 0 {
		return nil, errNoKEK
	}
	return m.kek, nil
}
func (m *memSealing) Seal(_ context.Context, kek []byte) error { m.kek = kek; return nil }

var errNoKEK = errTest("no-kek")

type errTest string

func (e errTest) Error() string { return string(e) }

func newTestVault(t *testing.T) *Vault {
	t.Helper()
	withTempKV(t)
	v, err := newVaultWithProvider(context.Background(), &memSealing{})
	if err != nil {
		t.Fatalf("newVaultWithProvider: %v", err)
	}
	return v
}

// withTempKV isolates the wrapped-keys blob to a temp file (fileKV treats the kv
// key as a path) so wrapped DEKs don't leak across tests or into the repo.
func withTempKV(t *testing.T) {
	t.Helper()
	backend = fileKV{}
	prev := wrappedKeysKey
	wrappedKeysKey = t.TempDir() + "/wrapped.json"
	t.Cleanup(func() { wrappedKeysKey = prev })
}

func TestVaultRoundTrip(t *testing.T) {
	v := newTestVault(t)
	ct, err := v.Encrypt("acme", "snmp.community", "public123")
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if !strings.HasPrefix(ct, secretVersionPrefix) {
		t.Fatalf("ciphertext not versioned: %q", ct)
	}
	if ct == "public123" {
		t.Fatal("ciphertext equals plaintext — not encrypted")
	}
	pt, err := v.Decrypt("acme", "snmp.community", ct)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if pt != "public123" {
		t.Fatalf("round-trip mismatch: got %q", pt)
	}
}

func TestVaultAADBindsTenantAndField(t *testing.T) {
	v := newTestVault(t)
	ct, err := v.Encrypt("acme", "snmp.community", "secret")
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	// Same ciphertext, wrong tenant → must fail (AAD + different DEK).
	if _, err := v.Decrypt("globex", "snmp.community", ct); err == nil {
		t.Fatal("cross-tenant decrypt must fail")
	}
	// Same tenant, wrong field → AAD mismatch must fail.
	if _, err := v.Decrypt("acme", "smtp.password", ct); err == nil {
		t.Fatal("cross-field decrypt must fail")
	}
}

func TestVaultDormantPassthrough(t *testing.T) {
	backend = fileKV{}
	withTempKV(t)
	v := &Vault{deks: map[string][]byte{}, wrapped: map[string]string{}} // no provider → dormant
	ct, err := v.Encrypt("acme", "f", "plain")
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if ct != "plain" {
		t.Fatalf("dormant Encrypt must pass through, got %q", ct)
	}
	// Dormant Decrypt accepts legacy plaintext unchanged.
	if pt, _ := v.Decrypt("acme", "f", "legacy-plain"); pt != "legacy-plain" {
		t.Fatalf("dormant Decrypt passthrough failed: %q", pt)
	}
}

func TestVaultDecryptPlaintextPassthroughWhenActive(t *testing.T) {
	v := newTestVault(t)
	// A value that predates encryption (no v1: prefix) is returned as-is even
	// when custody is active — this is what makes encrypt-on-next-write safe.
	if pt, err := v.Decrypt("acme", "f", "still-plain"); err != nil || pt != "still-plain" {
		t.Fatalf("active Decrypt of legacy plaintext: pt=%q err=%v", pt, err)
	}
}

func TestVaultTamperedCiphertextFails(t *testing.T) {
	v := newTestVault(t)
	ct, _ := v.Encrypt("acme", "f", "secret")
	// Flip a character in the base64 body.
	body := []byte(ct)
	if body[len(body)-2] == 'A' {
		body[len(body)-2] = 'B'
	} else {
		body[len(body)-2] = 'A'
	}
	if _, err := v.Decrypt("acme", "f", string(body)); err == nil {
		t.Fatal("tampered ciphertext must fail GCM auth")
	}
}

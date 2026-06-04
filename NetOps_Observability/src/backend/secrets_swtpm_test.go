package main

import (
	"context"
	"os"
	"testing"
)

// TestSwtpmSealUnseal exercises the real swtpm sidecar end-to-end. Gated like the
// DB tests: set SEAL_SWTPM_TEST=1 with the sidecar up (SEAL_SOCKET pointing at its
// socket). It seals a KEK and unseals it back, proving the socket protocol + the
// tpm2-tools seal/unseal round-trip. Skipped (and CI-safe) otherwise.
func TestSwtpmSealUnseal(t *testing.T) {
	if os.Getenv("SEAL_SWTPM_TEST") == "" {
		t.Skip("set SEAL_SWTPM_TEST=1 (with the secrets-seal sidecar up) to run")
	}
	p := newSwtpmSidecarProvider()
	ctx := context.Background()

	kek := make([]byte, kekLen)
	for i := range kek {
		kek[i] = byte(i + 1)
	}
	if err := p.Seal(ctx, kek); err != nil {
		t.Fatalf("seal: %v", err)
	}
	got, err := p.Unseal(ctx)
	if err != nil {
		t.Fatalf("unseal: %v", err)
	}
	if len(got) != kekLen {
		t.Fatalf("unsealed KEK wrong length: %d", len(got))
	}
	for i := range kek {
		if got[i] != kek[i] {
			t.Fatalf("unsealed KEK mismatch at %d", i)
		}
	}

	// A Vault built on the live provider must round-trip a secret too.
	v, err := newVaultWithProvider(ctx, p)
	if err != nil {
		t.Fatalf("vault: %v", err)
	}
	ct, err := v.Encrypt("acme", "snmp.community", "live-secret")
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if pt, err := v.Decrypt("acme", "snmp.community", ct); err != nil || pt != "live-secret" {
		t.Fatalf("round-trip: pt=%q err=%v", pt, err)
	}
}

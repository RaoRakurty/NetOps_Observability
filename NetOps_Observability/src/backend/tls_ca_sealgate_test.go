// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// tls_ca_sealgate_test.go — the internal CA must never mint its 10-year root
// key into plaintext storage.
//
// THE FOOT-GUN THIS PINS: tls_ca.go's own header states that with a dormant
// Vault "the CA key is stored plaintext (passthrough)". Enabling the mesh
// (TLS_INTERNAL_CA=true) without SEAL_PROVIDER therefore CREATES a long-lived
// credential that can mint an identity for every service — and leaves it in the
// clear. That is strictly worse than leaving TLS off, so boot must fail closed,
// in the same shape as ensureSigningSecret (SR-017).
//
// The security design (docs/security/CORRELIX_CLOUD_NATIVE_SECURITY_HLD.md,
// correction C2/E2) records this as a hard PHASE DEPENDENCY: nginx→API mTLS
// cannot precede the seal gate, because enabling that hop enables this CA.

import (
	"context"
	"os"
	"strings"
	"testing"

	"netops/backend/internal/vault"
)

func TestInternalCARefusesToBootUnsealed(t *testing.T) {
	t.Setenv("TLS_INTERNAL_CA", "true")
	t.Setenv("ALLOW_DEV_SECRETS", "")

	// A dormant vault is exactly what an operator gets when SEAL_PROVIDER is
	// unset — the default in the shipped .env.
	_, err := bootstrapInternalCA(vault.Dormant())
	if err == nil {
		t.Fatal("bootstrapInternalCA succeeded with an unsealed vault — it must refuse rather than write a plaintext CA root key")
	}
	// The error must name the control and the remediation (production-validator
	// contract: exact control, observed state, required value, how to fix).
	for _, want := range []string{"TLS_INTERNAL_CA", "sealing provider", "SEAL_PROVIDER", "ALLOW_DEV_SECRETS"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal message must mention %q so the operator can act on it; got: %v", want, err)
		}
	}
}

func TestInternalCAAllowsUnsealedOnlyWithExplicitDevOptIn(t *testing.T) {
	dir := t.TempDir()
	// Redirect CA material to temp kv paths (the file backend treats a kv key as
	// a path), so the test never touches real custody state.
	origCert, origKey := kvCACertKey, kvCAKeyKey
	kvCACertKey = dir + "/ca.pem"
	kvCAKeyKey = dir + "/ca.key.enc"
	t.Cleanup(func() { kvCACertKey, kvCAKeyKey = origCert, origKey })

	t.Setenv("TLS_INTERNAL_CA", "true")
	t.Setenv("ALLOW_DEV_SECRETS", "true")
	// No TLS_*_FILE vars → provisionFromEnv writes nothing; we are asserting the
	// GATE, not issuance.
	for _, k := range []string{"TLS_CLIENT_CA_FILE", "TLS_CERT_FILE", "TLS_KEY_FILE", "TLS_NGINX_CERT_DIR"} {
		t.Setenv(k, "")
	}

	m, err := bootstrapInternalCA(vault.Dormant())
	if err != nil {
		t.Fatalf("explicit dev opt-in must be honoured (lab profile): %v", err)
	}
	if m == nil {
		t.Fatal("expected a CA manager under the dev opt-in")
	}
}

func TestInternalCAStaysDormantWhenNotEnabled(t *testing.T) {
	t.Setenv("TLS_INTERNAL_CA", "")
	t.Setenv("ALLOW_DEV_SECRETS", "")
	m, err := bootstrapInternalCA(vault.Dormant())
	if err != nil || m != nil {
		t.Fatalf("with TLS_INTERNAL_CA unset the CA must stay dormant and must NOT fail boot; got m=%v err=%v", m, err)
	}
}

// A sealed vault is the production path: the gate must let it through.
func TestInternalCAAcceptsSealedVault(t *testing.T) {
	if os.Getenv("SKIP_SEALED_VAULT_TEST") == "true" {
		t.Skip("explicitly skipped")
	}
	dir := t.TempDir()
	origCert, origKey := kvCACertKey, kvCAKeyKey
	kvCACertKey = dir + "/ca.pem"
	kvCAKeyKey = dir + "/ca.key.enc"
	t.Cleanup(func() { kvCACertKey, kvCAKeyKey = origCert, origKey })

	t.Setenv("TLS_INTERNAL_CA", "true")
	t.Setenv("ALLOW_DEV_SECRETS", "")
	for _, k := range []string{"TLS_CLIENT_CA_FILE", "TLS_CERT_FILE", "TLS_KEY_FILE", "TLS_NGINX_CERT_DIR"} {
		t.Setenv(k, "")
	}

	sealed, err := vault.NewWithProvider(context.Background(), sealGateTestProvider{},
		sealGateTestStore{m: map[string][]byte{}}, func(string, string, map[string]any) {})
	if err != nil {
		t.Fatalf("build sealed vault: %v", err)
	}
	m, err := bootstrapInternalCA(sealed)
	if err != nil {
		t.Fatalf("a sealed vault must pass the gate: %v", err)
	}
	if m == nil {
		t.Fatal("expected a CA manager with a sealed vault")
	}
}

// Minimal in-memory custody root: a real SealingProvider so the gate sees a
// SEALED vault, without dragging in swtpm.
type sealGateTestProvider struct{}

func (sealGateTestProvider) Unseal(context.Context) ([]byte, error) {
	// First-run sentinel: the vault generates + seals a fresh KEK. Returning
	// (nil, nil) would now be refused as a wrong-length KEK (2026-08-04 fix).
	return nil, vault.ErrNoKEK
}
func (sealGateTestProvider) Seal(context.Context, []byte) error { return nil }

type sealGateTestStore struct{ m map[string][]byte }

func (s sealGateTestStore) Load(k string) ([]byte, error) { return s.m[k], nil }
func (s sealGateTestStore) Save(k string, b []byte) error { s.m[k] = b; return nil }

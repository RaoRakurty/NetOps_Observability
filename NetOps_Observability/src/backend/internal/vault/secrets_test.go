package vault

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// SR-027: tampering with the wrapped-DEK store (here, deleting a tenant's entry
// while keeping the old MAC) must be DETECTED on load — fail closed rather than
// silently minting a fresh DEK that orphans existing ciphertext.
func TestVaultWrappedStoreIntegrity(t *testing.T) {
	prov := &memSealing{}
	st, wn := newMemStore(), discardWarn
	v1, err := NewWithProvider(context.Background(), prov, st, wn)
	if err != nil {
		t.Fatalf("vault: %v", err)
	}
	if _, err := v1.Encrypt("acme", "f1", "secret"); err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	// Tamper: drop the tenant entry but leave the MAC (covering the original map).
	raw, err := st.Load(wrappedKeysKey)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	var s wrappedStore
	if err := json.Unmarshal(raw, &s); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	delete(s.Keys, "acme")
	b, _ := json.Marshal(s)
	if err := st.Save(wrappedKeysKey, b); err != nil {
		t.Fatalf("save: %v", err)
	}
	// same store: the point is that the SECOND construction reads the
	// tampered bytes the first one wrote.
	if _, err := NewWithProvider(context.Background(), prov, st, wn); err == nil {
		t.Fatal("tampered wrapped-DEK store must fail the integrity check")
	}
}

// memSealing is an in-memory SealingProvider for unit tests — it holds the KEK in
// a field instead of a TPM, so the Vault's envelope logic is exercised without
// swtpm. (The real swtpm path is gated behind SEAL_SWTPM_TEST, like DATABASE_URL_TEST.)
type memSealing struct{ kek []byte }

func (m *memSealing) Unseal(context.Context) ([]byte, error) {
	if len(m.kek) == 0 {
		return nil, ErrNoKEK // the one signal that permits first-run generation
	}
	return m.kek, nil
}
func (m *memSealing) Seal(_ context.Context, kek []byte) error { m.kek = kek; return nil }

func newTestVault(t *testing.T) *Vault {
	t.Helper()
	st, wn := testDeps()
	v, err := NewWithProvider(context.Background(), &memSealing{}, st, wn)
	if err != nil {
		t.Fatalf("NewWithProvider: %v", err)
	}
	return v
}

func TestVaultRoundTrip(t *testing.T) {
	v := newTestVault(t)
	ct, err := v.Encrypt("acme", "snmp.community", "public123")
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if !strings.HasPrefix(ct, VersionPrefix) {
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
	v := &Vault{store: newMemStore(), warn: discardWarn, deks: map[string][]byte{}, wrapped: map[string]string{}} // no provider → dormant
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

	// VAULT_STRICT=true closes that door: once every value has migrated, a
	// non-"v1:" value under active custody can only be an injected/downgraded
	// one, and passing it through would bypass the AAD binding entirely.
	t.Setenv("VAULT_STRICT", "true")
	sv := newTestVault(t)
	if _, err := sv.Decrypt("acme", "f", "still-plain"); err == nil {
		t.Fatal("VAULT_STRICT=true must refuse plaintext passthrough while custody is active")
	}
	// An unset field ("") is not a downgrade — it stays passthrough.
	if pt, err := sv.Decrypt("acme", "f", ""); err != nil || pt != "" {
		t.Fatalf("strict mode must still pass an empty (unset) value: pt=%q err=%v", pt, err)
	}
	// Real ciphertext still round-trips in strict mode.
	ct, err := sv.Encrypt("acme", "f", "sealed")
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if pt, err := sv.Decrypt("acme", "f", ct); err != nil || pt != "sealed" {
		t.Fatalf("strict round-trip: pt=%q err=%v", pt, err)
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

// brokenSealing simulates a provider whose sealed KEK exists but is unreadable
// (sidecar down, stale TPM context, corrupt state). It records Seal calls: the
// Vault must NEVER seal a fresh KEK over one it merely failed to read.
type brokenSealing struct {
	unsealErr error
	kek       []byte // returned when unsealErr is nil (may be wrong length)
	sealCalls int
}

func (b *brokenSealing) Unseal(context.Context) ([]byte, error) {
	if b.unsealErr != nil {
		return nil, b.unsealErr
	}
	return b.kek, nil
}
func (b *brokenSealing) Seal(context.Context, []byte) error { b.sealCalls++; return nil }

// TestVaultUnsealFailureDoesNotMintNewKEK pins the 2026-08-04 near-miss: a
// stale swtpm primary context made unseal fail with a load error, activation
// treated it as first-run, and only the seal ALSO failing kept the real KEK
// from being overwritten (which would have orphaned every sealed secret).
// Any unseal failure other than ErrNoKEK must abort activation with no Seal.
func TestVaultUnsealFailureDoesNotMintNewKEK(t *testing.T) {
	st, wn := testDeps()
	p := &brokenSealing{unsealErr: errors.New("swtpm unseal: ERR load")}
	if _, err := NewWithProvider(context.Background(), p, st, wn); err == nil {
		t.Fatal("activation must fail when unseal fails for any reason other than ErrNoKEK")
	}
	if p.sealCalls != 0 {
		t.Fatalf("Seal was called %d times after a non-first-run unseal failure — this overwrites the real KEK and orphans every sealed secret", p.sealCalls)
	}
}

// TestVaultWrongLengthKEKRefusesActivation: a KEK of the wrong length is
// corruption, not first-run — activation must abort without sealing.
func TestVaultWrongLengthKEKRefusesActivation(t *testing.T) {
	st, wn := testDeps()
	p := &brokenSealing{kek: []byte("short")}
	if _, err := NewWithProvider(context.Background(), p, st, wn); err == nil {
		t.Fatal("activation must fail on a wrong-length KEK")
	}
	if p.sealCalls != 0 {
		t.Fatalf("Seal was called %d times on a wrong-length KEK — refusing to overwrite is the whole point", p.sealCalls)
	}
}

// TestVaultFirstRunSealsExactlyOnce: the explicit ErrNoKEK signal (and only
// it) generates a fresh KEK, seals it once, and activates.
func TestVaultFirstRunSealsExactlyOnce(t *testing.T) {
	st, wn := testDeps()
	m := &memSealing{}
	v, err := NewWithProvider(context.Background(), m, st, wn)
	if err != nil {
		t.Fatalf("first-run activation: %v", err)
	}
	if len(m.kek) != kekLen {
		t.Fatalf("first run sealed a KEK of length %d, want %d", len(m.kek), kekLen)
	}
	// The sealed KEK must be the one in use: a second activation over the same
	// provider + store must decrypt what the first encrypted.
	ct, err := v.Encrypt("acme", "f", "sealed-secret")
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	v2, err := NewWithProvider(context.Background(), m, st, wn)
	if err != nil {
		t.Fatalf("re-activation: %v", err)
	}
	if pt, err := v2.Decrypt("acme", "f", ct); err != nil || pt != "sealed-secret" {
		t.Fatalf("round-trip across activations: pt=%q err=%v", pt, err)
	}
}

// TestVaultRefusesMacLessDowngrade pins the SR-027 downgrade fix: a wrapped-DEK
// store presented WITHOUT its integrity MAC (an attacker who lacks the KEK
// cannot forge one, so they strip it to a plain map) must be REFUSED by default,
// not silently accepted as "legacy". A genuine one-time upgrade migrates it
// under the explicit opt-in and re-persists the MAC'd format.
func TestVaultRefusesMacLessDowngrade(t *testing.T) {
	prov := &memSealing{}
	st, wn := newMemStore(), discardWarn
	v1, err := NewWithProvider(context.Background(), prov, st, wn)
	if err != nil {
		t.Fatalf("vault: %v", err)
	}
	if _, err := v1.Encrypt("acme", "f1", "secret"); err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	// Downgrade: rewrite the store as a bare plain map (no "mac" field) — exactly
	// what a tamperer without the KEK can produce.
	raw, err := st.Load(wrappedKeysKey)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	var s wrappedStore
	if err := json.Unmarshal(raw, &s); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	plain, _ := json.Marshal(s.Keys) // just the map, no MAC → s.Keys==nil on reload
	if err := st.Save(wrappedKeysKey, plain); err != nil {
		t.Fatalf("save: %v", err)
	}

	// Default: refuse.
	if _, err := NewWithProvider(context.Background(), prov, st, wn); err == nil {
		t.Fatal("a MAC-less (downgraded) wrapped store must be REFUSED by default")
	}

	// Opt-in migration: accept once, and the store is re-persisted WITH a MAC.
	t.Setenv("VAULT_MIGRATE_LEGACY_WRAPPED", "true")
	if _, err := NewWithProvider(context.Background(), prov, st, wn); err != nil {
		t.Fatalf("migration opt-in should accept the legacy store: %v", err)
	}
	migrated, err := st.Load(wrappedKeysKey)
	if err != nil {
		t.Fatalf("load migrated: %v", err)
	}
	if !strings.Contains(string(migrated), `"mac"`) {
		t.Fatal("eager migration must re-persist the store in the MAC'd format")
	}
	// After migration, it loads cleanly even WITHOUT the opt-in (it is MAC'd now).
	t.Setenv("VAULT_MIGRATE_LEGACY_WRAPPED", "")
	if _, err := NewWithProvider(context.Background(), prov, st, wn); err != nil {
		t.Fatalf("migrated MAC'd store must load without the opt-in: %v", err)
	}
}

// TestVaultRefusesWipedWrappedStore (M16): once a KEK exists, an absent or
// zero-length wrapped-DEK store is a WIPE, not a first run. The old code
// treated both shapes as "no keys yet" and silently minted fresh DEKs on the
// next Encrypt — turning a store truncation into a permanent, authenticated
// re-key that orphans every existing ciphertext. Boot must refuse instead,
// with an explicit one-boot override for the one legitimate shape.
func TestVaultRefusesWipedWrappedStore(t *testing.T) {
	prov := &memSealing{}
	st, wn := newMemStore(), discardWarn
	v1, err := NewWithProvider(context.Background(), prov, st, wn)
	if err != nil {
		t.Fatalf("vault: %v", err)
	}
	if _, err := v1.Encrypt("acme", "f1", "secret"); err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	// Wipe shape 1: the store DELETED while the sealed KEK still exists.
	st.mu.Lock()
	delete(st.data, wrappedKeysKey)
	st.mu.Unlock()
	if _, err := NewWithProvider(context.Background(), prov, st, wn); err == nil {
		t.Fatal("a deleted wrapped store under an EXISTING KEK must refuse boot, not silently re-key")
	}

	// Wipe shape 2: TRUNCATED to zero bytes.
	if err := st.Save(wrappedKeysKey, nil); err != nil {
		t.Fatalf("save: %v", err)
	}
	if _, err := NewWithProvider(context.Background(), prov, st, wn); err == nil {
		t.Fatal("a truncated (empty) wrapped store under an EXISTING KEK must refuse boot")
	}

	// The explicit one-boot override accepts — and warns loudly.
	t.Setenv("VAULT_ALLOW_EMPTY_STORE", "true")
	var warned bool
	warnRec := func(_, msg string, _ map[string]any) {
		if strings.Contains(msg, "VAULT_ALLOW_EMPTY_STORE") {
			warned = true
		}
	}
	if _, err := NewWithProvider(context.Background(), prov, st, warnRec); err != nil {
		t.Fatalf("VAULT_ALLOW_EMPTY_STORE=true must permit the one-boot recovery: %v", err)
	}
	if !warned {
		t.Fatal("accepting an empty custody store under an existing KEK must be WARNED, never silent")
	}
}

// TestVaultFirstRunPersistsEmptyCustodyStore (M16): a genuine first run
// (ErrNoKEK) writes an empty-but-MAC'd custody store immediately, so "custody
// active but store absent" never becomes a legitimate steady state — which is
// what lets every later boot treat absence as a wipe.
func TestVaultFirstRunPersistsEmptyCustodyStore(t *testing.T) {
	prov := &memSealing{}
	st, wn := newMemStore(), discardWarn
	if _, err := NewWithProvider(context.Background(), prov, st, wn); err != nil {
		t.Fatalf("first-run activation: %v", err)
	}
	raw, err := st.Load(wrappedKeysKey)
	if err != nil {
		t.Fatalf("first run must persist the (empty) custody store: %v", err)
	}
	if !strings.Contains(string(raw), `"mac"`) {
		t.Fatalf("first-run custody store is not MAC'd: %s", raw)
	}
	// A second boot over that store (KEK exists, store present) loads cleanly
	// without any override.
	if _, err := NewWithProvider(context.Background(), prov, st, wn); err != nil {
		t.Fatalf("re-activation over the persisted empty store: %v", err)
	}
}

// TestVaultMigrateFlagWarnsEveryBoot (M16): while VAULT_MIGRATE_LEGACY_WRAPPED
// stands, a MAC-less (tamper-indistinguishable) store would be accepted — so
// EVERY boot with the flag set must say so loudly, even over a healthy MAC'd
// store, or a "one boot" flag silently becomes a standing downgrade.
func TestVaultMigrateFlagWarnsEveryBoot(t *testing.T) {
	prov := &memSealing{}
	st, wn := newMemStore(), discardWarn
	v1, err := NewWithProvider(context.Background(), prov, st, wn)
	if err != nil {
		t.Fatalf("vault: %v", err)
	}
	if _, err := v1.Encrypt("acme", "f1", "secret"); err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	t.Setenv("VAULT_MIGRATE_LEGACY_WRAPPED", "true")
	var warned bool
	warnRec := func(_, msg string, _ map[string]any) {
		if strings.Contains(msg, "VAULT_MIGRATE_LEGACY_WRAPPED") {
			warned = true
		}
	}
	if _, err := NewWithProvider(context.Background(), prov, st, warnRec); err != nil {
		t.Fatalf("healthy MAC'd store must still load with the flag set: %v", err)
	}
	if !warned {
		t.Fatal("a boot with VAULT_MIGRATE_LEGACY_WRAPPED=true recorded no warning")
	}
}

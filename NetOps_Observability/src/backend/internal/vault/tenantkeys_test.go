// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package vault

// tenantkeys_test.go — versioned per-tenant key material.
//
// These pin the properties Sealed Fields depends on. The one that matters most
// is BACKWARD COMPATIBILITY: version 1 must remain byte-identical to the
// single-key scheme this replaced, because a store written before this code
// existed still has to unwrap. If that breaks, every reversible secret a
// deployment holds — SMTP, OIDC, LDAP, TACACS, SNMP — becomes unreadable.

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
)

func TestTenantKeyMaterialMintsVersionOne(t *testing.T) {
	v := newTestVault(t)
	m, version, err := v.TenantKeyMaterial("acme")
	if err != nil {
		t.Fatalf("material: %v", err)
	}
	if version != 1 {
		t.Fatalf("a fresh tenant must start at version 1, got %d", version)
	}
	if len(m) != dekLen {
		t.Fatalf("material must be %d bytes, got %d", dekLen, len(m))
	}
	// Stable across calls — a second call must not mint a second key, which
	// would orphan everything sealed under the first.
	again, _, err := v.TenantKeyMaterial("acme")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(m, again) {
		t.Fatal("a second read minted a different key — previously sealed values would be unrecoverable")
	}
}

// Version 1 MUST be the same key the pre-versioning scheme used, or existing
// custody stores stop opening. This is the compatibility contract.
func TestVersionOneIsTheLegacyKey(t *testing.T) {
	v := newTestVault(t)

	// Force the legacy path: Encrypt uses dek(tenant, true), the original code.
	ct, err := v.Encrypt("acme", "smtp.password", "hunter2")
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	legacy, err := v.dek("acme", false)
	if err != nil {
		t.Fatalf("legacy dek: %v", err)
	}
	versioned, version, err := v.TenantKeyMaterial("acme")
	if err != nil {
		t.Fatalf("versioned: %v", err)
	}
	if version != 1 {
		t.Fatalf("the legacy key must present as version 1, got %d", version)
	}
	if !bytes.Equal(legacy, versioned) {
		t.Fatal("version 1 is not the legacy DEK — every already-encrypted secret would fail to decrypt")
	}
	// And the secret still round-trips through the ordinary path.
	pt, err := v.Decrypt("acme", "smtp.password", ct)
	if err != nil || pt != "hunter2" {
		t.Fatalf("legacy secret no longer decrypts: %q %v", pt, err)
	}
}

func TestRotateAdvancesAndKeepsOldVersionsReadable(t *testing.T) {
	v := newTestVault(t)
	v1, _, err := v.TenantKeyMaterial("acme")
	if err != nil {
		t.Fatal(err)
	}

	next, err := v.RotateTenantKey("acme")
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if next != 2 {
		t.Fatalf("rotation must advance to 2, got %d", next)
	}

	active, version, err := v.TenantKeyMaterial("acme")
	if err != nil {
		t.Fatal(err)
	}
	if version != 2 {
		t.Fatalf("active version after rotation must be 2, got %d", version)
	}
	if bytes.Equal(active, v1) {
		t.Fatal("rotation produced the same key material — nothing rotated")
	}

	// The whole point: values sealed under v1 must still be openable.
	old, err := v.TenantKeyMaterialVersion("acme", 1)
	if err != nil {
		t.Fatalf("version 1 must remain readable after rotation: %v", err)
	}
	if !bytes.Equal(old, v1) {
		t.Fatal("version 1 material changed after rotation")
	}

	// Rotating again keeps climbing and keeps both predecessors.
	if third, err := v.RotateTenantKey("acme"); err != nil || third != 3 {
		t.Fatalf("second rotation: got %d %v", third, err)
	}
	for _, want := range []int{1, 2, 3} {
		if _, err := v.TenantKeyMaterialVersion("acme", want); err != nil {
			t.Errorf("version %d unreadable after two rotations: %v", want, err)
		}
	}
}

// Asking for a version that does not exist must FAIL, never mint. A minted
// replacement would decrypt nothing while looking like success.
func TestUnknownVersionFailsRatherThanMinting(t *testing.T) {
	v := newTestVault(t)
	if _, _, err := v.TenantKeyMaterial("acme"); err != nil {
		t.Fatal(err)
	}
	if _, err := v.TenantKeyMaterialVersion("acme", 7); err == nil {
		t.Fatal("a nonexistent version must not be minted on demand")
	}
	if _, err := v.TenantKeyMaterialVersion("acme", 0); err == nil {
		t.Fatal("version 0 is not a valid version")
	}
	if _, err := v.TenantKeyMaterialVersion("acme", MaxKeyVersion+1); err == nil {
		t.Fatal("versions beyond the bound must be refused")
	}
}

// Retiring a version (deleting its custody entry) must take effect: the value
// becomes unreadable rather than silently opening under a different key.
func TestRetiredVersionBecomesUnavailable(t *testing.T) {
	v := newTestVault(t)
	if _, _, err := v.TenantKeyMaterial("acme"); err != nil {
		t.Fatal(err)
	}
	if _, err := v.RotateTenantKey("acme"); err != nil {
		t.Fatal(err)
	}

	v.mu.Lock()
	delete(v.wrapped, dekVersionKey("acme", 1))
	delete(v.deks, dekVersionKey("acme", 1))
	v.mu.Unlock()

	if _, err := v.TenantKeyMaterialVersion("acme", 1); err == nil {
		t.Fatal("a retired key version must fail closed")
	}
}

func TestTenantKeysAreIsolated(t *testing.T) {
	v := newTestVault(t)
	a, _, err := v.TenantKeyMaterial("acme")
	if err != nil {
		t.Fatal(err)
	}
	b, _, err := v.TenantKeyMaterial("globex")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a, b) {
		t.Fatal("two tenants share key material — a compromise of one would expose the other")
	}
	// Rotating one tenant must not touch another's active version.
	if _, err := v.RotateTenantKey("acme"); err != nil {
		t.Fatal(err)
	}
	if _, version, err := v.TenantKeyMaterial("globex"); err != nil || version != 1 {
		t.Fatalf("rotating acme moved globex to version %d (%v)", version, err)
	}
}

// A wrapped key is bound to its tenant AND version, so a swapped custody entry
// fails to unwrap instead of silently cross-wiring keys.
func TestWrappedKeysAreBoundToTenantAndVersion(t *testing.T) {
	v := newTestVault(t)
	if _, _, err := v.TenantKeyMaterial("acme"); err != nil {
		t.Fatal(err)
	}
	if _, err := v.RotateTenantKey("acme"); err != nil {
		t.Fatal(err)
	}

	// Move v2's wrapped blob into v1's slot and drop the caches.
	v.mu.Lock()
	v.wrapped[dekVersionKey("acme", 1)] = v.wrapped[dekVersionKey("acme", 2)]
	delete(v.deks, dekVersionKey("acme", 1))
	v.mu.Unlock()

	if _, err := v.TenantKeyMaterialVersion("acme", 1); err == nil {
		t.Fatal("a v2 key presented as v1 must not unwrap — the AAD binds the version")
	}
}

// Custody not configured must be reported distinctly, so callers can tell
// "sealing is off" from "this tenant has no key".
func TestDormantVaultReportsCustodyUnavailable(t *testing.T) {
	st, wn := testDeps()
	v, err := New(context.Background(), st, wn) // SEAL_PROVIDER unset → dormant
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, _, err := v.TenantKeyMaterial("acme"); !errors.Is(err, ErrCustodyUnavailable) {
		t.Fatalf("want ErrCustodyUnavailable, got %v", err)
	}
	if _, err := v.TenantKeyMaterialVersion("acme", 1); !errors.Is(err, ErrCustodyUnavailable) {
		t.Fatalf("want ErrCustodyUnavailable, got %v", err)
	}
	if _, err := v.RotateTenantKey("acme"); !errors.Is(err, ErrCustodyUnavailable) {
		t.Fatalf("want ErrCustodyUnavailable, got %v", err)
	}
}

// Keys must survive a restart: the persisted custody store is the source of
// truth, not the in-memory cache.
func TestVersionsSurviveAReload(t *testing.T) {
	st, wn := testDeps()
	// The SAME sealing provider across both vaults: the custody store's
	// integrity MAC is keyed by the root KEK, so a different root is a
	// different (and correctly rejected) store, not a restart.
	provider := &memSealing{}
	v, err := NewWithProvider(context.Background(), provider, st, wn)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := v.TenantKeyMaterial("acme"); err != nil {
		t.Fatal(err)
	}
	if _, err := v.RotateTenantKey("acme"); err != nil {
		t.Fatal(err)
	}
	want1, err := v.TenantKeyMaterialVersion("acme", 1)
	if err != nil {
		t.Fatal(err)
	}
	want2, err := v.TenantKeyMaterialVersion("acme", 2)
	if err != nil {
		t.Fatal(err)
	}

	// Same store, same sealed KEK → a fresh Vault must resolve identical keys.
	reloaded, err := NewWithProvider(context.Background(), provider, st, wn)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	got1, err := reloaded.TenantKeyMaterialVersion("acme", 1)
	if err != nil {
		t.Fatalf("v1 after reload: %v", err)
	}
	got2, version, err := reloaded.TenantKeyMaterial("acme")
	if err != nil {
		t.Fatalf("active after reload: %v", err)
	}
	if version != 2 {
		t.Fatalf("active version did not survive reload: got %d", version)
	}
	if !bytes.Equal(got1, want1) || !bytes.Equal(got2, want2) {
		t.Fatal("key material changed across a reload — sealed values would be unreadable after a restart")
	}
}

// The ingest path resolves keys per event; concurrent resolution must not mint
// duplicates or race.
func TestConcurrentKeyResolution(t *testing.T) {
	v := newTestVault(t)
	first, _, err := v.TenantKeyMaterial("acme")
	if err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	errs := make(chan error, 64)
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			tenant := "acme"
			if n%2 == 0 {
				tenant = "globex"
			}
			m, _, err := v.TenantKeyMaterial(tenant)
			if err != nil {
				errs <- err
				return
			}
			if tenant == "acme" && !bytes.Equal(m, first) {
				errs <- errors.New("acme key changed under concurrency")
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}

// The custody store keeps its integrity MAC across versioned writes — a
// versioned key must not be a way to slip past the tamper check.
func TestVersionedWritesKeepStoreIntegrity(t *testing.T) {
	st, wn := testDeps()
	provider := &memSealing{}
	v, err := NewWithProvider(context.Background(), provider, st, wn)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := v.TenantKeyMaterial("acme"); err != nil {
		t.Fatal(err)
	}
	if _, err := v.RotateTenantKey("acme"); err != nil {
		t.Fatal(err)
	}

	raw, err := st.Load(wrappedKeysKey)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"mac"`) {
		t.Fatal("versioned custody store lost its integrity MAC")
	}
	// Tamper with a versioned entry; a reload must refuse to start.
	tampered := strings.Replace(string(raw), "dekv2|acme", "dekv2|other", 1)
	if err := st.Save(wrappedKeysKey, []byte(tampered)); err != nil {
		t.Fatal(err)
	}
	if _, err := NewWithProvider(context.Background(), provider, st, wn); err == nil {
		t.Fatal("a tampered versioned custody store must fail closed on load")
	}
}

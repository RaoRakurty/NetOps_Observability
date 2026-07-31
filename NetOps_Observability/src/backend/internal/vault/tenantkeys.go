package vault

// tenantkeys.go — VERSIONED per-tenant key material.
//
// The vault already mints one DEK per tenant for reversible secrets (SMTP
// passwords, OIDC client secrets, …). Those never needed a version: a secret is
// re-encrypted whenever it is rewritten, so a single current key is enough.
//
// Sealed Fields is the opposite shape. A sealed log value is written ONCE, kept
// for the retention window, and must still open months later. Rotating a key can
// therefore never mean "re-encrypt everything" — there is far too much of it, and
// most of it is immutable in OpenSearch/ClickHouse. Rotation has to mean "new
// values use a new version; old values keep naming the version that sealed them."
// That requires the vault to hold SEVERAL versions per tenant at once, which is
// what this file adds.
//
// STORAGE MODEL — additive, no migration, no format change:
//
//   - version 1 is the EXISTING `wrapped[tenant]` entry, wrapped under the
//     unchanged AAD "dek|<tenant>". Every store already written keeps working
//     and every secret already encrypted still decrypts.
//   - versions ≥2 live under a distinct key with a version-specific AAD, so even
//     a contrived tenant-id collision fails to unwrap rather than silently
//     cross-wiring two tenants' keys.
//   - the ACTIVE version is simply the HIGHEST one present. No metadata record,
//     nothing to keep in sync, and nothing that can disagree with the keys it
//     describes.
//
// RETIRING a version is deleting its entry: the next unseal of a value naming it
// fails closed with a key-unavailable error rather than returning plaintext.

import (
	"errors"
	"fmt"
	"io"
	"strconv"

	"crypto/rand"
	"encoding/base64"
)

// MaxKeyVersion bounds the version scan. Rotation is an operator action measured
// in months; a bound this high is unreachable in practice and keeps the lookup
// from becoming unbounded work driven by stored state (§9).
const MaxKeyVersion = 1000

// ErrCustodyUnavailable — key custody is not configured (SEAL_PROVIDER unset).
// Distinct from "this tenant has no key": callers surface a different remedy.
var ErrCustodyUnavailable = errors.New("vault: key custody is not configured (set SEAL_PROVIDER)")

// dekVersionKey is the custody-store key for one tenant's DEK at a version.
// Version 1 keeps the bare tenant id so pre-existing stores are unchanged.
func dekVersionKey(tenant string, version int) string {
	if version <= 1 {
		return tenant
	}
	return "dekv" + strconv.Itoa(version) + "|" + tenant
}

// dekAAD binds a wrapped DEK to its tenant AND version. Version 1's AAD is
// unchanged from the original scheme; higher versions add the version so a key
// can never be unwrapped as a different version of itself.
func dekAAD(tenant string, version int) []byte {
	if version <= 1 {
		return []byte("dek|" + tenant)
	}
	return []byte("dek|" + tenant + "|v" + strconv.Itoa(version))
}

// activeVersionLocked reports the highest version present for a tenant, or 1
// when only the original (or no) entry exists. Caller holds at least RLock.
func (v *Vault) activeVersionLocked(tenant string) int {
	active := 1
	for n := 2; n <= MaxKeyVersion; n++ {
		if _, ok := v.wrapped[dekVersionKey(tenant, n)]; !ok {
			break
		}
		active = n
	}
	return active
}

// TenantKeyMaterial returns the tenant's DEK at its ACTIVE version, minting the
// first one on demand. This is the material Sealed Fields derives from — it is
// never used directly as a cipher key (see package sealing: the seal key is
// HKDF-separated from it, so a weakness in high-volume field sealing cannot
// become recovery of the stored credentials that share this DEK).
func (v *Vault) TenantKeyMaterial(tenant string) ([]byte, int, error) {
	if !v.active() {
		return nil, 0, ErrCustodyUnavailable
	}
	v.mu.RLock()
	version := v.activeVersionLocked(tenant)
	v.mu.RUnlock()

	material, err := v.dekAtVersion(tenant, version, true)
	if err != nil {
		return nil, 0, err
	}
	return material, version, nil
}

// TenantKeyMaterialVersion returns a SPECIFIC version so values sealed before a
// rotation stay readable. It never creates: asking for a version that was
// retired must fail, not mint a new key that would decrypt nothing.
func (v *Vault) TenantKeyMaterialVersion(tenant string, version int) ([]byte, error) {
	if !v.active() {
		return nil, ErrCustodyUnavailable
	}
	if version < 1 || version > MaxKeyVersion {
		return nil, fmt.Errorf("vault: key version %d out of range", version)
	}
	return v.dekAtVersion(tenant, version, false)
}

// RotateTenantKey mints the next key version and makes it active.
//
// Existing sealed values are NOT re-encrypted and do not need to be: each names
// the version that sealed it and keeps opening until an operator deliberately
// retires that version. Reversible secrets (Encrypt/Decrypt) deliberately stay
// on version 1 — those are re-encrypted on write, so moving them would mean
// rewriting every stored secret for no gain.
func (v *Vault) RotateTenantKey(tenant string) (int, error) {
	if !v.active() {
		return 0, ErrCustodyUnavailable
	}
	v.mu.Lock()
	defer v.mu.Unlock()

	next := v.activeVersionLocked(tenant) + 1
	if next > MaxKeyVersion {
		return 0, fmt.Errorf("vault: tenant %q has reached the maximum of %d key versions", tenant, MaxKeyVersion)
	}
	if _, err := v.mintVersionLocked(tenant, next); err != nil {
		return 0, err
	}
	return next, nil
}

// dekAtVersion resolves (and caches) one tenant/version DEK.
func (v *Vault) dekAtVersion(tenant string, version int, create bool) ([]byte, error) {
	key := dekVersionKey(tenant, version)

	v.mu.RLock()
	if d, ok := v.deks[key]; ok {
		v.mu.RUnlock()
		return d, nil
	}
	wrapped, has := v.wrapped[key]
	v.mu.RUnlock()

	v.mu.Lock()
	defer v.mu.Unlock()
	// Re-check under the write lock — another goroutine may have won the race.
	if d, ok := v.deks[key]; ok {
		return d, nil
	}
	if w, ok := v.wrapped[key]; ok {
		return v.unwrapVersionLocked(tenant, version, w)
	}
	if has {
		return v.unwrapVersionLocked(tenant, version, wrapped)
	}
	if !create {
		return nil, fmt.Errorf("vault: no key version %d for tenant %q", version, tenant)
	}
	return v.mintVersionLocked(tenant, version)
}

// mintVersionLocked generates, wraps and persists a new tenant/version DEK.
// Caller holds the write lock.
func (v *Vault) mintVersionLocked(tenant string, version int) ([]byte, error) {
	key := dekVersionKey(tenant, version)
	dek := make([]byte, dekLen)
	if _, err := io.ReadFull(rand.Reader, dek); err != nil {
		return nil, err
	}
	wrapped, err := gcmSeal(v.kek, dek, dekAAD(tenant, version))
	if err != nil {
		return nil, err
	}
	v.deks[key] = dek
	v.wrapped[key] = base64.StdEncoding.EncodeToString(wrapped)
	if err := v.saveWrappedLocked(); err != nil {
		// Roll the in-memory state back so a retry mints and persists cleanly
		// rather than leaving a key that exists in memory but not in custody.
		delete(v.deks, key)
		delete(v.wrapped, key)
		return nil, err
	}
	return dek, nil
}

func (v *Vault) unwrapVersionLocked(tenant string, version int, wrappedB64 string) ([]byte, error) {
	key := dekVersionKey(tenant, version)
	raw, err := base64.StdEncoding.DecodeString(wrappedB64)
	if err != nil {
		return nil, fmt.Errorf("vault: malformed wrapped DEK for %q v%d: %w", tenant, version, err)
	}
	dek, err := gcmOpen(v.kek, raw, dekAAD(tenant, version))
	if err != nil {
		return nil, fmt.Errorf("vault: unwrap DEK for %q v%d: %w", tenant, version, err)
	}
	v.deks[key] = dek
	return dek, nil
}

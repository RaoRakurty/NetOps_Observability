package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
)

// secrets.go — the secret-custody Vault: stdlib AES-256-GCM envelope encryption
// (#17, design `docs/design/secret-custody.md`). It is the crypto complement to
// RLS (#15/#33): RLS controls row *visibility*; the Vault controls plaintext
// *recoverability*. A query/RLS bug then leaks ciphertext, not secrets.
//
// Key hierarchy: a sealed root KEK wraps a per-tenant (and a platform) DEK;
// secrets are AES-256-GCM under the owning tenant's DEK with AAD = tenant|fieldID,
// so a ciphertext copied into another tenant's row (or another field) fails to
// decrypt — no confused-deputy. Unwrapped DEKs live in memory only; the wrapped
// DEKs persist via the existing kv backend (file → disk, postgres → app_kv).
// The root KEK is supplied by a SealingProvider (swtpm/TPM/KMS) and never written.
//
// DORMANT BY DEFAULT: with no SEAL_PROVIDER configured the Vault passes plaintext
// through unchanged, and Decrypt accepts legacy plaintext (anything lacking the
// "v1:" prefix). So the default build and the running stack behave exactly as
// before until an operator activates custody with SEAL_PROVIDER=swtpm. This is
// the design's migration step 1 ("ship the Vault dormant").

const (
	secretVersionPrefix = "v1:" // versioned, self-describing ciphertext
	kekLen              = 32    // AES-256
	dekLen              = 32    // AES-256
)

// wrappedKeysKey is the kv key under which the platform-custody store of wrapped
// DEKs lives (file → disk path, postgres → app_kv row). A var, not a const, so
// tests can redirect it to a temp path.
var wrappedKeysKey = "secrets_wrapped_keys.json"

// SealingProvider seals/unseals the 32-byte root KEK — the ONLY component that
// talks to the custody root. swtpm is impl #1; TPM2/KMS/HSM drop in with no
// caller change. Selected by SEAL_PROVIDER (fail-closed: an unknown/unavailable
// provider aborts boot rather than silently storing plaintext).
type SealingProvider interface {
	// Unseal returns the root KEK, or fails closed if the root is unavailable.
	Unseal(ctx context.Context) ([]byte, error)
	// Seal persists a freshly generated root KEK under the custody root (first run).
	Seal(ctx context.Context, kek []byte) error
}

// Vault encrypts/decrypts reversible secrets under per-tenant DEKs. The zero
// value is not usable — construct via newVault / newVaultWithProvider.
type Vault struct {
	mu       sync.RWMutex
	provider SealingProvider   // nil → dormant (plaintext passthrough)
	kek      []byte            // root KEK, unwrapped, memory only
	deks     map[string][]byte // tenant → unwrapped DEK (memory cache)
	wrapped  map[string]string // tenant → base64 wrapped DEK (persisted)
}

// newVault selects the sealing provider from SEAL_PROVIDER and activates custody,
// or returns a dormant (passthrough) Vault when unset. Fail-closed: a configured
// provider that can't unseal the KEK returns an error so the caller aborts boot.
func newVault(ctx context.Context) (*Vault, error) {
	name := strings.ToLower(strings.TrimSpace(os.Getenv("SEAL_PROVIDER")))
	switch name {
	case "", "none", "off":
		// Dormant: reversible secrets (SMTP/Twilio/Slack/PD/OIDC client-secret/
		// LDAP bind pw/TACACS/SNMP creds/integration webhook secrets/internal-CA
		// key) are stored in CLEARTEXT. Surface this (SR-016) instead of leaving
		// it silent; REQUIRE_SEAL=true fails closed for production profiles.
		if os.Getenv("REQUIRE_SEAL") == "true" {
			return nil, errors.New("REQUIRE_SEAL=true but SEAL_PROVIDER is unset — refusing to start storing reversible secrets in cleartext; set SEAL_PROVIDER=swtpm")
		}
		logWarn("secrets", "secret-custody Vault is DORMANT (no SEAL_PROVIDER) — reversible secrets (SMTP/Slack/PagerDuty/OIDC/LDAP/TACACS/SNMP/webhook/internal-CA key) are stored in cleartext at rest. Set SEAL_PROVIDER=swtpm to encrypt, or REQUIRE_SEAL=true to fail closed.", nil)
		return &Vault{deks: map[string][]byte{}, wrapped: map[string]string{}}, nil
	case "swtpm":
		return newVaultWithProvider(ctx, newSwtpmSidecarProvider())
	default:
		return nil, fmt.Errorf("unknown SEAL_PROVIDER %q (want swtpm|none)", name)
	}
}

// newVaultWithProvider activates a Vault against a concrete provider (used by
// newVault and by tests with an in-memory provider). It unseals (or, first run,
// generates+seals) the root KEK and loads the persisted wrapped DEKs.
func newVaultWithProvider(ctx context.Context, p SealingProvider) (*Vault, error) {
	v := &Vault{provider: p, deks: map[string][]byte{}, wrapped: map[string]string{}}
	kek, err := p.Unseal(ctx)
	if err != nil || len(kek) != kekLen {
		// First run: no sealed KEK yet → generate one and seal it.
		if kek, err = v.firstRunKEK(ctx); err != nil {
			return nil, fmt.Errorf("vault: unseal root KEK: %w", err)
		}
	}
	v.kek = kek
	if err := v.loadWrapped(); err != nil {
		return nil, fmt.Errorf("vault: load wrapped keys: %w", err)
	}
	return v, nil
}

func (v *Vault) firstRunKEK(ctx context.Context) ([]byte, error) {
	kek := make([]byte, kekLen)
	if _, err := io.ReadFull(rand.Reader, kek); err != nil {
		return nil, err
	}
	if err := v.provider.Seal(ctx, kek); err != nil {
		return nil, err
	}
	return kek, nil
}

// active reports whether custody is on (a provider was configured).
func (v *Vault) active() bool { return v != nil && v.provider != nil }

// Encrypt returns a versioned ciphertext for a secret owned by tenant ("" =
// platform). When dormant it returns the plaintext unchanged. AAD binds the
// ciphertext to tenant|fieldID.
func (v *Vault) Encrypt(tenant, fieldID, plaintext string) (string, error) {
	if !v.active() || plaintext == "" {
		return plaintext, nil
	}
	dek, err := v.dek(tenant, true)
	if err != nil {
		return "", err
	}
	blob, err := gcmSeal(dek, []byte(plaintext), aad(tenant, fieldID))
	if err != nil {
		return "", err
	}
	return secretVersionPrefix + base64.StdEncoding.EncodeToString(blob), nil
}

// Decrypt reverses Encrypt. Plaintext-passthrough: a value lacking the "v1:"
// prefix is returned as-is (legacy plaintext, or a dormant Vault), so encryption
// can be rolled out encrypt-on-next-write without a flag day.
func (v *Vault) Decrypt(tenant, fieldID, stored string) (string, error) {
	if !strings.HasPrefix(stored, secretVersionPrefix) {
		return stored, nil // legacy plaintext / dormant
	}
	if !v.active() {
		return "", errors.New("vault: encrypted secret present but custody is not configured (set SEAL_PROVIDER)")
	}
	blob, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(stored, secretVersionPrefix))
	if err != nil {
		return "", fmt.Errorf("vault: malformed ciphertext: %w", err)
	}
	dek, err := v.dek(tenant, false)
	if err != nil {
		return "", err
	}
	pt, err := gcmOpen(dek, blob, aad(tenant, fieldID))
	if err != nil {
		return "", fmt.Errorf("vault: decrypt (wrong tenant/field or tampered): %w", err)
	}
	return string(pt), nil
}

// dek returns the unwrapped DEK for a tenant, creating+wrapping+persisting a new
// one when create is true and none exists. Platform secrets use tenant "".
func (v *Vault) dek(tenant string, create bool) ([]byte, error) {
	v.mu.RLock()
	if d, ok := v.deks[tenant]; ok {
		v.mu.RUnlock()
		return d, nil
	}
	w, hasWrapped := v.wrapped[tenant]
	v.mu.RUnlock()

	if hasWrapped {
		return v.unwrapAndCache(tenant, w)
	}
	if !create {
		return nil, fmt.Errorf("vault: no key for tenant %q", tenant)
	}

	v.mu.Lock()
	defer v.mu.Unlock()
	// Re-check under the write lock (another goroutine may have created it).
	if d, ok := v.deks[tenant]; ok {
		return d, nil
	}
	if w, ok := v.wrapped[tenant]; ok {
		return v.unwrapLocked(tenant, w)
	}
	dek := make([]byte, dekLen)
	if _, err := io.ReadFull(rand.Reader, dek); err != nil {
		return nil, err
	}
	wrapped, err := gcmSeal(v.kek, dek, []byte("dek|"+tenant))
	if err != nil {
		return nil, err
	}
	v.deks[tenant] = dek
	v.wrapped[tenant] = base64.StdEncoding.EncodeToString(wrapped)
	if err := v.saveWrappedLocked(); err != nil {
		// Roll back the in-memory state so a retry re-creates+persists cleanly.
		delete(v.deks, tenant)
		delete(v.wrapped, tenant)
		return nil, err
	}
	return dek, nil
}

func (v *Vault) unwrapAndCache(tenant, wrappedB64 string) ([]byte, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if d, ok := v.deks[tenant]; ok {
		return d, nil
	}
	return v.unwrapLocked(tenant, wrappedB64)
}

func (v *Vault) unwrapLocked(tenant, wrappedB64 string) ([]byte, error) {
	wrapped, err := base64.StdEncoding.DecodeString(wrappedB64)
	if err != nil {
		return nil, fmt.Errorf("vault: malformed wrapped DEK: %w", err)
	}
	dek, err := gcmOpen(v.kek, wrapped, []byte("dek|"+tenant))
	if err != nil {
		return nil, fmt.Errorf("vault: unwrap DEK for %q: %w", tenant, err)
	}
	v.deks[tenant] = dek
	return dek, nil
}

// wrappedStore is the on-disk shape of the wrapped-DEK custody store. The MAC
// (SR-027) is an HMAC-SHA256 over the canonical Keys JSON keyed by the root KEK,
// giving the whole map top-level integrity: deleting or tampering with an entry
// is DETECTED on load (fail-closed) instead of silently causing the next write
// to mint a fresh DEK — which would render that tenant's existing ciphertext
// permanently unrecoverable (a stealthy tamper/DoS).
type wrappedStore struct {
	Keys map[string]string `json:"keys"`
	MAC  string            `json:"mac"`
}

// wrappedMAC computes the integrity tag over the canonical (sorted-key) JSON of
// the wrapped map, keyed by the root KEK.
func (v *Vault) wrappedMAC(keys map[string]string) (string, error) {
	canon, err := json.Marshal(keys) // Go sorts string map keys → deterministic
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, v.kek)
	mac.Write(canon)
	return hex.EncodeToString(mac.Sum(nil)), nil
}

func (v *Vault) loadWrapped() error {
	b, err := kvLoad(wrappedKeysKey)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil // first run — no wrapped keys yet
		}
		return err
	}
	if len(b) == 0 {
		return nil
	}
	var s wrappedStore
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	if s.Keys == nil {
		// Legacy plain-map format (pre-SR-027): accept once, migrate to a MAC'd
		// store on the next write.
		m := map[string]string{}
		if err := json.Unmarshal(b, &m); err != nil {
			return err
		}
		v.wrapped = m
		return nil
	}
	want, err := v.wrappedMAC(s.Keys)
	if err != nil {
		return err
	}
	if !hmac.Equal([]byte(want), []byte(s.MAC)) {
		return errors.New("vault: wrapped-DEK store integrity check failed (tampered or truncated) — refusing to start; restore the custody store from backup")
	}
	v.wrapped = s.Keys
	return nil
}

func (v *Vault) saveWrappedLocked() error {
	mac, err := v.wrappedMAC(v.wrapped)
	if err != nil {
		return err
	}
	b, err := json.MarshalIndent(wrappedStore{Keys: v.wrapped, MAC: mac}, "", "  ")
	if err != nil {
		return err
	}
	return kvSave(wrappedKeysKey, b)
}

// aad binds a ciphertext to its owning tenant and field, defeating cross-tenant
// or cross-field copy-paste of an encrypted value.
func aad(tenant, fieldID string) []byte { return []byte(tenant + "|" + fieldID) }

// gcmSeal returns nonce||ciphertext for plaintext under key, authenticating aad.
func gcmSeal(key, plaintext, additional []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plaintext, additional), nil
}

// gcmOpen reverses gcmSeal on a nonce||ciphertext blob.
func gcmOpen(key, blob, additional []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	ns := gcm.NonceSize()
	if len(blob) < ns {
		return nil, errors.New("ciphertext shorter than nonce")
	}
	return gcm.Open(nil, blob[:ns], blob[ns:], additional)
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

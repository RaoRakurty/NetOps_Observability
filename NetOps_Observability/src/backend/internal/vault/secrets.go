package vault

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
	VersionPrefix = "v1:" // versioned, self-describing ciphertext
	kekLen        = 32    // AES-256
	dekLen        = 32    // AES-256
)

// wrappedKeysKey is the kv key under which the platform-custody store of wrapped
// DEKs lives (file → disk path, postgres → app_kv row). A var, not a const, so
// tests can redirect it to a temp path.
var wrappedKeysKey = "secrets_wrapped_keys.json"

// ErrNoKEK is the explicit first-run signal: the provider is reachable and
// healthy but holds no sealed KEK yet. It is the ONLY unseal outcome that
// authorizes generating a fresh root KEK. Every other unseal failure aborts
// activation — minting a new KEK over an existing (but momentarily unreadable)
// one would permanently orphan every sealed secret. That is exactly what a
// stale swtpm primary context nearly caused on 2026-08-04: unseal failed with
// a load error, activation treated it as first-run, and only the seal ALSO
// failing prevented the real KEK from being overwritten.
var ErrNoKEK = errors.New("no sealed KEK (first run)")

// SealingProvider seals/unseals the 32-byte root KEK — the ONLY component that
// talks to the custody root. swtpm is impl #1; TPM2/KMS/HSM drop in with no
// caller change. Selected by SEAL_PROVIDER (fail-closed: an unknown/unavailable
// provider aborts boot rather than silently storing plaintext).
type SealingProvider interface {
	// Unseal returns the root KEK, or fails closed if the root is unavailable.
	// A provider that is healthy but holds no sealed KEK yet MUST return an
	// error wrapping ErrNoKEK — that is the only signal that permits first-run
	// KEK generation.
	Unseal(ctx context.Context) ([]byte, error)
	// Seal persists a freshly generated root KEK under the custody root (first run).
	Seal(ctx context.Context, kek []byte) error
}

// Vault encrypts/decrypts reversible secrets under per-tenant DEKs. The zero
// value is not usable — construct via New / NewWithProvider.
type Vault struct {
	mu       sync.RWMutex
	store    Store             // injected persistence (see Store)
	warn     Warnf             // injected operator-visible warning (see Warnf)
	provider SealingProvider   // nil → dormant (plaintext passthrough)
	kek      []byte            // root KEK, unwrapped, memory only
	deks     map[string][]byte // tenant → unwrapped DEK (memory cache)
	wrapped  map[string]string // tenant → base64 wrapped DEK (persisted)
	strict   bool              // VAULT_STRICT=true → active Decrypt refuses non-"v1:" values
}

// New selects the sealing provider from SEAL_PROVIDER and activates custody,
// or returns a dormant (passthrough) Vault when unset. Fail-closed: a configured
// provider that can't unseal the KEK returns an error so the caller aborts boot.
// Store is the persistence the vault needs. It is INJECTED rather than reached
// for: the vault is security-critical code and must be testable against a
// failing/empty store without standing up the platform's kv layer, and a
// package that owns key custody should not also know how the platform happens
// to persist bytes today.
type Store interface {
	Load(key string) ([]byte, error)
	Save(key string, b []byte) error
}

// Warnf reports a condition an operator must see (a dormant vault leaves
// reversible secrets in cleartext at rest). Injected for the same reason.
type Warnf func(component, msg string, fields map[string]any)

func New(ctx context.Context, store Store, warn Warnf) (*Vault, error) {
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
		warn("secrets", "secret-custody Vault is DORMANT (no SEAL_PROVIDER) — reversible secrets (SMTP/Slack/PagerDuty/OIDC/LDAP/TACACS/SNMP/webhook/internal-CA key) are stored in cleartext at rest. Set SEAL_PROVIDER=swtpm to encrypt, or REQUIRE_SEAL=true to fail closed.", nil)
		return &Vault{store: store, warn: warn, deks: map[string][]byte{}, wrapped: map[string]string{}}, nil
	case "swtpm":
		return NewWithProvider(ctx, newSwtpmSidecarProvider(), store, warn)
	default:
		return nil, fmt.Errorf("unknown SEAL_PROVIDER %q (want swtpm|none)", name)
	}
}

// NewWithProvider activates a Vault against a concrete provider (used by
// New and by tests with an in-memory provider). It unseals (or, first run,
// generates+seals) the root KEK and loads the persisted wrapped DEKs.
func NewWithProvider(ctx context.Context, p SealingProvider, store Store, warn Warnf) (*Vault, error) {
	v := &Vault{provider: p, store: store, warn: warn, deks: map[string][]byte{}, wrapped: map[string]string{},
		strict: os.Getenv("VAULT_STRICT") == "true"}
	kek, err := p.Unseal(ctx)
	firstRun := errors.Is(err, ErrNoKEK)
	switch {
	case firstRun:
		// Explicit first-run: the provider is healthy and holds no KEK yet.
		if kek, err = v.firstRunKEK(ctx); err != nil {
			return nil, fmt.Errorf("vault: seal first-run KEK: %w", err)
		}
	case err != nil:
		// Any other failure means a KEK may exist but be unreadable right now
		// (sidecar down, stale TPM context, corrupt state). Generating a fresh
		// KEK here would overwrite it and orphan every sealed secret — abort.
		return nil, fmt.Errorf("vault: unseal root KEK: %w", err)
	case len(kek) != kekLen:
		return nil, fmt.Errorf("vault: unsealed root KEK has length %d, want %d — custody state may be corrupt; refusing to overwrite it", len(kek), kekLen)
	}
	v.kek = kek
	if err := v.loadWrapped(firstRun); err != nil {
		return nil, fmt.Errorf("vault: load wrapped keys: %w", err)
	}
	if firstRun && len(v.wrapped) == 0 {
		// Persist an EMPTY (but MAC'd) custody store NOW, so "KEK exists but the
		// wrapped store is absent" is never a legitimate steady state. From this
		// boot on, an absent/empty store under an existing KEK can only mean a
		// wipe/truncation — which loadWrapped refuses (M16) instead of silently
		// re-keying over it. Construction is single-threaded, so calling
		// saveWrappedLocked without the mutex is safe (same as the migrate path).
		if err := v.saveWrappedLocked(); err != nil {
			return nil, fmt.Errorf("vault: persist first-run custody store: %w", err)
		}
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
	return VersionPrefix + base64.StdEncoding.EncodeToString(blob), nil
}

// Decrypt reverses Encrypt. Plaintext-passthrough: a value lacking the "v1:"
// prefix is returned as-is (legacy plaintext, or a dormant Vault), so encryption
// can be rolled out encrypt-on-next-write without a flag day. VAULT_STRICT=true
// closes that door once custody is active: with every value migrated, a non-"v1:"
// value can only be an injected/downgraded one, and passing it through would let
// a store-writer bypass the AAD binding entirely. Off by default (compat with
// the encrypt-on-next-write migration); "" stays passthrough (an unset field).
func (v *Vault) Decrypt(tenant, fieldID, stored string) (string, error) {
	if !strings.HasPrefix(stored, VersionPrefix) {
		if v.active() && v.strict && stored != "" {
			return "", errors.New("vault: VAULT_STRICT=true — refusing plaintext passthrough of a non-encrypted stored value while custody is active")
		}
		return stored, nil // legacy plaintext / dormant
	}
	if !v.active() {
		return "", errors.New("vault: encrypted secret present but custody is not configured (set SEAL_PROVIDER)")
	}
	blob, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(stored, VersionPrefix))
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

// loadWrapped reads the persisted wrapped-DEK custody store. firstRun reports
// whether THIS boot generated the KEK (the provider returned ErrNoKEK) — the
// only state in which an absent store is genuinely "no keys yet".
func (v *Vault) loadWrapped(firstRun bool) error {
	if os.Getenv("VAULT_MIGRATE_LEGACY_WRAPPED") == "true" {
		// Loud on EVERY boot the flag is set (M16): while it stands, a MAC-less
		// (i.e. unauthenticated, possibly tampered) store would be accepted — a
		// flag meant for one boot must not become a silent standing downgrade.
		v.warn("secrets", "VAULT_MIGRATE_LEGACY_WRAPPED=true — this boot ACCEPTS a MAC-less wrapped-DEK custody store (tamper-indistinguishable). Intended for a single migration boot; unset it now that the store is MAC'd.", nil)
	}
	b, err := v.store.Load(wrappedKeysKey)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if errors.Is(err, os.ErrNotExist) || len(b) == 0 {
		if firstRun {
			return nil // genuine first run (ErrNoKEK) — no wrapped keys yet
		}
		// The KEK EXISTS (we unsealed it from the provider) but the custody
		// store is gone/empty. Treating that as "first run" — as this code once
		// did — silently mints fresh DEKs, so a wipe/truncation of the store
		// becomes a permanent, authenticated re-key that orphans every existing
		// ciphertext (M16). Refuse instead; the one legitimate shape (custody
		// activated before this check existed, and no DEK ever wrapped) gets an
		// explicit one-boot override.
		if os.Getenv("VAULT_ALLOW_EMPTY_STORE") == "true" {
			v.warn("secrets", "wrapped-DEK custody store is absent/empty while the root KEK EXISTS — accepted ONLY because VAULT_ALLOW_EMPTY_STORE=true. If any secret was ever encrypted, it is now unrecoverable; unset the flag after this boot.", nil)
			return nil
		}
		return errors.New("vault: root KEK exists but the wrapped-DEK custody store is absent/empty — a wiped or truncated store, not a first run; minting fresh DEKs would permanently orphan every existing ciphertext. Restore the custody store from backup, or (only if no DEK was ever wrapped) set VAULT_ALLOW_EMPTY_STORE=true for ONE boot")
	}
	var s wrappedStore
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	if s.Keys == nil {
		// Legacy plain-map format (pre-SR-027): NO integrity MAC. This shape is
		// indistinguishable from a DOWNGRADE ATTACK — an adversary who can write
		// the custody store but does not hold the KEK cannot forge a valid MAC, so
		// they strip it and present a plain map. Accepting it silently (as the old
		// code did, "accept once") let them tamper with wrapped DEKs — swap or
		// remove a tenant's key — undetected. So REFUSE by default; a MAC-less
		// custody store fails closed exactly like a MAC-mismatched one.
		//
		// A genuine one-time upgrade from a pre-MAC store sets
		// VAULT_MIGRATE_LEGACY_WRAPPED=true for a single boot: we accept the plain
		// map, then IMMEDIATELY re-persist it in the MAC'd format so the
		// unauthenticated shape never survives to be accepted again, and the
		// operator unsets the flag.
		if os.Getenv("VAULT_MIGRATE_LEGACY_WRAPPED") != "true" {
			return errors.New("vault: wrapped-DEK custody store has NO integrity MAC — refusing to start " +
				"(this is a pre-SR-027 legacy store OR a downgrade/tamper). For a genuine one-time upgrade " +
				"set VAULT_MIGRATE_LEGACY_WRAPPED=true for a single boot to migrate it to the MAC'd format, then unset it")
		}
		m := map[string]string{}
		if err := json.Unmarshal(b, &m); err != nil {
			return err
		}
		v.wrapped = m
		// Eager migrate: persist the MAC'd format NOW (construction is single-
		// threaded, so calling saveWrappedLocked without the mutex is safe) so the
		// unauthenticated plain shape does not linger for a second boot to accept.
		if err := v.saveWrappedLocked(); err != nil {
			return fmt.Errorf("vault: migrate legacy wrapped store to MAC'd format: %w", err)
		}
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
	return v.store.Save(wrappedKeysKey, b)
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

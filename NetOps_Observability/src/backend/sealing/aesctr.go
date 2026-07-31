package sealing

// aesctr.go — the CURRENT CryptoProvider: AES-256-CTR with encrypt-then-MAC
// (HMAC-SHA256), keys derived per tenant from the vault's envelope hierarchy.
//
// WHY CTR AND NOT GCM: sealing happens in the ingest runtime (Vector's VRL),
// which offers AES-CTR but no AEAD mode — verified against the pinned binary
// rather than assumed. So the construction is composed by hand, correctly:
// encrypt-then-MAC over the authenticated context, verified in constant time
// BEFORE decryption. When the runtime gains AES-GCM, gcmProvider replaces this
// file and nothing above CryptoProvider changes; existing v1 tokens keep
// unsealing through this code path, which is exactly why the token carries its
// own version.

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
)

const (
	ivLen  = 16 // AES block size
	macLen = 32 // SHA-256
	// maxSealBytes bounds one sealed value. A log field is not a file; the cap
	// stops a pathological event from turning into an expensive seal (§9).
	maxSealBytes = 8 << 10
)

// KeyProvider is the narrow view of the vault this package needs: give me the
// tenant's key material and its current version. Declared HERE (not imported
// from vault) so sealing has no compile-time dependency on a concrete vault —
// a KMS-backed implementation satisfies the same seam.
type KeyProvider interface {
	// TenantKey returns durable per-tenant key material (the unwrapped DEK) and
	// the ACTIVE key version for that tenant.
	TenantKey(ctx context.Context, tenant string) (material []byte, version int, err error)
	// TenantKeyVersion returns material for a SPECIFIC historical version so
	// values sealed before a rotation stay readable.
	TenantKeyVersion(ctx context.Context, tenant string, version int) (material []byte, err error)
	// RotateTenant advances the active version and returns the new one.
	RotateTenant(ctx context.Context, tenant string) (version int, err error)
}

// aesCTRProvider is the default CryptoProvider.
type aesCTRProvider struct {
	keys KeyProvider

	// derived caches HKDF output per (tenant, version). Derivation is cheap but
	// not free, and the ingest path seals continuously; the cache is bounded and
	// holds DERIVED keys only, never the DEK itself.
	mu      sync.RWMutex
	derived map[string]derivedKeys
}

type derivedKeys struct{ seal, mac []byte }

// NewAESCTRProvider builds the default provider over a key source.
func NewAESCTRProvider(keys KeyProvider) CryptoProvider {
	return &aesCTRProvider{keys: keys, derived: map[string]derivedKeys{}}
}

func cacheKey(tenant string, version int) string { return fmt.Sprintf("%s#%d", tenant, version) }

// ctrXOR applies the keystream of the counter mode THE EDGE USES.
//
// This is not the Go standard library's CTR, and that is the entire point.
// crypto/cipher.NewCTR treats the whole 16-byte IV as one big-endian counter;
// Vector's "AES-256-CTR" (Rust's ctr::Ctr64LE) uses the FIRST EIGHT BYTES as a
// LITTLE-ENDIAN block counter and holds the rest fixed. The two agree on block
// 0 and diverge from block 1 onward — so a value of 16 bytes or less round-trips
// perfectly and anything longer silently decrypts to garbage.
//
// That is exactly how it presented: card numbers worked, email addresses did
// not. Discovered by running the pinned binary (see vrl_parity_test.go) rather
// than by reading either implementation, and pinned forever by the golden
// keystream in TestCounterModeMatchesTheEdge — which fails without Docker
// present, so this cannot regress unnoticed.
func ctrXOR(block cipher.Block, iv, src []byte) []byte {
	dst := make([]byte, len(src))
	ctr := make([]byte, aes.BlockSize)
	copy(ctr, iv)
	base := binary.LittleEndian.Uint64(iv[:8])
	ks := make([]byte, aes.BlockSize)
	for off := 0; off < len(src); off += aes.BlockSize {
		binary.LittleEndian.PutUint64(ctr[:8], base+uint64(off/aes.BlockSize))
		block.Encrypt(ks, ctr)
		for i := 0; i < aes.BlockSize && off+i < len(src); i++ {
			dst[off+i] = src[off+i] ^ ks[i]
		}
	}
	return dst
}

// keysFor resolves the derived seal+mac keys for a tenant key version.
//
// `cache` is true ONLY on the sealing path (the active version, called per
// event). Unsealing always re-derives, which costs one HKDF on a rare,
// human-initiated, audited operation — and buys a security property worth far
// more than that: RETIRING A KEY TAKES EFFECT IMMEDIATELY. A cache that
// remembered historical versions would keep decrypting with a key the operator
// had already withdrawn, until the process happened to restart.
func (p *aesCTRProvider) keysFor(ctx context.Context, tenant string, version int, cache bool) (derivedKeys, error) {
	ck := cacheKey(tenant, version)
	if cache {
		p.mu.RLock()
		dk, ok := p.derived[ck]
		p.mu.RUnlock()
		if ok {
			return dk, nil
		}
	}

	material, err := p.keys.TenantKeyVersion(ctx, tenant, version)
	if err != nil {
		return derivedKeys{}, fmt.Errorf("%w: %w", ErrKeyUnavailable, err)
	}
	sealKey, err := deriveSealKey(material, version)
	if err != nil {
		return derivedKeys{}, err
	}
	mk, err := macKey(sealKey)
	if err != nil {
		return derivedKeys{}, err
	}
	dk := derivedKeys{seal: sealKey, mac: mk}

	if cache {
		p.mu.Lock()
		if len(p.derived) > 512 { // bounded (§9): one entry per active tenant
			p.derived = map[string]derivedKeys{}
		}
		p.derived[ck] = dk
		p.mu.Unlock()
	}
	return dk, nil
}

func (p *aesCTRProvider) Seal(ctx context.Context, c Context, plaintext string) (string, error) {
	if err := c.valid(); err != nil {
		return "", err
	}
	if plaintext == "" {
		return "", nil // nothing to seal; callers leave the field untouched
	}
	if len(plaintext) > maxSealBytes {
		return "", fmt.Errorf("sealing: value exceeds %d bytes", maxSealBytes)
	}
	_, version, err := p.keys.TenantKey(ctx, c.Tenant)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrKeyUnavailable, err)
	}
	dk, err := p.keysFor(ctx, c.Tenant, version, true) // active version — cacheable
	if err != nil {
		return "", err
	}

	iv := make([]byte, ivLen)
	if _, err := rand.Read(iv); err != nil {
		// Fail the seal rather than fall back to a predictable IV: a reused IV
		// under CTR is catastrophic (keystream reuse reveals plaintext XOR).
		return "", fmt.Errorf("sealing: entropy unavailable: %w", err)
	}
	block, err := aes.NewCipher(dk.seal)
	if err != nil {
		return "", fmt.Errorf("sealing: cipher: %w", err)
	}
	ct := ctrXOR(block, iv, []byte(plaintext))

	return encodeToken(token{
		Tenant:     c.Tenant,
		KeyVersion: version,
		IV:         iv,
		Ciphertext: ct,
		MAC:        computeMAC(dk.mac, c, version, iv, ct),
	}), nil
}

func (p *aesCTRProvider) Unseal(ctx context.Context, c Context, raw string) (string, error) {
	if err := c.valid(); err != nil {
		return "", err
	}
	t, err := parseToken(raw)
	if err != nil {
		return "", err
	}
	// Cross-tenant replay is refused BEFORE any key is touched: the caller's
	// tenant must own the token. Distinct from a MAC failure so the audit trail
	// can tell "someone pasted another tenant's value" from "this was corrupted".
	if t.Tenant != c.Tenant {
		return "", ErrWrongContext
	}
	// Never cached: a retired key must stop working at once, not at restart.
	dk, err := p.keysFor(ctx, c.Tenant, t.KeyVersion, false)
	if err != nil {
		return "", err
	}

	// VERIFY BEFORE DECRYPT. hmac.Equal is constant time, so a wrong MAC leaks
	// no information through timing, and no plaintext is produced on failure.
	want := computeMAC(dk.mac, c, t.KeyVersion, t.IV, t.Ciphertext)
	if !hmac.Equal(want, t.MAC) {
		// The MAC covers the context too, so this fires both for tampering and
		// for a token replayed into a different processor/field. Report the
		// context case distinctly where we can tell them apart.
		if probe := p.contextMismatch(ctx, c, t); probe {
			return "", ErrWrongContext
		}
		return "", ErrTampered
	}

	block, err := aes.NewCipher(dk.seal)
	if err != nil {
		return "", fmt.Errorf("sealing: cipher: %w", err)
	}
	return string(ctrXOR(block, t.IV, t.Ciphertext)), nil
}

// contextMismatch distinguishes "sealed for a different field/processor" from
// genuine tampering by re-checking the MAC with the binding fields relaxed. It
// is diagnostic only — it NEVER decrypts and never widens what unseals; a true
// mismatch still returns an error.
func (p *aesCTRProvider) contextMismatch(ctx context.Context, c Context, t token) bool {
	dk, err := p.keysFor(ctx, c.Tenant, t.KeyVersion, false)
	if err != nil {
		return false
	}
	// Same tenant + key, but wildcard the per-field binding: if THAT verifies,
	// the value is authentic and simply belongs to another field/processor.
	relaxed := Context{Tenant: c.Tenant}
	return hmac.Equal(computeMAC(dk.mac, relaxed, t.KeyVersion, t.IV, t.Ciphertext), t.MAC)
}

func (p *aesCTRProvider) Rotate(ctx context.Context, tenant string) (int, error) {
	if tenant == "" {
		return 0, errors.New("sealing: tenant is required")
	}
	v, err := p.keys.RotateTenant(ctx, tenant)
	if err != nil {
		return 0, err
	}
	// Drop cached derivations for this tenant so the next seal uses the new
	// version immediately. Old versions re-derive on demand for unsealing.
	p.mu.Lock()
	for k := range p.derived {
		if len(k) > len(tenant) && k[:len(tenant)] == tenant && k[len(tenant)] == '#' {
			delete(p.derived, k)
		}
	}
	p.mu.Unlock()
	return v, nil
}

func (p *aesCTRProvider) EdgeKey(ctx context.Context, tenant string) (EdgeMaterial, error) {
	material, version, err := p.keys.TenantKey(ctx, tenant)
	if err != nil {
		return EdgeMaterial{}, fmt.Errorf("%w: %w", ErrKeyUnavailable, err)
	}
	sealKey, err := deriveSealKey(material, version)
	if err != nil {
		return EdgeMaterial{}, err
	}
	mk, err := macKey(sealKey)
	if err != nil {
		return EdgeMaterial{}, err
	}
	// The DERIVED keys cross to the edge — never the tenant DEK itself. A router
	// compromise therefore cannot unwrap stored credentials, which use a
	// different derivation from the same DEK.
	return EdgeMaterial{SealKey: sealKey, MACKey: mk, Version: version}, nil
}

var _ CryptoProvider = (*aesCTRProvider)(nil)

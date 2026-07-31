// Package sealing is the CryptoProvider abstraction behind Sealed Fields
// (reversible masking): a sensitive value is ENCRYPTED at ingest rather than
// destroyed, so an authorized operator can recover it later through an audited
// unseal, while everyone else sees only a masked display form.
//
// # WHY THIS PACKAGE EXISTS SEPARATELY FROM package processors
//
// The processor framework must never learn a cipher. It asks a CryptoProvider
// to Seal/Unseal and receives an opaque, self-describing token; swapping
// AES-CTR+HMAC for AES-GCM, a cloud KMS or an HSM is then a provider change
// with no edit to the compiler, the simulator, the API or the UI. That is the
// whole point of the indirection — the current cipher is a CONSTRAINT OF THE
// RUNTIME, not a design choice (see §Cipher below), and constraints move.
//
// KEY MODEL — envelope, never a master-derivation
//
//	root KEK (TPM/sealed, internal/vault)
//	   └─ per-tenant DEK (wrapped at rest, unwrapped in memory)
//	        └─ per-tenant SEAL key (HKDF-separated from the DEK, §Separation)
//	             └─ sealed value
//
// The platform already runs exactly this hierarchy for reversible secrets
// (internal/vault: per-tenant DEKs under a sealed root KEK, AES-256-GCM with
// AAD = tenant|field). Sealed Fields REUSES it rather than standing up a
// second key system. Deliberately rejected: HKDF(master_secret, tenant_id) —
// one compromised master would expose every tenant, including tenants created
// after the compromise.
//
// # SEPARATION OF PURPOSE
//
// The seal key is HKDF-Expanded from the tenant DEK with a distinct info label
// rather than being the DEK itself. Domain separation means a weakness in one
// use (log-field sealing, a high-volume path touching attacker-influenced data)
// cannot become plaintext recovery in the other (stored credentials). Both
// still chain to the same wrapped, rotatable tenant DEK.
//
// # CIPHER
//
// The edge runtime (Vector's VRL) offers AES-CTR but not AES-GCM — verified
// empirically against the pinned binary, not assumed. CTR alone gives
// confidentiality WITHOUT integrity, so this provider is strictly
// encrypt-then-MAC: HMAC-SHA256 over the full authenticated context, verified
// in constant time BEFORE any decryption is attempted. A tampered token is an
// error, never plaintext.
//
// # CONTEXT BINDING
//
// The MAC covers tenant, processor id, field name and key version alongside the
// ciphertext, so a token cannot be replayed into another tenant, another field
// or another processor. Moving a sealed value anywhere it did not originate
// makes it undecryptable rather than silently portable.
package sealing

import (
	"context"
	"crypto/hkdf" // stdlib since Go 1.24 — no new dependency (CLAUDE.md §6)
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
)

// Errors the callers above this package distinguish. They map to HTTP status
// codes at the API boundary, so they must stay meaningfully separate: a
// tampered token (400) is a different operational event from an unavailable
// key (410), and neither is "not found".
var (
	// ErrTampered — the MAC did not verify. The value is NOT decrypted.
	ErrTampered = errors.New("sealed value failed integrity verification")
	// ErrMalformed — the token is not a well-formed sealed value.
	ErrMalformed = errors.New("malformed sealed value")
	// ErrKeyUnavailable — the referenced key version cannot be resolved (rotated
	// out, or a tenant whose custody is not configured).
	ErrKeyUnavailable = errors.New("sealing key unavailable for this value")
	// ErrWrongContext — the token is authentic but was sealed for a different
	// tenant/processor/field. Deliberately distinct from ErrTampered: this is a
	// replay attempt, not corruption.
	ErrWrongContext = errors.New("sealed value belongs to a different tenant, processor or field")
)

// Context is the authenticated binding of a sealed value. Every field here is
// covered by the MAC; changing any of them invalidates the token.
type Context struct {
	Tenant      string // owning tenant — the isolation boundary
	ProcessorID string // which processor sealed it (provenance + revocation scope)
	Field       string // the field it was sealed FROM
	DataType    string // semantic type ("card", "email", …) for audit and UI
}

// maxContextField bounds each binding field. Nothing legitimate approaches it —
// tenant ids, processor ids and field names are short — but the MAC encoding
// length-prefixes these values, so leaving them unbounded would mean trusting
// caller-supplied lengths in a cryptographic encoding (§3: validate at every
// boundary). Bounded here, the prefix width is provably sufficient.
const maxContextField = 512

func (c Context) valid() error {
	if c.Tenant == "" {
		return errors.New("sealing: tenant is required")
	}
	if c.Field == "" {
		return errors.New("sealing: field is required")
	}
	for _, f := range [...]struct {
		name, val string
	}{
		{"tenant", c.Tenant}, {"processor", c.ProcessorID},
		{"field", c.Field}, {"data type", c.DataType},
	} {
		if len(f.val) > maxContextField {
			return fmt.Errorf("sealing: %s exceeds %d bytes", f.name, maxContextField)
		}
	}
	return nil
}

// CryptoProvider seals and unseals values. Implementations must be safe for
// concurrent use: the ingest path seals continuously while operators unseal.
//
// The interface is deliberately narrow — no algorithm, key material or
// encoding appears in it — so an AES-GCM, KMS or HSM implementation can be
// substituted without touching a single caller.
type CryptoProvider interface {
	// Seal encrypts plaintext under the tenant's current key and returns a
	// self-describing token (see token.go). Sealing the same value twice yields
	// DIFFERENT tokens: the IV is random, so equal plaintexts are not linkable
	// by inspection. Searchability, when needed, is the hash action's job —
	// never a weakened cipher.
	Seal(ctx context.Context, c Context, plaintext string) (string, error)

	// Unseal verifies integrity and context, then decrypts. It returns
	// ErrTampered/ErrWrongContext/ErrKeyUnavailable rather than any partial or
	// corrupted plaintext — this path fails closed, always.
	Unseal(ctx context.Context, c Context, token string) (string, error)

	// Rotate advances the tenant to a new key version. Existing tokens keep
	// naming the version that sealed them and stay decryptable (old versions are
	// retained, not destroyed), so rotation never orphans stored data.
	Rotate(ctx context.Context, tenant string) (version int, err error)

	// EdgeKey returns the key material the INGEST RUNTIME needs to seal for a
	// tenant, with its version. It exists because sealing happens at the edge
	// (Vector), which cannot call this process per event.
	//
	// Security note: this is the one method that returns key material, so it is
	// the one to audit. It is served only to the router's secret backend, over
	// a loopback/authenticated channel, and the router holds the returned keys
	// IN MEMORY ONLY — Vector's `exec` secret backend resolves SECRET[…] at
	// config load, so no unwrapped key is ever written to disk. A router
	// compromise therefore exposes the keys of tenants that ENABLED sealing,
	// not a master capable of deriving every tenant's key.
	EdgeKey(ctx context.Context, tenant string) (key []byte, version int, err error)
}

// sealKeyInfo domain-separates the field-sealing key from every other use of
// the tenant DEK. Changing this string changes every derived key, so it is
// versioned in place rather than edited.
const sealKeyInfo = "correlix/sealed-fields/v1"

// deriveSealKey expands a tenant DEK into the key used for field sealing.
// HKDF-Expand (not Extract) is correct here: the DEK is already a uniformly
// random 256-bit key, so there is no entropy to condense — only to separate by
// purpose and version.
func deriveSealKey(dek []byte, version int) ([]byte, error) {
	if len(dek) < 32 {
		return nil, fmt.Errorf("sealing: tenant key material is too short (%d bytes)", len(dek))
	}
	info := fmt.Sprintf("%s/key-%d", sealKeyInfo, version)
	out, err := hkdf.Expand(sha256.New, dek, info, 32) // AES-256
	if err != nil {
		return nil, fmt.Errorf("sealing: derive key: %w", err)
	}
	return out, nil
}

// macKey derives the authentication key. Encrypt-then-MAC with a SEPARATE key
// from the encryption key: reusing one key for both is the classic misuse, and
// deriving costs one HKDF call per seal.
func macKey(sealKey []byte) ([]byte, error) {
	out, err := hkdf.Expand(sha256.New, sealKey, sealKeyInfo+"/mac", 32)
	if err != nil {
		return nil, fmt.Errorf("sealing: derive mac key: %w", err)
	}
	return out, nil
}

// computeMAC authenticates the ciphertext TOGETHER WITH its context. The
// context fields are length-prefixed so that ("ab","c") and ("a","bc") cannot
// produce the same MAC input — canonical encoding, not naive concatenation.
func computeMAC(key []byte, c Context, version int, iv, ciphertext []byte) []byte {
	m := hmac.New(sha256.New, key)
	write := func(s string) {
		// Callers reach here only through Context.valid(), which caps each field
		// at maxContextField; the clamp is belt-and-braces so the uint32 prefix
		// can never truncate silently on a path that skipped validation.
		if len(s) > maxContextField {
			s = s[:maxContextField]
		}
		var n [4]byte
		// #nosec G115 -- len(s) is clamped to maxContextField (512) on the line
		// above, so the uint32 conversion provably cannot overflow. gosec does
		// not follow the clamp through the reassignment of s.
		binary.BigEndian.PutUint32(n[:], uint32(len(s)))
		m.Write(n[:])
		m.Write([]byte(s))
	}
	write(tokenVersion)
	write(c.Tenant)
	write(c.ProcessorID)
	write(c.Field)
	write(c.DataType)
	write(fmt.Sprint(version))
	m.Write(iv)
	m.Write(ciphertext)
	return m.Sum(nil)
}

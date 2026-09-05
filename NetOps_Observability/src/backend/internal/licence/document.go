// Package licence implements the Correlix licence FILE: a JSON document signed
// with ed25519 (Go stdlib `crypto/ed25519`), verified offline, that supplies the
// answers the central entitlement service (internal/entitlement) hands to
// business code.
//
// Design of record: docs/design/LICENSING_MODEL_2026-09-04.md §3 (the file) and
// §4 (the enforcement points), refined by the binding owner spec of 2026-09-04.
//
// # Division of labour
//
//	internal/entitlement  the SEMANTIC layer: Feature/Ceiling vocabulary, the
//	                      Service interface, the structured 402 refusal. Business
//	                      code and future enterprise/** packages import ONLY this.
//	internal/licence      THIS package: the file format, the ed25519 verification,
//	                      the store, and one implementation of entitlement.Service.
//
// The direction is deliberate. Swapping the licence file for some other source
// of truth later must not touch a single call site.
//
// # Properties this package exists to hold
//
//   - **Offline.** No activation server, no phone-home. The public keys are
//     embedded in the binary and published, so a customer can verify a file we
//     issued them without talking to us (`correlix-licence verify`).
//   - **Enforce by data, not by hiding code.** One binary, one image set; a tier
//     is a file, never a build.
//   - **Degrade honestly.** Over-ceiling items are LISTED, never hidden and
//     never deleted (see Service.Overages).
//   - **A licence problem can never weaken a safety property.** Isolation, RLS,
//     authorization, integrity and core authentication (OIDC included) do not
//     consult this package at all. See internal/entitlement's package doc and
//     safety_invariant_test.go.
//
// # Expiry, grace and overage (owner decision, 2026-09-05)
//
// The policy is decided and recorded in docs/design/TIERING_PLAN_2026-09-03.md
// §9 and the LICENSING_MODEL addendum. Three states, and the file states its
// own terms:
//
//	valid       now <= expires_at.
//	in_grace    expires_at < now <= expires_at + grace_days. NOTHING changes for
//	            the user; the page and a warning alert say how long is left.
//	post_grace  past that. The commercial ceilings and features fall back to
//	            Community for CREATION and CONFIGURATION only: existing data
//	            stays viewable and exportable (State.LapsedFeatures is what
//	            entitlement.RequireRead honours), over-ceiling state is LISTED,
//	            and nothing is disabled or deleted.
//
// The DEFAULTS live in the issuer (`correlix-licence sign`): 30 days for a paid
// tier, 7 for a trial, and whatever `--grace-days` says when it is given. There
// is still no default in the FORMAT — a file that omits `grace_days` carries
// zero — so a licence issued before the policy existed is never reinterpreted
// by it.
//
// No part of this touches a safety property. Isolation, RLS, authorization,
// integrity and core authentication do not consult this package
// (internal/entitlement/safety_invariant_test.go), so there is no expiry state
// in which they differ.
package licence

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"netops/backend/internal/entitlement"
)

// Support is the support entitlement recorded in the licence. Informational:
// nothing in the product gates on it. The admin page shows it so an operator
// knows who to call.
type Support struct {
	Level   string `json:"level,omitempty"`
	Contact string `json:"contact,omitempty"`
}

// Document is the on-disk licence file (design §3).
//
// Field order below IS the canonical signing order — see CanonicalPayload.
// `key_id` and `signature` sit outside the signed payload for the obvious
// reason that a signature cannot cover itself.
type Document struct {
	LicenceID string                `json:"licence_id"`
	Customer  string                `json:"customer"`
	Tier      entitlement.Tier      `json:"tier"`
	IssuedAt  time.Time             `json:"issued_at"`
	ExpiresAt time.Time             `json:"expires_at"`
	Ceilings  entitlement.Ceilings  `json:"ceilings"`
	Features  []entitlement.Feature `json:"features"`
	Support   Support               `json:"support,omitzero"`
	// GraceDays is issuer-set: the number of days AFTER ExpiresAt during which
	// the licence keeps working exactly as before.
	//
	// There is still no default IN THE FORMAT, and that is deliberate. The
	// owner's 2026-09-05 policy (30 days for paid tiers, 7 for trials) is
	// applied by the ISSUER, in `correlix-licence sign`, and lands in the file
	// as an explicit number. A file that omits the field carries zero, exactly
	// as it always did — already-issued licences are never reinterpreted by a
	// later change of policy, which is what keeps a signed document a complete
	// statement of its own terms.
	GraceDays int `json:"grace_days"`
	// Trial marks an EVALUATION licence: a short, signed Team/Enterprise file
	// issued with no card, which works offline like any other (owner decision,
	// 2026-09-05, TIERING_PLAN §9 "Trials"). It changes NOTHING about
	// enforcement — a trial grants exactly what its tier, ceilings and features
	// say — and exists so the product can say "Evaluation licence, N days left"
	// instead of leaving a customer to discover the difference at expiry.
	//
	// It is `omitempty` in the canonical payload as well as here, so a
	// non-trial document signs to the byte sequence it always did and every
	// licence issued before this field existed still verifies.
	Trial bool `json:"trial,omitempty"`

	// KeyID names the signing key so rotation is diagnosable ("signed by the
	// retired key", "signed by a key this build does not trust") rather than an
	// undifferentiated "bad signature".
	KeyID string `json:"key_id"`
	// Signature is standard base64 of the ed25519 signature over
	// CanonicalPayload.
	Signature string `json:"signature"`
}

// canonicalPayload mirrors Document minus key_id and signature. It is a
// separate type rather than a `json:"-"` trick so the canonical form cannot
// drift by accident: adding a field to Document without adding it here breaks
// the round-trip test in document_test.go.
type canonicalPayload struct {
	LicenceID string                `json:"licence_id"`
	Customer  string                `json:"customer"`
	Tier      entitlement.Tier      `json:"tier"`
	IssuedAt  string                `json:"issued_at"`
	ExpiresAt string                `json:"expires_at"`
	Ceilings  entitlement.Ceilings  `json:"ceilings"`
	Features  []entitlement.Feature `json:"features"`
	Support   Support               `json:"support"`
	GraceDays int                   `json:"grace_days"`
	// Trial is `omitempty` so a NON-trial document canonicalises to exactly the
	// bytes it did before this field existed. That is what makes the field a
	// backward-compatible addition rather than a mass invalidation of every
	// licence ever issued. A trial document carries `"trial":true` and the
	// signature covers it, so the flag can be neither added to nor stripped
	// from a signed file.
	Trial bool `json:"trial,omitempty"`
}

// CanonicalPayload is the exact byte sequence the signature covers.
//
// Canonicalisation matters because the signer and the verifier must agree
// byte-for-byte across Go versions, pretty-printers and whatever an operator's
// editor does to the file. Three rules do it:
//
//  1. a FIXED field order (Go marshals struct fields in declaration order),
//  2. timestamps as RFC3339 in UTC, so a file re-serialised in another zone
//     still verifies,
//  3. features sorted and de-duplicated, so a list's order carries no meaning.
//
// Everything outside the payload — whitespace, key order in the outer file,
// trailing newlines — is therefore free: an operator can pretty-print an issued
// licence and it still verifies.
func CanonicalPayload(d Document) ([]byte, error) {
	p := canonicalPayload{
		LicenceID: d.LicenceID,
		Customer:  d.Customer,
		Tier:      d.Tier,
		IssuedAt:  d.IssuedAt.UTC().Format(time.RFC3339),
		ExpiresAt: d.ExpiresAt.UTC().Format(time.RFC3339),
		Ceilings:  d.Ceilings,
		Features:  NormaliseFeatures(d.Features),
		Support:   d.Support,
		GraceDays: d.GraceDays,
		Trial:     d.Trial,
	}
	if p.Features == nil {
		// An explicit empty array, never `null`: "no features" must have one
		// byte sequence, not two.
		p.Features = []entitlement.Feature{}
	}
	return json.Marshal(p)
}

// NormaliseFeatures sorts and de-duplicates a feature list so a document has
// exactly one canonical representation.
func NormaliseFeatures(in []entitlement.Feature) []entitlement.Feature {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[entitlement.Feature]bool, len(in))
	out := make([]entitlement.Feature, 0, len(in))
	for _, f := range in {
		if f == "" || seen[f] {
			continue
		}
		seen[f] = true
		out = append(out, f)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// ─────────────────────────────────────────────────────────────────────────────
// Keys
// ─────────────────────────────────────────────────────────────────────────────

// PublicKey is a trusted signing key with its identity and role.
type PublicKey struct {
	// ID is the key fingerprint (see KeyID) — what a Document names.
	ID string `json:"id"`
	// Key is the raw ed25519 public key.
	Key ed25519.PublicKey `json:"-"`
	// Role is "current" or "previous" (design §3: "the binary carries the
	// current + previous key").
	Role string `json:"role"`
	// Purpose is what this key is ALLOWED to sign: PurposeLab or
	// PurposeProduction. It is a separate axis from Role — a lab key can be the
	// current one, which is exactly the state this build is in — and it exists
	// so "may a release be cut with this key set?" is answerable by a machine
	// instead of by reading a note. Empty means UNLABELLED and is treated as
	// not-production by ReleaseReady: the guard fails closed.
	Purpose string `json:"purpose,omitempty"`
	// Note records the ceremony this key came from, so an operator reading the
	// admin page or `correlix-licence verify` knows which key they are looking
	// at without a lookup.
	Note string `json:"note,omitempty"`
	// Base64 is the standard-base64 encoding an operator copies out of the admin
	// page and pastes into an offline verification.
	Base64 string `json:"base64"`
}

// Key roles.
const (
	RoleCurrent  = "current"
	RolePrevious = "previous"
)

// Key purposes — what a key is permitted to sign. The vocabulary is closed:
// docs/runbooks/licence-signing-ceremony.md is the procedure that turns a
// generated key into a PurposeProduction entry, and nothing else may.
const (
	// PurposeLab is a development key generated on a lab host. It signs lab and
	// trial licences and MUST NEVER be promoted to production, whatever its
	// role.
	PurposeLab = "lab"
	// PurposeProduction is a key generated by the two-person offline ceremony
	// and held in HSM/sealed custody. Only such a key may sign a customer
	// licence.
	PurposeProduction = "production"
)

// KeyID is a public key's fingerprint: the first 8 bytes of its SHA-256, hex.
// Short enough to read aloud during a key ceremony, long enough that two keys
// colliding is not a thing that happens.
func KeyID(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:8])
}

// NewPublicKey builds a PublicKey record from a raw key, with no purpose
// label. An unlabelled key verifies exactly as before — labelling governs what
// may SIGN a release, not what may be verified — and, being unlabelled, it can
// never make a build look release-ready (see ReleaseReady).
func NewPublicKey(pub ed25519.PublicKey, role, note string) PublicKey {
	return NewPublicKeyWithPurpose(pub, role, "", note)
}

// NewPublicKeyWithPurpose builds a PublicKey record and states what the key is
// allowed to sign (PurposeLab or PurposeProduction). This is the constructor
// the embedded set uses; ad-hoc keys supplied on a command line stay unlabelled.
func NewPublicKeyWithPurpose(pub ed25519.PublicKey, role, purpose, note string) PublicKey {
	return PublicKey{
		ID:      KeyID(pub),
		Key:     pub,
		Role:    role,
		Purpose: purpose,
		Note:    note,
		Base64:  base64.StdEncoding.EncodeToString(pub),
	}
}

// ParsePublicKey decodes a standard-base64 ed25519 public key.
func ParsePublicKey(s string) (ed25519.PublicKey, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return nil, fmt.Errorf("%w: public key is not base64: %w", ErrMalformed, err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%w: public key is %d bytes, want %d", ErrMalformed, len(raw), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(raw), nil
}

// ─────────────────────────────────────────────────────────────────────────────
// Errors
// ─────────────────────────────────────────────────────────────────────────────

var (
	// ErrMalformed — the bytes are not a well-formed licence document.
	ErrMalformed = errors.New("licence: malformed document")
	// ErrSignature — the document did not authenticate against the named key.
	ErrSignature = errors.New("licence: signature does not verify")
	// ErrUnknownKey — the document names a signing key this build does not
	// trust. Distinct from ErrSignature so a rotation mistake is diagnosable.
	ErrUnknownKey = errors.New("licence: unknown signing key")
	// ErrVocabulary — the document uses a tier or feature outside the closed
	// vocabulary. Refused, never ignored: a typo in an issued licence must be a
	// loud refusal at issue time, not a capability the customer paid for and
	// silently did not get.
	ErrVocabulary = errors.New("licence: value outside the closed vocabulary")
)

// Validate checks a document's SHAPE and vocabulary, independent of its
// signature. Called by the verifier after the signature checks out, and by the
// signer BEFORE signing, so an invalid licence can never be issued in the first
// place.
func (d Document) Validate() error {
	switch {
	case strings.TrimSpace(d.LicenceID) == "":
		return fmt.Errorf("%w: licence_id is empty", ErrMalformed)
	case strings.TrimSpace(d.Customer) == "":
		return fmt.Errorf("%w: customer is empty", ErrMalformed)
	case d.IssuedAt.IsZero():
		return fmt.Errorf("%w: issued_at is empty", ErrMalformed)
	case d.ExpiresAt.IsZero():
		return fmt.Errorf("%w: expires_at is empty", ErrMalformed)
	case !d.ExpiresAt.After(d.IssuedAt):
		return fmt.Errorf("%w: expires_at (%s) is not after issued_at (%s)",
			ErrMalformed, d.ExpiresAt.UTC().Format(time.RFC3339), d.IssuedAt.UTC().Format(time.RFC3339))
	case d.GraceDays < 0:
		return fmt.Errorf("%w: grace_days is negative", ErrMalformed)
	}
	if !entitlement.ValidTier(d.Tier) {
		return fmt.Errorf("%w: tier %q", ErrVocabulary, d.Tier)
	}
	for _, f := range d.Features {
		if !entitlement.ValidFeature(f) {
			return fmt.Errorf("%w: feature %q", ErrVocabulary, f)
		}
	}
	for _, n := range entitlement.CeilingNames() {
		v, _ := d.Ceilings.Get(n)
		if v < entitlement.Unlimited {
			return fmt.Errorf("%w: ceiling %s is %d (only -1 means unlimited)", ErrMalformed, n, v)
		}
	}
	return nil
}

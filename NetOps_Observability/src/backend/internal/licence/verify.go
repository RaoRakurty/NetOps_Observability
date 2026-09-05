package licence

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"netops/backend/internal/entitlement"
)

// Verifier turns raw licence-file bytes into an evaluated State.
//
// A Verifier NEVER returns a usable State for a document it could not
// cryptographically authenticate: unsigned, tampered, or signed by an untrusted
// key is an ERROR, not a quiet downgrade. Expiry is different in kind — an
// expired file is still authentic, so it verifies and the resulting State
// carries InGrace/Degraded and the honest Reason.
type Verifier interface {
	// Verify authenticates raw and evaluates it as at `now`.
	Verify(raw []byte, now time.Time) (State, error)
	// PublicKeys returns the trusted keys, current first — for the admin page's
	// "download public key" and the runbook's offline verification recipe.
	PublicKeys() []PublicKey
}

// keyVerifier is the ed25519 Verifier. Zero external dependencies: the whole
// mechanism is `crypto/ed25519` plus `encoding/json`, which is exactly why the
// offline promise is credible.
type keyVerifier struct{ keys []PublicKey }

// NewVerifier builds a Verifier over an explicit key set (tests, and
// `correlix-licence verify --pubkey`).
func NewVerifier(keys ...PublicKey) Verifier {
	return &keyVerifier{keys: append([]PublicKey(nil), keys...)}
}

// DefaultVerifier trusts the keys embedded in this build — the current key and,
// after a rotation, the previous one (design §3).
func DefaultVerifier() Verifier { return NewVerifier(EmbeddedKeys()...) }

func (v *keyVerifier) PublicKeys() []PublicKey { return append([]PublicKey(nil), v.keys...) }

// Parse decodes raw into a Document WITHOUT authenticating it. Exported for
// `correlix-licence show`, which must be able to display a file the operator
// cannot verify (that is often exactly why they are looking at it). Every path
// that grants anything goes through Verify instead.
func Parse(raw []byte) (Document, error) {
	var d Document
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	// Reject unknown fields: a licence with a misspelled ceiling must fail
	// loudly at issue/install time rather than silently granting the default.
	dec.DisallowUnknownFields()
	if err := dec.Decode(&d); err != nil {
		return Document{}, fmt.Errorf("%w: %w", ErrMalformed, err)
	}
	return d, nil
}

// Verify authenticates raw against the trusted keys and evaluates the result.
//
// Order is load-bearing:
//
//  1. parse — a document we cannot read is malformed, full stop;
//  2. resolve the named key — an unknown key_id is its OWN error, so a rotation
//     mistake reads as "unknown signing key" and not as "bad signature";
//  3. verify the signature over the canonical payload;
//  4. only then validate shape and vocabulary. Validating first would leak,
//     via error messages, what an unsigned file would have to look like to get
//     further — small, but free to avoid.
func (v *keyVerifier) Verify(raw []byte, now time.Time) (State, error) {
	doc, err := Parse(raw)
	if err != nil {
		return Community(), err
	}
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(doc.Signature))
	if err != nil || len(sig) != ed25519.SignatureSize {
		return Community(), fmt.Errorf("%w: signature is not %d base64 bytes", ErrMalformed, ed25519.SignatureSize)
	}
	key, ok := v.key(doc.KeyID)
	if !ok {
		return Community(), fmt.Errorf("%w: key_id %q (this build trusts %s)",
			ErrUnknownKey, doc.KeyID, v.keyIDs())
	}
	payload, err := CanonicalPayload(doc)
	if err != nil {
		return Community(), fmt.Errorf("%w: %w", ErrMalformed, err)
	}
	if !ed25519.Verify(key.Key, payload, sig) {
		return Community(), fmt.Errorf("%w (key %s): the file was modified after it was issued, or it was not issued by Correlix",
			ErrSignature, doc.KeyID)
	}
	if err := doc.Validate(); err != nil {
		return Community(), err
	}
	return evaluate(doc, now), nil
}

// key resolves a key_id. An EMPTY key_id is not accepted by any lookup: a
// document must name the key it was signed with, so "try them all until one
// works" — the shape that makes key rotation untraceable — is impossible here.
func (v *keyVerifier) key(id string) (PublicKey, bool) {
	id = strings.TrimSpace(id)
	if id == "" {
		return PublicKey{}, false
	}
	for _, k := range v.keys {
		if k.ID == id {
			return k, true
		}
	}
	return PublicKey{}, false
}

func (v *keyVerifier) keyIDs() string {
	if len(v.keys) == 0 {
		return "no keys"
	}
	ids := make([]string, 0, len(v.keys))
	for _, k := range v.keys {
		ids = append(ids, k.ID+" ("+k.Role+")")
	}
	return strings.Join(ids, ", ")
}

// ─────────────────────────────────────────────────────────────────────────────
// Evaluation
// ─────────────────────────────────────────────────────────────────────────────

// evaluate turns an authenticated document into the State the product reads.
//
// EXPIRY SEMANTICS ARE AN OWNER DECISION PENDING (see the package doc). What is
// implemented is the mechanism and nothing more:
//
//	now <= expires_at                    → live at the licensed tier.
//	expires_at < now <= +grace_days      → InGrace: still the licensed tier, with
//	                                       a Reason the banner and the warning
//	                                       alert rule show. grace_days is
//	                                       ISSUER-SET; omitted means zero.
//	now > expires_at + grace_days        → Degraded: the effective ceilings and
//	                                       features fall back to Community, the
//	                                       licensed tier is REMEMBERED (so the
//	                                       page can say "your Team licence
//	                                       expired" rather than pretending the
//	                                       customer was always Community), and
//	                                       over-ceiling items are LISTED, never
//	                                       hidden and never deleted.
//
// No safety property appears anywhere in this function, and that is the point:
// isolation, RLS, authorization, integrity and core authentication are not
// reachable from any State field.
func evaluate(doc Document, now time.Time) State {
	st := State{
		Source:       SourceFile,
		Tier:         doc.Tier,
		LicensedTier: doc.Tier,
		Ceilings:     doc.Ceilings,
		Features:     NormaliseFeatures(doc.Features),
		Customer:     doc.Customer,
		LicenceID:    doc.LicenceID,
		IssuedAt:     doc.IssuedAt.UTC(),
		ExpiresAt:    doc.ExpiresAt.UTC(),
		GraceDays:    doc.GraceDays,
		Support:      doc.Support,
		KeyID:        doc.KeyID,
	}
	if !now.After(doc.ExpiresAt) {
		return st
	}
	graceEnd := doc.ExpiresAt.Add(time.Duration(doc.GraceDays) * 24 * time.Hour)
	expired := doc.ExpiresAt.UTC().Format("2006-01-02")
	if !now.After(graceEnd) {
		st.InGrace = true
		st.Reason = fmt.Sprintf("licence expired on %s; running at %s under the issuer's %d-day grace until %s",
			expired, doc.Tier.Label(), doc.GraceDays, graceEnd.UTC().Format("2006-01-02"))
		return st
	}
	st.Degraded = true
	st.Tier = entitlement.TierCommunity
	st.Ceilings = entitlement.CommunityCeilings()
	st.Features = nil
	if doc.GraceDays > 0 {
		st.Reason = fmt.Sprintf("licence expired on %s and the %d-day grace ended on %s; running at Community ceilings — nothing has been deleted and everything over a ceiling is listed",
			expired, doc.GraceDays, graceEnd.UTC().Format("2006-01-02"))
	} else {
		st.Reason = fmt.Sprintf("licence expired on %s and carries no grace period; running at Community ceilings — nothing has been deleted and everything over a ceiling is listed",
			expired)
	}
	return st
}

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

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
// THE POST-EXPIRY STATE MACHINE (owner decision, 2026-09-05 —
// docs/design/TIERING_PLAN_2026-09-03.md §9, row "Paid expiry / grace"):
//
//	now <= expires_at                 → valid. Live at the licensed tier.
//	expires_at < now <= +grace_days   → in_grace. NOTHING changes for the user:
//	                                    the licensed tier, ceilings and features
//	                                    are still in force. The page says how
//	                                    many days are left and the LicenceInGrace
//	                                    warning rule fires. grace_days is
//	                                    ISSUER-SET (the signer defaults it to 30
//	                                    for a paid tier, 7 for a trial); a file
//	                                    that omits it carries zero, because a
//	                                    licence issued before the policy existed
//	                                    is never reinterpreted by it.
//	now > expires_at + grace_days     → post_grace. The effective ceilings and
//	                                    features fall back to Community, so
//	                                    CREATION and CONFIGURATION of paid
//	                                    capability refuse (402, carrying
//	                                    licence_state: post_grace). What does NOT
//	                                    happen is the whole point:
//	                                      · LapsedFeatures keeps the granted set,
//	                                        so entitlement.RequireRead still
//	                                        admits reads and exports of existing
//	                                        data;
//	                                      · the licensed tier is REMEMBERED, so
//	                                        the page says "your Team licence
//	                                        expired" rather than pretending the
//	                                        customer was always Community;
//	                                      · over-ceiling items are LISTED, never
//	                                        hidden, never disabled, never
//	                                        deleted, and nothing here chooses
//	                                        which devices "lose" — no such choice
//	                                        is made anywhere.
//
// No safety property appears anywhere in this function, and that is the point:
// isolation, RLS, authorization, integrity and core authentication are not
// reachable from any State field.
func evaluate(doc Document, now time.Time) State {
	graceEnd := doc.ExpiresAt.UTC().Add(time.Duration(doc.GraceDays) * 24 * time.Hour)
	st := State{
		Source:       SourceFile,
		Tier:         doc.Tier,
		LicensedTier: doc.Tier,
		Phase:        entitlement.PhaseValid,
		Ceilings:     doc.Ceilings,
		Features:     NormaliseFeatures(doc.Features),
		Customer:     doc.Customer,
		LicenceID:    doc.LicenceID,
		IssuedAt:     doc.IssuedAt.UTC(),
		ExpiresAt:    doc.ExpiresAt.UTC(),
		GraceEndsAt:  graceEnd,
		GraceDays:    doc.GraceDays,
		Trial:        doc.Trial,
		Support:      doc.Support,
		KeyID:        doc.KeyID,
	}
	if !now.After(doc.ExpiresAt) {
		return st
	}
	expired := doc.ExpiresAt.UTC().Format("2006-01-02")
	kind := "licence"
	if doc.Trial {
		kind = "evaluation licence"
	}
	if !now.After(graceEnd) {
		st.Phase = entitlement.PhaseInGrace
		st.InGrace = true
		st.Reason = fmt.Sprintf("%s expired on %s; nothing has changed yet — the %s ceilings and capabilities stay in force under the issuer's %d-day grace until %s",
			kind, expired, doc.Tier.Label(), doc.GraceDays, graceEnd.UTC().Format("2006-01-02"))
		return st
	}
	st.Phase = entitlement.PhasePostGrace
	st.Degraded = true
	st.Tier = entitlement.TierCommunity
	st.Ceilings = entitlement.CommunityCeilings()
	// The granted set moves to LapsedFeatures rather than being discarded: what
	// the customer already has stays readable and exportable, and only creating
	// or configuring more is refused.
	st.LapsedFeatures = st.Features
	st.Features = nil
	grace := fmt.Sprintf("the %d-day grace ended on %s", doc.GraceDays, graceEnd.UTC().Format("2006-01-02"))
	if doc.GraceDays <= 0 {
		grace = "it carries no grace period"
	}
	st.Reason = fmt.Sprintf("%s expired on %s and %s; the Community ceilings are the ones in force. "+
		"Existing data stays visible and exportable and everything over a ceiling is listed — nothing has been disabled or deleted. "+
		"Creating or configuring paid capability is refused until a renewed licence is installed",
		kind, expired, grace)
	return st
}

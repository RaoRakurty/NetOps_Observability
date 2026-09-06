// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package licence

import (
	"errors"
	"fmt"
	"strings"
	"sync"
)

// keys.go — the PUBLIC signing keys this build trusts.
//
// Design §3: "the public key is embedded in the binary AND printed in the docs
// so a customer can verify a file themselves. Key rotation: the binary carries
// the current + previous key."
//
// Public keys only. There is no private key in this repository, in any build,
// or in any container image — signing happens on a separate machine with the
// key custody described in docs/runbooks/licensing.md §6, and, for the
// production key, under the two-person offline ceremony in
// docs/runbooks/licence-signing-ceremony.md. That is checkable, not just
// stated: nothing in the api's import graph reaches internal/licence/signer.
//
// # Rotation procedure
//
//  1. Generate the new key on the signing host (`correlix-licence keygen`).
//     For a PRODUCTION key that generation is the ceremony, not a command run
//     on a laptop — docs/runbooks/licence-signing-ceremony.md §3.
//  2. Move the entry below that is currently RoleCurrent to RolePrevious.
//  3. Add the new key as RoleCurrent, with its purpose stated.
//  4. Ship. Both keys verify, so every licence already in the field keeps
//     working while new ones are issued under the new key.
//  5. After every outstanding licence has been reissued (i.e. after the longest
//     term expires), drop the previous entry.
//
// Never more than two entries: a build that trusts a long tail of retired keys
// has no rotation story, it has an accumulation story.

// embeddedKeySpec is a key as declared in source: base64 plus its role, its
// purpose (what it is allowed to sign) and the ceremony note. Parsed once, at
// first use.
type embeddedKeySpec struct {
	base64  string
	role    string
	purpose string
	note    string
}

// embeddedKeySpecs is the trusted set.
//
// The LAB key below is exactly what its note says: a development key generated
// on the owner's lab host on 2026-09-04 so lab licences can be issued today. It
// is NOT a production key and no production customer licence will ever be signed
// with it. The production key ceremony
// (docs/runbooks/licence-signing-ceremony.md — BLOCKED ON CUSTODIANS) has not
// happened yet; when it does, its public key is added here as RoleCurrent with
// PurposeProduction, and this one becomes RolePrevious and is then dropped, per
// the rotation procedure above.
//
// The `purpose` field is not decoration: ReleaseReady reads it, so promoting the
// lab key by editing its role alone cannot make a build look release-ready.
var embeddedKeySpecs = []embeddedKeySpec{
	{
		base64:  "Q+PMj3/TNIjbRvopQwXLM5tJfgjzPTsoHIWwiM0apR8=",
		role:    RoleCurrent,
		purpose: PurposeLab,
		note:    "LAB/dev key, generated 2026-09-04 on the owner's lab host — issues lab and trial licences only; superseded by the production key at its ceremony",
	},
}

// embeddedKeys parses the specs once. A malformed or mislabelled spec is a
// build-time mistake that must be loud, so it panics rather than quietly
// trusting fewer keys — a binary that silently trusts NO key would refuse every
// valid licence and look like a customer problem, and a key with an unknown
// purpose would defeat the release guard below.
var embeddedKeys = sync.OnceValue(func() []PublicKey {
	out := make([]PublicKey, 0, len(embeddedKeySpecs))
	for _, s := range embeddedKeySpecs {
		pub, err := ParsePublicKey(s.base64)
		if err != nil {
			panic(fmt.Sprintf("licence: embedded %s key is malformed: %v", s.role, err))
		}
		if s.purpose != PurposeLab && s.purpose != PurposeProduction {
			panic(fmt.Sprintf("licence: embedded %s key has purpose %q, want %q or %q", s.role, s.purpose, PurposeLab, PurposeProduction))
		}
		out = append(out, NewPublicKeyWithPurpose(pub, s.role, s.purpose, s.note))
	}
	return out
})

// EmbeddedKeys returns the public keys this build trusts, current first.
func EmbeddedKeys() []PublicKey { return append([]PublicKey(nil), embeddedKeys()...) }

// CurrentKey returns the key new licences are expected to be signed with.
func CurrentKey() (PublicKey, bool) {
	for _, k := range embeddedKeys() {
		if k.Role == RoleCurrent {
			return k, true
		}
	}
	return PublicKey{}, false
}

// ErrNoProductionKey is what ReleaseReady returns while the trusted set contains
// no PurposeProduction key. It is not a defect and not a runtime failure: it is
// the state this build is deliberately in until the ceremony happens, and the
// thing a release step must refuse on.
var ErrNoProductionKey = errors.New("licence: no production signing key is embedded in this build")

// ReleaseReady reports whether this build's embedded key set is fit to ship to a
// customer: it returns nil only when at least one trusted key is labelled
// PurposeProduction.
//
// Why this exists (tracker 259, owner decision 2026-09-05). A licence signed by
// the lab key verifies perfectly — that is the point of the lab key — so nothing
// in the verification path can tell a customer release apart from a lab one. The
// only place the difference is visible is the SET OF KEYS THE BUILD CARRIES, and
// this is the machine-readable form of that question. `correlix-licence keys
// --release-check` is the operator surface for it; the release procedure in
// docs/runbooks/licence-signing-ceremony.md §10 names both.
//
// It is deliberately NOT called at boot: shipping the lab key is the correct
// state today, and a running installation that verifies a lab licence is doing
// exactly what it should. The question is only asked when a release is cut.
func ReleaseReady() error { return releaseReady(embeddedKeys()) }

// releaseReady is the pure form, so both outcomes are testable without inventing
// a production key in the shipped set.
func releaseReady(keys []PublicKey) error {
	if len(keys) == 0 {
		return fmt.Errorf("%w: the build trusts no signing key at all", ErrNoProductionKey)
	}
	for _, k := range keys {
		if k.Purpose == PurposeProduction {
			return nil
		}
	}
	described := make([]string, 0, len(keys))
	for _, k := range keys {
		purpose := k.Purpose
		if purpose == "" {
			purpose = "unlabelled"
		}
		described = append(described, fmt.Sprintf("%s (%s, %s)", k.ID, k.Role, purpose))
	}
	return fmt.Errorf("%w: it trusts only %s — see docs/runbooks/licence-signing-ceremony.md", ErrNoProductionKey, strings.Join(described, ", "))
}

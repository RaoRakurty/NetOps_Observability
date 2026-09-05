package licence

import (
	"fmt"
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
// key custody described in docs/runbooks/licensing.md. That is checkable, not
// just stated: nothing in the api's import graph reaches
// internal/licence/signer.
//
// # Rotation procedure
//
//  1. Generate the new key on the signing host (`correlix-licence keygen`).
//  2. Move the entry below that is currently RoleCurrent to RolePrevious.
//  3. Add the new key as RoleCurrent.
//  4. Ship. Both keys verify, so every licence already in the field keeps
//     working while new ones are issued under the new key.
//  5. After every outstanding licence has been reissued (i.e. after the longest
//     term expires), drop the previous entry.
//
// Never more than two entries: a build that trusts a long tail of retired keys
// has no rotation story, it has an accumulation story.

// embeddedKeySpec is a key as declared in source: base64 plus its role and the
// ceremony note. Parsed once, at first use.
type embeddedKeySpec struct {
	base64 string
	role   string
	note   string
}

// embeddedKeySpecs is the trusted set.
//
// The LAB key below is exactly what its note says: a development key generated
// on the owner's lab host on 2026-09-04 so lab licences can be issued today. It
// is NOT a production key and no production customer licence will ever be signed
// with it. The production key ceremony (docs/runbooks/licensing.md §"Key
// ceremony") has not happened yet; when it does, its public key is added here as
// RoleCurrent and this one becomes RolePrevious and is then dropped, per the
// rotation procedure above.
var embeddedKeySpecs = []embeddedKeySpec{
	{
		base64: "Q+PMj3/TNIjbRvopQwXLM5tJfgjzPTsoHIWwiM0apR8=",
		role:   RoleCurrent,
		note:   "LAB/dev key, generated 2026-09-04 on the owner's lab host — issues lab and trial licences only; superseded by the production key at its ceremony",
	},
}

// embeddedKeys parses the specs once. A malformed spec is a build-time mistake
// that must be loud, so it panics rather than quietly trusting fewer keys — a
// binary that silently trusts NO key would refuse every valid licence and look
// like a customer problem.
var embeddedKeys = sync.OnceValue(func() []PublicKey {
	out := make([]PublicKey, 0, len(embeddedKeySpecs))
	for _, s := range embeddedKeySpecs {
		pub, err := ParsePublicKey(s.base64)
		if err != nil {
			panic(fmt.Sprintf("licence: embedded %s key is malformed: %v", s.role, err))
		}
		out = append(out, NewPublicKey(pub, s.role, s.note))
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

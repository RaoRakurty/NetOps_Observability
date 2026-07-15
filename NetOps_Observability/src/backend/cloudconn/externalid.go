package cloudconn

import (
	"crypto/rand"
	"encoding/base32"
	"strings"
)

// externalIDBytes = 20 bytes = 160 bits of entropy. base32 (no padding) → 32
// chars. Unpredictable and non-enumerable; well within AWS's ExternalId charset
// and length limits (2–1224 chars, [A-Za-z0-9+=,.@:/-]).
const externalIDBytes = 20

// externalIDPrefix labels the value so it is self-describing in trust policies and
// audit without leaking the tenant/connector it belongs to.
const externalIDPrefix = "correlix-"

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// NewExternalID mints a cryptographically-random AWS STS ExternalId. It is the
// confused-deputy protection for cross-account AssumeRole and is UNIQUE PER
// tenant+connector and UNPREDICTABLE. It is DERIVED FROM RANDOMNESS ONLY — never
// from tenant name/slug/account id/email/display name (deriving it from any of
// those would make it guessable and defeat the protection).
//
// Panics only if the OS CSPRNG fails (unrecoverable — we must never mint a
// predictable ExternalId), consistent with the rest of the identity crypto.
func NewExternalID() string {
	var b [externalIDBytes]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("cloudconn: CSPRNG unavailable for ExternalId: " + err.Error())
	}
	return externalIDPrefix + strings.ToLower(b32.EncodeToString(b[:]))
}

// ValidExternalID reports whether s looks like a minted ExternalId: correct
// prefix and enough encoded entropy. Used to reject operator-supplied or derived
// values that would weaken confused-deputy protection.
func ValidExternalID(s string) bool {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, externalIDPrefix) {
		return false
	}
	enc := strings.TrimPrefix(s, externalIDPrefix)
	// 20 bytes → 32 base32 chars (no padding).
	if len(enc) != b32.EncodedLen(externalIDBytes) {
		return false
	}
	if _, err := b32.DecodeString(strings.ToUpper(enc)); err != nil {
		return false
	}
	return true
}

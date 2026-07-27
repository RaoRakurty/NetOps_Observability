package totp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // TOTP (RFC 6238) is defined over HMAC-SHA1; this is the interop standard, not a security hash choice
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// totp.go — time-based one-time passwords (RFC 6238) for local-account MFA.
// Stdlib only (HMAC-SHA1 per the spec, base32 secrets) — no third-party module.
// SHA1 here is the RFC-mandated interop primitive for authenticator apps, not a
// general-purpose hash choice, so the gosec flag is suppressed deliberately.

const (
	totpDigits = 6
	totpPeriod = 30 * time.Second
	// totpSkew tolerates ±1 step (±30s) of clock drift between server and phone.
	totpSkew = 1
)

// NewSecret returns a fresh base32 (no-padding) secret suitable for an
// authenticator app. 20 bytes = 160 bits, the RFC 4226 recommendation.
func NewSecret() (string, error) {
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return strings.ToUpper(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b)), nil
}

// URI builds the otpauth:// provisioning URI an authenticator app scans (as a
// QR code). issuer + account label the entry in the user's app.
func URI(secret, issuer, account string) string {
	label := url.PathEscape(issuer + ":" + account)
	q := url.Values{}
	q.Set("secret", secret)
	q.Set("issuer", issuer)
	q.Set("algorithm", "SHA1")
	q.Set("digits", fmt.Sprintf("%d", totpDigits))
	q.Set("period", fmt.Sprintf("%d", int(totpPeriod.Seconds())))
	return "otpauth://totp/" + label + "?" + q.Encode()
}

// At computes the TOTP code for a secret at a point in time. Returns "" if the
// secret can't be decoded.
func At(secret string, t time.Time) string {
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(strings.TrimSpace(secret)))
	if err != nil || len(key) == 0 {
		return ""
	}
	counter := uint64(t.Unix()) / uint64(totpPeriod.Seconds())
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], counter)
	mac := hmac.New(sha1.New, key)
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	bin := (uint32(sum[offset]&0x7f) << 24) | (uint32(sum[offset+1]) << 16) | (uint32(sum[offset+2]) << 8) | uint32(sum[offset+3])
	mod := uint32(1)
	for i := 0; i < totpDigits; i++ {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", totpDigits, bin%mod)
}

// Verify reports whether code matches the secret within ±totpSkew steps of
// now (clock-drift tolerance), using a constant-time compare per candidate.
func Verify(secret, code string) bool {
	code = strings.TrimSpace(code)
	if len(code) != totpDigits || secret == "" {
		return false
	}
	now := time.Now()
	for i := -totpSkew; i <= totpSkew; i++ {
		want := At(secret, now.Add(time.Duration(i)*totpPeriod))
		if want != "" && subtle.ConstantTimeCompare([]byte(want), []byte(code)) == 1 {
			return true
		}
	}
	return false
}

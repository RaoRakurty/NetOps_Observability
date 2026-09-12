// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package sealing

// token.go — the self-describing sealed-value token.
//
//	<enc:v1:tenant:keyVersion:iv:ciphertext:mac>
//
// Every field a reader needs to unseal is IN the token. That is what lets the
// unseal API take the token itself rather than a document id: our logs live in
// OpenSearch, ClickHouse and retention windows with no stable cross-store
// identity, so "unseal this value" is answerable while "unseal field X of
// document Y" is not.
//
// Encoding rules, and why:
//   - angle brackets delimit it so a token is recognisable inside a free-text
//     log line and can be extracted by eye or by regex;
//   - ":" separates parts, and every variable part is base64url (no padding,
//     no ":"), so parsing is unambiguous without escaping;
//   - the tenant is base64url too — tenant ids are UUID-ish today but must not
//     become a parsing constraint tomorrow;
//   - the VERSION LEADS, so a future format is detectable before anything else
//     is interpreted.
//
// The token is NOT a secret in itself: it carries ciphertext plus routing
// metadata. It is still access-controlled, because possession is what the
// unseal API operates on and because the tenant id is metadata.

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
)

const (
	// tokenVersion is the format version — bumped when the LAYOUT changes, and
	// covered by the MAC so a downgrade cannot be forged.
	tokenVersion = "v1"
	tokenPrefix  = "<enc:"
	tokenSuffix  = ">"
	// tokenParts is the field count INSIDE the envelope (the "<enc:" prefix and
	// ">" suffix are stripped first): version, tenant, keyVersion, iv,
	// ciphertext, mac.
	tokenParts = 6
)

var b64 = base64.RawURLEncoding

// token is the parsed form of a sealed value.
type token struct {
	Tenant     string
	KeyVersion int
	IV         []byte
	Ciphertext []byte
	MAC        []byte
}

// encode renders the wire form.
func encodeToken(t token) string {
	var b strings.Builder
	b.Grow(len(t.Ciphertext)*2 + 96)
	b.WriteString(tokenPrefix)
	b.WriteString(tokenVersion)
	b.WriteByte(':')
	b.WriteString(b64.EncodeToString([]byte(t.Tenant)))
	b.WriteByte(':')
	b.WriteString(strconv.Itoa(t.KeyVersion))
	b.WriteByte(':')
	b.WriteString(b64.EncodeToString(t.IV))
	b.WriteByte(':')
	b.WriteString(b64.EncodeToString(t.Ciphertext))
	b.WriteByte(':')
	b.WriteString(b64.EncodeToString(t.MAC))
	b.WriteString(tokenSuffix)
	return b.String()
}

// IsSealed reports whether a string looks like a sealed token. Cheap and
// allocation-free — the UI calls it per rendered field.
func IsSealed(s string) bool {
	return strings.HasPrefix(s, tokenPrefix) && strings.HasSuffix(s, tokenSuffix)
}

// parseToken decodes the wire form. It validates SHAPE only — never trust,
// authenticity is the MAC's job — and returns ErrMalformed for anything it
// cannot read, so a malformed value can never be mistaken for a tampered one.
func parseToken(s string) (token, error) {
	if !IsSealed(s) {
		return token{}, fmt.Errorf("%w: missing <enc:…> envelope", ErrMalformed)
	}
	body := s[len(tokenPrefix) : len(s)-len(tokenSuffix)]
	parts := strings.Split(body, ":")
	if len(parts) != tokenParts {
		return token{}, fmt.Errorf("%w: expected %d fields, got %d", ErrMalformed, tokenParts, len(parts))
	}
	if parts[0] != tokenVersion {
		// A future/unknown version is NOT malformed input — it is a value this
		// build cannot read, which is an operationally different situation.
		return token{}, fmt.Errorf("%w: unsupported token version %q", ErrKeyUnavailable, parts[0])
	}
	tenant, err := b64.DecodeString(parts[1])
	if err != nil {
		return token{}, fmt.Errorf("%w: tenant: %w", ErrMalformed, err)
	}
	kv, err := strconv.Atoi(parts[2])
	if err != nil || kv < 1 {
		return token{}, fmt.Errorf("%w: key version", ErrMalformed)
	}
	iv, err := b64.DecodeString(parts[3])
	if err != nil {
		return token{}, fmt.Errorf("%w: iv: %w", ErrMalformed, err)
	}
	ct, err := b64.DecodeString(parts[4])
	if err != nil {
		return token{}, fmt.Errorf("%w: ciphertext: %w", ErrMalformed, err)
	}
	mac, err := b64.DecodeString(parts[5])
	if err != nil {
		return token{}, fmt.Errorf("%w: mac: %w", ErrMalformed, err)
	}
	if len(iv) != ivLen {
		return token{}, fmt.Errorf("%w: iv length %d", ErrMalformed, len(iv))
	}
	if len(mac) != macLen {
		return token{}, fmt.Errorf("%w: mac length %d", ErrMalformed, len(mac))
	}
	return token{Tenant: string(tenant), KeyVersion: kv, IV: iv, Ciphertext: ct, MAC: mac}, nil
}

// TenantOf reports the tenant a token was sealed for WITHOUT unsealing it, so
// the API can reject a cross-tenant unseal attempt before touching key
// material. Unauthenticated by design: it is a routing hint used to deny
// early, never to grant — the MAC still binds the tenant on the unseal path.
func TenantOf(s string) (string, bool) {
	t, err := parseToken(s)
	if err != nil {
		return "", false
	}
	return t.Tenant, true
}

// KeyVersionOf exposes the key version for audit records and rotation reporting.
func KeyVersionOf(s string) (int, bool) {
	t, err := parseToken(s)
	if err != nil {
		return 0, false
	}
	return t.KeyVersion, true
}

// Display renders the masked form shown in place of a sealed value. Sealing
// keeps a readable tail so an operator can still recognise a record (the last
// four of a card) without revealing it — the same contract the mask action
// offers, so the two read consistently in a log line.
func Display(plaintext string, keepLast int) string {
	r := []rune(plaintext)
	if keepLast < 0 {
		keepLast = 0
	}
	if keepLast > len(r) {
		keepLast = len(r)
	}
	head := len(r) - keepLast
	if head > displayHeadCap {
		head = displayHeadCap
	}
	return strings.Repeat("*", head) + string(r[len(r)-keepLast:])
}

// displayHeadCap bounds the mask head so a long value cannot produce an
// unreadable wall of asterisks in a log line.
const displayHeadCap = 16

// TokenFingerprint is a short, non-reversible handle for a sealed value, so an
// audit trail can tell "this same value was revealed three times by two people"
// without STORING the value.
//
// It hashes the ciphertext, never the plaintext (which this package would have
// to decrypt to see, and deliberately does not here). Storing the raw token in
// the audit trail would be defensible — it is ciphertext — but it would also
// hand anyone who later obtains a key a ready-made list of exactly the values
// worth decrypting, concentrated in one admin-readable place.
func TokenFingerprint(s string) string {
	if s == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:6])
}

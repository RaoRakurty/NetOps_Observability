package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"

	"netops/backend/internal/token"
)

// PBKDF2-SHA256 password hashing implemented in pure stdlib so the
// scaffold builds without any extra Go modules.
//
// The OWASP password storage cheat sheet (2023) lists PBKDF2-HMAC-SHA256
// with 600,000 iterations as an acceptable choice when Argon2 isn't
// available. We follow that.
//
// Stored format mirrors Django's pbkdf2 encoder:
//   pbkdf2_sha256$<iterations>$<base64(salt)>$<base64(hash)>

const (
	pbkdf2Iter   = 600_000
	pbkdf2KeyLen = 32
	saltLen      = 16
)

func hashPassword(password string) (string, error) {
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := pbkdf2SHA256([]byte(password), salt, pbkdf2Iter, pbkdf2KeyLen)
	return fmt.Sprintf(
		"pbkdf2_sha256$%d$%s$%s",
		pbkdf2Iter,
		base64.StdEncoding.EncodeToString(salt),
		base64.StdEncoding.EncodeToString(key),
	), nil
}

func verifyPassword(password, encoded string) bool {
	// SR-013: bound the input BEFORE running the 600k-round KDF. An over-long
	// password can never be valid (creation/change reject > maxPasswordLen), so
	// reject it cheaply rather than hashing megabytes 600k times — closes a
	// pre-hash amplification DoS on the unauthenticated login path.
	if len(password) > maxPasswordLen {
		return false
	}
	parts := strings.Split(encoded, "$")
	if len(parts) != 4 || parts[0] != "pbkdf2_sha256" {
		return false
	}
	iter, err := strconv.Atoi(parts[1])
	if err != nil || iter < 1 {
		return false
	}
	salt, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil {
		return false
	}
	expected, err := base64.StdEncoding.DecodeString(parts[3])
	if err != nil {
		return false
	}
	actual := pbkdf2SHA256([]byte(password), salt, iter, len(expected))
	// Constant-time compare via hmac.Equal.
	return hmac.Equal(actual, expected)
}

// passwordNeedsRehash reports whether a stored hash uses fewer PBKDF2 iterations
// than the current cost (SR-029). When true, the caller should opportunistically
// re-hash the just-verified plaintext at the current cost and persist it, so a
// hash minted under a weaker (or attacker-supplied low) iteration count is
// upgraded on next successful login.
func passwordNeedsRehash(encoded string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 4 || parts[0] != "pbkdf2_sha256" {
		return false
	}
	iter, err := strconv.Atoi(parts[1])
	return err == nil && iter < pbkdf2Iter
}

// pbkdf2SHA256 — RFC 8018 §5.2 with HMAC-SHA256 as the underlying PRF.
func pbkdf2SHA256(password, salt []byte, iter, keyLen int) []byte {
	prf := hmac.New(sha256.New, password)
	hashLen := prf.Size()
	blocks := (keyLen + hashLen - 1) / hashLen
	out := make([]byte, 0, blocks*hashLen)

	var buf [4]byte
	for i := 1; i <= blocks; i++ {
		prf.Reset()
		prf.Write(salt)
		binary.BigEndian.PutUint32(buf[:], uint32(i)) // #nosec G115 -- PBKDF2 32-bit block index (RFC 8018); i is a small bounded counter
		prf.Write(buf[:])
		u := prf.Sum(nil)
		f := make([]byte, hashLen)
		copy(f, u)
		for j := 2; j <= iter; j++ {
			prf.Reset()
			prf.Write(u)
			u = prf.Sum(nil)
			for k := range f {
				f[k] ^= u[k]
			}
		}
		out = append(out, f...)
	}
	return out[:keyLen]
}

// ---- JWT (HS256) ---------------------------------------------------------
//
// The claims model and HS256 signer/verifier live in internal/token. The alias
// keeps the 90+ in-package consumers source-compatible; the security property
// the old unexported actingTenant field carried (a token can never set the
// platform-owner override) is now enforced by `json:"-"` on
// token.Claims.ActingTenant and pinned by TestCraftedTokenCannotSetActingTenant.

type jwtClaims = token.Claims

package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"
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
		binary.BigEndian.PutUint32(buf[:], uint32(i))
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

var errJWT = errors.New("invalid token")

type jwtClaims struct {
	Sub    string   `json:"sub"`
	Role   string   `json:"role"`
	Tenant string   `json:"tenant,omitempty"` // tenant id the principal is bound to
	Scopes []string `json:"scopes,omitempty"` // API-key scopes (empty for human sessions)
	Iat    int64    `json:"iat"`
	Exp    int64    `json:"exp"`
}

// hasScope reports whether the principal carries an API-key scope. Human
// sessions carry none, so they fall through to RBAC role checks instead.
//nolint:unused // API-token scope check (#23); sessions use RBAC roles, so unwired until API tokens land
func (c jwtClaims) hasScope(want string) bool {
	for _, s := range c.Scopes {
		if s == want || s == "admin:*" {
			return true
		}
		// "read:*" satisfies any "read:<x>"; "write:*" any "write:<x>".
		if strings.HasSuffix(s, ":*") && strings.HasPrefix(want, strings.TrimSuffix(s, "*")) {
			return true
		}
	}
	return false
}

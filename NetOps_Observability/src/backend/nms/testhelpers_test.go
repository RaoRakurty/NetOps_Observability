package nms

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"hash"
)

func hmacNewSHA256(secret []byte) hash.Hash { return hmac.New(sha256.New, secret) }
func hexEncode(b []byte) string             { return hex.EncodeToString(b) }

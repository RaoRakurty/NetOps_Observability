// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package cloudconn

// sigv4.go — AWS Signature Version 4 request signing, stdlib-only.
//
// This is hand-rolled wire crypto, which the zero-trust rules treat with
// suspicion — so the implementation is pinned to the OFFICIAL AWS SigV4
// test-vector suite (vendored under testdata/sigv4/, exercised by
// sigv4_test.go). Every canonicalization rule below is asserted against those
// vectors; do not "simplify" any of it without the suite staying green.
//
// Scope: header-based signing (Authorization header) as used by the STS Query
// API. Query-string (presigned) signing is intentionally not implemented.

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"sort"
	"strings"
	"time"
)

// AWSCredentials is an AWS credential triplet used to SIGN a request (either
// the broker's platform identity or short-lived STS session credentials).
// SecretAccessKey and SessionToken are secrets: the type redacts itself when
// formatted so an accidental %v / %+v in a log line never leaks them.
type AWSCredentials struct {
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
}

// String implements fmt.Stringer with the secret fields REDACTED.
func (c AWSCredentials) String() string {
	return "AWSCredentials{AccessKeyID:" + c.AccessKeyID + " SecretAccessKey:<redacted> SessionToken:<redacted>}"
}

// GoString implements fmt.GoStringer (%#v) with the secret fields REDACTED.
func (c AWSCredentials) GoString() string { return c.String() }

// Empty reports whether no usable key pair is present.
func (c AWSCredentials) Empty() bool {
	return strings.TrimSpace(c.AccessKeyID) == "" || strings.TrimSpace(c.SecretAccessKey) == ""
}

const (
	sigv4Algorithm   = "AWS4-HMAC-SHA256"
	sigv4TimeFormat  = "20060102T150405Z"
	sigv4DateFormat  = "20060102"
	amzDateHeader    = "x-amz-date"
	amzTokenHeader   = "x-amz-security-token" // #nosec G101 -- header NAME, not a credential
	amzContentSHA256 = "x-amz-content-sha256"
)

// sigv4Input is everything the signer needs. Headers is an ORDERED list of
// name/value pairs (duplicates allowed — SigV4 canonicalizes them in arrival
// order). Path/RawQuery are the on-the-wire request-target components.
type sigv4Input struct {
	Method        string
	Path          string // request-target path, possibly partially percent-encoded
	RawQuery      string
	Headers       [][2]string
	PayloadHash   string // hex sha256 of the request body
	Region        string
	Service       string
	Time          time.Time
	Creds         AWSCredentials
	NormalizePath bool // true for every service except S3
}

// signAWSRequest signs req in place per SigV4: it stamps X-Amz-Date (and
// X-Amz-Security-Token when the credentials carry a session token), signs
// host + all headers already present on the request, and sets Authorization.
func signAWSRequest(req *http.Request, payload []byte, creds AWSCredentials, region, service string, now time.Time) {
	sum := sha256.Sum256(payload)
	payloadHash := hex.EncodeToString(sum[:])
	req.Header.Set("X-Amz-Date", now.UTC().Format(sigv4TimeFormat))
	if creds.SessionToken != "" {
		req.Header.Set("X-Amz-Security-Token", creds.SessionToken)
	}
	in := sigv4Input{
		Method:        req.Method,
		Path:          req.URL.EscapedPath(),
		RawQuery:      req.URL.RawQuery,
		PayloadHash:   payloadHash,
		Region:        region,
		Service:       service,
		Time:          now.UTC(),
		Creds:         creds,
		NormalizePath: true,
	}
	in.Headers = append(in.Headers, [2]string{"host", req.Host})
	if in.Headers[0][1] == "" {
		in.Headers[0][1] = req.URL.Host
	}
	for name, vals := range req.Header {
		for _, v := range vals {
			in.Headers = append(in.Headers, [2]string{name, v})
		}
	}
	req.Header.Set("Authorization", sigv4Authorization(in))
}

// sigv4Authorization computes the full Authorization header value.
func sigv4Authorization(in sigv4Input) string {
	creq, signedHeaders := sigv4CanonicalRequest(in)
	sts := sigv4StringToSign(in, creq)
	sig := sigv4Sign(in, sts)
	scope := sigv4Scope(in)
	return sigv4Algorithm + " Credential=" + in.Creds.AccessKeyID + "/" + scope +
		", SignedHeaders=" + signedHeaders + ", Signature=" + sig
}

func sigv4Scope(in sigv4Input) string {
	return in.Time.Format(sigv4DateFormat) + "/" + in.Region + "/" + in.Service + "/aws4_request"
}

// sigv4CanonicalRequest builds the canonical request and the signed-headers
// list exactly per the SigV4 spec (asserted by the official test suite).
func sigv4CanonicalRequest(in sigv4Input) (creq string, signedHeaders string) {
	names, headerLines := sigv4CanonicalHeaders(in.Headers)
	signedHeaders = strings.Join(names, ";")
	var b strings.Builder
	b.WriteString(strings.ToUpper(in.Method))
	b.WriteByte('\n')
	b.WriteString(sigv4CanonicalURI(in.Path, in.NormalizePath))
	b.WriteByte('\n')
	b.WriteString(sigv4CanonicalQuery(in.RawQuery))
	b.WriteByte('\n')
	b.WriteString(headerLines)
	b.WriteByte('\n')
	b.WriteString(signedHeaders)
	b.WriteByte('\n')
	b.WriteString(in.PayloadHash)
	return b.String(), signedHeaders
}

func sigv4StringToSign(in sigv4Input, creq string) string {
	sum := sha256.Sum256([]byte(creq))
	return sigv4Algorithm + "\n" +
		in.Time.Format(sigv4TimeFormat) + "\n" +
		sigv4Scope(in) + "\n" +
		hex.EncodeToString(sum[:])
}

// sigv4Sign derives the signing key (nested HMAC chain) and signs.
func sigv4Sign(in sigv4Input, stringToSign string) string {
	kDate := hmacSHA256([]byte("AWS4"+in.Creds.SecretAccessKey), in.Time.Format(sigv4DateFormat))
	kRegion := hmacSHA256(kDate, in.Region)
	kService := hmacSHA256(kRegion, in.Service)
	kSigning := hmacSHA256(kService, "aws4_request")
	return hex.EncodeToString(hmacSHA256(kSigning, stringToSign))
}

func hmacSHA256(key []byte, msg string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(msg))
	return h.Sum(nil)
}

// ── canonical URI ─────────────────────────────────────────────────────────────

// sigv4CanonicalURI canonicalizes the request path. When normalize is true
// (every service except S3): dot segments are resolved and duplicate slashes
// collapsed; each segment is then percent-decoded and strictly re-encoded, so
// pre-encoded input ("%20") and raw input (" ") canonicalize identically.
func sigv4CanonicalURI(path string, normalize bool) string {
	if path == "" {
		return "/"
	}
	segs := strings.Split(path, "/")
	if !normalize {
		// Encode in place, preserving the exact slash structure.
		for i, s := range segs {
			segs[i] = sigv4URIEncode(sigv4PercentDecode(s))
		}
		out := strings.Join(segs, "/")
		if out == "" {
			return "/"
		}
		return out
	}
	trailing := strings.HasSuffix(path, "/")
	stack := make([]string, 0, len(segs))
	for _, s := range segs {
		switch s {
		case "", ".":
			// skip empty (collapses "//") and same-dir segments
		case "..":
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
			trailing = true
		default:
			stack = append(stack, sigv4URIEncode(sigv4PercentDecode(s)))
			trailing = strings.HasSuffix(path, "/") || strings.HasSuffix(path, "/.")
		}
	}
	if len(stack) == 0 {
		return "/"
	}
	out := "/" + strings.Join(stack, "/")
	if trailing && !strings.HasSuffix(out, "/") {
		out += "/"
	}
	return out
}

// sigv4PercentDecode decodes %XX triplets; malformed escapes are kept literal
// (they will be re-encoded), matching the tolerant suite behavior.
func sigv4PercentDecode(s string) string {
	if !strings.Contains(s, "%") {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) {
			hi, ok1 := unhex(s[i+1])
			lo, ok2 := unhex(s[i+2])
			if ok1 && ok2 {
				b.WriteByte(hi<<4 | lo)
				i += 2
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func unhex(c byte) (byte, bool) {
	switch {
	case '0' <= c && c <= '9':
		return c - '0', true
	case 'a' <= c && c <= 'f':
		return c - 'a' + 10, true
	case 'A' <= c && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

const upperhex = "0123456789ABCDEF"

// sigv4URIEncode percent-encodes every byte except the RFC 3986 unreserved set
// (A-Z a-z 0-9 - . _ ~), with uppercase hex — the exact SigV4 URI-encode rule.
func sigv4URIEncode(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if ('A' <= c && c <= 'Z') || ('a' <= c && c <= 'z') || ('0' <= c && c <= '9') ||
			c == '-' || c == '.' || c == '_' || c == '~' {
			b.WriteByte(c)
			continue
		}
		b.WriteByte('%')
		b.WriteByte(upperhex[c>>4])
		b.WriteByte(upperhex[c&0xf])
	}
	return b.String()
}

// ── canonical query ───────────────────────────────────────────────────────────

// sigv4CanonicalQuery decodes then strictly re-encodes each key/value and sorts
// by encoded key, then encoded value (code-point order).
func sigv4CanonicalQuery(rawQuery string) string {
	if rawQuery == "" {
		return ""
	}
	type kv struct{ k, v string }
	pairs := make([]kv, 0, 8)
	for _, part := range strings.Split(rawQuery, "&") {
		if part == "" {
			continue
		}
		k, v, _ := strings.Cut(part, "=")
		pairs = append(pairs, kv{
			k: sigv4URIEncode(sigv4PercentDecode(k)),
			v: sigv4URIEncode(sigv4PercentDecode(v)),
		})
	}
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].k != pairs[j].k {
			return pairs[i].k < pairs[j].k
		}
		return pairs[i].v < pairs[j].v
	})
	var b strings.Builder
	for i, p := range pairs {
		if i > 0 {
			b.WriteByte('&')
		}
		b.WriteString(p.k)
		b.WriteByte('=')
		b.WriteString(p.v)
	}
	return b.String()
}

// ── canonical headers ─────────────────────────────────────────────────────────

// sigv4CanonicalHeaders lowercases names, trims + space-collapses values,
// joins duplicate names with commas IN ARRIVAL ORDER, and sorts by name.
// Returns the sorted names and the canonical "name:value\n" block.
func sigv4CanonicalHeaders(headers [][2]string) (names []string, block string) {
	byName := map[string][]string{}
	for _, h := range headers {
		name := strings.ToLower(strings.TrimSpace(h[0]))
		byName[name] = append(byName[name], sigv4TrimHeaderValue(h[1]))
	}
	names = make([]string, 0, len(byName))
	for n := range byName {
		names = append(names, n)
	}
	sort.Strings(names)
	var b strings.Builder
	for _, n := range names {
		b.WriteString(n)
		b.WriteByte(':')
		b.WriteString(strings.Join(byName[n], ","))
		b.WriteByte('\n')
	}
	return names, b.String()
}

// sigv4TrimHeaderValue trims leading/trailing whitespace and collapses internal
// whitespace runs to a single space (applies inside quotes too, per the suite).
func sigv4TrimHeaderValue(v string) string {
	var b strings.Builder
	b.Grow(len(v))
	inSpace := false
	for i := 0; i < len(v); i++ {
		c := v[i]
		if c == ' ' || c == '\t' || c == '\n' || c == '\r' {
			inSpace = true
			continue
		}
		if inSpace && b.Len() > 0 {
			b.WriteByte(' ')
		}
		inSpace = false
		b.WriteByte(c)
	}
	return b.String()
}

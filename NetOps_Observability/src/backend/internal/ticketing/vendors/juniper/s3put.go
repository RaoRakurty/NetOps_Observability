package juniper

// s3put.go — the middle leg of Juniper's three-step attachment flow:
// getfileuploadtoken → **client PUTs to S3** → attachfile.
//
// The credentials handed back are AWS STS session credentials, so the PUT is
// signed with AWS Signature Version 4. SigV4 is implemented here from the
// public AWS specification using only crypto/hmac + crypto/sha256 (CLAUDE.md
// §6: no AWS SDK is on the allowlist, and this is ~100 lines of well-specified
// arithmetic rather than a foundational capability the stdlib lacks).
//
// The upload is UNSIGNED-PAYLOAD-free: the body hash is computed over the real
// bytes, because S3 requires either the true payload hash or the explicit
// streaming/unsigned sentinel, and a bundle whose digest we already know is
// cheapest to hash once. The bundle is therefore read twice — once to hash,
// once to send — which is why Open() is a factory rather than a reader.
//
// SECURITY: the session credentials are short-lived and per-upload. They are
// never persisted, never logged, and never placed in a URL — the signature
// travels in the Authorization header (research §8.6).

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// s3Endpoint builds the virtual-hosted-style object URL for a bucket/key.
func (c *Client) s3Endpoint(t UploadToken) (string, error) {
	if c.baseOverride != "" {
		// Tests point the whole flow at one fake server; keep the object path.
		return strings.TrimRight(c.baseOverride, "/") + "/" + s3EscapePath(t.ObjectKey), nil
	}
	host := t.Bucket + ".s3." + t.Region + ".amazonaws.com"
	u := &url.URL{Scheme: "https", Host: host, Path: "/" + t.ObjectKey}
	if u.Host == "" {
		return "", fmt.Errorf("%w: juniper: cannot build the S3 endpoint from the upload token", ErrRequestInvalid)
	}
	return u.Scheme + "://" + u.Host + "/" + s3EscapePath(t.ObjectKey), nil
}

// PutObject uploads the bundle to the token's S3 location. open is called
// twice: once to hash the payload for the signature, once to send it, so a
// large bundle is never buffered in memory.
func (c *Client) PutObject(ctx context.Context, t UploadToken, contentType string, open func() (io.ReadCloser, error), size int64) error {
	if open == nil || size <= 0 {
		return fmt.Errorf("%w: juniper: the S3 upload needs a reader factory and a known size", ErrRequestInvalid)
	}
	if t.AccessKeyID == "" || t.SecretAccessKey == "" || t.Region == "" {
		return fmt.Errorf("%w: juniper: the upload token is incomplete", ErrRequestInvalid)
	}
	payloadHash, err := hashPayload(open, size)
	if err != nil {
		return err
	}
	endpoint, err := c.s3Endpoint(t)
	if err != nil {
		return err
	}

	body, err := open()
	if err != nil {
		return fmt.Errorf("juniper: open bundle for upload: %w", err)
	}
	defer func() { _ = body.Close() }() // the request owns the read; a close error is not actionable

	ctx, cancel := context.WithTimeout(ctx, uploadTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, endpoint, io.LimitReader(body, size))
	if err != nil {
		return fmt.Errorf("juniper: build S3 request: %w", err)
	}
	req.ContentLength = size
	if contentType == "" {
		contentType = "application/octet-stream"
	}
	req.Header.Set("Content-Type", contentType)
	if err := signV4(req, t, payloadHash, time.Now().UTC()); err != nil {
		return err
	}

	resp, err := c.httpClient().Do(req)
	if err != nil {
		return errors.New("juniper: S3 upload request failed")
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, maxRespBytes)) // best-effort diagnostic snippet
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return &StatusError{Op: "S3 PUT", Status: resp.StatusCode, Body: truncate(string(raw), 240)}
	}
	return nil
}

// hashPayload streams the bundle through SHA-256 and verifies the declared size
// on the way. A mismatch is fatal: a signature over a different length than the
// Content-Length would be rejected by S3 anyway, and silently truncating an
// evidence bundle is worse than failing.
func hashPayload(open func() (io.ReadCloser, error), size int64) (string, error) {
	rc, err := open()
	if err != nil {
		return "", fmt.Errorf("juniper: open bundle for hashing: %w", err)
	}
	h := sha256.New()
	n, copyErr := io.Copy(h, io.LimitReader(rc, size))
	closeErr := rc.Close()
	if copyErr != nil {
		return "", fmt.Errorf("juniper: hash bundle: %w", copyErr)
	}
	if closeErr != nil {
		return "", fmt.Errorf("juniper: close bundle after hashing: %w", closeErr)
	}
	if n != size {
		return "", fmt.Errorf("juniper: bundle is %d bytes but declared %d", n, size)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// ── AWS Signature Version 4 ─────────────────────────────────────────────────

const (
	sigV4Algorithm = "AWS4-HMAC-SHA256"
	s3Service      = "s3"
	iso8601        = "20060102T150405Z"
	shortDate      = "20060102"
)

// signV4 signs req in place. It sets x-amz-date, x-amz-content-sha256, the
// session token (when present) and Authorization.
func signV4(req *http.Request, t UploadToken, payloadHash string, now time.Time) error {
	amzDate := now.Format(iso8601)
	scopeDate := now.Format(shortDate)

	req.Header.Set("Host", req.URL.Host)
	req.Header.Set("X-Amz-Date", amzDate)
	req.Header.Set("X-Amz-Content-Sha256", payloadHash)
	if t.SessionToken != "" {
		req.Header.Set("X-Amz-Security-Token", t.SessionToken)
	}

	signed, canonicalHeaders := canonicalizeHeaders(req)
	canonicalRequest := strings.Join([]string{
		req.Method,
		s3CanonicalURI(req.URL),
		req.URL.RawQuery,
		canonicalHeaders,
		signed,
		payloadHash,
	}, "\n")

	scope := strings.Join([]string{scopeDate, t.Region, s3Service, "aws4_request"}, "/")
	stringToSign := strings.Join([]string{
		sigV4Algorithm,
		amzDate,
		scope,
		hex.EncodeToString(sha256Sum([]byte(canonicalRequest))),
	}, "\n")

	key := hmacSHA256([]byte("AWS4"+t.SecretAccessKey), scopeDate)
	key = hmacSHA256(key, t.Region)
	key = hmacSHA256(key, s3Service)
	key = hmacSHA256(key, "aws4_request")
	signature := hex.EncodeToString(hmacSHA256(key, stringToSign))

	req.Header.Set("Authorization", fmt.Sprintf("%s Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		sigV4Algorithm, t.AccessKeyID, scope, signed, signature))
	return nil
}

// canonicalizeHeaders returns the signed-header list and the canonical header
// block. Host, and every x-amz-*, plus content-type are signed.
func canonicalizeHeaders(req *http.Request) (signedHeaders, canonical string) {
	names := []string{"host"}
	values := map[string]string{"host": req.URL.Host}
	for k, v := range req.Header {
		lk := strings.ToLower(k)
		if lk != "content-type" && !strings.HasPrefix(lk, "x-amz-") {
			continue
		}
		if lk == "x-amz-content-sha256" || lk == "x-amz-date" || lk == "x-amz-security-token" ||
			lk == "content-type" {
			names = append(names, lk)
			values[lk] = strings.TrimSpace(strings.Join(v, ","))
		}
	}
	sort.Strings(names)
	var b strings.Builder
	for _, n := range names {
		b.WriteString(n + ":" + values[n] + "\n")
	}
	return strings.Join(names, ";"), b.String()
}

// s3CanonicalURI is the URI-encoded path, encoding every segment but keeping
// the separators. S3 requires single (not double) encoding.
func s3CanonicalURI(u *url.URL) string {
	if u.Path == "" || u.Path == "/" {
		return "/"
	}
	return "/" + s3EscapePath(strings.TrimPrefix(u.Path, "/"))
}

// s3EscapePath percent-encodes a key per RFC 3986, leaving "/" as a separator.
func s3EscapePath(key string) string {
	segments := strings.Split(key, "/")
	for i, s := range segments {
		segments[i] = rfc3986Escape(s)
	}
	return strings.Join(segments, "/")
}

// rfc3986Escape encodes everything but the unreserved set. url.PathEscape is
// close but leaves sub-delims that SigV4 requires encoded.
func rfc3986Escape(s string) string {
	const unreserved = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.~"
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if strings.IndexByte(unreserved, c) >= 0 {
			b.WriteByte(c)
			continue
		}
		fmt.Fprintf(&b, "%%%02X", c)
	}
	return b.String()
}

func hmacSHA256(key []byte, data string) []byte {
	m := hmac.New(sha256.New, key)
	_, _ = m.Write([]byte(data)) // hash.Write never returns an error
	return m.Sum(nil)
}

func sha256Sum(b []byte) []byte {
	s := sha256.Sum256(b)
	return s[:]
}

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Package caplink owns the bearer-capability link crypto (P2 RA.3): the
// tamper-proof, short-lived, tenant-bound tokens that authorize report views
// and raw log exports without a session, and the log-masking algorithm that
// keeps those tokens out of every log store (PIPE-HIGH-2). Pure: the signing
// secret and TTLs arrive as parameters; env resolution and the route table
// stay with the entrypoint.
package caplink

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// ReportTTL is the report-link lifetime: long enough for an emailed weekly
// report to be read on Monday, bounded because the token is a bearer credential.
const ReportTTL = 7 * 24 * time.Hour

// TokenHeader is the header form of the capability (the form that never
// touches a URL, a proxy log, browser history or Referer). It cannot be the
// ONLY form: a report link is emailed and clicked in a mail client, and a
// plain browser navigation carries no custom header.
//
// Authorization: is deliberately NOT accepted for these routes — the SPA
// already sends the user's session JWT in that header, and honouring it here
// would turn every authenticated browser request into a failed link
// verification (403) on a route that works today.
const TokenHeader = "X-Link-Token" //nolint:gosec // G101 false positive: this is a header NAME, not a credential value

// MaskedTokenSegment is what a capability token becomes in a log line. It is
// deliberately not a fixed-width blob of the same shape as a token: an operator
// reading the log should see redaction, not a token they might try to use.
const MaskedTokenSegment = "[token-redacted]"

// PathRule marks a URL prefix whose remaining path segments are (or contain) a
// bearer-equivalent capability token. Keep is the number of leading segments
// after the prefix that are safe to log — everything after them is masked,
// because when in doubt the safe answer is to redact. The rule TABLE lives with
// the entrypoint (it is route knowledge); this package owns the algorithm.
type PathRule struct {
	Prefix string
	Keep   int
}

// MaskTokenPath returns a path safe to write to a log store: the route
// survives (so the log is still useful for traffic analysis and error triage),
// the credential does not. Non-token paths are returned untouched.
func MaskTokenPath(p string, rules []PathRule) string {
	for _, rule := range rules {
		if !strings.HasPrefix(p, rule.Prefix) {
			continue
		}
		rest := strings.TrimPrefix(p, rule.Prefix)
		if rest == "" {
			return p // no token in the path (header form) — nothing to mask
		}
		segs := strings.Split(rest, "/")
		if len(segs) <= rule.Keep {
			return p // shorter than the safe prefix — nothing sensitive present
		}
		out := append([]string{}, segs[:rule.Keep]...)
		return rule.Prefix + strings.Join(append(out, MaskedTokenSegment), "/")
	}
	return p
}

// TokenFromRequest resolves the capability token for a token-authenticated
// view route: the TokenHeader first (the form that never touches a log or a
// proxy), falling back to the path segment for plain browser navigation from
// an emailed link. Returns "" when neither is present, which callers turn into
// the same "invalid or expired link" refusal as a bad token — an absent
// capability and a wrong one are indistinguishable to the caller.
func TokenFromRequest(r *http.Request, pathPrefix string) string {
	if tok := strings.TrimSpace(r.Header.Get(TokenHeader)); tok != "" {
		return tok
	}
	return strings.TrimPrefix(r.URL.Path, pathPrefix)
}

// ClampExportTTL bounds an export-link lifetime to [5min, 15min] per the
// hardening policy: a raw log export is bulk sensitive data and links may be
// forwarded externally.
func ClampExportTTL(d time.Duration) time.Duration {
	if d < 5*time.Minute {
		return 5 * time.Minute
	}
	if d > 15*time.Minute {
		return 15 * time.Minute
	}
	return d
}

// ---- signing ---------------------------------------------------------------
//
// Tokens are "b64(execID).b64(tenant).b64(expiryUnix).b64(hmac)". SR-018: the
// tenant is bound INTO the token so a leaked token can't be replayed against
// another tenant's execution id. The domain label ("report."/"export.") keeps
// the two capability kinds from validating for each other.

func sig(secret, domain, execID, tenant, exp string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(domain + "." + execID + "." + tenant + "." + exp))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func sign(secret, domain, execID, tenant string, ttl time.Duration) string {
	exp := strconv.FormatInt(time.Now().Add(ttl).Unix(), 10)
	enc := base64.RawURLEncoding.EncodeToString
	return enc([]byte(execID)) + "." + enc([]byte(tenant)) + "." + enc([]byte(exp)) + "." + sig(secret, domain, execID, tenant, exp)
}

func verify(secret, domain, token string) (string, string, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 4 {
		return "", "", errors.New("malformed token")
	}
	dec := base64.RawURLEncoding.DecodeString
	idB, e1 := dec(parts[0])
	tB, e2 := dec(parts[1])
	expB, e3 := dec(parts[2])
	if e1 != nil || e2 != nil || e3 != nil {
		return "", "", errors.New("malformed token")
	}
	execID, tenant, exp := string(idB), string(tB), string(expB)
	if !hmac.Equal([]byte(sig(secret, domain, execID, tenant, exp)), []byte(parts[3])) {
		return "", "", errors.New("bad signature")
	}
	expUnix, err := strconv.ParseInt(exp, 10, 64)
	if err != nil {
		return "", "", err
	}
	if time.Now().Unix() > expUnix {
		return "", "", errors.New("link expired")
	}
	return execID, tenant, nil
}

// SignReport mints a report-view capability bound to (execID, tenant).
func SignReport(secret, execID, tenant string, ttl time.Duration) string {
	return sign(secret, "report", execID, tenant, ttl)
}

// VerifyReport returns (execID, tenant) iff the token is well-formed, the
// signature matches, and it has not expired.
func VerifyReport(secret, token string) (string, string, error) {
	return verify(secret, "report", token)
}

// SignExport mints an export-view capability bound to (execID, tenant).
func SignExport(secret, execID, tenant string, ttl time.Duration) string {
	return sign(secret, "export", execID, tenant, ttl)
}

// VerifyExport returns (execID, tenant) iff the token is well-formed, the
// signature matches, and it has not expired.
func VerifyExport(secret, token string) (string, string, error) {
	return verify(secret, "export", token)
}

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Package logredact removes credentials from text and structured fields bound
// for a log, an error string or an API response (CLAUDE.md §8: no secrets in
// logs; tracker 367).
//
// It is the BACKSTOP, not the design: credentials should never reach a log in
// the first place (367 layer 1 takes them out of URLs). This package makes
// sure that when one does — a future error string that prints a URL, a field
// someone names `token` — it is masked before it is written.
//
// Pure: no state, no imports from the rest of the backend, safe for concurrent
// use. The patterns are shared with the correlation engine's Python twin
// through src/contracts/log_redaction_corpus.json, so the two cannot drift.
package logredact

import (
	"bytes"
	"io"
	"net/url"
	"regexp"
	"strings"
)

// Mask replaces every redacted value.
const Mask = "***"

// triggers is the fast path: a line containing none of these substrings
// (case-insensitively for the words) cannot match any pattern, so the regexes
// are skipped — the common case for the ~900 log call sites.
var triggers = []string{"://", "assword", "asswd", "ecret", "oken", "pi_key", "pikey", "uthorization", "earer", "BEGIN", "redential"}

var (
	// scheme://user:pass@ and scheme://token@ (a bare userinfo is a token as
	// often as it is a username, so it is masked too).
	reUserPass = regexp.MustCompile(`([A-Za-z][A-Za-z0-9+.\-]*://)([^/@\s:"'<>]+):([^/@\s"'<>]+)@`)
	reUserOnly = regexp.MustCompile(`([A-Za-z][A-Za-z0-9+.\-]*://)([^/@\s:"'<>]+)@`)
	// Authorization: Basic|Bearer <credential>
	reAuthz = regexp.MustCompile(`(?i)(authorization["']?\s*[:=]\s*["']?)(basic|bearer|token)\s+[A-Za-z0-9._~+/=\-]+`)
	// A bare bearer token anywhere.
	reBearer = regexp.MustCompile(`(?i)\b(bearer)\s+[A-Za-z0-9._~+/\-]{8,}=*`)
	// JSON "…password": "value"  (key may carry a prefix: "db_password").
	reJSON = regexp.MustCompile(`(?i)("[A-Za-z0-9_\-]*(?:password|passwd|secret|token|api_key|apikey|credentials?)"\s*:\s*)"(?:[^"\\]|\\.)*"`)
	// key=value / key: value (key may carry a prefix: db_token=). The keyword
	// must END the key, so max_tokens= and tokens= are left alone.
	reKV = regexp.MustCompile(`(?i)\b([A-Za-z0-9_\-]*(?:password|passwd|secret|token|api_key|apikey|credentials?))(\s*[=:]\s*)("?)([^\s"&,;'}]+)`)
	// PEM private keys.
	rePEM = regexp.MustCompile(`-----BEGIN ([A-Z ]*)PRIVATE KEY-----[\s\S]*?-----END ([A-Z ]*)PRIVATE KEY-----`)
)

func mayContain(s string) bool {
	if s == "" {
		return false
	}
	low := strings.ToLower(s)
	for _, t := range triggers {
		if strings.Contains(low, strings.ToLower(t)) {
			return true
		}
	}
	return false
}

// String returns s with every recognised credential masked.
func String(s string) string {
	if !mayContain(s) {
		return s
	}
	s = rePEM.ReplaceAllString(s, "-----BEGIN ${1}PRIVATE KEY----- "+Mask+" -----END ${2}PRIVATE KEY-----")
	s = reUserPass.ReplaceAllString(s, "${1}${2}:"+Mask+"@")
	s = reUserOnly.ReplaceAllString(s, "${1}"+Mask+"@")
	s = reAuthz.ReplaceAllString(s, "${1}${2} "+Mask)
	s = reBearer.ReplaceAllString(s, "${1} "+Mask)
	s = reJSON.ReplaceAllString(s, `${1}"`+Mask+`"`)
	s = reKV.ReplaceAllStringFunc(s, func(m string) string {
		g := reKV.FindStringSubmatch(m)
		if g[4] == Mask {
			return m
		}
		return g[1] + g[2] + g[3] + Mask
	})
	return s
}

// URL returns raw with any userinfo removed entirely ("https://h/p"), for
// values that are SHOWN (API responses, UI) rather than logged. An unparseable
// value falls back to String, so it can never echo a credential either.
func URL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		// Not a URL at all: it may still carry a credential, so it gets the
		// text redactor rather than being echoed.
		return String(raw)
	}
	if u.Host == "" {
		// Parsed, but no authority ("kafka:9092", a bare path): there is no
		// userinfo to strip; the text redactor still masks anything key-like.
		return String(raw)
	}
	u.User = nil
	return u.String()
}

// sensitiveKey reports whether a structured-field NAME holds a secret: the
// whole key, or its last `_`/`-` segment, is one of the secret words. So
// `token` and `db_token` are sensitive; `max_tokens` and `tokens` are not.
func sensitiveKey(k string) bool {
	low := strings.ToLower(k)
	if i := strings.LastIndexAny(low, "_-."); i >= 0 {
		if secretWords[low[i+1:]] {
			return true
		}
	}
	return secretWords[low]
}

var secretWords = map[string]bool{
	"password": true, "passwd": true, "secret": true, "token": true, "apikey": true,
	"api_key": true, "client_secret": true, "authorization": true, "credential": true,
	"credentials": true, "privatekey": true, "private_key": true,
}

// Fields returns fields with credentials masked. Copy-on-write: the caller's
// map is never mutated, and when nothing needed masking the SAME map is
// returned (no allocation on the hot path). Non-string scalars (numbers,
// times, structs) are left as they are — only text can carry a credential.
func Fields(fields map[string]any) map[string]any {
	out, _ := redactMap(fields)
	return out
}

// redactMap is Fields reporting whether anything was masked.
func redactMap(fields map[string]any) (map[string]any, bool) {
	var out map[string]any
	for k, v := range fields {
		nv, changed := value(k, v)
		if !changed {
			continue
		}
		if out == nil {
			out = make(map[string]any, len(fields))
			for k2, v2 := range fields {
				out[k2] = v2
			}
		}
		out[k] = nv
	}
	if out == nil {
		return fields, false
	}
	return out, true
}

func value(key string, v any) (any, bool) {
	if sensitiveKey(key) {
		switch v.(type) {
		case nil:
			return v, false
		case string, []byte, error:
			return Mask, true
		}
	}
	switch t := v.(type) {
	case string:
		r := String(t)
		return r, r != t
	case error:
		if t == nil {
			return v, false
		}
		s := t.Error()
		r := String(s)
		if r != s {
			return r, true // the error becomes its redacted TEXT
		}
		return v, false
	case []byte:
		r := String(string(t))
		return r, r != string(t)
	case map[string]any:
		return redactMap(t)
	case []any:
		var cp []any
		for i, e := range t {
			ne, ch := value("", e)
			if !ch {
				continue
			}
			if cp == nil {
				cp = append([]any(nil), t...)
			}
			cp[i] = ne
		}
		if cp == nil {
			return v, false
		}
		return cp, true
	case []string:
		var cp []string
		for i, e := range t {
			ne := String(e)
			if ne == e {
				continue
			}
			if cp == nil {
				cp = append([]string(nil), t...)
			}
			cp[i] = ne
		}
		if cp == nil {
			return v, false
		}
		return cp, true
	}
	return v, false
}

// Writer redacts every write before passing it on. It is meant for the
// stdlib `log` output (one write per line), so a credential split across two
// writes is not a case it needs to handle.
type Writer struct{ w io.Writer }

// NewWriter wraps w.
func NewWriter(w io.Writer) *Writer { return &Writer{w: w} }

// Write redacts p and writes it; it reports len(p) on success so callers that
// check the count are not confused by a shorter masked line.
func (rw *Writer) Write(p []byte) (int, error) {
	if !mayContain(string(p)) {
		return rw.w.Write(p)
	}
	red := []byte(String(string(p)))
	if bytes.Equal(red, p) {
		return rw.w.Write(p)
	}
	if _, err := rw.w.Write(red); err != nil {
		return 0, err
	}
	return len(p), nil
}

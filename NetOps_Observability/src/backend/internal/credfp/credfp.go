// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Package credfp computes the keyed fingerprints that let the ingest tier drop
// an SNMP community from a syslog line before it is stored (tracker 387 (a),
// owner decision D1: "drop it; store only present/absent").
//
// ConfD names an SNMP v1/v2c session by the COMMUNITY the request carried, so
// `audit user: <community>/N assigned to groups` and `... terminated session`
// carry the credential, and they look exactly like a person's session: no
// stateless grammar can tell the two apart. The platform knows which values
// are communities (internal/credscrub holds every tenant's configured and
// retired ones), but those values must never be written where the ingest tier
// can read them. So the api publishes, per tenant, HMAC-SHA256 fingerprints of
// them under a per-install key, and the Vector aggregator HMACs the user slot
// of each such line under the same key and replaces a match with a token
// before the line reaches Kafka, OpenSearch or anything downstream.
//
// The wire contract, which the aggregator's VRL (deployment/docker/vector/
// vector.yaml, the "D1 at rest" block) reproduces byte for byte and the
// `vector test` suite proves against this package's own output:
//
//	scope       = "*" for a platform-global value, else the tenant id,
//	              trimmed and lower-cased ("global" is the platform's own
//	              tenant and folds to "*", as in internal/credscrub)
//	fingerprint = base64url_nopad( HMAC-SHA256( key, scope + ":" + value ) )
//	file line   = scope + "/" + fingerprint
//
// A tenant id never holds ":" or "/" (tenancy ids are [A-Za-z0-9_-]), so the
// first separator is unambiguous. The key is the ASCII bytes of the rendered
// secret, not a decoding of it: the edge has no base64 step to get wrong.
//
// Nothing here ever returns, logs or prints a value. A fingerprint is safe to
// write to the shared enrichment volume: without the key it is an opaque
// 256-bit string, and the key lives only in the api's and the aggregator's
// read-only secret mounts.
//
// Stdlib only (§6).
package credfp

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

// FileName is the file the aggregator's set backend reads from the shared
// enrichment directory (cx-credfp-set.sh).
const FileName = "community_fp.txt"

// GlobalScope is the scope of a platform-global value.
const GlobalScope = "*"

// MinKeyBytes is the shortest key accepted. install.py mints 43 characters
// (secrets.token_urlsafe(32)); anything shorter is a broken render.
const MinKeyBytes = 32

// MaxLines bounds the published set. internal/credscrub keeps every configured
// value plus at most 4096 retired ones; the bound leaves headroom for
// configured values and refuses a runaway rather than writing it (§9).
const MaxLines = 16384

// ErrShortKey is returned for a key under MinKeyBytes.
var ErrShortKey = fmt.Errorf("credfp: key shorter than %d bytes", MinKeyBytes)

// ErrBadKey is returned for a key the edge could not carry: Vector substitutes
// the secret into a VRL string literal, so only URL-safe base64 characters are
// accepted (install.py mints exactly that alphabet).
var ErrBadKey = errors.New("credfp: key holds a character outside the URL-safe base64 alphabet")

// Pair is one published fingerprint.
type Pair struct {
	Scope string
	FP    string
}

// Scope folds a tenant id to its fingerprint scope.
func Scope(tenant string) string {
	t := strings.ToLower(strings.TrimSpace(tenant))
	if t == "" || t == "global" {
		return GlobalScope
	}
	return t
}

// ValidKey reports why a key cannot be used, or nil.
func ValidKey(key string) error {
	if len(key) < MinKeyBytes {
		return ErrShortKey
	}
	for i := 0; i < len(key); i++ {
		c := key[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '_':
		default:
			return ErrBadKey
		}
	}
	return nil
}

// Fingerprint returns the fingerprint of value under key for scope (already
// folded by Scope). The caller validates the key once (ValidKey).
func Fingerprint(key, scope, value string) string {
	m := hmac.New(sha256.New, []byte(key))
	_, _ = m.Write([]byte(scope)) // hash.Hash.Write never returns an error
	_, _ = m.Write([]byte{':'})   // hash.Hash.Write never returns an error
	_, _ = m.Write([]byte(value)) // hash.Hash.Write never returns an error
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

// validScope reports whether a scope can be written to the file and matched
// by the edge's literal search: "*" or a tenant id of [a-z0-9_-].
func validScope(s string) bool {
	if s == GlobalScope {
		return true
	}
	if s == "" || len(s) > 128 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '_':
		default:
			return false
		}
	}
	return true
}

// Render returns the file body for pairs: one "scope/fp" line each, sorted and
// de-duplicated so an unchanged set renders byte-identical (the aggregator's
// reload wrapper keys off the content hash). A pair whose scope the edge could
// not match is refused, not silently dropped: it would be a value published
// that no line can ever match.
func Render(pairs []Pair) ([]byte, error) {
	if len(pairs) > MaxLines {
		return nil, fmt.Errorf("credfp: %d fingerprints exceed the %d bound; refusing to publish", len(pairs), MaxLines)
	}
	lines := make([]string, 0, len(pairs))
	seen := make(map[string]bool, len(pairs))
	for _, p := range pairs {
		if !validScope(p.Scope) {
			return nil, fmt.Errorf("credfp: scope %q cannot be matched at the edge", p.Scope)
		}
		if len(p.FP) != 43 {
			return nil, errors.New("credfp: a fingerprint is not 43 base64url characters")
		}
		l := p.Scope + "/" + p.FP
		if !seen[l] {
			seen[l] = true
			lines = append(lines, l)
		}
	}
	sort.Strings(lines)
	var b bytes.Buffer
	for _, l := range lines {
		b.WriteString(l)
		b.WriteByte('\n')
	}
	return b.Bytes(), nil
}

// Publisher keeps dir/FileName in step with the platform's held communities.
// Every field is required; a Publisher is safe for concurrent use (the
// enrichment tick and a credential write may both publish).
type Publisher struct {
	// Dir is the shared enrichment directory (TENANT_ENRICHMENT_DIR).
	Dir string
	// Key returns the current key (internal/credfile: a rotation is picked up
	// on the next publish). Its error never carries the key.
	Key func() (string, error)
	// Pairs returns every held value's (scope, fingerprint) pair, computing
	// each fingerprint with fp. fp receives the value's tenant UNFOLDED; the
	// Publisher folds it. Values never leave the callee except through fp.
	Pairs func(fp func(tenant, value string) string) []Pair
	// Report is told about a CHANGE of state only: an error the first time it
	// differs from the last one, nil once a publish succeeds again, and wrote
	// counts when the file changed. It must not block.
	Report func(err error, wrote bool, n int)

	mu      sync.Mutex
	lastErr string
}

// Publish recomputes the set and writes it when it changed. A failure leaves
// the previous file standing: its fingerprints were computed under the key the
// aggregator still holds, so it keeps masking until a good publish replaces it.
func (p *Publisher) Publish() (wrote bool, err error) {
	if p == nil {
		return false, nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	wrote, n, err := p.publishLocked()
	msg := ""
	if err != nil {
		msg = err.Error()
	}
	if p.Report != nil && (msg != p.lastErr || wrote) {
		p.Report(err, wrote, n)
	}
	p.lastErr = msg
	return wrote, err
}

func (p *Publisher) publishLocked() (bool, int, error) {
	if p.Dir == "" || p.Key == nil || p.Pairs == nil {
		return false, 0, errors.New("credfp: publisher is not configured")
	}
	key, err := p.Key()
	if err != nil {
		return false, 0, fmt.Errorf("credfp: the fingerprint key is unreadable, the published set stays as it stands: %w", err)
	}
	if err := ValidKey(key); err != nil {
		return false, 0, fmt.Errorf("credfp: the fingerprint key is unusable, the published set stays as it stands: %w", err)
	}
	pairs := p.Pairs(func(tenant, value string) string {
		return Fingerprint(key, Scope(tenant), value)
	})
	for i := range pairs {
		pairs[i].Scope = Scope(pairs[i].Scope)
	}
	body, err := Render(pairs)
	if err != nil {
		return false, 0, err
	}
	wrote, err := Write(p.Dir, body)
	if err != nil {
		return false, 0, fmt.Errorf("credfp: writing %s: %w", FileName, err)
	}
	return wrote, bytes.Count(body, []byte{'\n'}), nil
}

// Write publishes body as dir/FileName: atomically (temp + rename, so the
// aggregator never reads half a set) and only when the content changed. It
// reports whether it wrote. The file is 0644: the aggregator runs as another
// uid, and a fingerprint is not a secret (see the package comment).
func Write(dir string, body []byte) (bool, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return false, err
	}
	final := filepath.Join(dir, FileName)
	if prev, err := os.ReadFile(final); err == nil && bytes.Equal(prev, body) {
		return false, nil
	}
	tmp, err := os.CreateTemp(dir, ".community_fp-*.tmp")
	if err != nil {
		return false, err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op once renamed; cleans up on any failure below

	if _, err := tmp.Write(body); err != nil {
		_ = tmp.Close() // best-effort: the write error is the one reported
		return false, err
	}
	if err := tmp.Close(); err != nil {
		return false, err
	}
	if err := os.Chmod(tmpName, 0o644); err != nil {
		return false, err
	}
	if err := os.Rename(tmpName, final); err != nil {
		return false, err
	}
	return true, nil
}

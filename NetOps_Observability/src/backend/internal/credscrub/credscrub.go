// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Package credscrub masks configured credential VALUES wherever they appear in
// data the platform serves.
//
// # Why it exists
//
// Cisco SD-WAN vEdges run ConfD. ConfD opens a session for every SNMP v1/v2c
// request, and since such a request carries no user, ConfD names the session by
// the COMMUNITY it carried. Three audit lines per poll follow (found live
// 2026-11-11):
//
//	audit user: <community>/49119 created new session via snmp from 127.0.0.1:54873 with udp
//	audit user: <community>/49119 assigned to groups: basic
//	audit user: <community>/49088 terminated session (reason: normal)
//
// The vendor pack no longer copies the user of the first line into any parsed
// field, and ai.RedactSecrets masks that line's shape. Neither can help with
// the other two: they look exactly like a person's CLI or NETCONF session,
// where the user is a real account that must stay visible for security
// attribution (owner D7). No pattern can tell them apart. Only the VALUE can:
// the platform knows every community it was configured with, so it can mask
// exactly those, wherever they occur. That is this package.
//
// # What it masks
//
// Every value the Source returns that is eligible (see eligible): at least
// MinValueRunes characters, not purely numeric, not made only of separators.
// A shorter or numeric value would mask ordinary tokens (a "1234" in a counter,
// a "dev" in a path) far more often than it hides a credential, and v1/v2c
// communities that short are rare. "public" and "private" ARE communities: when
// an operator configures one, it is masked like any other, and the word
// "public" in a log line then reads "***". That over-masking is the deliberate
// trade: masking only removes information, and a configured community is a
// credential whatever it spells. The protocol default the poller falls back to
// when nothing is configured ("public" with SNMP_COMMUNITY unset) is NOT a
// configured value and is not masked.
//
// A value is matched exactly (communities are case-sensitive) and only as a
// whole token: its neighbours must be the start or end of the string or one of
// the separators isBoundary names (whitespace, quotes, / : = , ( ) [ ] { } < >
// ; | @ \). A full stop counts after the value only when the text ends or a
// space follows it, so a sentence end is masked and "public.example.com" is
// not. Longer values are applied first, so a value that contains another is
// masked whole.
//
// # Rotation
//
// A value removed from the configuration stays masked until the process
// restarts: the records stored while it was in force still hold it, and a
// rotated community is often still live on a device nobody has updated yet. The
// retained set is bounded (maxRetained); past the bound, retired values are
// dropped first and the configured ones are always kept. Nothing is persisted:
// after a restart only what is configured is masked.
//
// # Tenancy
//
// The set is the UNION of every tenant's communities. Masking with another
// tenant's value is safe in the only direction it can err: it removes text from
// a document the caller was already allowed to read, and never adds a document
// or a field. Tenant scoping stays where it is (the index pattern and the
// per-document filter of each read path); this package never selects data.
//
// # Never revealing the set
//
// The values live only in this process's memory. No method returns them, no
// error carries one, String/GoString print a constant, and the package logs
// nothing. Output for input that holds no value is the input itself, byte for
// byte, so a caller cannot probe the set by watching other text change.
package credscrub

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"
)

// Mask replaces a masked value. It is the house mask (ai.Mask), restated here
// so this package imports nothing of the platform.
const Mask = "***"

// MinValueRunes is the shortest value that is masked.
const MinValueRunes = 4

// maxRetained bounds the values kept after they leave the configuration (§9).
const maxRetained = 4096

// Source returns the credential values in force now. It is called on every
// Refresh. An error keeps the previous set: a transient store failure must not
// silently stop masking.
type Source func(ctx context.Context) ([]string, error)

// Scrubber holds the current value set and masks with it. The zero value and
// a nil *Scrubber mask nothing. It is safe for concurrent use: readers load an
// immutable matcher through an atomic pointer, and refreshes are serialised.
type Scrubber struct {
	src       Source
	refreshMu sync.Mutex
	// retired are eligible values that left the configuration; guarded by
	// refreshMu.
	retired map[string]bool
	cur     atomic.Pointer[matcher]
}

// matcher is one immutable snapshot of the eligible values.
type matcher struct {
	// values are distinct, longest first (then lexical, for determinism).
	values []string
	// needles are what MayHold searches serialized JSON for: each value as
	// itself and as encoding/json spells it inside a string.
	needles [][]byte
}

// New returns a Scrubber over src. It holds no values until the first Refresh.
func New(src Source) *Scrubber {
	return &Scrubber{src: src}
}

// String never prints the values.
func (s *Scrubber) String() string { return "credscrub.Scrubber{values redacted}" }

// GoString never prints the values (fmt's %#v).
func (s *Scrubber) GoString() string { return s.String() }

// Refresh brings the value set up to what the Source returns now; a value that
// left the configuration stays masked (see Rotation). On a Source error the
// previous set stays in force and the error is returned; the error never
// carries a value.
func (s *Scrubber) Refresh(ctx context.Context) error {
	if s == nil {
		return nil
	}
	if s.src == nil {
		return errors.New("credscrub: no source configured")
	}
	s.refreshMu.Lock()
	defer s.refreshMu.Unlock()
	values, err := s.src(ctx)
	if err != nil {
		return fmt.Errorf("credscrub: reading the configured values failed; the previous set stays in force: %w", err)
	}
	current := make(map[string]bool, len(values))
	for _, v := range values {
		if eligible(v) {
			current[v] = true
		}
	}
	if prev := s.cur.Load(); prev != nil {
		for _, v := range prev.values {
			if !current[v] {
				if s.retired == nil {
					s.retired = make(map[string]bool)
				}
				s.retired[v] = true
			}
		}
	}
	for v := range current {
		delete(s.retired, v) // configured again: no longer retired
	}
	if len(current)+len(s.retired) > maxRetained {
		s.retired = nil // past the bound: the configured values are what must stay
	}
	all := make([]string, 0, len(current)+len(s.retired))
	for v := range current {
		all = append(all, v)
	}
	for v := range s.retired {
		all = append(all, v)
	}
	s.cur.Store(build(all))
	return nil
}

// Run refreshes now and then every interval until ctx is done. A refresh error
// goes to onErr (which may be nil) and the loop continues on the last good set.
func (s *Scrubber) Run(ctx context.Context, interval time.Duration, onErr func(error)) {
	if s == nil {
		return
	}
	if interval <= 0 {
		interval = time.Minute
	}
	report := func(err error) {
		if err != nil && onErr != nil {
			onErr(err)
		}
	}
	report(s.Refresh(ctx))
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			report(s.Refresh(ctx))
		}
	}
}

func (s *Scrubber) load() *matcher {
	if s == nil {
		return nil
	}
	m := s.cur.Load()
	if m == nil || len(m.values) == 0 {
		return nil
	}
	return m
}

// Mask returns str with every whole-token occurrence of a value replaced by
// Mask. A string that holds none is returned unchanged.
func (s *Scrubber) Mask(str string) string {
	m := s.load()
	if m == nil {
		return str
	}
	for _, v := range m.values {
		str = maskToken(str, v)
	}
	return str
}

// MaskValue masks every string inside a decoded JSON value (maps, slices and
// strings, at any depth; map keys are left alone) and reports whether anything
// changed. The input is never mutated: a changed map or slice is a copy.
// Numbers, booleans and nil pass through.
func (s *Scrubber) MaskValue(v any) (any, bool) {
	m := s.load()
	if m == nil {
		return v, false
	}
	return m.maskValue(v)
}

// MayHold is the fast path for serialized JSON: false means raw cannot hold a
// value, so it need not be parsed. A JSON escape (\u or \/) could spell a value
// another way, so either one answers true.
func (s *Scrubber) MayHold(raw []byte) bool {
	m := s.load()
	if m == nil {
		return false
	}
	if bytes.Contains(raw, []byte(`\u`)) || bytes.Contains(raw, []byte(`\/`)) {
		return true
	}
	for _, n := range m.needles {
		if bytes.Contains(raw, n) {
			return true
		}
	}
	return false
}

// MaskJSON masks every string value inside a serialized JSON document and
// returns the re-encoded document (numbers keep their literal text, HTML is not
// escaped). A document that holds no value comes back as the same bytes.
// Bytes that are not JSON are masked as text.
func (s *Scrubber) MaskJSON(raw []byte) []byte {
	if !s.MayHold(raw) {
		return raw
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil || dec.More() {
		return []byte(s.Mask(string(raw)))
	}
	masked, changed := s.MaskValue(v)
	if !changed {
		return raw
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(masked); err != nil {
		// Unreachable for a value the decoder produced; fail towards masking.
		return []byte(s.Mask(string(raw)))
	}
	return bytes.TrimRight(buf.Bytes(), "\n")
}

func (m *matcher) maskValue(v any) (any, bool) {
	switch t := v.(type) {
	case string:
		out := t
		for _, val := range m.values {
			out = maskToken(out, val)
		}
		return out, out != t
	case map[string]any:
		var out map[string]any
		for k, e := range t {
			masked, changed := m.maskValue(e)
			if !changed {
				continue
			}
			if out == nil {
				out = make(map[string]any, len(t))
				for k2, e2 := range t {
					out[k2] = e2
				}
			}
			out[k] = masked
		}
		if out == nil {
			return t, false
		}
		return out, true
	case []any:
		var out []any
		for i, e := range t {
			masked, changed := m.maskValue(e)
			if !changed {
				continue
			}
			if out == nil {
				out = append([]any(nil), t...)
			}
			out[i] = masked
		}
		if out == nil {
			return t, false
		}
		return out, true
	}
	return v, false
}

// build turns the Source's values into a matcher: eligible values only,
// distinct, longest first.
func build(values []string) *matcher {
	seen := make(map[string]bool, len(values))
	kept := make([]string, 0, len(values))
	for _, v := range values {
		if !eligible(v) || seen[v] {
			continue
		}
		seen[v] = true
		kept = append(kept, v)
	}
	sort.Slice(kept, func(i, j int) bool {
		if len(kept[i]) != len(kept[j]) {
			return len(kept[i]) > len(kept[j])
		}
		return kept[i] < kept[j]
	})
	m := &matcher{values: kept}
	for _, v := range kept {
		m.needles = append(m.needles, []byte(v))
		if enc := jsonInner(v); enc != v {
			m.needles = append(m.needles, []byte(enc))
		}
	}
	return m
}

// eligible says whether a value is masked at all (see the package comment).
func eligible(v string) bool {
	if utf8.RuneCountInString(v) < MinValueRunes {
		return false
	}
	digits, substance := true, false
	for i := 0; i < len(v); i++ {
		c := v[i]
		if c < '0' || c > '9' {
			digits = false
		}
		if !isBoundary(c) && c != '.' {
			substance = true
		}
	}
	return !digits && substance
}

// jsonInner is v as encoding/json writes it between the quotes of a string,
// HTML characters left alone (the escapes they would get are \u forms, which
// MayHold already treats as a hit).
func jsonInner(v string) string {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return v
	}
	out := strings.TrimSuffix(buf.String(), "\n")
	if len(out) >= 2 {
		return out[1 : len(out)-1]
	}
	return v
}

// maskToken replaces every whole-token occurrence of v in s with Mask.
func maskToken(s, v string) string {
	if len(v) == 0 || len(s) < len(v) {
		return s
	}
	var b strings.Builder
	from, written, changed := 0, 0, false
	for from <= len(s)-len(v) {
		j := strings.Index(s[from:], v)
		if j < 0 {
			break
		}
		start := from + j
		end := start + len(v)
		if leftEdge(s, start) && rightEdge(s, end) {
			if !changed {
				b.Grow(len(s))
				changed = true
			}
			b.WriteString(s[written:start])
			b.WriteString(Mask)
			written, from = end, end
			continue
		}
		from = start + 1
	}
	if !changed {
		return s
	}
	b.WriteString(s[written:])
	return b.String()
}

func leftEdge(s string, start int) bool {
	return start == 0 || isBoundary(s[start-1])
}

func rightEdge(s string, end int) bool {
	if end == len(s) || isBoundary(s[end]) {
		return true
	}
	// A full stop ends a sentence only when the text ends or a space follows.
	return s[end] == '.' && (end+1 == len(s) || isSpace(s[end+1]))
}

// isBoundary names the bytes that separate tokens. All are ASCII, so a byte
// inside a multi-byte UTF-8 sequence (always >= 0x80) never counts.
func isBoundary(c byte) bool {
	if isSpace(c) {
		return true
	}
	switch c {
	case '"', '\'', '`', '/', ':', '=', ',', '(', ')', '[', ']', '{', '}', '<', '>', ';', '|', '@', '\\':
		return true
	}
	return false
}

func isSpace(c byte) bool {
	switch c {
	case ' ', '\t', '\n', '\r', '\f', '\v':
		return true
	}
	return false
}

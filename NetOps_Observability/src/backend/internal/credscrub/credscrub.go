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
// MinValueRunes characters, not made only of separators, and, when it is
// purely numeric, at least MinNumericDigits digits. Numeric communities exist
// in the field; a short number would mask ordinary counters and ids far more
// often than it hides a credential. "public" and "private" ARE communities: when
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
// # Tenancy: a mask set per caller
//
// Every value belongs to a tenant (Value.Tenant; "" or "global" is
// platform-global, which is also where an operator-set SNMP_COMMUNITY and a
// legacy discovery community land). A read path asks For(tenant, cross) and
// masks with THAT caller's set: its own tenant's values plus the global ones.
// It never masks with another tenant's values, because doing so would be a
// cross-tenant oracle: a tenant that can put a candidate string into its own
// logs (any device it owns can log text) and read it back would learn whether
// the string is SOME tenant's community. A cross-tenant (platform) caller
// already reads every tenant's records, so it gets the union.
//
// The one exception is the provider egress pass (Union), which runs on a
// payload on its way OUT to an external LLM provider and returns nothing to any
// caller: masking with the union there cannot reveal anything and only removes
// information.
//
// Tenant scoping of the data itself stays where it is (the index pattern and
// the per-document filter of each read path); this package never selects data.
//
// # Rotation
//
// A value removed from the configuration stays masked, for the tenant it
// belonged to, until the process restarts: the records stored while it was in
// force still hold it, and a rotated community is often still live on a device
// nobody has updated yet. Retired values are bounded per tenant
// (maxRetiredPerTenant) and in total (maxRetiredTotal); past a bound the OLDEST
// retired values go first, from the tenant holding the most, so one tenant
// churning its own profiles cannot evict another tenant's history. A configured
// value is never evicted. Nothing is persisted: after a restart only what is
// configured is masked.
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

// MinNumericDigits is the shortest purely numeric value that is masked.
const MinNumericDigits = 6

// Bounds on the values kept after they leave the configuration (§9).
const (
	maxRetiredPerTenant = 512
	maxRetiredTotal     = 4096
)

// Value is one configured credential value and the tenant that owns it. A
// Tenant of "" or "global" is platform-global: masked for every caller.
type Value struct {
	Tenant string
	Text   string
}

// Source returns the credential values in force now. It is called on every
// Refresh. An error keeps the previous set: a transient store failure must not
// silently stop masking.
type Source func(ctx context.Context) ([]Value, error)

// Scrubber holds the current value sets. The zero value and a nil *Scrubber
// mask nothing. It is safe for concurrent use: readers load an immutable
// snapshot through an atomic pointer, and refreshes are serialised.
type Scrubber struct {
	src       Source
	refreshMu sync.Mutex
	// configured and retired are guarded by refreshMu. retired maps an entry
	// to the order it was retired in (smaller = older).
	configured map[entry]bool
	retired    map[entry]uint64
	seq        uint64
	cur        atomic.Pointer[snapshot]
}

// entry is a value under its normalized tenant ("" = global).
type entry struct {
	tenant string
	text   string
}

// snapshot is one immutable set of matchers.
type snapshot struct {
	union    *matcher
	global   *matcher
	byTenant map[string]*matcher // the tenant's own values plus the global ones
}

// matcher is one immutable list of eligible values.
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

// normTenant folds a tenant id the way rbac.SameTenantStrict compares them;
// "global" is the platform's own tenant, the same bucket as untagged.
func normTenant(t string) string {
	t = strings.ToLower(strings.TrimSpace(t))
	if t == "global" {
		return ""
	}
	return t
}

// Refresh brings the value sets up to what the Source returns now; a value
// that left the configuration stays masked for its tenant (see Rotation). On a
// Source error the previous sets stay in force and the error is returned; the
// error never carries a value.
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
	current := make(map[entry]bool, len(values))
	for _, v := range values {
		if eligible(v.Text) {
			current[entry{tenant: normTenant(v.Tenant), text: v.Text}] = true
		}
	}
	if s.retired == nil {
		s.retired = make(map[entry]uint64)
	}
	// Deterministic retirement order within one refresh.
	gone := make([]entry, 0)
	for e := range s.configured {
		if !current[e] {
			gone = append(gone, e)
		}
	}
	sort.Slice(gone, func(i, j int) bool {
		if gone[i].tenant != gone[j].tenant {
			return gone[i].tenant < gone[j].tenant
		}
		return gone[i].text < gone[j].text
	})
	for _, e := range gone {
		if _, already := s.retired[e]; !already {
			s.seq++
			s.retired[e] = s.seq
		}
	}
	for e := range current {
		delete(s.retired, e) // configured again: no longer retired
	}
	s.evict()
	s.configured = current

	all := make([]entry, 0, len(current)+len(s.retired))
	for e := range current {
		all = append(all, e)
	}
	for e := range s.retired {
		all = append(all, e)
	}
	s.cur.Store(buildSnapshot(all))
	return nil
}

// evict enforces the retirement bounds, oldest first. Caller holds refreshMu.
func (s *Scrubber) evict() {
	perTenant := map[string][]entry{}
	for e := range s.retired {
		perTenant[e.tenant] = append(perTenant[e.tenant], e)
	}
	oldestFirst := func(es []entry) {
		sort.Slice(es, func(i, j int) bool { return s.retired[es[i]] < s.retired[es[j]] })
	}
	total := 0
	for t, es := range perTenant {
		oldestFirst(es)
		for len(es) > maxRetiredPerTenant {
			delete(s.retired, es[0])
			es = es[1:]
		}
		perTenant[t] = es
		total += len(es)
	}
	for total > maxRetiredTotal {
		// The tenant holding the most retired values gives up its oldest.
		var worst string
		for t, es := range perTenant {
			if len(es) > len(perTenant[worst]) || (len(es) == len(perTenant[worst]) && t < worst) {
				worst = t
			}
		}
		es := perTenant[worst]
		delete(s.retired, es[0])
		perTenant[worst] = es[1:]
		total--
	}
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

// For returns the mask set for one caller: its own tenant's values plus the
// global ones, or every tenant's when cross is true. The View is a snapshot:
// obtain one per request, never keep it across a refresh.
func (s *Scrubber) For(tenant string, cross bool) View {
	if s == nil {
		return View{}
	}
	snap := s.cur.Load()
	if snap == nil {
		return View{}
	}
	if cross {
		return View{m: snap.union}
	}
	if m, ok := snap.byTenant[normTenant(tenant)]; ok {
		return View{m: m}
	}
	return View{m: snap.global}
}

// Union returns every tenant's values. Only for a payload that leaves for an
// external provider and is returned to no caller (see the package comment).
func (s *Scrubber) Union() View {
	return s.For("", true)
}

// View masks with one caller's set. The zero View masks nothing.
type View struct {
	m *matcher
}

// String never prints the values.
func (v View) String() string { return "credscrub.View{values redacted}" }

// GoString never prints the values (fmt's %#v).
func (v View) GoString() string { return v.String() }

func (v View) matcher() *matcher {
	if v.m == nil || len(v.m.values) == 0 {
		return nil
	}
	return v.m
}

// Mask returns str with every whole-token occurrence of a value replaced by
// Mask. A string that holds none is returned unchanged.
func (v View) Mask(str string) string {
	m := v.matcher()
	if m == nil {
		return str
	}
	for _, val := range m.values {
		str = maskToken(str, val)
	}
	return str
}

// MaskValue masks every string inside a decoded JSON value (maps, slices and
// strings, at any depth; map keys are left alone) and reports whether anything
// changed. The input is never mutated: a changed map or slice is a copy.
// Numbers, booleans and nil pass through.
func (v View) MaskValue(x any) (any, bool) {
	m := v.matcher()
	if m == nil {
		return x, false
	}
	return m.maskValue(x)
}

// MayHold is the fast path for serialized JSON: false means raw cannot hold a
// value, so it need not be parsed. A JSON escape (\u or \/) could spell a value
// another way, so either one answers true.
func (v View) MayHold(raw []byte) bool {
	m := v.matcher()
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
func (v View) MaskJSON(raw []byte) []byte {
	if !v.MayHold(raw) {
		return raw
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var x any
	if err := dec.Decode(&x); err != nil || dec.More() {
		return []byte(v.Mask(string(raw)))
	}
	masked, changed := v.MaskValue(x)
	if !changed {
		return raw
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(masked); err != nil {
		// Unreachable for a value the decoder produced; fail towards masking.
		return []byte(v.Mask(string(raw)))
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

// buildSnapshot builds the union, the global set and one set per tenant.
func buildSnapshot(entries []entry) *snapshot {
	var union, global []string
	own := map[string][]string{}
	for _, e := range entries {
		union = append(union, e.text)
		if e.tenant == "" {
			global = append(global, e.text)
		} else {
			own[e.tenant] = append(own[e.tenant], e.text)
		}
	}
	snap := &snapshot{union: build(union), global: build(global), byTenant: make(map[string]*matcher, len(own))}
	for t, vs := range own {
		snap.byTenant[t] = build(append(append([]string(nil), vs...), global...))
	}
	return snap
}

// build turns values into a matcher: eligible values only, distinct, longest
// first.
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
	if digits {
		return len(v) >= MinNumericDigits
	}
	return substance
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

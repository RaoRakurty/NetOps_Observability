// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package credscrub

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

// Fabricated values, built at run time so no literal looks like a credential.
var (
	comm  = "fixture-comm-" + strings.Repeat("q", 6)
	comm2 = "fixture-ro-" + strings.Repeat("z", 4)
)

// global wraps values as platform-global (masked for every caller).
func global(values ...string) []Value {
	out := make([]Value, 0, len(values))
	for _, v := range values {
		out = append(out, Value{Text: v})
	}
	return out
}

func fixed(values ...string) Source {
	return func(context.Context) ([]Value, error) { return global(values...), nil }
}

func newScrubber(t *testing.T, values ...string) *Scrubber {
	t.Helper()
	s := New(fixed(values...))
	if err := s.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	return s
}

func TestMaskTheConfdSessionLinesByValue(t *testing.T) {
	s := newScrubber(t, comm)
	for in, want := range map[string]string{
		"audit user: " + comm + "/49119 created new session via snmp from 127.0.0.1:54873 with udp": "audit user: ***/49119 created new session via snmp from 127.0.0.1:54873 with udp",
		"audit user: " + comm + "/49119 assigned to groups: basic":                                  "audit user: ***/49119 assigned to groups: basic",
		"audit user: " + comm + "/49088 terminated session (reason: normal)":                        "audit user: ***/49088 terminated session (reason: normal)",
		"Session closed on vEdge-20 for " + comm + " (normal)":                                      "Session closed on vEdge-20 for *** (normal)",
		comm: Mask,
	} {
		if got := s.Union().Mask(in); got != want {
			t.Errorf("Mask(%q)\n got %q\nwant %q", in, got, want)
		}
	}
}

func TestMaskOnlyWholeTokens(t *testing.T) {
	s := newScrubber(t, comm)
	masked := []string{
		"x " + comm, comm + " x", "'" + comm + "'", `"` + comm + `"`, "`" + comm + "`",
		"a/" + comm + "/b", "user:" + comm, "community=" + comm, comm + ",next", "(" + comm + ")",
		"[" + comm + "]", "{" + comm + "}", "<" + comm + ">", comm + ";", "a|" + comm, comm + "@10",
		"tab\t" + comm + "\n", `path\` + comm, "it was " + comm + ".", "it was " + comm + ". Next",
	}
	for _, in := range masked {
		if got := s.Union().Mask(in); strings.Contains(got, comm) || !strings.Contains(got, Mask) {
			t.Errorf("Mask(%q) = %q, want the value masked", in, got)
		}
	}
	kept := []string{
		"x" + comm, comm + "x", comm + "-2", "pre-" + comm, comm + ".example.com", comm + "_a",
		strings.ToUpper(comm), comm[:len(comm)-1],
	}
	for _, in := range kept {
		if got := s.Union().Mask(in); got != in {
			t.Errorf("Mask(%q) = %q, want it unchanged (not a whole token)", in, got)
		}
	}
}

func TestMaskEveryOccurrenceAndLongestFirst(t *testing.T) {
	long := comm + "/" + comm2
	s := newScrubber(t, comm, comm2, long)
	in := comm + " " + comm2 + " " + long + " " + comm
	if got, want := s.Union().Mask(in), "*** *** *** ***"; got != want {
		t.Errorf("Mask = %q, want %q", got, want)
	}
	// Adjacent tokens separated by a boundary are each masked.
	if got := s.Union().Mask(comm + ":" + comm2); got != "***:***" {
		t.Errorf("Mask = %q", got)
	}
}

func TestMaskLeavesTextWithoutAValueByteIdentical(t *testing.T) {
	s := newScrubber(t, comm, "public")
	for _, in := range []string{
		"", "ordinary line", "café ünïcode \x00\xff raw bytes", "publicity", "publicly", "PUBLIC",
		"fixture-comm-qqqqq", strings.Repeat("a", 4096),
	} {
		got := s.Union().Mask(in)
		if got != in {
			t.Errorf("Mask(%q) = %q, want byte-identical", in, got)
		}
	}
	raw := []byte(`{"message":"ordinary line","n":12345678901234567890}`)
	if out := s.Union().MaskJSON(raw); string(out) != string(raw) {
		t.Errorf("MaskJSON changed a document without a value: %s", out)
	}
}

func TestShortNumericAndSeparatorValuesAreIgnored(t *testing.T) {
	s := newScrubber(t, "abc", "1234", "12345", "////", "....", "a.b")
	for _, in := range []string{"abc", "x 1234 y", "12345", "a //// b", "....", "a.b"} {
		if got := s.Union().Mask(in); got != in {
			t.Errorf("Mask(%q) = %q: an ineligible value was masked", in, got)
		}
	}
	if s.Union().MayHold([]byte(`{"a":"abc 1234"}`)) {
		t.Error("MayHold matched an ineligible value")
	}
	// Four characters with a letter is eligible.
	s2 := newScrubber(t, "ab12")
	if got := s2.Union().Mask("x ab12 y"); got != "x *** y" {
		t.Errorf("Mask = %q", got)
	}
}

// Numeric communities exist in the field: six digits or more are masked, five
// or fewer (counters, ids, ports) are not.
func TestNumericValuesAreMaskedFromSixDigits(t *testing.T) {
	five, six, seven := "40213", "402137", "4021379"
	s := newScrubber(t, five, six, seven)
	if got := s.Union().Mask("a " + five + " b"); got != "a "+five+" b" {
		t.Errorf("a five-digit value was masked: %q", got)
	}
	for _, v := range []string{six, seven} {
		if got := s.Union().Mask("community " + v + " ok"); got != "community *** ok" {
			t.Errorf("a %d-digit value was not masked: %q", len(v), got)
		}
	}
	// Whole token only: a longer number holding it is left alone.
	if got := s.Union().Mask("ifIndex 14021370"); got != "ifIndex 14021370" {
		t.Errorf("a number containing the value was masked: %q", got)
	}
}

func TestConfiguredPublicIsMaskedTheProtocolWordIsNot(t *testing.T) {
	s := newScrubber(t, "public")
	if got := s.Union().Mask("bad community name: public 10.0.0.1"); got != "bad community name: *** 10.0.0.1" {
		t.Errorf("Mask = %q", got)
	}
	if got := newScrubber(t).Union().Mask("public"); got != "public" {
		t.Errorf("an empty set masked %q", got)
	}
}

func TestMaskValueWalksEveryStringAtAnyDepth(t *testing.T) {
	s := newScrubber(t, comm)
	doc := map[string]any{
		"audit_user":       comm,
		"title":            "SNMP session on vEdge-20 by " + comm + " from 127.0.0.1 (poll)",
		"summary":          "Session of " + comm + " closed (normal)",
		"correlation_key":  "audit:vEdge-20:groups:" + comm,
		"dedup_key":        "vEdge-20|confd|" + comm,
		"message":          "audit user: " + comm + "/1 terminated session (reason: normal)",
		"message_original": "<190>... audit user: " + comm + "/1 ...",
		"structured_data":  map[string]any{"meta": []any{map[string]any{"user": comm}, "keep", 7.0}},
		comm:               "a key is left alone",
		"n":                json.Number("12345678901234567890"),
		"ok":               true,
		"nil":              nil,
	}
	before := fmt.Sprint(doc)
	out, changed := s.Union().MaskValue(doc)
	if !changed {
		t.Fatal("changed = false")
	}
	if fmt.Sprint(doc) != before {
		t.Fatal("MaskValue mutated its input")
	}
	b, err := json.Marshal(out)
	if err != nil {
		t.Fatal(err)
	}
	str := string(b)
	// The only surviving copy is the map key, which is not a value.
	if strings.Count(str, comm) != 1 || !strings.Contains(str, `"`+comm+`":"a key is left alone"`) {
		t.Errorf("value survived: %s", str)
	}
	for _, want := range []string{`"n":12345678901234567890`, `"ok":true`, `"nil":null`, `"keep"`, `7`} {
		if !strings.Contains(str, want) {
			t.Errorf("lost %s in %s", want, str)
		}
	}
	if _, changed := s.Union().MaskValue(map[string]any{"a": []any{"b", 1.0}}); changed {
		t.Error("changed = true for a document without a value")
	}
}

func TestMayHoldSeesRawAndEscapedSpellings(t *testing.T) {
	quoted := `pub"lic-` + strings.Repeat("q", 3)
	s := newScrubber(t, comm, quoted, "a/b/c/d")
	for _, raw := range []string{
		`{"m":"` + comm + `"}`,
		`{"m":"pub\"lic-qqq"}`,           // a quote inside a value is escaped in JSON
		`{"m":"` + `\` + `u0066ixture"}`, // any \u escape could spell a value
		`{"m":"a\/b\/c\/d"}`,             // so could \/
	} {
		if !s.Union().MayHold([]byte(raw)) {
			t.Errorf("MayHold(%s) = false", raw)
		}
	}
	if s.Union().MayHold([]byte(`{"m":"nothing here"}`)) {
		t.Error("MayHold = true for a document without a value")
	}
	out := string(s.Union().MaskJSON([]byte(`{"m":"pub\"lic-qqq x","e":"a\/b\/c\/d"}`)))
	if strings.Contains(out, "lic-qqq") || strings.Contains(out, "a/b/c/d") || strings.Contains(out, `a\/b`) {
		t.Errorf("MaskJSON left a value: %s", out)
	}
}

func TestMaskJSONKeepsNumbersAndFallsBackToTextForNonJSON(t *testing.T) {
	s := newScrubber(t, comm)
	out := string(s.Union().MaskJSON([]byte(`{"messages":[{"content":"seen ` + comm + ` <b>"}],"max":12345678901234567890}`)))
	if strings.Contains(out, comm) || !strings.Contains(out, `12345678901234567890`) || !strings.Contains(out, "<b>") {
		t.Errorf("MaskJSON = %s", out)
	}
	if got := string(s.Union().MaskJSON([]byte("not json " + comm))); got != "not json ***" {
		t.Errorf("MaskJSON(non-JSON) = %q", got)
	}
}

func TestRefreshPicksUpACredentialChange(t *testing.T) {
	var mu sync.Mutex
	current := []string{comm}
	s := New(func(context.Context) ([]Value, error) {
		mu.Lock()
		defer mu.Unlock()
		return global(current...), nil
	})
	if got := s.Union().Mask(comm); got != comm {
		t.Fatalf("masked before the first refresh: %q", got)
	}
	if err := s.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := s.Union().Mask(comm); got != Mask {
		t.Fatalf("Mask = %q after refresh", got)
	}
	mu.Lock()
	current = []string{comm2} // rotated: the old value is no longer configured
	mu.Unlock()
	if err := s.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	// The new value is masked, and the retired one still is: lines stored while
	// it was in force hold it, and a device may not have been updated yet.
	if got := s.Union().Mask(comm + " " + comm2); got != "*** ***" {
		t.Errorf("Mask = %q after rotation", got)
	}
	// Configured again, then retired again: still one value, still masked.
	mu.Lock()
	current = []string{comm, comm2}
	mu.Unlock()
	if err := s.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	current = nil
	mu.Unlock()
	if err := s.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := s.Union().Mask(comm + " " + comm2); got != "*** ***" {
		t.Errorf("Mask = %q after both were removed", got)
	}
}

// swappable is a Source whose values a test replaces between refreshes.
type swappable struct {
	mu  sync.Mutex
	cur []Value
}

func (w *swappable) set(v []Value) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.cur = v
}

func (w *swappable) source(context.Context) ([]Value, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]Value(nil), w.cur...), nil
}

func tenantValues(tenant, prefix string, n int) []Value {
	out := make([]Value, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, Value{Tenant: tenant, Text: fmt.Sprintf("%s-%05d", prefix, i)})
	}
	return out
}

// A burst of retirements evicts the OLDEST retired values of that tenant first,
// and never a value still configured.
func TestRetiredValuesAreEvictedOldestFirstPerTenant(t *testing.T) {
	w := &swappable{}
	s := New(w.source)
	keep := Value{Tenant: "acme", Text: "fixture-keep-" + strings.Repeat("k", 4)}
	refresh := func(v []Value) {
		t.Helper()
		w.set(v)
		if err := s.Refresh(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	// Round 0's values, then round 1's: round 0 retires first (oldest).
	r0 := tenantValues("acme", "fixture-r0", maxRetiredPerTenant/2)
	r1 := tenantValues("acme", "fixture-r1", maxRetiredPerTenant)
	refresh(append([]Value{keep}, r0...))
	refresh(append([]Value{keep}, r1...)) // r0 retired
	refresh([]Value{keep})                // r1 retired: acme now holds 1.5x its bound
	acme := s.For("acme", false)
	if acme.Mask(keep.Text) != Mask {
		t.Fatal("a configured value was evicted")
	}
	if acme.Mask(r0[0].Text) != r0[0].Text {
		t.Error("the oldest retired value survived while newer ones were evicted")
	}
	if acme.Mask(r1[len(r1)-1].Text) != Mask {
		t.Error("the newest retired value was evicted")
	}
	held := 0
	for _, v := range append(r0, r1...) {
		if acme.Mask(v.Text) == Mask {
			held++
		}
	}
	if held != maxRetiredPerTenant {
		t.Errorf("acme holds %d retired values, bound %d", held, maxRetiredPerTenant)
	}
}

// One tenant churning its own profiles cannot evict another tenant's retired
// values, and the total stays bounded.
func TestOneTenantsBurstDoesNotEvictAnothersHistory(t *testing.T) {
	w := &swappable{}
	s := New(w.source)
	globex := Value{Tenant: "globex", Text: "fixture-globex-" + strings.Repeat("g", 4)}
	w.set([]Value{globex})
	if err := s.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	w.set(nil) // globex's value retires
	if err := s.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	// Another tenant cycles far more values than the total bound through
	// configured -> retired, and keeps many configured.
	for round := 0; round < 12; round++ {
		w.set(tenantValues(fmt.Sprintf("t%02d", round), fmt.Sprintf("fixture-b%02d", round), maxRetiredPerTenant))
		if err := s.Refresh(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if s.For("globex", false).Mask(globex.Text) != Mask {
		t.Error("another tenant's burst evicted globex's retired value")
	}
	s.refreshMu.Lock()
	n := len(s.retired)
	s.refreshMu.Unlock()
	if n > maxRetiredTotal {
		t.Errorf("held %d retired values, total bound %d", n, maxRetiredTotal)
	}
	// The last round is configured, so every one of its values is masked.
	for _, v := range tenantValues("t11", "fixture-b11", maxRetiredPerTenant) {
		if s.For("t11", false).Mask(v.Text) != Mask {
			t.Fatal("a configured value was dropped by the bound")
		}
	}
}

// §3a: a caller masks with its own tenant's values and the global ones, never
// another tenant's (that would be an oracle on the other tenant's community).
func TestEachCallerMasksWithItsOwnSet(t *testing.T) {
	a, b := "fixture-acme-"+strings.Repeat("a", 4), "fixture-globex-"+strings.Repeat("b", 4)
	g, env := "fixture-global-"+strings.Repeat("c", 4), "fixture-env-"+strings.Repeat("d", 4)
	s := New(func(context.Context) ([]Value, error) {
		return []Value{{Tenant: "acme", Text: a}, {Tenant: " GlobEx ", Text: b}, {Tenant: "", Text: g}, {Tenant: "global", Text: env}}, nil
	})
	if err := s.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	line := strings.Join([]string{a, b, g, env}, " ")
	for _, c := range []struct {
		name   string
		tenant string
		cross  bool
		want   string
	}{
		{"acme", "acme", false, "*** " + b + " *** ***"},
		{"globex, any case", "GLOBEX", false, a + " *** *** ***"},
		{"a tenant with no profile", "initech", false, a + " " + b + " *** ***"},
		{"the provider scope", "global", false, a + " " + b + " *** ***"},
		{"cross-tenant", "", true, "*** *** *** ***"},
	} {
		if got := s.For(c.tenant, c.cross).Mask(line); got != c.want {
			t.Errorf("%s: Mask = %q, want %q", c.name, got, c.want)
		}
	}
	if got := s.Union().Mask(line); got != "*** *** *** ***" {
		t.Errorf("Union = %q", got)
	}
}

func TestARetiredValueKeepsItsTenant(t *testing.T) {
	w := &swappable{}
	s := New(w.source)
	a := Value{Tenant: "acme", Text: "fixture-acme-" + strings.Repeat("a", 4)}
	w.set([]Value{a})
	if err := s.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	w.set(nil)
	if err := s.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if s.For("acme", false).Mask(a.Text) != Mask {
		t.Error("acme's retired value is no longer masked for acme")
	}
	if s.For("globex", false).Mask(a.Text) != a.Text {
		t.Error("acme's retired value is masked for globex (cross-tenant oracle)")
	}
}

func TestASourceErrorKeepsTheLastGoodSetAndNamesNoValue(t *testing.T) {
	fail := false
	s := New(func(context.Context) ([]Value, error) {
		if fail {
			return nil, errors.New("store unavailable")
		}
		return global(comm), nil
	})
	if err := s.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	fail = true
	err := s.Refresh(context.Background())
	if err == nil {
		t.Fatal("want the source error")
	}
	if strings.Contains(err.Error(), comm) {
		t.Errorf("error carries a value: %v", err)
	}
	if got := s.Union().Mask(comm); got != Mask {
		t.Errorf("a failed refresh dropped the set: %q", got)
	}
}

func TestNilAndZeroScrubbersMaskNothing(t *testing.T) {
	var nilS *Scrubber
	if nilS.Union().Mask(comm) != comm || nilS.Union().MayHold([]byte(comm)) || nilS.Refresh(context.Background()) != nil {
		t.Error("nil scrubber is not a no-op")
	}
	if v, ch := nilS.Union().MaskValue(comm); ch || v != comm {
		t.Error("nil MaskValue changed something")
	}
	var zero Scrubber
	if zero.Union().Mask(comm) != comm {
		t.Error("zero scrubber masked")
	}
	if err := zero.Refresh(context.Background()); err == nil {
		t.Error("a scrubber without a source must say so")
	}
	nilS.Run(context.Background(), time.Millisecond, nil) // returns at once
}

func TestTheSetIsNeverPrinted(t *testing.T) {
	s := newScrubber(t, comm)
	for _, verb := range []string{"%v", "%+v", "%#v", "%s"} {
		if out := fmt.Sprintf(verb, s); strings.Contains(out, comm) {
			t.Errorf("%s printed a value: %s", verb, out)
		}
	}
	for _, verb := range []string{"%v", "%+v", "%#v", "%s"} {
		if out := fmt.Sprintf(verb, s.Union()); strings.Contains(out, comm) {
			t.Errorf("View %s printed a value: %s", verb, out)
		}
	}
	holder := struct{ S *Scrubber }{s}
	if out := fmt.Sprintf("%+v", holder); strings.Contains(out, comm) {
		t.Errorf("an embedding struct printed a value: %s", out)
	}
}

func TestRunRefreshesUntilCancelled(t *testing.T) {
	var mu sync.Mutex
	calls := 0
	s := New(func(context.Context) ([]Value, error) {
		mu.Lock()
		defer mu.Unlock()
		calls++
		if calls == 2 {
			return nil, errors.New("blip")
		}
		return global(comm), nil
	})
	ctx, cancel := context.WithCancel(context.Background())
	errs := make(chan error, 8)
	done := make(chan struct{})
	go func() {
		s.Run(ctx, time.Millisecond, func(err error) { errs <- err })
		close(done)
	}()
	deadline := time.After(5 * time.Second)
	for {
		mu.Lock()
		n := calls
		mu.Unlock()
		if n >= 3 {
			break
		}
		select {
		case <-deadline:
			t.Fatal("Run did not keep refreshing")
		case <-time.After(time.Millisecond):
		}
	}
	cancel()
	<-done
	select {
	case err := <-errs:
		if strings.Contains(err.Error(), comm) {
			t.Errorf("reported error carries a value: %v", err)
		}
	default:
		t.Error("the refresh error was not reported")
	}
	if s.Union().Mask(comm) != Mask {
		t.Error("set lost after a failed tick")
	}
}

// Readers and refreshes run together; go test -race (CI) proves the absence of
// data races, and this asserts every reader sees a whole snapshot.
func TestConcurrentMaskAndRefresh(t *testing.T) {
	var mu sync.Mutex
	flip := false
	s := New(func(context.Context) ([]Value, error) {
		mu.Lock()
		defer mu.Unlock()
		flip = !flip
		if flip {
			return global(comm, comm2), nil
		}
		return global(comm2, comm), nil
	})
	if err := s.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for w := 0; w < 8; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 500; i++ {
				if got := s.Union().Mask(comm + " " + comm2); got != "*** ***" {
					t.Errorf("Mask = %q", got)
					return
				}
				_ = s.Union().MayHold([]byte(comm))
			}
		}()
	}
	for i := 0; i < 200; i++ {
		if err := s.Refresh(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	wg.Wait()
}

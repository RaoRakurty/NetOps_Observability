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

func fixed(values ...string) Source {
	return func(context.Context) ([]string, error) { return values, nil }
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
		if got := s.Mask(in); got != want {
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
		if got := s.Mask(in); strings.Contains(got, comm) || !strings.Contains(got, Mask) {
			t.Errorf("Mask(%q) = %q, want the value masked", in, got)
		}
	}
	kept := []string{
		"x" + comm, comm + "x", comm + "-2", "pre-" + comm, comm + ".example.com", comm + "_a",
		strings.ToUpper(comm), comm[:len(comm)-1],
	}
	for _, in := range kept {
		if got := s.Mask(in); got != in {
			t.Errorf("Mask(%q) = %q, want it unchanged (not a whole token)", in, got)
		}
	}
}

func TestMaskEveryOccurrenceAndLongestFirst(t *testing.T) {
	long := comm + "/" + comm2
	s := newScrubber(t, comm, comm2, long)
	in := comm + " " + comm2 + " " + long + " " + comm
	if got, want := s.Mask(in), "*** *** *** ***"; got != want {
		t.Errorf("Mask = %q, want %q", got, want)
	}
	// Adjacent tokens separated by a boundary are each masked.
	if got := s.Mask(comm + ":" + comm2); got != "***:***" {
		t.Errorf("Mask = %q", got)
	}
}

func TestMaskLeavesTextWithoutAValueByteIdentical(t *testing.T) {
	s := newScrubber(t, comm, "public")
	for _, in := range []string{
		"", "ordinary line", "café ünïcode \x00\xff raw bytes", "publicity", "publicly", "PUBLIC",
		"fixture-comm-qqqqq", strings.Repeat("a", 4096),
	} {
		got := s.Mask(in)
		if got != in {
			t.Errorf("Mask(%q) = %q, want byte-identical", in, got)
		}
	}
	raw := []byte(`{"message":"ordinary line","n":12345678901234567890}`)
	if out := s.MaskJSON(raw); string(out) != string(raw) {
		t.Errorf("MaskJSON changed a document without a value: %s", out)
	}
}

func TestShortNumericAndSeparatorValuesAreIgnored(t *testing.T) {
	s := newScrubber(t, "abc", "1234", "56789012", "////", "....", "a.b")
	for _, in := range []string{"abc", "x 1234 y", "56789012", "a //// b", "....", "a.b"} {
		if got := s.Mask(in); got != in {
			t.Errorf("Mask(%q) = %q: an ineligible value was masked", in, got)
		}
	}
	if s.MayHold([]byte(`{"a":"abc 1234"}`)) {
		t.Error("MayHold matched an ineligible value")
	}
	// Four characters with a letter is eligible.
	s2 := newScrubber(t, "ab12")
	if got := s2.Mask("x ab12 y"); got != "x *** y" {
		t.Errorf("Mask = %q", got)
	}
}

func TestConfiguredPublicIsMaskedTheProtocolWordIsNot(t *testing.T) {
	s := newScrubber(t, "public")
	if got := s.Mask("bad community name: public 10.0.0.1"); got != "bad community name: *** 10.0.0.1" {
		t.Errorf("Mask = %q", got)
	}
	if got := newScrubber(t).Mask("public"); got != "public" {
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
	out, changed := s.MaskValue(doc)
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
	if _, changed := s.MaskValue(map[string]any{"a": []any{"b", 1.0}}); changed {
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
		if !s.MayHold([]byte(raw)) {
			t.Errorf("MayHold(%s) = false", raw)
		}
	}
	if s.MayHold([]byte(`{"m":"nothing here"}`)) {
		t.Error("MayHold = true for a document without a value")
	}
	out := string(s.MaskJSON([]byte(`{"m":"pub\"lic-qqq x","e":"a\/b\/c\/d"}`)))
	if strings.Contains(out, "lic-qqq") || strings.Contains(out, "a/b/c/d") || strings.Contains(out, `a\/b`) {
		t.Errorf("MaskJSON left a value: %s", out)
	}
}

func TestMaskJSONKeepsNumbersAndFallsBackToTextForNonJSON(t *testing.T) {
	s := newScrubber(t, comm)
	out := string(s.MaskJSON([]byte(`{"messages":[{"content":"seen ` + comm + ` <b>"}],"max":12345678901234567890}`)))
	if strings.Contains(out, comm) || !strings.Contains(out, `12345678901234567890`) || !strings.Contains(out, "<b>") {
		t.Errorf("MaskJSON = %s", out)
	}
	if got := string(s.MaskJSON([]byte("not json " + comm))); got != "not json ***" {
		t.Errorf("MaskJSON(non-JSON) = %q", got)
	}
}

func TestRefreshPicksUpACredentialChange(t *testing.T) {
	var mu sync.Mutex
	current := []string{comm}
	s := New(func(context.Context) ([]string, error) {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), current...), nil
	})
	if got := s.Mask(comm); got != comm {
		t.Fatalf("masked before the first refresh: %q", got)
	}
	if err := s.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := s.Mask(comm); got != Mask {
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
	if got := s.Mask(comm + " " + comm2); got != "*** ***" {
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
	if got := s.Mask(comm + " " + comm2); got != "*** ***" {
		t.Errorf("Mask = %q after both were removed", got)
	}
}

func TestRetiredValuesAreBounded(t *testing.T) {
	var mu sync.Mutex
	var current []string
	s := New(func(context.Context) ([]string, error) {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), current...), nil
	})
	keep := "fixture-keep-" + strings.Repeat("k", 4)
	for round := 0; round < 3; round++ {
		batch := []string{keep}
		for i := 0; i < maxRetained/2+1; i++ {
			batch = append(batch, fmt.Sprintf("fixture-r%d-%05d", round, i))
		}
		mu.Lock()
		current = batch
		mu.Unlock()
		if err := s.Refresh(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if n := len(s.cur.Load().values); n > maxRetained {
		t.Fatalf("held %d values, bound %d", n, maxRetained)
	}
	if s.Mask(keep) != Mask || s.Mask("fixture-r2-00000") != Mask {
		t.Error("a configured value was dropped by the bound")
	}
}

func TestASourceErrorKeepsTheLastGoodSetAndNamesNoValue(t *testing.T) {
	fail := false
	s := New(func(context.Context) ([]string, error) {
		if fail {
			return nil, errors.New("store unavailable")
		}
		return []string{comm}, nil
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
	if got := s.Mask(comm); got != Mask {
		t.Errorf("a failed refresh dropped the set: %q", got)
	}
}

func TestNilAndZeroScrubbersMaskNothing(t *testing.T) {
	var nilS *Scrubber
	if nilS.Mask(comm) != comm || nilS.MayHold([]byte(comm)) || nilS.Refresh(context.Background()) != nil {
		t.Error("nil scrubber is not a no-op")
	}
	if v, ch := nilS.MaskValue(comm); ch || v != comm {
		t.Error("nil MaskValue changed something")
	}
	var zero Scrubber
	if zero.Mask(comm) != comm {
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
	holder := struct{ S *Scrubber }{s}
	if out := fmt.Sprintf("%+v", holder); strings.Contains(out, comm) {
		t.Errorf("an embedding struct printed a value: %s", out)
	}
}

func TestRunRefreshesUntilCancelled(t *testing.T) {
	var mu sync.Mutex
	calls := 0
	s := New(func(context.Context) ([]string, error) {
		mu.Lock()
		defer mu.Unlock()
		calls++
		if calls == 2 {
			return nil, errors.New("blip")
		}
		return []string{comm}, nil
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
	if s.Mask(comm) != Mask {
		t.Error("set lost after a failed tick")
	}
}

// Readers and refreshes run together; go test -race (CI) proves the absence of
// data races, and this asserts every reader sees a whole snapshot.
func TestConcurrentMaskAndRefresh(t *testing.T) {
	var mu sync.Mutex
	flip := false
	s := New(func(context.Context) ([]string, error) {
		mu.Lock()
		defer mu.Unlock()
		flip = !flip
		if flip {
			return []string{comm, comm2}, nil
		}
		return []string{comm2, comm}, nil
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
				if got := s.Mask(comm + " " + comm2); got != "*** ***" {
					t.Errorf("Mask = %q", got)
					return
				}
				_ = s.MayHold([]byte(comm))
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

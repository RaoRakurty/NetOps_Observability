package httppage

// contract_test.go — INVARIANTS gap #7: the paginated response SHAPE was
// prose. These tests pin it mechanically: the five header names (and that
// every write stamps all five), and the opt-in envelope's exact JSON keys.
// A client integrates against these literals; renaming one is a breaking API
// change and MUST fail this build, not surface as a customer's silently-empty
// dashboard. docs/API_ACCESS.md documents the same contract for integrators.

import (
	"net/http/httptest"
	"testing"
)

// TestHeaderNamesArePinned pins the LITERAL header names clients parse.
func TestHeaderNamesArePinned(t *testing.T) {
	pins := map[string]string{
		HeaderTotalCount: "X-Total-Count",
		HeaderPageLimit:  "X-Page-Limit",
		HeaderPageOffset: "X-Page-Offset",
		HeaderPageDone:   "X-Page-Complete",
		HeaderPageMax:    "X-Page-Max-Limit",
	}
	for got, want := range pins {
		if got != want {
			t.Errorf("header constant renamed: %q, clients expect %q — this is a "+
				"breaking API change; if intentional, version it, don't rename it", got, want)
		}
	}
}

// TestWriteHeadersStampsTheWholeContract — a header-blind proxy stripping one
// header is a client-side bug; the SERVER omitting one is ours.
func TestWriteHeadersStampsTheWholeContract(t *testing.T) {
	w := httptest.NewRecorder()
	WriteHeaders(w, Request{Limit: 50, Offset: 10, Max: 500}, 50, 120)
	h := w.Header()
	for _, name := range []string{HeaderTotalCount, HeaderPageLimit, HeaderPageOffset, HeaderPageDone, HeaderPageMax} {
		if h.Get(name) == "" {
			t.Errorf("paginated write omitted %s — a walking client cannot size or terminate its walk", name)
		}
	}
	if h.Get(HeaderTotalCount) != "120" || h.Get(HeaderPageDone) != "false" {
		t.Errorf("total/done wrong: total=%q done=%q", h.Get(HeaderTotalCount), h.Get(HeaderPageDone))
	}

	w = httptest.NewRecorder()
	WriteHeaders(w, Request{Limit: 50, Offset: 0, Max: 500}, 20, 20)
	if w.Header().Get(HeaderPageDone) != "true" {
		t.Error("a response that IS the whole set must say X-Page-Complete: true")
	}
}

// TestEnvelopeKeysArePinned — the opt-in body for header-blind clients carries
// the same numbers under EXACTLY these keys.
func TestEnvelopeKeysArePinned(t *testing.T) {
	env := Envelope("items", []int{1, 2}, Request{Limit: 10, Offset: 0}, 2, 2)
	for _, key := range []string{"items", "total", "returned", "limit", "offset", "complete"} {
		if _, ok := env[key]; !ok {
			t.Errorf("envelope lost key %q — header-blind clients read this shape", key)
		}
	}
	if env["total"] != 2 || env["complete"] != true {
		t.Errorf("envelope numbers wrong: %+v", env)
	}
	if len(env) != 6 {
		t.Errorf("envelope grew/shrank to %d keys — additive changes need a doc row in API_ACCESS.md, removals are breaking: %+v", len(env), env)
	}
}

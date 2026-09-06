// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package experience

// ingest_test.go — tracker 254: the two ingest routes' contract.
//
// The cross-org half lives in src/backend/dem_ingest_isolation_test.go (real
// router, real auth, real gate mapping). What is proven HERE is the module's
// own promise: the owner comes from the credential and cannot be expressed in
// the body, the bounds are refusals rather than truncations, privacy is
// enforced with an instruction rather than a silent repair, and a busy or
// unwired lane answers with the truth instead of 202.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"netops/backend/internal/dem"
)

// recordingSink captures what the routes hand it.
type recordingSink struct {
	events   []ExperienceEvent
	business []BusinessEvent
	err      error
}

func (s *recordingSink) WriteEvents(_ context.Context, evs []ExperienceEvent) error {
	if s.err != nil {
		return s.err
	}
	s.events = append(s.events, evs...)
	return nil
}

func (s *recordingSink) WriteBusinessEvents(_ context.Context, evs []BusinessEvent) error {
	if s.err != nil {
		return s.err
	}
	s.business = append(s.business, evs...)
	return nil
}

func newIngestAPI(t *testing.T, sink EventSink) (*API, *Counters) {
	t.Helper()
	policy, err := EmbeddedScorePolicy()
	if err != nil {
		t.Fatal(err)
	}
	counters := NewCounters()
	api, err := NewAPI(Deps{
		Authz: func(_ http.ResponseWriter, r *http.Request, gate dem.Gate) (dem.Principal, bool) {
			if gate != dem.GateIngest {
				t.Fatalf("an ingest route used gate %v — the operator write gate would let a public page edit the catalogue", gate)
			}
			return dem.Principal{Tenant: "acme", Subject: "rum-key"}, true
		},
		Store:   NewFileStore(""),
		Targets: &memCatalogue{},
		Events:  sink,
		Policy:  policy,
		Enabled: true,
		Now:     func() time.Time { return testNow },
		WriteJSON: func(w http.ResponseWriter, status int, body any) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
			_ = json.NewEncoder(w).Encode(body)
		},
		WriteError: func(w http.ResponseWriter, status int, e error) {
			w.WriteHeader(status)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": e.Error()})
		},
		LogWarn:  func(string, map[string]any) {},
		Counters: counters,
	})
	if err != nil {
		t.Fatalf("NewAPI: %v", err)
	}
	return api, counters
}

const oneEvent = `{"events":[{"id":"ev-1","app":"checkout","type":"page_view","success":true,
  "route":"/checkout","duration_ms":812,"cohort":{"site":"dc1","browser":"chrome"}}]}`

func TestIngestStampsTheTenantFromTheCredential(t *testing.T) {
	sink := &recordingSink{}
	api, counters := newIngestAPI(t, sink)
	code, body := call(t, api.HandleEvents, http.MethodPost, EventsPath, oneEvent, nil)
	if code != http.StatusAccepted {
		t.Fatalf("POST events: %d %s", code, body)
	}
	if len(sink.events) != 1 {
		t.Fatalf("sink received %d events", len(sink.events))
	}
	got := sink.events[0]
	if got.TenantID != "acme" {
		t.Fatalf("tenant = %q, want acme (stamped from the credential)", got.TenantID)
	}
	if got.Source != SourceRUM || got.Producer != "rum-key" {
		t.Fatalf("provenance was not stamped from the caller: %+v", got.Provenance)
	}
	if !got.ObservedAt.Equal(testNow) {
		t.Fatalf("observed_at = %s, want our clock, not the producer's", got.ObservedAt)
	}
	if counters.EventsIngested.Load() != 1 {
		t.Fatalf("counter = %d", counters.EventsIngested.Load())
	}
}

func TestABodyCannotAskToBeFiledUnderAnotherTenant(t *testing.T) {
	sink := &recordingSink{}
	api, _ := newIngestAPI(t, sink)
	// `tenant_id` is not a field on the wire type, and DisallowUnknownFields
	// turns the attempt into a visible 400 rather than a silent no-op.
	body := `{"events":[{"id":"ev-1","app":"checkout","type":"page_view","tenant_id":"globex"}]}`
	code, resp := call(t, api.HandleEvents, http.MethodPost, EventsPath, body, nil)
	if code != http.StatusBadRequest {
		t.Fatalf("a tenant_id in the body returned %d %s — it must be refused, not ignored", code, resp)
	}
	if len(sink.events) != 0 {
		t.Fatal("the event was stored despite the refusal")
	}
	// Same for the provenance block: a producer may not declare where a fact
	// came from, because that is what makes it evidence.
	body = `{"events":[{"id":"ev-1","app":"checkout","type":"page_view","provenance":{"source":"synthetic"}}]}`
	if code, _ = call(t, api.HandleEvents, http.MethodPost, EventsPath, body, nil); code != http.StatusBadRequest {
		t.Fatalf("a producer-supplied provenance block returned %d, want 400", code)
	}
}

func TestADirectIdentifierIsRefusedWithTheInstructionThatFixesIt(t *testing.T) {
	sink := &recordingSink{}
	api, counters := newIngestAPI(t, sink)
	body := `{"events":[{"id":"ev-1","app":"checkout","type":"page_view","user_ref":"alice@example.com"}]}`
	code, resp := call(t, api.HandleEvents, http.MethodPost, EventsPath, body, nil)
	if code != http.StatusBadRequest {
		t.Fatalf("a direct identifier was accepted: %d %s", code, resp)
	}
	if !strings.Contains(string(resp), "hash it per tenant") {
		t.Fatalf("the refusal did not say what to do instead: %s", resp)
	}
	if len(sink.events) != 0 {
		t.Fatal("the email reached the sink")
	}
	if counters.IngestRejected.Load() == 0 {
		t.Fatal("the rejection was not counted")
	}
}

func TestIngestBoundsAreRefusalsNotTruncations(t *testing.T) {
	sink := &recordingSink{}
	api, _ := newIngestAPI(t, sink)

	if code, _ := call(t, api.HandleEvents, http.MethodPost, EventsPath, `{"events":[]}`, nil); code != http.StatusBadRequest {
		t.Fatalf("an empty batch returned %d, want 400", code)
	}
	var b strings.Builder
	b.WriteString(`{"events":[`)
	for i := 0; i <= MaxEventsPerRequest; i++ {
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString(`{"id":"ev-` + itoaSmall(i) + `","app":"checkout","type":"page_view"}`)
	}
	b.WriteString(`]}`)
	code, _ := call(t, api.HandleEvents, http.MethodPost, EventsPath, b.String(), nil)
	if code != http.StatusRequestEntityTooLarge {
		t.Fatalf("an oversized batch returned %d, want 413 — a truncated batch is silent loss", code)
	}
	if len(sink.events) != 0 {
		t.Fatalf("%d events survived a refused batch", len(sink.events))
	}
}

func TestAProducerClockIsNotASourceOfTruth(t *testing.T) {
	sink := &recordingSink{}
	api, _ := newIngestAPI(t, sink)
	future := testNow.Add(time.Hour).Format(time.RFC3339)
	body := `{"events":[{"id":"ev-1","app":"checkout","type":"page_view","event_at":"` + future + `"}]}`
	if code, resp := call(t, api.HandleEvents, http.MethodPost, EventsPath, body, nil); code != http.StatusBadRequest {
		t.Fatalf("a beacon from the future was accepted: %d %s", code, resp)
	}
	old := testNow.Add(-30 * 24 * time.Hour).Format(time.RFC3339)
	body = `{"events":[{"id":"ev-1","app":"checkout","type":"page_view","event_at":"` + old + `"}]}`
	if code, resp := call(t, api.HandleEvents, http.MethodPost, EventsPath, body, nil); code != http.StatusBadRequest {
		t.Fatalf("a month-old beacon was accepted: %d %s — it would rewrite a reported window", code, resp)
	}
	// A slightly-skewed clock inside the tolerance is accepted, not refused:
	// every browser clock is a little wrong and refusing all of them would
	// collect nothing.
	near := testNow.Add(-2 * time.Minute).Format(time.RFC3339)
	body = `{"events":[{"id":"ev-1","app":"checkout","type":"page_view","event_at":"` + near + `"}]}`
	if code, resp := call(t, api.HandleEvents, http.MethodPost, EventsPath, body, nil); code != http.StatusAccepted {
		t.Fatalf("a slightly-skewed clock was refused: %d %s", code, resp)
	}
}

func TestABusyLaneAnswers503WithARetryAfterNot202(t *testing.T) {
	sink := &recordingSink{err: ErrIngestBusy}
	api, counters := newIngestAPI(t, sink)
	w, code, body := callRecorder(t, api.HandleEvents, http.MethodPost, EventsPath, oneEvent)
	if code != http.StatusServiceUnavailable {
		t.Fatalf("a full queue answered %d %s — 202 for data that went nowhere is the failure this product exists to refuse", code, body)
	}
	if w.Header().Get("Retry-After") == "" {
		t.Fatal("the 503 carried no Retry-After, so the producer cannot act on the backpressure")
	}
	if counters.IngestRefused.Load() != 1 {
		t.Fatalf("refused = %d, want 1", counters.IngestRefused.Load())
	}
}

func TestAnUnwiredLaneSaysSoInsteadOfAccepting(t *testing.T) {
	api, _ := newIngestAPI(t, nil)
	code, body := call(t, api.HandleEvents, http.MethodPost, EventsPath, oneEvent, nil)
	if code != http.StatusServiceUnavailable {
		t.Fatalf("an unwired lane answered %d %s", code, body)
	}
	if !strings.Contains(string(body), "not wired") {
		t.Fatalf("the refusal did not name the cause: %s", body)
	}
	code, body = call(t, api.HandleBusinessEvents, http.MethodPost, BusinessEventPath,
		`{"events":[{"id":"b1","business_event_type":"purchase","success":true}]}`, nil)
	if code != http.StatusServiceUnavailable {
		t.Fatalf("the business route answered %d %s", code, body)
	}
}

func TestBusinessEventsRoundTripAndRefuseAnUnlabelledAmount(t *testing.T) {
	sink := &recordingSink{}
	api, counters := newIngestAPI(t, sink)
	ok := `{"events":[{"id":"b1","business_event_type":"purchase","success":true,"value":42.5,"currency":"USD","quantity":2}]}`
	if code, body := call(t, api.HandleBusinessEvents, http.MethodPost, BusinessEventPath, ok, nil); code != http.StatusAccepted {
		t.Fatalf("POST business-events: %d %s", code, body)
	}
	if len(sink.business) != 1 || sink.business[0].TenantID != "acme" {
		t.Fatalf("business sink: %+v", sink.business)
	}
	if counters.BusinessEventsIngested.Load() != 1 {
		t.Fatalf("counter = %d", counters.BusinessEventsIngested.Load())
	}
	bad := `{"events":[{"id":"b2","business_event_type":"purchase","success":true,"value":42.5}]}`
	if code, body := call(t, api.HandleBusinessEvents, http.MethodPost, BusinessEventPath, bad, nil); code != http.StatusBadRequest {
		t.Fatalf("a value with no currency returned %d %s — an unlabelled number is not an amount", code, body)
	}
}

func TestIngestRefusesTheWrongMethodAndUnknownParameters(t *testing.T) {
	api, _ := newIngestAPI(t, &recordingSink{})
	for _, h := range []http.HandlerFunc{api.HandleEvents, api.HandleBusinessEvents} {
		if code, _ := call(t, h, http.MethodGet, EventsPath, "", nil); code != http.StatusMethodNotAllowed {
			t.Fatalf("GET on an ingest route returned %d — the credential must never be able to read", code)
		}
		if code, _ := call(t, h, http.MethodPost, EventsPath+"?tenant=globex", oneEvent, nil); code != http.StatusBadRequest {
			t.Fatalf("an unknown query parameter returned %d, want 400", code)
		}
	}
}

func TestANilSurfaceIs404NotAnUnscopedWrite(t *testing.T) {
	var api *API
	code, _ := call(t, api.HandleEvents, http.MethodPost, EventsPath, oneEvent, nil)
	if code != http.StatusNotFound {
		t.Fatalf("an unbuilt surface answered %d, want 404", code)
	}
}

func TestTheIngestBusySentinelIsShared(t *testing.T) {
	// The transport package returns its own ErrBusy; the route maps
	// ErrIngestBusy onto 503. Two sentinels that are not errors.Is-equal is how
	// backpressure starts answering 400.
	if !errors.Is(ErrIngestBusy, ErrIngestBusy) {
		t.Fatal("unreachable")
	}
}

// callRecorder is call() with the ResponseRecorder returned, so a test can
// assert on headers as well as the body.
func callRecorder(t *testing.T, h http.HandlerFunc, method, target, body string) (*httptest.ResponseRecorder, int, []byte) {
	t.Helper()
	r := httptest.NewRequest(method, target, strings.NewReader(body))
	w := httptest.NewRecorder()
	h(w, r)
	return w, w.Code, w.Body.Bytes()
}

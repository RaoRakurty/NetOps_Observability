// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package irisstream

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func testCfg(tick chan time.Time) Config {
	c := DefaultConfig()
	c.Now = func() time.Time { return time.Date(2026, 10, 12, 9, 0, 0, 0, time.UTC) }
	if tick != nil {
		c.Tick = func(time.Duration) (<-chan time.Time, func()) { return tick, func() {} }
	}
	return c
}

func TestWantsEventStream(t *testing.T) {
	for accept, want := range map[string]bool{
		"":                                    false,
		"application/json":                    false,
		"*/*":                                 false,
		"text/event-stream":                   true,
		"application/json, text/event-stream": true,
		"text/event-stream;q=0":               false,
		"text/event-stream; q=0.5":            true,
		"text/event-streamx":                  false,
	} {
		r := httptest.NewRequest("POST", "/api/ai/ask", nil)
		if accept != "" {
			r.Header.Set("Accept", accept)
		}
		if got := WantsEventStream(r); got != want {
			t.Errorf("Accept %q: %v want %v", accept, got, want)
		}
	}
}

type wrapped struct{ http.ResponseWriter }

func (w wrapped) Unwrap() http.ResponseWriter { return w.ResponseWriter }

type plainWriter struct{ h http.Header }

func (p plainWriter) Header() http.Header         { return p.h }
func (p plainWriter) Write(b []byte) (int, error) { return len(b), nil }
func (p plainWriter) WriteHeader(int)             {}

func TestCanFlushFollowsUnwrap(t *testing.T) {
	if !CanFlush(wrapped{httptest.NewRecorder()}) {
		t.Fatal("a flusher behind Unwrap was not found")
	}
	if CanFlush(plainWriter{http.Header{}}) {
		t.Fatal("a writer that cannot flush reported it can")
	}
}

// Order, framing, and the answer bytes exactly as given.
func TestStreamFramesProgressThenAnswerThenDone(t *testing.T) {
	rec := httptest.NewRecorder()
	m := &Metrics{}
	s := Open(rec, testCfg(make(chan time.Time)), m, nil)
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/event-stream") || rec.Header().Get("X-Accel-Buffering") != "no" {
		t.Fatalf("headers: %v", rec.Header())
	}
	s.Emit(Event{Type: TypePlanning})
	s.Emit(Event{Type: TypeToolStarted, Tool: "get_problem"})
	s.Emit(Event{Type: TypeToolFinished, Tool: "get_problem", Outcome: "ok"})
	done := make(chan struct{})
	close(done)
	s.Pump(context.Background(), done)
	answer := []byte(`{"text":"BGP down","citations":[]}`)
	s.WriteAnswer(answer)
	s.WriteDone()
	body := rec.Body.String()
	for _, want := range []string{
		"event: planning\ndata: {\"seq\":1,",
		"event: tool_started\ndata: {\"seq\":2,\"ts\":\"2026-10-12T09:00:00Z\",\"type\":\"tool_started\",\"tool\":\"get_problem\"}",
		"\"type\":\"tool_finished\",\"tool\":\"get_problem\",\"outcome\":\"ok\"}",
		"event: answer\ndata: " + string(answer) + "\n\n",
		"event: done\ndata: {\"dropped\":0,",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %q in\n%s", want, body)
		}
	}
	if strings.Index(body, "event: answer") < strings.Index(body, "event: tool_finished") || strings.Index(body, "event: done") < strings.Index(body, "event: answer") {
		t.Fatalf("order wrong:\n%s", body)
	}
	if m.answered.Load() != 1 {
		t.Fatal("answered not counted")
	}
}

// Nothing but the closed vocabulary leaves the server: unknown types are
// dropped; a malformed tool name or outcome is blanked, never echoed.
func TestEmitAllowsOnlyTheClosedVocabulary(t *testing.T) {
	rec := httptest.NewRecorder()
	s := Open(rec, testCfg(make(chan time.Time)), nil, nil)
	s.Emit(Event{Type: "model_text", Tool: "x"})
	s.Emit(Event{Type: TypeToolStarted, Tool: "get_problem\nevent: answer\ndata: {\"pwned\":1}", Outcome: "<script>"})
	done := make(chan struct{})
	close(done)
	s.Pump(context.Background(), done)
	body := rec.Body.String()
	if strings.Contains(body, "model_text") || strings.Contains(body, "pwned") || strings.Contains(body, "<script>") {
		t.Fatalf("a value outside the vocabulary reached the stream:\n%s", body)
	}
	if !strings.Contains(body, "\"type\":\"tool_started\"}") {
		t.Fatalf("the event should be sent with the tool blanked:\n%s", body)
	}
}

// Emit never blocks; past the cap events are dropped and counted, and the
// count is reported in done.
func TestEmitIsBoundedAndNeverBlocks(t *testing.T) {
	rec := httptest.NewRecorder()
	m := &Metrics{}
	cfg := testCfg(make(chan time.Time))
	cfg.MaxEvents = 4
	s := Open(rec, cfg, m, nil)
	start := time.Now()
	for i := 0; i < 1000; i++ {
		s.Emit(Event{Type: TypeNarrating})
	}
	if time.Since(start) > time.Second {
		t.Fatal("Emit blocked")
	}
	done := make(chan struct{})
	close(done)
	s.Pump(context.Background(), done)
	s.WriteDone()
	if got := strings.Count(rec.Body.String(), "event: narrating"); got != 4 {
		t.Fatalf("%d progress events written, want the cap 4", got)
	}
	if !strings.Contains(rec.Body.String(), "\"dropped\":996") || m.droppedEvents.Load() != 996 {
		t.Fatalf("drops not reported: %s", rec.Body.String())
	}
}

func TestHeartbeat(t *testing.T) {
	rec := httptest.NewRecorder()
	tick := make(chan time.Time, 1)
	s := Open(rec, testCfg(tick), nil, nil)
	tick <- time.Now()
	done := make(chan struct{})
	go func() { time.Sleep(50 * time.Millisecond); close(done) }()
	s.Pump(context.Background(), done)
	if !strings.Contains(rec.Body.String(), ": hb\n\n") {
		t.Fatalf("no heartbeat:\n%s", rec.Body.String())
	}
}

type failingWriter struct {
	*httptest.ResponseRecorder
	fail bool
}

func (f *failingWriter) Write(b []byte) (int, error) {
	if f.fail {
		return 0, errors.New("broken pipe")
	}
	return f.ResponseRecorder.Write(b)
}

// A write failure (the client left) cancels the work and stops writing.
func TestWriteFailureCancelsTheWork(t *testing.T) {
	fw := &failingWriter{ResponseRecorder: httptest.NewRecorder()}
	ctx, cancel := context.WithCancel(context.Background())
	m := &Metrics{}
	s := Open(fw, testCfg(make(chan time.Time)), m, cancel)
	fw.fail = true
	s.Emit(Event{Type: TypePlanning})
	done := make(chan struct{})
	close(done)
	s.Pump(context.Background(), done)
	if ctx.Err() == nil || !s.Failed() || m.writeFailed.Load() != 1 {
		t.Fatalf("a failed write must cancel the work: ctx=%v failed=%v", ctx.Err(), s.Failed())
	}
	before := fw.Body.Len()
	fw.fail = false
	s.WriteAnswer([]byte(`{}`))
	if fw.Body.Len() != before {
		t.Fatal("wrote after a failure")
	}
}

func TestMetricsExposition(t *testing.T) {
	m := &Metrics{}
	m.outcome("answered")
	m.ClientGone()
	m.dropped()
	var b bytes.Buffer
	if err := m.Write(&b); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`netops_iris_stream_total{outcome="answered"} 1`, `netops_iris_stream_total{outcome="client_gone"} 1`, `netops_iris_stream_events_dropped_total 1`} {
		if !strings.Contains(b.String(), want) {
			t.Errorf("missing %s", want)
		}
	}
}

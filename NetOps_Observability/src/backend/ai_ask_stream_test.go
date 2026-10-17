// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// ai_ask_stream_test.go — tracker 337 N-E2: /api/ai/ask streams progress when
// asked for text/event-stream, and is unchanged otherwise.

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type sseEvent struct{ name, data string }

func parseSSE(t *testing.T, body string) []sseEvent {
	t.Helper()
	var out []sseEvent
	for _, block := range strings.Split(body, "\n\n") {
		var ev sseEvent
		for _, line := range strings.Split(block, "\n") {
			switch {
			case strings.HasPrefix(line, "event: "):
				ev.name = strings.TrimPrefix(line, "event: ")
			case strings.HasPrefix(line, "data: "):
				ev.data = strings.TrimPrefix(line, "data: ")
			}
		}
		if ev.name != "" {
			out = append(out, ev)
		}
	}
	return out
}

func askReq(c jwtClaims, question, accept string) *http.Request {
	body, _ := json.Marshal(map[string]any{"question": question}) // discard: cannot fail
	r := httptest.NewRequest(http.MethodPost, "/api/ai/ask", strings.NewReader(string(body)))
	if accept != "" {
		r.Header.Set("Accept", accept)
	}
	return r.WithContext(context.WithValue(r.Context(), userCtxKey, c))
}

// Without text/event-stream the response is the JSON it always was: JSON
// content type, no buffering header, one JSON document plus the newline.
func TestAskWithoutStreamAcceptIsUnchanged(t *testing.T) {
	s, a, _ := ledgerFixture(t)
	for _, accept := range []string{"", "application/json", "*/*"} {
		w := httptest.NewRecorder()
		s.handleAIAsk(w, askReq(a, "show cpu on edge-a for the last hour", accept))
		if w.Code != http.StatusOK || w.Header().Get("Content-Type") != "application/json" || w.Header().Get("X-Accel-Buffering") != "" {
			t.Fatalf("Accept %q: %d %v", accept, w.Code, w.Header())
		}
		body := w.Body.Bytes()
		if len(body) == 0 || body[len(body)-1] != '\n' || !json.Valid(body[:len(body)-1]) {
			t.Fatalf("Accept %q: body is not one JSON document + newline: %q", accept, body)
		}
	}
}

// With it: progress, then `answer` carrying the same answer the JSON path
// returns (ids differ per decision; everything else matches), then `done`.
func TestAskStreamsProgressThenTheSameAnswer(t *testing.T) {
	s, a, _ := ledgerFixture(t)
	const q = "show cpu on edge-a for the last hour"
	w := httptest.NewRecorder()
	s.handleAIAsk(w, askReq(a, q, "text/event-stream"))
	if w.Code != http.StatusOK || !strings.HasPrefix(w.Header().Get("Content-Type"), "text/event-stream") {
		t.Fatalf("%d %v", w.Code, w.Header())
	}
	evs := parseSSE(t, w.Body.String())
	if len(evs) < 3 || evs[0].name != "planning" || evs[len(evs)-2].name != "answer" || evs[len(evs)-1].name != "done" {
		t.Fatalf("event order: %+v", evs)
	}
	var streamed map[string]any
	if err := json.Unmarshal([]byte(evs[len(evs)-2].data), &streamed); err != nil {
		t.Fatalf("answer is not JSON: %v", err)
	}
	var plain map[string]any
	jw := httptest.NewRecorder()
	s.handleAIAsk(jw, askReq(a, q, ""))
	if err := json.Unmarshal(jw.Body.Bytes(), &plain); err != nil {
		t.Fatal(err)
	}
	// Per-decision / per-execution values differ between two runs; nothing else may.
	for _, m := range []map[string]any{streamed, plain} {
		delete(m, "decision_id")
		delete(m, "answer_id")
		if d, ok := m["data"].(map[string]any); ok {
			delete(d, "query_log_id")
			if res, ok := d["result"].(map[string]any); ok {
				delete(res, "window")
				if pv, ok := res["provenance"].(map[string]any); ok {
					delete(pv, "executed_at")
					delete(pv, "duration_ms")
				}
			}
		}
	}
	sb, _ := json.Marshal(streamed) // discard: re-marshal of decoded JSON cannot fail
	pb, _ := json.Marshal(plain)    // discard: same
	if string(sb) != string(pb) {
		t.Fatalf("streamed answer differs from the JSON answer:\nstream %s\njson   %s", sb, pb)
	}
	// Progress carries the closed vocabulary only — never the question.
	for _, ev := range evs[:len(evs)-2] {
		if strings.Contains(ev.data, "edge-a") || strings.Contains(ev.data, "cpu") {
			t.Fatalf("question text reached a progress event: %+v", ev)
		}
	}
}

// Refusals before the answer starts stay JSON (the client branches on the
// content type).
func TestAskStreamRefusalsAreJSON(t *testing.T) {
	s, a, _ := ledgerFixture(t)
	w := httptest.NewRecorder()
	s.handleAIAsk(w, askReq(a, "", "text/event-stream"))
	if w.Code != http.StatusBadRequest || w.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("an empty question must be a JSON 400 even when streaming was asked: %d %v", w.Code, w.Header())
	}
}

// §3a: a streamed ask is the asker's decision, in the asker's tenant only.
func TestAskStreamLedgerStaysInTheAskersTenant(t *testing.T) {
	s, a, b := ledgerFixture(t)
	w := httptest.NewRecorder()
	s.handleAIAsk(w, askReq(a, "show cpu on edge-a for the last hour", "text/event-stream"))
	evs := parseSSE(t, w.Body.String())
	var ans map[string]any
	if err := json.Unmarshal([]byte(evs[len(evs)-2].data), &ans); err != nil {
		t.Fatal(err)
	}
	id, _ := ans["decision_id"].(string)
	if id == "" {
		t.Fatal("a streamed ask must be a ledgered decision")
	}
	if es := ledgerEntries(t, s, a, "?decision_id="+id); len(es) == 0 {
		t.Fatal("the asker cannot read their own streamed decision")
	}
	if es := ledgerEntries(t, s, b, "?decision_id="+id); len(es) != 0 {
		t.Fatalf("TENANT LEAK: another tenant read the streamed decision: %v", es)
	}
}

// A client that disconnects cancels the work: the metrics read the answer was
// waiting on sees its request context end.
func TestAskStreamClientDisconnectCancelsTheWork(t *testing.T) {
	s, a, _ := ledgerFixture(t)
	vmSawCancel := make(chan struct{}, 1)
	vmStarted := make(chan struct{}, 1)
	vm := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case vmStarted <- struct{}{}:
		default:
		}
		<-r.Context().Done()
		select {
		case vmSawCancel <- struct{}{}:
		default:
		}
	}))
	defer vm.Close()
	t.Setenv("VICTORIA_URL", vm.URL)
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.handleAIAsk(&statusRecorder{ResponseWriter: w, status: http.StatusOK}, r.WithContext(context.WithValue(r.Context(), userCtxKey, a)))
	}))
	defer api.Close()
	ctx, cancel := context.WithCancel(context.Background())
	body := strings.NewReader(`{"question":"show cpu on edge-a for the last hour"}`)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, api.URL, body)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Accept", "text/event-stream")
	go func() {
		resp, err := http.DefaultClient.Do(req)
		if err == nil {
			// Keep reading until the operator "closes the panel" (cancel):
			// closing the body early would itself be the disconnect.
			_, _ = io.Copy(io.Discard, resp.Body) // discard: ends with the cancellation
			_ = resp.Body.Close()                 // discard: client side of a test
		}
	}()
	select {
	case <-vmStarted:
	case <-time.After(10 * time.Second):
		t.Fatal("the answer never reached the metrics store")
	}
	cancel() // the operator closed the panel
	select {
	case <-vmSawCancel:
	case <-time.After(5 * time.Second):
		t.Fatal("the disconnect did not cancel the read the answer was waiting on")
	}
}

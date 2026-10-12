// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ai

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"
)

// trace_test.go — tracker 337 N-E2: an answer's progress, in order, carrying
// nothing but the closed vocabulary.

type traceRec struct {
	mu  sync.Mutex
	evs []TraceEvent
}

func (r *traceRec) Trace(e TraceEvent) { r.mu.Lock(); r.evs = append(r.evs, e); r.mu.Unlock() }

func (r *traceRec) seq() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, 0, len(r.evs))
	for _, e := range r.evs {
		s := string(e.Type)
		if e.Tool != "" {
			s += ":" + e.Tool
		}
		if e.Outcome != "" {
			s += "=" + e.Outcome
		}
		out = append(out, s)
	}
	return out
}

func TestProblemPathTracesInOrder(t *testing.T) {
	o := newOrch(newMockDS())
	rec := &traceRec{}
	o.Trace = rec
	if _, err := o.Ask(context.Background(), tenantA(), "explain this", map[string]string{"correlation_id": "pa"}); err != nil {
		t.Fatal(err)
	}
	got := strings.Join(rec.seq(), " ")
	for _, want := range []string{
		"planning",
		"tool_started:get_problem tool_finished:get_problem=ok",
		"tool_started:get_problem_evidence tool_finished:get_problem_evidence=ok",
		"narrating", "grounding",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in %s", want, got)
		}
	}
	if strings.Index(got, "planning") != 0 || strings.Index(got, "narrating") < strings.Index(got, "tool_finished:get_problem_evidence") ||
		strings.Index(got, "grounding") < strings.Index(got, "narrating") {
		t.Fatalf("order wrong: %s", got)
	}
	// Every start has its finish.
	if strings.Count(got, "tool_started") != strings.Count(got, "tool_finished") {
		t.Fatalf("unpaired tool events: %s", got)
	}
}

// Sentinels planted in the evidence, the problem title and the model reply
// never appear in a progress event; the event has exactly three keys.
func TestTraceCarriesNothingButTheVocabulary(t *testing.T) {
	const sentinel = "SENTINEL-7f3a"
	ds := newMockDS()
	ds.problems["t-a"]["pa"].Title = "title " + sentinel
	o := newOrch(ds)
	o.LLM = MockLLM{Reply: "model says " + sentinel + " [log:os:1]"}
	rec := &traceRec{}
	o.Trace = rec
	if _, err := o.Ask(context.Background(), tenantA(), "explain this "+sentinel, map[string]string{"correlation_id": "pa"}); err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(rec.evs)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), sentinel) {
		t.Fatalf("question, evidence or model text leaked into progress: %s", b)
	}
	one, _ := json.Marshal(TraceEvent{Type: TraceToolFinished, Tool: "x", Outcome: "ok"}) // discard: cannot fail
	var keys map[string]any
	if err := json.Unmarshal(one, &keys); err != nil || len(keys) != 3 {
		t.Fatalf("TraceEvent must marshal to exactly type/tool/outcome: %s", one)
	}
}

// blockingDS blocks GetProblem until its context ends.
type blockingDS struct{ *mockDS }

func (b blockingDS) GetProblem(ctx context.Context, _ Principal, _ string) (*Problem, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

// A client that leaves cancels the work: Ask returns promptly and nothing
// reports success.
func TestCancellingTheRequestStopsTheAnswer(t *testing.T) {
	ds := blockingDS{newMockDS()}
	o := newOrch(ds)
	o.Tools = Tools(ds)
	rec := &traceRec{}
	o.Trace = rec
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(50 * time.Millisecond); cancel() }()
	start := time.Now()
	_, _ = o.Ask(ctx, tenantA(), "explain this", map[string]string{"correlation_id": "pa"}) // discard: the outcome under test is timing + trace
	if time.Since(start) > 3*time.Second {
		t.Fatalf("Ask did not return promptly after cancel: %s", time.Since(start))
	}
	// The problem is read before any tool runs, so the cancellation may stop
	// the answer there; whatever ran must not report success.
	if strings.Contains(strings.Join(rec.seq(), " "), "=ok") {
		t.Fatalf("a cancelled read reported ok: %v", rec.seq())
	}
}

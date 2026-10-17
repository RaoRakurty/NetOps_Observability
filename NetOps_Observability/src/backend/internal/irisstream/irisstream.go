// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Package irisstream writes an Iris answer's PROGRESS as Server-Sent Events
// (tracker 337 N-E2): planning, tool started / finished (tool NAME only),
// narrating, grounding — then the answer, exactly as the JSON path would send
// it, and done.
//
// WHAT AN EVENT MAY CARRY is closed: a type from a fixed set, a registry tool
// name that matches the tool-name shape, an outcome from a fixed set. Never
// model text before grounding, never tool arguments, never evidence — those
// reach the client only inside the final `answer`, built after verification.
//
// BOUNDED: progress events go through a buffered channel (cap MaxEvents); a
// full channel drops and counts (§9 backpressure) — Emit never blocks the
// orchestrator. Every write carries a deadline. A heartbeat comment keeps
// idle proxies from closing the stream. A write failure (the client left)
// cancels the work.
//
// Stdlib only.
package irisstream

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"regexp"
	"strings"
	"sync/atomic"
	"time"
)

// Progress event types (closed).
const (
	TypePlanning     = "planning"
	TypeToolStarted  = "tool_started"
	TypeToolFinished = "tool_finished"
	TypeNarrating    = "narrating"
	TypeGrounding    = "grounding"
)

var progressTypes = map[string]bool{TypePlanning: true, TypeToolStarted: true, TypeToolFinished: true, TypeNarrating: true, TypeGrounding: true}

// Outcomes a tool_finished may carry (closed; anything else is sent empty).
var outcomes = map[string]bool{"ok": true, "denied": true, "not_wired": true, "not_found": true, "error": true, "skipped": true}

var toolName = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)

// Event is one progress step. Only these three fields exist.
type Event struct {
	Type    string
	Tool    string
	Outcome string
}

// Config bounds a stream.
type Config struct {
	Heartbeat    time.Duration
	WriteTimeout time.Duration
	MaxEvents    int
	Now          func() time.Time
	// Tick returns a ticker channel and its stop func (injectable in tests).
	Tick func(d time.Duration) (<-chan time.Time, func())
}

// DefaultConfig: a 15 s heartbeat, a 10 s deadline per write, 64 progress
// events per answer.
func DefaultConfig() Config {
	return Config{
		Heartbeat: 15 * time.Second, WriteTimeout: 10 * time.Second, MaxEvents: 64, Now: time.Now,
		Tick: func(d time.Duration) (<-chan time.Time, func()) {
			t := time.NewTicker(d)
			return t.C, t.Stop
		},
	}
}

// WantsEventStream reports whether the client asked for SSE: an Accept
// element of text/event-stream with q ≠ 0. */*, application/json or nothing
// keep the JSON response.
func WantsEventStream(r *http.Request) bool {
	for _, part := range strings.Split(r.Header.Get("Accept"), ",") {
		mt, params, err := mime.ParseMediaType(strings.TrimSpace(part))
		if err != nil || mt != "text/event-stream" {
			continue
		}
		if q, ok := params["q"]; ok && (q == "0" || q == "0.0" || q == "0.00" || q == "0.000") {
			continue
		}
		return true
	}
	return false
}

// CanFlush reports whether w (or a writer it wraps) can flush.
func CanFlush(w http.ResponseWriter) bool {
	for w != nil {
		if _, ok := w.(http.Flusher); ok {
			return true
		}
		u, ok := w.(interface{ Unwrap() http.ResponseWriter })
		if !ok {
			return false
		}
		w = u.Unwrap()
	}
	return false
}

// Stream is one open SSE response.
type Stream struct {
	w       http.ResponseWriter
	rc      *http.ResponseController
	cfg     Config
	m       *Metrics
	events  chan Event
	dropped atomic.Int64
	seq     int
	failed  bool
	cancel  context.CancelFunc
}

// Open starts the response: headers, 200, flush.
func Open(w http.ResponseWriter, cfg Config, m *Metrics, cancel context.CancelFunc) *Stream {
	if cfg.MaxEvents <= 0 {
		cfg.MaxEvents = 64
	}
	h := w.Header()
	h.Set("Content-Type", "text/event-stream; charset=utf-8")
	h.Set("Cache-Control", "no-cache, no-transform")
	h.Set("X-Accel-Buffering", "no") // nginx: do not buffer this response
	w.WriteHeader(http.StatusOK)
	s := &Stream{w: w, rc: http.NewResponseController(w), cfg: cfg, m: m, events: make(chan Event, cfg.MaxEvents), cancel: cancel}
	s.flush()
	return s
}

// Emit queues a progress event. It never blocks: a full queue drops and
// counts. Unknown types are dropped; a malformed tool name or outcome is
// sent empty.
func (s *Stream) Emit(e Event) {
	if s == nil || !progressTypes[e.Type] {
		return
	}
	if !toolName.MatchString(e.Tool) {
		e.Tool = ""
	}
	if !outcomes[e.Outcome] {
		e.Outcome = ""
	}
	select {
	case s.events <- e:
	default:
		s.dropped.Add(1)
		s.m.dropped()
	}
}

// Pump writes queued events and heartbeats until done is closed or ctx ends.
// It is the only goroutine that writes progress; call WriteAnswer/WriteError/
// WriteDone after it returns.
func (s *Stream) Pump(ctx context.Context, done <-chan struct{}) {
	tick, stop := s.cfg.Tick(s.cfg.Heartbeat)
	defer stop()
	for {
		select {
		case e := <-s.events:
			s.writeProgress(e)
		case <-tick:
			s.write([]byte(": hb\n\n"))
		case <-done:
			for { // drain what the work queued before it finished
				select {
				case e := <-s.events:
					s.writeProgress(e)
				default:
					return
				}
			}
		case <-ctx.Done():
			return
		}
	}
}

type progressData struct {
	Seq     int    `json:"seq"`
	TS      string `json:"ts"`
	Type    string `json:"type"`
	Tool    string `json:"tool,omitempty"`
	Outcome string `json:"outcome,omitempty"`
}

func (s *Stream) writeProgress(e Event) {
	s.seq++
	b, err := json.Marshal(progressData{Seq: s.seq, TS: s.cfg.Now().UTC().Format(time.RFC3339Nano), Type: e.Type, Tool: e.Tool, Outcome: e.Outcome})
	if err != nil {
		return // cannot happen: closed string fields
	}
	s.frame(e.Type, b)
}

// WriteAnswer sends the final answer: raw is exactly the JSON body the
// non-streaming path writes (without its trailing newline).
func (s *Stream) WriteAnswer(raw []byte) {
	s.frame("answer", raw)
	s.m.outcome("answered")
}

// WriteError sends the error the JSON path would have sent.
func (s *Stream) WriteError(status int, msg string) {
	b, err := json.Marshal(map[string]any{"error": msg, "status": status})
	if err != nil {
		b = []byte(`{"error":"internal error","status":500}`)
	}
	s.frame("error", b)
	s.m.outcome("error")
}

// WriteDone ends the stream, reporting how many progress events were dropped.
func (s *Stream) WriteDone() {
	s.seq++
	b, err := json.Marshal(map[string]any{"seq": s.seq, "ts": s.cfg.Now().UTC().Format(time.RFC3339Nano), "type": "done", "dropped": s.dropped.Load()})
	if err == nil {
		s.frame("done", b)
	}
}

// Failed reports whether a write failed (the client left or stalled).
func (s *Stream) Failed() bool { return s.failed }

func (s *Stream) frame(event string, data []byte) {
	// data is one line of JSON (encoding/json never emits a raw newline).
	s.write([]byte(fmt.Sprintf("id: %d\nevent: %s\ndata: %s\n\n", s.seq, event, data)))
}

func (s *Stream) write(b []byte) {
	if s.failed {
		return
	}
	if err := s.rc.SetWriteDeadline(s.cfg.Now().Add(s.cfg.WriteTimeout)); err != nil && !errors.Is(err, http.ErrNotSupported) {
		s.fail()
		return
	}
	if _, err := s.w.Write(b); err != nil {
		s.fail()
		return
	}
	s.flush()
}

func (s *Stream) flush() {
	if err := s.rc.Flush(); err != nil && !errors.Is(err, http.ErrNotSupported) {
		s.fail()
	}
}

func (s *Stream) fail() {
	if s.failed {
		return
	}
	s.failed = true
	s.m.outcome("write_failed")
	if s.cancel != nil {
		s.cancel() // the client is gone: stop the work
	}
}

// ── metrics ────────────────────────────────────────────────────────────────

// Metrics counts streams by outcome and dropped progress events.
type Metrics struct {
	answered, errored, writeFailed, clientGone atomic.Int64
	droppedEvents                              atomic.Int64
}

func (m *Metrics) outcome(o string) {
	if m == nil {
		return
	}
	switch o {
	case "answered":
		m.answered.Add(1)
	case "error":
		m.errored.Add(1)
	case "write_failed":
		m.writeFailed.Add(1)
	case "client_gone":
		m.clientGone.Add(1)
	}
}

func (m *Metrics) dropped() {
	if m != nil {
		m.droppedEvents.Add(1)
	}
}

// ClientGone counts a stream whose client left before the answer.
func (m *Metrics) ClientGone() { m.outcome("client_gone") }

// Write renders Prometheus text.
func (m *Metrics) Write(w io.Writer) error {
	if m == nil {
		return nil
	}
	_, err := fmt.Fprintf(w, "# HELP netops_iris_stream_total Iris progress streams by outcome (N-E2).\n# TYPE netops_iris_stream_total counter\n"+
		"netops_iris_stream_total{outcome=\"answered\"} %d\nnetops_iris_stream_total{outcome=\"error\"} %d\n"+
		"netops_iris_stream_total{outcome=\"write_failed\"} %d\nnetops_iris_stream_total{outcome=\"client_gone\"} %d\n"+
		"# HELP netops_iris_stream_events_dropped_total Progress events dropped because the stream's queue was full.\n"+
		"# TYPE netops_iris_stream_events_dropped_total counter\nnetops_iris_stream_events_dropped_total %d\n",
		m.answered.Load(), m.errored.Load(), m.writeFailed.Load(), m.clientGone.Load(), m.droppedEvents.Load())
	return err
}

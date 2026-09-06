// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package pipedebug

// ring.go — the API's bounded, in-memory debug ring, keyed by marker.
//
// WHY IT EXISTS. Stage 7 of a trace is "the api's own request/handler debug
// lines for the marker" (design §2). Reading those back out of the applog →
// Kafka → OpenSearch applogs index would make the API's own stage depend on the
// very pipeline under test — a debugger that cannot report on a broken pipeline
// is not a debugger. The ring is the independent path: the process keeps its
// last N marker-tagged lines in memory and serves them directly.
//
// It is BOUNDED in three dimensions on purpose (§9: all queues are bounded):
// total lines, lines per marker, and markers tracked. A debug facility must not
// become the memory leak that takes the API down during an incident.

import (
	"strings"
	"sync"
	"time"
)

const (
	// RingCapacity is the total number of retained lines across all markers.
	RingCapacity = 1000
	// ringPerMarker bounds one marker's share so a single noisy trace cannot
	// evict every other trace's evidence.
	ringPerMarker = 200
	// ringMaxMarkers bounds how many distinct markers are tracked at once.
	ringMaxMarkers = 64
	// ringMaxLine bounds one retained line.
	ringMaxLine = 4096
)

// RingLine is one retained log line.
type RingLine struct {
	TS        time.Time      `json:"ts"`
	Level     string         `json:"level"`
	Component string         `json:"component"`
	Msg       string         `json:"msg"`
	Fields    map[string]any `json:"fields,omitempty"`
}

// Ring is a bounded FIFO of marker-tagged log lines. Safe for concurrent use.
type Ring struct {
	mu    sync.Mutex
	order []ringEntry // insertion order, oldest first — the global bound
	byMk  map[string][]RingLine
}

type ringEntry struct{ marker string }

// NewRing builds an empty ring.
func NewRing() *Ring { return &Ring{byMk: map[string][]RingLine{}} }

// MarkerIn extracts a marker from a log event: an explicit `marker` field wins,
// otherwise the `cx_debug=<ulid>` token is looked for in the message and in any
// string field. Returns "" when the event is not part of a trace — which is the
// common case, so this must stay cheap.
func MarkerIn(msg string, fields map[string]any) string {
	if fields != nil {
		if v, ok := fields["marker"].(string); ok {
			if m, err := NormalizeMarker(v); err == nil {
				return m
			}
		}
	}
	if m := markerToken(msg); m != "" {
		return m
	}
	for _, v := range fields {
		if s, ok := v.(string); ok {
			if m := markerToken(s); m != "" {
				return m
			}
		}
	}
	return ""
}

// markerToken finds `cx_debug=<26 chars>` in a string and validates the value.
func markerToken(s string) string {
	const tag = MarkerField + "="
	i := strings.Index(s, tag)
	if i < 0 {
		return ""
	}
	rest := s[i+len(tag):]
	if len(rest) < MarkerLen {
		return ""
	}
	m, err := NormalizeMarker(rest[:MarkerLen])
	if err != nil {
		return ""
	}
	return m
}

// Append retains one line under a marker. A blank or invalid marker is dropped
// (the ring only ever holds trace evidence). The line is REDACTED on the way in
// so nothing sensitive is retained in memory even before it is served.
func (r *Ring) Append(marker string, ln RingLine) {
	if r == nil {
		return
	}
	m, err := NormalizeMarker(marker)
	if err != nil {
		return
	}
	ln.Msg = truncate(RedactString(ln.Msg), ringMaxLine)
	ln.Fields = RedactFields(ln.Fields)
	if ln.TS.IsZero() {
		ln.TS = time.Now().UTC()
	} else {
		ln.TS = ln.TS.UTC()
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if _, known := r.byMk[m]; !known && len(r.byMk) >= ringMaxMarkers {
		r.evictOldestMarkerLocked()
	}
	lines := r.byMk[m]
	if len(lines) >= ringPerMarker {
		lines = lines[1:]
		r.dropOneLocked(m)
	}
	r.byMk[m] = append(lines, ln)
	r.order = append(r.order, ringEntry{marker: m})
	for len(r.order) > RingCapacity {
		old := r.order[0]
		r.order = r.order[1:]
		r.dropHeadLocked(old.marker)
	}
}

// dropHeadLocked removes the oldest retained line of one marker.
func (r *Ring) dropHeadLocked(m string) {
	lines := r.byMk[m]
	if len(lines) <= 1 {
		delete(r.byMk, m)
		return
	}
	r.byMk[m] = lines[1:]
}

// dropOneLocked removes one order entry for a marker whose per-marker cap was
// hit, keeping len(order) consistent with the retained lines.
func (r *Ring) dropOneLocked(m string) {
	for i, e := range r.order {
		if e.marker == m {
			r.order = append(r.order[:i], r.order[i+1:]...)
			return
		}
	}
}

// evictOldestMarkerLocked drops every line of the least-recently-inserted
// marker, so a new trace is never refused because the ring is full of old ones.
func (r *Ring) evictOldestMarkerLocked() {
	if len(r.order) == 0 {
		for m := range r.byMk {
			delete(r.byMk, m)
			return
		}
		return
	}
	victim := r.order[0].marker
	delete(r.byMk, victim)
	kept := r.order[:0]
	for _, e := range r.order {
		if e.marker != victim {
			kept = append(kept, e)
		}
	}
	r.order = kept
}

// Lines returns a COPY of the retained lines for a marker, oldest first.
func (r *Ring) Lines(marker string) []RingLine {
	if r == nil {
		return nil
	}
	m, err := NormalizeMarker(marker)
	if err != nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	src := r.byMk[m]
	out := make([]RingLine, len(src))
	copy(out, src)
	return out
}

// Len returns the total retained line count (tests and the /metrics surface).
func (r *Ring) Len() int {
	if r == nil {
		return 0
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, v := range r.byMk {
		n += len(v)
	}
	return n
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…[truncated]"
}

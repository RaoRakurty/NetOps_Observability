// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package pipedebug

// ring_admission_test.go — who may put a line in the debug ring (review 3.3-13).
//
// THE DEFECT. A record is traced unconditionally when it carries a
// `cx_debug=<ulid>` token, which is the design and must stay the design: making
// the parser stage depend on a second "arm the filter" call would produce empty
// parser.log files that read as "the parser never saw it". But the ring that
// KEEPS those lines took the marker from the record, and the records reaching
// the parse hook include unauthenticated ones — an SNMP trap only loses device
// attribution on a community mismatch; it is still parsed. Anyone who can reach
// the trap port could therefore mint markers of their own and push an
// operator's in-flight trace out of a ring bounded at RingCapacity lines, in
// the middle of the incident the trace was opened for.
//
// THE RULE NOW: a line is retained only under a marker this process MINTED
// (HandleTrace). Tracing is unchanged — the parser still decides, still emits,
// and a marked record still traces without an arm — but the memory a trace
// depends on is no longer writable by whoever can reach a collector port.

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"
)

func TestTheRingKeepsOnlyMarkersThisProcessMinted(t *testing.T) {
	r := NewRing()
	mine := NewMarker(time.Unix(1757000000, 0))
	theirs := NewMarker(time.Unix(1757000001, 0))

	r.Admit(mine)
	r.Append(mine, RingLine{Msg: "the operator's own trace"})
	r.Append(theirs, RingLine{Msg: "a marker off the trap port"})

	if got := len(r.Lines(mine)); got != 1 {
		t.Fatalf("the admitted trace kept %d lines, want 1", got)
	}
	if got := len(r.Lines(theirs)); got != 0 {
		t.Fatalf("a marker nobody minted kept %d lines — the ring is writable from the wire", got)
	}
	if r.Rejected() != 1 {
		t.Errorf("the refusal is not counted (%d): a silent drop is not observable (§10)", r.Rejected())
	}
}

// The harm, driven end to end: an unadmitted flood must not evict the trace an
// operator is running.
func TestAFloodOfForeignMarkersCannotEvictALiveTrace(t *testing.T) {
	r := NewRing()
	mine := NewMarker(time.Unix(1757000000, 0))
	r.Admit(mine)
	for i := 0; i < 10; i++ {
		r.Append(mine, RingLine{Msg: "decision line"})
	}

	for i := 0; i < RingCapacity*2; i++ {
		r.Append(NewMarker(time.Unix(int64(1757100000+i), 0)), RingLine{Msg: "flood"})
	}

	if got := len(r.Lines(mine)); got != 10 {
		t.Fatalf("the live trace kept %d of its 10 lines after a flood of foreign markers — "+
			"an unauthenticated record flushed the evidence an operator was collecting", got)
	}
}

// Admission is bounded like everything else here: the set cannot grow without
// limit, and the OLDEST admission is the one that ages out.
func TestAdmissionIsBounded(t *testing.T) {
	r := NewRing()
	first := NewMarker(time.Unix(1757000000, 0))
	r.Admit(first)
	var later []string
	for i := 0; i < ringMaxMarkers; i++ {
		m := NewMarker(time.Unix(int64(1757200000+i), 0))
		later = append(later, m)
		r.Admit(m)
	}
	r.Append(first, RingLine{Msg: "late line for a long-finished trace"})
	if got := len(r.Lines(first)); got != 0 {
		t.Fatalf("the admission set is unbounded: the oldest marker still admits lines (%d)", got)
	}
	newest := later[len(later)-1]
	r.Append(newest, RingLine{Msg: "recent"})
	if got := len(r.Lines(newest)); got != 1 {
		t.Fatalf("a recently admitted marker was refused (%d)", got)
	}
}

// A trace started through the real handler must record its own lines, or the
// admission rule has broken the feature it protects.
func TestHandleTraceAdmitsItsOwnMarker(t *testing.T) {
	f := newFakeBackend()
	deps := f.deps()
	api := New(deps)
	w := post(t, api.HandleTrace, "/api/debug/trace", `{"kind":"syslog","device":"edge-1"}`)
	if w.Code != http.StatusAccepted {
		t.Fatalf("trace: %d %s", w.Code, w.Body.String())
	}
	var receipt traceReceipt
	if err := json.Unmarshal(w.Body.Bytes(), &receipt); err != nil {
		t.Fatal(err)
	}
	if len(deps.Ring.Lines(receipt.Marker)) == 0 {
		t.Fatalf("a trace this API minted kept no ring lines under %q — the admission rule "+
			"has broken stage 7 rather than protecting it", receipt.Marker)
	}
}

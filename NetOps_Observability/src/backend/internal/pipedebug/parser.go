package pipedebug

// parser.go — stage 2's SERVER-SIDE half: the Go collectors' decision path, and
// the runtime switch that turns it on for a real (unmarked) record.
//
// STAGE 2 HAS TWO EVIDENCE SOURCES, and they are complementary rather than
// redundant:
//
//   - the Vector tap (host-side, cli/collect.go) shows the record as it LEFT
//     each VRL transform, plus the `.cx_parse_trace` decision string the
//     transforms stamp on a marked record;
//   - this file serves the GO collectors' decisions — the SNMP trap decoder and
//     anything else a trace crosses in-process — out of the same bounded ring
//     the api stage uses, so the parser stage does not depend on the pipeline
//     it is debugging.
//
// The CLI merges both into ONE parser.log and ONE timeline entry, because "the
// parser" is one hop to the operator reading the file.

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// ParseComponentPrefix marks a ring line as a PARSER decision rather than an
// api request line. The prefix is the whole routing rule between stage 2 and
// stage 7, so it lives here as a constant instead of being spelled out at each
// call site.
const ParseComponentPrefix = "parse:"

// ParseSwitch is the runtime parser decision-trace filter, as this package
// needs it. internal/parsetrace.Filter implements it; the interface keeps the
// debug API testable without the collectors' package-level default (§5).
type ParseSwitch interface {
	// Arm turns the filter on for a bounded window and returns the disarm time.
	Arm(needle string, window time.Duration) (time.Time, error)
	// Disarm turns it off now.
	Disarm()
	// Active reports the armed needle and its deadline.
	Active() (needle string, until time.Time, on bool)
}

// ParserStage answers stage 2 from the Go collectors' decision lines.
//
// A trace whose kind never crosses a Go parser gets NOT-OBSERVABLE with that
// reason, never `not_seen`: syslog is parsed in Vector, so an empty Go-side
// answer for a syslog probe says nothing at all about whether the record was
// parsed, and rendering it as a miss would point an operator at the wrong hop.
func (a *API) ParserStage(kind Kind, marker string) Entry {
	e := Entry{Stage: StageParser, Module: string(StageParser)}
	e.Query = fmt.Sprintf("in-process parser decision ring, marker=%s, component prefix %q", marker, ParseComponentPrefix)
	if a.deps.Ring == nil {
		return notObservable(e, "the API debug ring is not wired into this build")
	}
	lines := a.deps.Ring.Lines(marker)
	decisions := make([]RingLine, 0, len(lines))
	for _, ln := range lines {
		if strings.HasPrefix(ln.Component, ParseComponentPrefix) {
			decisions = append(decisions, ln)
		}
	}
	if len(decisions) == 0 {
		if !GoParsed(kind) {
			return notObservable(e, fmt.Sprintf(
				"a %s record is parsed in Vector, not in a Go collector, so this process holds no decision line for it — the Vector-side decision path is in the same parser.log, stamped as `cx_parse_trace` on the tapped event", kind))
		}
		e.Verdict = VerdictNotSeen
		e.Reason = "no Go parser recorded a decision for this marker — the record did not reach the in-process parser, or the parse hook is not wired on the lane it crossed"
		return e
	}
	e.Verdict = VerdictSeen
	e.FirstSeen = decisions[0].TS
	e.EvidenceRef = StageParser.LogFile()
	e.Detail = map[string]any{
		"decisions": decisions,
		"source":    "Go collector parse hook (internal/parsetrace)",
	}
	return e
}

// GoParsed reports whether a kind crosses a Go collector's parser at all.
//
// It is a TABLE, not a guess: syslog and flow are decoded outside this process
// (Vector and goflow2 respectively), the trap PDU is decoded here, and gNMI is
// decoded by gnmic. Getting this wrong in the permissive direction would turn
// every syslog trace's parser stage into a false `not_seen`.
func GoParsed(kind Kind) bool { return kind == KindTrap }

// ── PUT/GET /api/debug/parsemarker ──────────────────────────────────────────

type parseMarkerRequest struct {
	// Marker is the needle. A trace marker is the normal value; any bounded
	// substring is accepted so a REAL record can be traced by, say, its
	// hostname or a message fragment.
	Marker string `json:"marker"`
	// ForSeconds is the window, clamped to MaxWindow. 0 = the default window.
	ForSeconds int `json:"for_seconds"`
	// Off disarms immediately, whatever else is set.
	Off bool `json:"off"`
}

// ParseMarkerState is the switch's answer — the same shape for arm, disarm and
// read, so an operator polling it never has to reconcile two schemas.
type ParseMarkerState struct {
	Armed  bool      `json:"armed"`
	Marker string    `json:"marker,omitempty"`
	Until  time.Time `json:"until,omitempty"`
	Reason string    `json:"reason,omitempty"`
}

// HandleParseMarker serves PUT and GET /api/debug/parsemarker.
//
// It is the DEBUG_PARSE_MARKER switch of the design: default-off, bounded,
// auto-reverting inside the traced process. An injected record is traced
// regardless (it carries its own marker) — this route exists for the other
// case, a REAL record an operator wants the decision path for.
func (a *API) HandleParseMarker(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet, http.MethodPut:
	default:
		w.Header().Set("Allow", "GET, PUT")
		a.deps.WriteError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	p, ok := a.deps.Authz(w, r)
	if !ok {
		return
	}
	if a.deps.ParseFilter == nil {
		// 200 with armed=false and a reason, not a 5xx: the REQUEST succeeded
		// and the answer is "this build has no parser hook". A 5xx would make
		// an honest capability gap indistinguishable from a broken endpoint.
		a.deps.WriteJSON(w, http.StatusOK, ParseMarkerState{
			Reason: "no parser decision-trace filter is wired into this API build",
		})
		return
	}
	if r.Method == http.MethodGet {
		a.deps.WriteJSON(w, http.StatusOK, a.parseMarkerState())
		return
	}

	var req parseMarkerRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxDebugBody)).Decode(&req); err != nil {
		a.deps.WriteError(w, http.StatusBadRequest, err)
		return
	}
	if req.Off {
		a.deps.ParseFilter.Disarm()
		a.audit(r, p.Tenant, "debug.parsemarker", map[string]any{"armed": false})
		a.deps.WriteJSON(w, http.StatusOK, a.parseMarkerState())
		return
	}
	window := ClampWindow(time.Duration(req.ForSeconds) * time.Second)
	until, err := a.deps.ParseFilter.Arm(strings.TrimSpace(req.Marker), window)
	if err != nil {
		a.deps.WriteError(w, http.StatusBadRequest, err)
		return
	}
	// The needle is NOT audited verbatim: an operator may legitimately trace by
	// a message fragment, and a fragment of a customer's log line in the
	// immutable trail is exactly the PII leak §8 forbids. Its length and the
	// window are what an auditor needs.
	a.audit(r, p.Tenant, "debug.parsemarker", map[string]any{
		"armed": true, "needle_len": len(strings.TrimSpace(req.Marker)),
		"for_seconds": int(window.Seconds()), "until": until.UTC().Format(time.RFC3339),
	})
	a.deps.WriteJSON(w, http.StatusOK, a.parseMarkerState())
}

func (a *API) parseMarkerState() ParseMarkerState {
	needle, until, on := a.deps.ParseFilter.Active()
	st := ParseMarkerState{Armed: on, Until: until}
	if on {
		st.Marker = needle
		st.Reason = "auto-disarms at the stamped time inside the traced process, even if the caller dies"
	} else {
		st.Reason = "off — an injected record carrying its own cx_debug marker is still traced; this switch is for tracing a REAL, unmarked record"
	}
	return st
}

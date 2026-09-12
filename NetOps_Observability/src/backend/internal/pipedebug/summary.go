// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package pipedebug

// summary.go — summary.txt, the stage table a human reads first (design §3).
//
// It is plain text on purpose. The machine-readable form is timeline.json; this
// is what an operator pastes into an incident channel, so it must be legible in
// a monospace font with no tooling, and it must never round an unobservable
// stage up to a pass.

import (
	"fmt"
	"strings"
	"time"
)

// RenderSummary formats a timeline as the human stage table.
func RenderSummary(t Timeline, sessionDir string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "CORRELIX PIPELINE DEBUG — TRACE SUMMARY\n")
	fmt.Fprintf(&b, "======================================\n")
	fmt.Fprintf(&b, "marker   : %s\n", t.Marker)
	fmt.Fprintf(&b, "kind     : %s\n", t.Kind)
	fmt.Fprintf(&b, "device   : %s\n", orDash(t.Device))
	fmt.Fprintf(&b, "tenant   : %s\n", orDash(t.Tenant))
	fmt.Fprintf(&b, "started  : %s\n", t.Started.Format(time.RFC3339))
	fmt.Fprintf(&b, "session  : %s\n", sessionDir)
	b.WriteString("\n")

	fmt.Fprintf(&b, "%-2s %-13s %-15s %-10s %s\n", "#", "STAGE", "VERDICT", "Δ PREV", "EVIDENCE / REASON")
	fmt.Fprintf(&b, "%s\n", strings.Repeat("-", 92))
	for _, e := range t.Entries {
		delta := "-"
		if e.LatencyFromPrevMS != nil {
			delta = fmt.Sprintf("%d ms", *e.LatencyFromPrevMS)
		}
		detail := e.EvidenceRef
		if e.Verdict != VerdictSeen && e.Reason != "" {
			detail = e.Reason
		}
		fmt.Fprintf(&b, "%-2d %-13s %-15s %-10s %s\n",
			e.Index, e.Stage, e.Verdict, delta, oneLine(detail))
	}
	b.WriteString("\n")

	seen, notSeen, notObs := 0, 0, 0
	for _, e := range t.Entries {
		switch e.Verdict {
		case VerdictSeen:
			seen++
		case VerdictNotSeen:
			notSeen++
		case VerdictNotObservable:
			notObs++
		}
	}
	fmt.Fprintf(&b, "stages: %d seen, %d not seen, %d not observable\n", seen, notSeen, notObs)
	if t.Reached(StageAPI) {
		b.WriteString("VERDICT: the record reached the UI-facing API (exit 0)\n")
	} else {
		b.WriteString("VERDICT: the record did NOT reach the UI-facing API (exit 1)\n")
		if last := lastSeen(t); last != "" {
			fmt.Fprintf(&b, "         last stage that saw it: %s\n", last)
		} else {
			b.WriteString("         no stage saw it — start at ingress.log\n")
		}
	}
	if notObs > 0 {
		b.WriteString("NOTE:    a 'not observable' stage was NOT checked — it is neither a pass nor a fail.\n")
	}
	return b.String()
}

func lastSeen(t Timeline) string {
	out := ""
	for _, e := range t.Entries {
		if e.Seen {
			out = string(e.Stage)
		}
	}
	return out
}

func orDash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "-"
	}
	return s
}

// oneLine keeps the table one row per stage: a reason containing a newline
// would otherwise smear the table across the terminal.
func oneLine(s string) string {
	s = strings.ReplaceAll(strings.ReplaceAll(s, "\n", " "), "\r", " ")
	if len(s) > 60 {
		return s[:57] + "..."
	}
	return s
}

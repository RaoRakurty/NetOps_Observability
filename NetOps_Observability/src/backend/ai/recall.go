package ai

// recall.go — `recall_investigations`, the READ side of IRIS Phase B
// investigation memory (design §3.5).
//
// WHAT IT RETURNS. Up to MaxRecallRows prior CONCLUDED investigations for the
// entity in scope (device, peer, prefix or correlation case), newest conclusion
// first, each as one bounded EvidenceItem cited `memory:<id>` with its OUTCOME
// stated in operator words: "operator confirmed", "operator marked wrong",
// "unverified".
//
// THE RULE THAT MAKES THIS SAFE (NetClaw's own, kept verbatim in spirit):
// NEVER CARRY ASSUMPTIONS BETWEEN SESSIONS — VERIFY CURRENT STATE. Memory is
// prior context, not evidence about now. Every result carries that note, and
// the skills that gather it do so only AFTER the live-state step (the loader
// enforces the ordering), so a remembered cause can only ever be compared with
// what the device says today, never substituted for it.
//
// WHY IT DECLARES NO CHAIN SIGNAL (deliberate, design §3.5 "never as a rule").
// Every other tool may declare ToolResult.Signals, which the bounded
// investigation loop evaluates against authored `next=` conditions. This one
// declares NONE — there is no `memory:outcome=wrong_before` fact, and there
// never will be. A remembered conclusion is a HYPOTHESIS an operator once
// accepted or rejected; wiring it into the deterministic router would let one
// past judgement (or one mis-click on a thumbs-down) silently re-route every
// future investigation of that entity, and would make the assistant's path
// depend on its own history rather than on the evidence in front of it. Memory
// informs the NARRATIVE; the engine's facts alone choose the next check.
//
// ISOLATION (§3a). The seam is filled by the server with the caller's own
// tenant scope; a device reference is resolved through the caller's OWN
// inventory first, so another tenant's device name is ErrNotFound rather than
// "no memory" (which would confirm the device exists elsewhere). The store
// itself refuses an unkeyed recall, so there is no path to a tenant-wide dump.

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// Read-side caps (§9, §15 LLM04: memory becomes prompt text).
const (
	// MaxRecallRows is the hard ceiling on recalled investigations per call.
	// Five is a NOC's worth of "have we seen this before"; more would crowd out
	// the live evidence that must dominate the answer.
	MaxRecallRows = 5
	// maxRecallVerdictChars clips one remembered verdict inside the rendered
	// evidence line. The stored row is already clipped; this is the tighter
	// prompt-facing bound.
	maxRecallVerdictChars = 220
	// maxRecallCitedIDs bounds how many of the original citation ids are echoed
	// with a remembered conclusion (provenance without a wall of ids).
	maxRecallCitedIDs = 3
	// defaultRecallWindowDays is the lookback when the caller names none.
	defaultRecallWindowDays = 90
	// recallRouteHref is where an operator goes to see the investigation surface
	// when the memory is not attached to a correlation case.
	recallRouteHref = "#/investigate/troubleshooting"
	// recallVerifyNote is the NetClaw rule, restated on EVERY result — including
	// the empty one, so an absent memory is never read as "nothing ever
	// happened here".
	recallVerifyNote = "prior investigations are CONTEXT, not current state: verify what the device and the engine report NOW before relying on any remembered cause"
)

// recallWindows is the closed lookback vocabulary. A window is never a
// model-controlled duration (no unbounded scans).
var recallWindows = map[string]int{
	"24h": 1, "7d": 7, "30d": 30, "90d": 90, "180d": 180,
}

// recallInvestigationsTool is the read-only memory lookup.
type recallInvestigationsTool struct{ deps TroubleshootDeps }

func (t recallInvestigationsTool) Name() string            { return "recall_investigations" }
func (t recallInvestigationsTool) Module() string          { return "correlations_rca" }
func (t recallInvestigationsTool) Capability() Capability  { return CapRead }
func (t recallInvestigationsTool) RequiredPerms() []string { return []string{"correlations:read"} }
func (t recallInvestigationsTool) Freshness() Freshness    { return FreshnessHistorical }

func (t recallInvestigationsTool) Run(ctx context.Context, p Principal, args ToolArgs) (ToolResult, error) {
	q := InvestigationQuery{Limit: MaxRecallRows}
	days := recallWindows["90d"]
	if raw := strings.TrimSpace(args["window"]); raw != "" {
		d, ok := recallWindows[strings.ToLower(raw)]
		if !ok {
			return ToolResult{}, fmt.Errorf("window must be one of 24h, 7d, 30d, 90d, 180d")
		}
		days = d
	}
	if days <= 0 {
		days = defaultRecallWindowDays
	}
	q.Since = time.Now().UTC().Add(-time.Duration(days) * 24 * time.Hour)

	if raw := strings.TrimSpace(args["correlation_id"]); raw != "" {
		v, err := validIDArg("correlation_id", raw, 64)
		if err != nil {
			return ToolResult{}, err
		}
		q.CorrelationID = v
	}
	// Fixed order, so two malformed arguments always produce the SAME error.
	for _, a := range []struct {
		name string
		dst  *string
	}{{"peer", &q.Peer}, {"prefix", &q.Prefix}} {
		if raw := strings.TrimSpace(args[a.name]); raw != "" {
			v, err := validAddrArg(a.name, raw, 64)
			if err != nil {
				return ToolResult{}, err
			}
			*a.dst = v
		}
	}
	if raw := strings.TrimSpace(args["device"]); raw != "" {
		v, err := validIDArg("device", raw, 128)
		if err != nil {
			return ToolResult{}, err
		}
		// Resolve through the caller's OWN inventory first: a device the caller
		// cannot see must read as NOT FOUND, never as "no memory" — the latter
		// would silently confirm the device exists in another tenant (§3a r.1).
		if t.deps.ResolveDevice != nil {
			ref, rerr := t.deps.ResolveDevice(ctx, p, v)
			if rerr != nil {
				return ToolResult{}, rerr
			}
			v = firstNonEmpty(ref.Name, ref.ID)
		}
		q.Device = v
	}

	tr := ToolResult{}
	// NOTE: no ToolResult.Signals are ever set here — see the file header.
	if !q.HasKey() {
		tr.Notes = append(tr.Notes,
			"no device, peer, prefix or case id was in scope, so no prior investigation could be recalled — treat the history as UNKNOWN",
			recallVerifyNote)
		return tr, nil
	}
	rows, err := t.deps.RecallInvestigations(ctx, p, q)
	if err != nil {
		return ToolResult{}, err // ErrNotFound for unknown OR another tenant's id
	}
	if len(rows) > MaxRecallRows {
		rows = rows[:MaxRecallRows]
		tr.Truncated = true
		tr.Notes = append(tr.Notes, fmt.Sprintf("showing the %d most recent concluded investigations", MaxRecallRows))
	}
	if len(rows) == 0 {
		tr.Notes = append(tr.Notes,
			"no prior CONCLUDED investigation is recorded for this scope — say the history is EMPTY, not that this has never happened (memory only holds investigations an operator judged)",
			recallVerifyNote)
		return tr, nil
	}
	historical := false
	for _, r := range rows {
		historical = historical || len(r.Citations) > 0
		tr.Items = append(tr.Items, EvidenceItem{
			CitationID: "memory:" + r.ID,
			Kind:       "finding",
			Text:       renderRecalledInvestigation(r),
			Href:       recallHref(r),
		})
	}
	if historical {
		// The ids INSIDE a remembered conclusion belonged to that investigation's
		// evidence, not this one's. Citing them now would claim support this turn
		// never gathered — so say plainly which id is the citable one.
		tr.Notes = append(tr.Notes, "the evidence ids quoted inside a remembered conclusion are HISTORICAL — cite the memory row itself, never them")
	}
	tr.Notes = append(tr.Notes, recallVerifyNote)
	return tr, nil
}

// renderRecalledInvestigation puts one remembered conclusion into one bounded
// line: when it concluded, what it was about, which methods ran, what was
// concluded, and — always — how the operator judged it.
func renderRecalledInvestigation(r InvestigationRow) string {
	var b strings.Builder
	b.WriteString(r.ResolvedAt.Format("2006-01-02"))
	if subject := recallSubject(r); subject != "" {
		b.WriteString(" on " + subject)
	}
	if len(r.Skills) > 0 {
		b.WriteString(" via " + strings.Join(r.Skills, " → "))
	}
	b.WriteString(" — concluded: " + clampText(r.Verdict, maxRecallVerdictChars))
	b.WriteString(" (" + OutcomePhrase(r.Outcome) + ")")
	if validOutcome(r.Outcome) == OutcomeWrong {
		// The single most valuable thing memory can say.
		b.WriteString("; that conclusion was REJECTED by an operator — do not repeat it without new evidence")
	}
	if len(r.Citations) > 0 {
		cites := r.Citations
		if len(cites) > maxRecallCitedIDs {
			cites = cites[:maxRecallCitedIDs]
		}
		b.WriteString("; it rested at the time on " + strings.Join(cites, ", "))
	}
	return b.String()
}

// recallSubject names the entity a remembered investigation was about.
func recallSubject(r InvestigationRow) string {
	switch {
	case r.DeviceName != "" || r.DeviceID != "":
		return firstNonEmpty(r.DeviceName, r.DeviceID)
	case r.Peer != "":
		return "peer " + r.Peer
	case r.Prefix != "":
		return "prefix " + r.Prefix
	case r.CorrelationID != "":
		return "case " + shortToken(r.CorrelationID)
	}
	return ""
}

// recallHref deep-links a remembered investigation back to its case when it had
// one, else to the investigation surface.
func recallHref(r InvestigationRow) string {
	if r.CorrelationID != "" {
		return "#/monitoring/correlations?id=" + r.CorrelationID
	}
	return recallRouteHref
}

package ai

// recall_test.go — the `recall_investigations` contract. What is pinned here is
// what makes remembered context safe to hand a model:
//
//   - the result is CAPPED at MaxRecallRows and each line is CLIPPED;
//   - the outcome is stated in the exact operator words, and a REJECTED
//     conclusion is flagged as such;
//   - every result — including the empty one and the no-key one — carries the
//     "verify current state" rule;
//   - a device the caller cannot see is ErrNotFound, never "no memory";
//   - the tool declares NO chain signal: memory can never steer the router.

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func recallDeps(rows []InvestigationRow) TroubleshootDeps {
	d := tsDeps()
	d.RecallInvestigations = func(_ context.Context, _ Principal, q InvestigationQuery) ([]InvestigationRow, error) {
		out := []InvestigationRow{}
		for _, r := range rows {
			if q.matches(r) {
				out = append(out, r)
			}
		}
		return out, nil
	}
	return d
}

func TestRecallInvestigationsStatesOutcomeAndVerifyRule(t *testing.T) {
	rows := []InvestigationRow{{
		ID: "m-1", DeviceName: "edge-1", Peer: "10.0.0.1",
		Skills:    []string{"bgp-session-down", "interface-down"},
		Verdict:   "the session dropped because the uplink optic was failing",
		Citations: []string{"diagsig:sig-1", "state:dev-a:1"},
		Outcome:   OutcomeConfirmed, ResolvedAt: tsMemoryDay,
	}}
	reg := tsRegistry(t, recallDeps(rows))
	res := mustRun(t, reg, "recall_investigations", ToolArgs{"device": "edge-1"})

	if len(res.Items) != 1 {
		t.Fatalf("want one remembered investigation, got %d", len(res.Items))
	}
	item := res.Items[0]
	if item.CitationID != "memory:m-1" {
		t.Errorf("citation id = %q, want memory:m-1", item.CitationID)
	}
	for _, want := range []string{"2026-08-30", "edge-1", "bgp-session-down → interface-down", "operator confirmed", "diagsig:sig-1"} {
		if !strings.Contains(item.Text, want) {
			t.Errorf("evidence line is missing %q: %s", want, item.Text)
		}
	}
	if !hasNoteContaining(res.Notes, "verify what the device and the engine report NOW") {
		t.Errorf("every recall must carry the verify-current-state rule; notes = %v", res.Notes)
	}
	if !hasNoteContaining(res.Notes, "HISTORICAL — cite the memory row itself") {
		t.Errorf("the evidence ids inside a memory must be marked historical; notes = %v", res.Notes)
	}
	// The load-bearing rule: memory contributes NO machine fact to the chain.
	if len(res.Signals) != 0 {
		t.Fatalf("recall_investigations must declare NO signals (memory is never a rule), got %v", res.Signals)
	}
}

func TestRecallInvestigationsFlagsARejectedConclusion(t *testing.T) {
	reg := tsRegistry(t, recallDeps([]InvestigationRow{{
		ID: "m-2", DeviceName: "edge-1", Verdict: "blamed the ISP",
		Outcome: OutcomeWrong, ResolvedAt: tsMemoryDay,
	}}))
	res := mustRun(t, reg, "recall_investigations", ToolArgs{"device": "edge-1"})
	if len(res.Items) != 1 {
		t.Fatalf("got %d items", len(res.Items))
	}
	text := res.Items[0].Text
	if !strings.Contains(text, "operator marked wrong") || !strings.Contains(text, "REJECTED") {
		t.Errorf("a rejected conclusion must say so plainly: %s", text)
	}
}

func TestRecallInvestigationsUnratedReadsUnverified(t *testing.T) {
	reg := tsRegistry(t, recallDeps([]InvestigationRow{{
		ID: "m-3", CorrelationID: "case-9", Verdict: "link flap",
		Outcome: OutcomeUnknown, ResolvedAt: tsMemoryDay,
	}}))
	res := mustRun(t, reg, "recall_investigations", ToolArgs{"correlation_id": "case-9"})
	if len(res.Items) != 1 || !strings.Contains(res.Items[0].Text, "unverified") {
		t.Fatalf("an unjudged memory must read as unverified: %+v", res.Items)
	}
	if res.Items[0].Href != "#/monitoring/correlations?id=case-9" {
		t.Errorf("a case-keyed memory should deep-link to its case, got %q", res.Items[0].Href)
	}
}

func TestRecallInvestigationsCapsAndClips(t *testing.T) {
	long := strings.Repeat("z", maxRecallVerdictChars+400)
	rows := make([]InvestigationRow, 0, MaxRecallRows+4)
	for i := 0; i < MaxRecallRows+4; i++ {
		rows = append(rows, InvestigationRow{
			ID: "m-" + itoa(i), DeviceName: "edge-1", Verdict: long,
			Citations:  []string{"a", "b", "c", "d", "e"},
			Outcome:    OutcomeConfirmed,
			ResolvedAt: tsMemoryDay.Add(time.Duration(i) * time.Hour),
		})
	}
	reg := tsRegistry(t, recallDeps(rows))
	res := mustRun(t, reg, "recall_investigations", ToolArgs{"device": "edge-1"})
	if len(res.Items) != MaxRecallRows {
		t.Fatalf("recall returned %d rows, want the cap of %d", len(res.Items), MaxRecallRows)
	}
	if !res.Truncated || !hasNoteContaining(res.Notes, "most recent concluded investigations") {
		t.Errorf("a capped recall must disclose the cap; truncated=%v notes=%v", res.Truncated, res.Notes)
	}
	for _, it := range res.Items {
		if len(it.Text) > maxRecallVerdictChars+400 {
			t.Errorf("evidence line was not clipped: %d chars", len(it.Text))
		}
		if strings.Count(it.Text, ", ") > 0 && strings.Contains(it.Text, "d, e") {
			t.Errorf("more than %d citation ids were echoed: %s", maxRecallCitedIDs, it.Text)
		}
	}
}

func TestRecallInvestigationsEmptyAndKeylessAreHonest(t *testing.T) {
	reg := tsRegistry(t, recallDeps(nil))

	empty := mustRun(t, reg, "recall_investigations", ToolArgs{"device": "edge-1"})
	if len(empty.Items) != 0 {
		t.Fatalf("expected no items, got %d", len(empty.Items))
	}
	if !hasNoteContaining(empty.Notes, "no prior CONCLUDED investigation") ||
		!hasNoteContaining(empty.Notes, "verify what the device and the engine report NOW") {
		t.Errorf("an empty recall must say the history is EMPTY and still carry the verify rule: %v", empty.Notes)
	}

	keyless := mustRun(t, reg, "recall_investigations", ToolArgs{})
	if len(keyless.Items) != 0 {
		t.Fatalf("a keyless recall must return nothing, got %d items", len(keyless.Items))
	}
	if !hasNoteContaining(keyless.Notes, "no device, peer, prefix or case id was in scope") {
		t.Errorf("a keyless recall must disclose why it found nothing: %v", keyless.Notes)
	}
}

func TestRecallInvestigationsCrossTenantDeviceIsNotFound(t *testing.T) {
	reg := tsRegistry(t, recallDeps([]InvestigationRow{{
		ID: "m-4", DeviceName: "leaf-2", Verdict: "other tenant's memory", ResolvedAt: tsMemoryDay,
	}}))
	tool, ok := reg.Get("recall_investigations")
	if !ok {
		t.Fatal("recall_investigations is not registered")
	}
	// tsPrincipal is tenant t-a; "leaf-2" belongs to t-b. The answer must be
	// ErrNotFound — "no memory" would confirm the device exists elsewhere.
	if _, err := tool.Run(context.Background(), tsPrincipal(), ToolArgs{"device": "leaf-2"}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant device recall err = %v, want ErrNotFound", err)
	}
}

func TestRecallInvestigationsValidatesArguments(t *testing.T) {
	reg := tsRegistry(t, recallDeps(nil))
	tool, _ := reg.Get("recall_investigations")
	for name, args := range map[string]ToolArgs{
		"bad window": {"device": "edge-1", "window": "forever"},
		"bad peer":   {"peer": "not-an-address"},
		"bad prefix": {"prefix": "10.0.0.0/24; DROP"},
		"bad case":   {"correlation_id": "case id with spaces"},
	} {
		if _, err := tool.Run(context.Background(), tsPrincipal(), args); err == nil {
			t.Errorf("%s: expected a validation error for %v", name, args)
		}
	}
	// Every declared window token is accepted.
	for w := range recallWindows {
		if _, err := tool.Run(context.Background(), tsPrincipal(), ToolArgs{"device": "edge-1", "window": w}); err != nil {
			t.Errorf("window %q was rejected: %v", w, err)
		}
	}
}

func TestRecallInvestigationsWindowNarrowsTheQuery(t *testing.T) {
	var seen InvestigationQuery
	d := tsDeps()
	d.RecallInvestigations = func(_ context.Context, _ Principal, q InvestigationQuery) ([]InvestigationRow, error) {
		seen = q
		return nil, nil
	}
	reg := tsRegistry(t, d)
	mustRun(t, reg, "recall_investigations", ToolArgs{"device": "edge-1", "window": "7d"})
	if seen.Limit != MaxRecallRows {
		t.Errorf("the tool must bound the query itself: limit = %d", seen.Limit)
	}
	age := time.Since(seen.Since)
	if age < 6*24*time.Hour || age > 8*24*time.Hour {
		t.Errorf("window=7d produced a since of %s ago", age)
	}
	// The device argument is resolved to the caller's own inventory NAME.
	if seen.Device != "edge-1" {
		t.Errorf("device was not resolved through the inventory: %q", seen.Device)
	}
}

func hasNoteContaining(notes []string, want string) bool {
	for _, n := range notes {
		if strings.Contains(n, want) {
			return true
		}
	}
	return false
}

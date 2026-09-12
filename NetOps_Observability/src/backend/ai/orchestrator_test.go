// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ai

import (
	"context"
	"strings"
	"testing"
)

// mockDS is a two-tenant DataSource: tenant "t-a" owns problem "pa", "t-b" owns
// "pb". A principal only ever sees its own tenant's rows (ErrNotFound otherwise),
// mirroring the real chTenantScope/RLS guarantee.
type mockDS struct {
	problems map[string]map[string]*Problem
	evidence map[string][]EvidenceItem
}

func newMockDS() *mockDS {
	return &mockDS{
		problems: map[string]map[string]*Problem{
			"t-a": {"pa": {ID: "pa", Title: "BGP peer down on edge-1", Verdict: "confirmed", Confidence: 0.82,
				Devices: []string{"edge-1"}, MissingEvidence: []string{"flow"}, Owner: "neteng", SignalCount: 7, NodeCount: 3}},
			"t-b": {"pb": {ID: "pb", Title: "High CPU on leaf-2", Verdict: "suspected", Confidence: 0.55,
				Devices: []string{"leaf-2"}, SignalCount: 2, NodeCount: 1}},
		},
		evidence: map[string][]EvidenceItem{
			"pa": {{CitationID: "log:os:1", Kind: "log", Text: "edge-1 %BGP-5-ADJCHANGE neighbor Down", Href: "#/explore/logs"}},
		},
	}
}

func (m *mockDS) GetProblem(_ context.Context, p Principal, id string) (*Problem, error) {
	if pr, ok := m.problems[p.Tenant][id]; ok {
		return pr, nil
	}
	return nil, ErrNotFound // cross-tenant or unknown — never reveal existence
}

func (m *mockDS) GetProblemEvidence(_ context.Context, p Principal, id string) ([]EvidenceItem, error) {
	if _, ok := m.problems[p.Tenant][id]; !ok {
		return nil, ErrNotFound
	}
	return m.evidence[id], nil
}

func (m *mockDS) ListActiveProblems(_ context.Context, p Principal, _ int) ([]Problem, error) {
	var out []Problem
	for _, pr := range m.problems[p.Tenant] {
		out = append(out, *pr)
	}
	return out, nil
}

// ListProblemsInWindow makes mockDS a WindowDataSource. It returns data DISTINCT
// from the live list ("Overnight …") so tests can prove the time-range answer
// reads the WINDOW, not current state — and stays tenant-isolated.
func (m *mockDS) ListProblemsInWindow(_ context.Context, p Principal, _ int) ([]Problem, error) {
	win := map[string][]Problem{
		"t-a": {{ID: "wa", Title: "Overnight DIA latency", Verdict: "suspected", Confidence: 0.7, State: "closed", SignalCount: 3, NodeCount: 2}},
		"t-b": {{ID: "wb", Title: "Overnight leaf reboot", Verdict: "confirmed", Confidence: 0.9, State: "open", SignalCount: 4, NodeCount: 1}},
	}
	return win[p.Tenant], nil
}

// ModuleQuery makes mockDS a ModuleDataSource (P4) so the module read tools
// register. It returns per-tenant data keyed on the principal so the isolation
// tests can prove a module summary never crosses tenants: t-a sees edge-1,
// t-b sees leaf-2.
func (m *mockDS) ModuleQuery(_ context.Context, p Principal, query string, _ ToolArgs) (ToolResult, error) {
	dev := map[string]string{"t-a": "edge-1", "t-b": "leaf-2"}[p.Tenant]
	if dev == "" {
		return ToolResult{}, nil
	}
	switch query {
	case "top_talkers":
		return ToolResult{Items: []EvidenceItem{{CitationID: "flow:talker:0", Kind: "flow",
			Text: dev + " ↔ 10.0.0.9 — 4.2 GB over 24h", Href: "#/flows"}}}, nil
	case "flow_summary":
		return ToolResult{Items: []EvidenceItem{{CitationID: "flow:summary", Kind: "flow",
			Text: "24h flow volume: 9.0 GB across 1.2k flows from 7 sources (" + dev + ")", Href: "#/flows"}}}, nil
	case "metric_anomalies":
		return ToolResult{Items: []EvidenceItem{{CitationID: "finding:1", Kind: "metric",
			Text: "[warning] device_cpu_percent on " + dev + " z=3.3", Href: "#/monitoring/findings"}}}, nil
	}
	return ToolResult{}, ErrNotImplemented
}

func newOrch(ds DataSource) *Orchestrator {
	return &Orchestrator{DS: ds, Tools: Tools(ds), LLM: MockLLM{Reply: "Likely BGP session loss on edge-1 [log:os:1]. Next: check the peering link."},
		Flags: func(string) bool { return false }}
}

func tenantA() Principal {
	return Principal{Tenant: "t-a", Perms: map[string]bool{"correlations:read": true}}
}
func tenantB() Principal {
	return Principal{Tenant: "t-b", Perms: map[string]bool{"correlations:read": true}}
}

// opsA/opsB hold the broader operational perms the P4 module tools gate on
// (flows:read, infrastructure:read) so module routes are allowed.
func opsA() Principal {
	return Principal{Tenant: "t-a", Perms: map[string]bool{"correlations:read": true, "flows:read": true, "infrastructure:read": true}}
}
func opsB() Principal {
	return Principal{Tenant: "t-b", Perms: map[string]bool{"correlations:read": true, "flows:read": true, "infrastructure:read": true}}
}

func TestModuleRegistry(t *testing.T) {
	if len(Modules()) < 13 {
		t.Fatalf("expected the full module registry, got %d", len(Modules()))
	}
	if _, ok := ModuleByID("correlations_rca"); !ok {
		t.Fatal("correlations_rca module must exist")
	}
	if IsModuleEnabled("cloud_app_observability", func(string) bool { return false }) {
		t.Fatal("a future/flagged module must NOT be enabled when its flag is off")
	}
	if !IsModuleEnabled("correlations_rca", nil) {
		t.Fatal("a stable unflagged module must be enabled")
	}
}

func TestClassifyProblem(t *testing.T) {
	p := Classify("explain problem", map[string]string{"correlation_id": "pa"})
	if p.Mode != ModeProblemExplanation || p.Entities["problem_id"] != "pa" {
		t.Fatalf("expected problem_explanation for the UI-supplied id, got %+v", p)
	}
}

func TestAnswerProblemHappyPath(t *testing.T) {
	o := newOrch(newMockDS())
	ans, err := o.Ask(context.Background(), tenantA(), "explain this", map[string]string{"correlation_id": "pa"})
	if err != nil {
		t.Fatal(err)
	}
	if ans.Mode != ModeProblemExplanation || ans.Problem == nil {
		t.Fatalf("expected a problem_explanation answer, got %+v", ans)
	}
	if ans.Problem.Verdict != "confirmed" || ans.Problem.Confidence != "82%" {
		t.Fatalf("structured fields must come from the tool, got %+v", ans.Problem)
	}
	if len(ans.Citations) == 0 {
		t.Fatal("answer must be grounded with citations")
	}
	// Missing-evidence now lives in the structured field (clean bullets), not a
	// raw disclaimer (Response-Quality layer).
	if len(ans.MissingEvidence) == 0 {
		t.Fatalf("must surface missing evidence in the structured field, got %+v", ans)
	}
	// Status + confidence label are populated for the card badges.
	if ans.Status != "Confirmed" || ans.ConfidenceLabel == "" {
		t.Fatalf("status/confidence label must be set, got status=%q conf=%q", ans.Status, ans.ConfidenceLabel)
	}
}

// TestCrossTenantIsolation — the mandatory §3a.5 test: tenant B can never read
// tenant A's problem, and A's data never appears in B's answer.
func TestCrossTenantIsolation(t *testing.T) {
	o := newOrch(newMockDS())
	ans, err := o.Ask(context.Background(), tenantB(), "explain this", map[string]string{"correlation_id": "pa"})
	if err != nil {
		t.Fatal(err)
	}
	if ans.Problem != nil {
		t.Fatal("LEAK: tenant B received tenant A's problem object")
	}
	blob := ans.Text + strings.Join(ans.Disclaimers, " ")
	for _, secret := range []string{"BGP peer down on edge-1", "edge-1", "neteng"} {
		if strings.Contains(blob, secret) {
			t.Fatalf("LEAK: tenant A data %q surfaced to tenant B: %q", secret, blob)
		}
	}
}

func TestPermissionGate(t *testing.T) {
	o := newOrch(newMockDS())
	noPerm := Principal{Tenant: "t-a"} // no correlations:read
	ans, err := o.Ask(context.Background(), noPerm, "explain this", map[string]string{"correlation_id": "pa"})
	if err != nil {
		t.Fatal(err)
	}
	if ans.Mode != ModeUnavailable {
		t.Fatalf("a caller without correlations:read must be refused, got %s", ans.Mode)
	}
}

func TestProviderDownDegrades(t *testing.T) {
	ds := newMockDS()
	o := &Orchestrator{DS: ds, Tools: Tools(ds), LLM: MockLLM{Err: context.DeadlineExceeded}, Flags: func(string) bool { return false }}
	ans, err := o.Ask(context.Background(), tenantA(), "explain this", map[string]string{"correlation_id": "pa"})
	if err != nil {
		t.Fatal(err)
	}
	if ans.Problem == nil || ans.Text == "" {
		t.Fatal("must degrade to a deterministic evidence-only summary when the provider is down")
	}
	if ans.Provider != "none" {
		t.Fatalf("expected provider=none on fallback, got %q", ans.Provider)
	}
}

func TestCurrentStateSummary(t *testing.T) {
	o := newOrch(newMockDS())
	ans, err := o.Ask(context.Background(), tenantA(), "what is going on right now?", nil)
	if err != nil {
		t.Fatal(err)
	}
	if ans.Mode != ModeCurrentStateSummary || ans.CurrentState == nil {
		t.Fatalf("expected a current_state_summary, got %+v", ans)
	}
	if ans.CurrentState.Confirmed != 1 {
		t.Fatalf("tenant A has 1 confirmed problem, got %d", ans.CurrentState.Confirmed)
	}
	if len(ans.Citations) == 0 {
		t.Fatal("current-state must cite the active incidents")
	}
}

// Cross-tenant: B's current-state must never include A's problem.
func TestCurrentStateIsolation(t *testing.T) {
	o := newOrch(newMockDS())
	ans, _ := o.Ask(context.Background(), tenantB(), "what should the NOC focus on first?", nil)
	for _, l := range ans.CurrentState.ActiveIncidents {
		if strings.Contains(l, "edge-1") || strings.Contains(l, "BGP peer down") {
			t.Fatalf("LEAK: tenant A incident surfaced to tenant B: %q", l)
		}
	}
}

// TestTimeRangeSummary: a PAST-window question is summarized from the WINDOWED
// correlation query — never from live current-state. The honesty guard: the
// answer reflects the window data ("Overnight …") and NOT the live active
// correlation ("BGP peer down on edge-1").
func TestTimeRangeSummary(t *testing.T) {
	o := newOrch(newMockDS())
	for _, q := range []string{
		"what happened overnight?",
		"summarize the last 4 hours",
		"give me yesterday's incidents",
	} {
		ans, err := o.Ask(context.Background(), tenantA(), q, nil)
		if err != nil {
			t.Fatalf("%q: %v", q, err)
		}
		if ans.Mode != ModeTimeRangeOutageSummary || ans.Intent != "time_range_summary" {
			t.Fatalf("%q: want a time-range summary, got mode=%s intent=%s", q, ans.Mode, ans.Intent)
		}
		if ans.CurrentState != nil {
			t.Fatalf("%q: must NOT answer a past question with live current-state data", q)
		}
		// Reads the WINDOW, not live state.
		if strings.Contains(ans.Text, "BGP peer down") || strings.Contains(ans.Text, "edge-1") {
			t.Fatalf("%q: leaked LIVE correlation data into a historical answer: %q", q, ans.Text)
		}
		if ans.Module == nil || len(ans.Module.Items) == 0 {
			t.Fatalf("%q: expected windowed incident items, got %+v", q, ans.Module)
		}
	}

	// Tenant isolation: t-a sees only its window rows, t-b only its own.
	a, _ := o.Ask(context.Background(), tenantA(), "what happened overnight", nil)
	if !strings.Contains(a.Text, "Overnight DIA latency") {
		t.Errorf("t-a window summary should reflect its own data, got %q", a.Text)
	}
	if strings.Contains(a.Text, "leaf reboot") {
		t.Errorf("t-a must not see t-b's window incident: %q", a.Text)
	}
}

func TestParseLookback(t *testing.T) {
	cases := []struct {
		q        string
		wantSecs int
	}{
		{"what happened in the last 4 hours", 4 * 3600},
		{"summarize the past 2 days", 2 * 24 * 3600},
		{"last 30 minutes", 30 * 60},
		{"overnight incidents", 12 * 3600},
		{"what happened this morning", 6 * 3600},
		{"over the weekend", 72 * 3600},
	}
	for _, c := range cases {
		if got, _ := parseLookback(c.q); got != c.wantSecs {
			t.Errorf("parseLookback(%q) = %d, want %d", c.q, got, c.wantSecs)
		}
	}
	// Clamp: an absurd window is bounded to 30d.
	if got, _ := parseLookback("last 999 weeks"); got != 30*24*3600 {
		t.Errorf("parseLookback should clamp to 30d, got %d", got)
	}
}

// TestShiftHandoff: a shift pass-down request produces a real, deterministic
// handoff (active picture + priority incidents + checklist) — not a stub, not a
// provider call. Gated on correlations:read.
func TestShiftHandoff(t *testing.T) {
	o := newOrch(newMockDS())
	ans, err := o.Ask(context.Background(), tenantA(), "give me the shift handoff", nil)
	if err != nil {
		t.Fatal(err)
	}
	if ans.Mode != ModeShiftHandoff || ans.Intent != "shift_handoff" {
		t.Fatalf("expected a real shift_handoff answer, got mode=%s intent=%s", ans.Mode, ans.Intent)
	}
	if strings.TrimSpace(ans.Text) == "" {
		t.Error("shift handoff must have a narrative")
	}
	if len(ans.NextActions) == 0 {
		t.Error("shift handoff must include a handoff checklist")
	}
	if !containsStr(ans.ModeBadges, "Shift handoff") {
		t.Errorf("expected a Shift handoff badge, got %v", ans.ModeBadges)
	}
	// A caller without correlations:read is refused (no incident data leak).
	noPerm := Principal{Tenant: "t-a", Perms: map[string]bool{"reports:read": true}}
	if r, _ := o.Ask(context.Background(), noPerm, "shift handoff", nil); r.Mode != ModeUnavailable {
		t.Errorf("no correlations:read → must be refused, got %s", r.Mode)
	}
}

// TestPresentTenseStillCurrentState is the regression guard for the historical
// detector: present-tense phrasing must STILL route to the live current-state
// summary, not get swept into the time-range disclosure.
func TestPresentTenseStillCurrentState(t *testing.T) {
	o := newOrch(newMockDS())
	for _, q := range []string{
		"what's happening right now?",
		"what is going on currently?",
		"what should the NOC focus on at the moment?",
	} {
		ans, err := o.Ask(context.Background(), tenantA(), q, nil)
		if err != nil {
			t.Fatalf("%q: %v", q, err)
		}
		if ans.Mode != ModeCurrentStateSummary || ans.CurrentState == nil {
			t.Fatalf("%q: present-tense must stay live current-state, got mode=%s", q, ans.Mode)
		}
	}
}

func knownMode(m AnswerMode) bool {
	switch m {
	case ModeProblemExplanation, ModeCurrentStateSummary, ModeProductNavigationHelp,
		ModeProductAnswer, ModeModuleHealthSummary, ModeInvestigationPlan, ModeShiftHandoff,
		ModeTimeRangeOutageSummary, ModeNocFocusRecommendation, ModeIncidentStatusBreakdown,
		ModeUnavailable:
		return true
	}
	return false
}

// TestRandomQuestionsWellFormed fires a broad spread of phrasings (the "keep
// asking random questions" check) and asserts every answer is well-formed: a
// known mode, non-empty narrative text, and mode-consistent structure — so no
// question yields a blank or malformed card in the UI.
func TestRandomQuestionsWellFormed(t *testing.T) {
	o := newOrch(newMockDS())
	p := tenantA()
	questions := []string{
		"What is going on right now?",
		"what should the NOC focus on first?",
		"give me a status update",
		"is everything healthy?",
		"show me the worst incident",
		"asdfqwer random gibberish 123",
		"explain problem",
		"explain this incident",
		"explain the rca",
		"summarize the outage last night",
		"what happened overnight",
		"recap the last 4 hours",
		"give me the shift handoff",
		"end of shift summary",
		"where do I configure servicenow",
		"how do I set up SNMP discovery",
	}
	for _, q := range questions {
		ans, err := o.Ask(context.Background(), p, q, nil)
		if err != nil {
			t.Fatalf("%q: %v", q, err)
		}
		if !knownMode(ans.Mode) {
			t.Fatalf("%q: unknown answer mode %q", q, ans.Mode)
		}
		if strings.TrimSpace(ans.Text) == "" {
			t.Fatalf("%q: produced empty narrative text (mode=%s)", q, ans.Mode)
		}
		switch ans.Mode {
		case ModeCurrentStateSummary:
			cs := ans.CurrentState
			if cs == nil {
				t.Fatalf("%q: current_state mode without a CurrentState payload", q)
			}
			if cs.Confirmed+cs.Suspected+cs.Undetermined != len(cs.ActiveIncidents) {
				t.Fatalf("%q: verdict counts %d/%d/%d don't sum to %d active incidents",
					q, cs.Confirmed, cs.Suspected, cs.Undetermined, len(cs.ActiveIncidents))
			}
		case ModeUnavailable:
			if ans.CurrentState != nil {
				t.Fatalf("%q: an unavailable answer must not carry live current_state", q)
			}
		}
		// No answer, whatever the phrasing, may leak another tenant's device.
		if strings.Contains(ans.Text, "leaf-2") {
			t.Fatalf("%q: leaked tenant B's device into tenant A's answer", q)
		}
	}
}

// TestModuleRoutingClassify pins the P4 classifier routes: module-specific
// phrasings land on the right module + module_health_summary mode, and don't
// steal RCA / time-range / navigation intents.
func TestModuleRoutingClassify(t *testing.T) {
	cases := []struct {
		q      string
		module string
	}{
		{"show me the top talkers", "flow_analytics"},
		{"who is using the most bandwidth?", "flow_analytics"},
		{"any metric anomalies right now?", "telemetry"},
		{"is anything flapping?", "telemetry"},
		{"how is office365 doing?", "cloud_app_observability"},
	}
	for _, c := range cases {
		p := Classify(c.q, nil)
		if p.Mode != ModeModuleHealthSummary {
			t.Fatalf("%q: expected module_health_summary, got %s", c.q, p.Mode)
		}
		if len(p.Modules) != 1 || p.Modules[0] != c.module {
			t.Fatalf("%q: expected module %s, got %v", c.q, c.module, p.Modules)
		}
	}
	// Regression: an RCA / time-range question must NOT be swept into a module route.
	if Classify("explain this incident", nil).Mode != ModeProblemExplanation {
		t.Fatal("RCA intent regressed into a module route")
	}
	if Classify("what happened last night?", nil).Mode != ModeTimeRangeOutageSummary {
		t.Fatal("time-range intent regressed into a module route")
	}
}

// TestModuleHealthAnswer: a module question returns a grounded module_health_summary
// card with cited items from the module's tools.
func TestModuleHealthAnswer(t *testing.T) {
	o := newOrch(newMockDS())
	ans, err := o.Ask(context.Background(), opsA(), "show me the top talkers", nil)
	if err != nil {
		t.Fatal(err)
	}
	if ans.Mode != ModeModuleHealthSummary || ans.Module == nil {
		t.Fatalf("expected a module_health_summary, got %+v", ans)
	}
	if ans.Module.Module != "flow_analytics" || ans.Module.DisplayName == "" {
		t.Fatalf("module payload not populated: %+v", ans.Module)
	}
	if len(ans.Module.Items) == 0 || len(ans.Citations) == 0 {
		t.Fatal("module answer must carry cited evidence items")
	}
}

// TestModuleIsolation is the mandatory §3a.5 cross-tenant test for P4 module
// tools: tenant B's module summary must never contain tenant A's device. The
// LLM is in echo mode (Reply:"") so the model "headline" is exactly the grounded
// prompt — proving the prompt we hand the provider carries ONLY tenant B's data
// (a hardcoded canned reply would mask this).
func TestModuleIsolation(t *testing.T) {
	ds := newMockDS()
	o := &Orchestrator{DS: ds, Tools: Tools(ds), LLM: MockLLM{}, Flags: func(string) bool { return false }}
	for _, q := range []string{"show me the top talkers", "any metric anomalies?"} {
		ans, err := o.Ask(context.Background(), opsB(), q, nil)
		if err != nil {
			t.Fatalf("%q: %v", q, err)
		}
		blob := ans.Text
		for _, it := range ans.Module.Items {
			blob += " " + it
		}
		if strings.Contains(blob, "edge-1") {
			t.Fatalf("%q: LEAK — tenant A device edge-1 surfaced to tenant B: %q", q, blob)
		}
		if !strings.Contains(blob, "leaf-2") {
			t.Fatalf("%q: tenant B should see its own device leaf-2, got %q", q, blob)
		}
	}
}

// TestModulePermissionGate: a caller lacking the module perm is refused (not
// silently shown another scope's data).
func TestModulePermissionGate(t *testing.T) {
	o := newOrch(newMockDS())
	noFlows := Principal{Tenant: "t-a", Perms: map[string]bool{"correlations:read": true}} // no flows:read
	ans, err := o.Ask(context.Background(), noFlows, "show me the top talkers", nil)
	if err != nil {
		t.Fatal(err)
	}
	if ans.Mode != ModeUnavailable {
		t.Fatalf("a caller without flows:read must be refused, got %s", ans.Mode)
	}
	if ans.Module != nil {
		t.Fatal("refused module answer must not carry a module payload")
	}
}

// TestFutureModuleDisclosure: a question for a FUTURE/flagged module
// (cloud_app_observability, flag off) gets an honest "not available yet", never
// faked data.
func TestFutureModuleDisclosure(t *testing.T) {
	o := newOrch(newMockDS()) // Flags returns false → ENABLE_CLOUD_APP_OBS off
	ans, err := o.Ask(context.Background(), opsA(), "how is office365 doing?", nil)
	if err != nil {
		t.Fatal(err)
	}
	if ans.Mode != ModeUnavailable {
		t.Fatalf("a future module must disclose unavailability, got %s", ans.Mode)
	}
	if ans.Module != nil {
		t.Fatal("future-module disclosure must not fabricate a module payload")
	}
}

func TestNavigation(t *testing.T) {
	o := newOrch(newMockDS())
	ans, err := o.Ask(context.Background(), tenantA(), "where do I configure servicenow", nil)
	if err != nil {
		t.Fatal(err)
	}
	if ans.Mode != ModeProductNavigationHelp || len(ans.Navigation) == 0 {
		t.Fatalf("expected navigation help, got %+v", ans)
	}
}

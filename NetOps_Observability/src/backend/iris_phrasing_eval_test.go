// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// iris_phrasing_eval_test.go — does Iris understand the way a NOC actually
// asks? (tracker 337, owner 2026-11-11: "can it understand any natural way of
// asking?"). Every utterance in ai/testdata/phrasing_golden.json is asked
// through the REAL router on the deterministic path — no model, offline — and
// the router's first claim is scored against the label:
//
//   - the classic arms and the skill arm exactly as /api/ai/ask builds them
//     (s.newOrchestrator), so a rule ordering bug shows here;
//   - the data arm with its real grammar, resolver, admission and validator
//     in tenant A's scope (aiNLQueryRunning). Only the final executor is a
//     recorder: the validated query is scored, no backend is read.
//
// Split (internal/evalsplit, corpus "phrasing"): lab cases are dev by
// construction; synthetic cases are held out by hash. Held-out misses are
// NOT printed unless IRIS_PHRASING_SHOW_HELDOUT=1 — the point of the slice is
// that nobody tuned the rules on it. Floors ratchet (raise, never lower).

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"netops/backend/ai"
	"netops/backend/internal/evalsplit"
	nlqast "netops/backend/internal/nlquery/ast"
	"netops/backend/internal/nlquery/plan"
	"netops/backend/internal/nlquery/validate"
	"netops/backend/models"
)

// PhrasingCorpus is the evalsplit corpus name of the phrasing set.
const phrasingCorpus = "phrasing"

// Ratchet floors (share of cases routed right; raise when the measured value
// rises, never lower). Measured 2026-11-12 on 165 utterances: baseline before
// the phrasing work dev 87/139 (0.63), held-out 16/26 (0.62); after it dev
// 137/139 (0.99), held-out 22/26 (0.85).
const (
	minPhrasingDev     = 0.98
	minPhrasingHeldOut = 0.84
)

type phrasingSlots struct {
	Metric     string `json:"metric,omitempty"`
	Device     string `json:"device,omitempty"`
	State      string `json:"state,omitempty"`
	AllDevices bool   `json:"all_devices,omitempty"`
	MinWindow  string `json:"min_window,omitempty"`
	Skill      string `json:"skill,omitempty"`
	Limit      int    `json:"limit,omitempty"`
	Target     string `json:"target,omitempty"`
	// Verdict: the incident list is filtered to this verdict tier.
	Verdict string `json:"verdict,omitempty"`
}

type phrasingCase struct {
	ID     string        `json:"id"`
	Source string        `json:"source,omitempty"`
	Q      string        `json:"q"`
	Expect string        `json:"expect"`
	Alt    []string      `json:"alt,omitempty"`
	Slots  phrasingSlots `json:"slots"`
	// Context is the UI context the question is asked with — the RCA
	// workspace passes {"correlation_id": …}, so the problem in view is the
	// subject (route_policy.go).
	Context map[string]string `json:"context,omitempty"`
}

func (c phrasingCase) split() evalsplit.Split {
	src, err := evalsplit.ParseSource(c.Source)
	if err != nil {
		return evalsplit.HeldOut // unknown origin never reaches tuning
	}
	return evalsplit.Assign(phrasingCorpus, c.ID, src)
}

// phrasingFixtureDevices are tenant A's devices (plus edge-a from
// nlqFixture); names → ids for the device slot.
var phrasingFixtureDevices = map[string]string{"edge-a": "dev-a", "cedge-81": "dev-c81", "cedge-82": "dev-c82", "vedge-1": "dev-v1"}

// phrasingObs is what the router did with one utterance.
type phrasingObs struct {
	arm, mode, intent, skill string
	q                        *nlqast.AST
}

func (o phrasingObs) String() string {
	s := o.arm + "/" + o.mode + "/" + o.intent
	if o.skill != "" {
		s += " skill=" + o.skill
	}
	if o.q != nil {
		b, _ := json.Marshal(o.q)
		s += " " + string(b)
	}
	return s
}

func phrasingIsMetric(t nlqast.QueryType) bool {
	return t == nlqast.MetricSeries || t == nlqast.MetricTopK || t == nlqast.MetricFilter || t == nlqast.CompareWindows
}

// phrasingLabels: what each label accepts. Closed: a label not here fails
// loading.
var phrasingLabels = map[string]func(o phrasingObs) bool{
	"device_state": func(o phrasingObs) bool {
		return o.arm == ai.ArmData && o.q != nil && (o.q.Type == nlqast.EntityList || o.q.Type == nlqast.EntityCount) && o.q.Target == "device"
	},
	"incidents": func(o phrasingObs) bool {
		return o.arm == ai.ArmClassic && (o.intent == "incident_list" || o.intent == "incident_breakdown") ||
			o.arm == ai.ArmData && o.q != nil && o.q.Type == nlqast.IncidentList
	},
	"health": func(o phrasingObs) bool { return o.arm == ai.ArmClassic && o.intent == "current_state" },
	"bgp": func(o phrasingObs) bool {
		return o.arm == ai.ArmData && o.q != nil && phrasingIsMetric(o.q.Type) && o.q.Target == "bgp_peer"
	},
	"interfaces": func(o phrasingObs) bool {
		return o.arm == ai.ArmData && o.q != nil && phrasingIsMetric(o.q.Type) && o.q.Target == "interface"
	},
	"circuits": func(o phrasingObs) bool {
		return o.arm == ai.ArmData && o.q != nil && phrasingIsMetric(o.q.Type) && o.q.Target == "circuit"
	},
	"device_metric": func(o phrasingObs) bool {
		return o.arm == ai.ArmData && o.q != nil && phrasingIsMetric(o.q.Type) && o.q.Target == "device"
	},
	"top_n": func(o phrasingObs) bool { return o.arm == ai.ArmData && o.q != nil && o.q.Type == nlqast.MetricTopK },
	"flows": func(o phrasingObs) bool {
		return o.arm == ai.ArmClassic && o.intent == "flow_analytics_summary" || o.arm == ai.ArmData && o.q != nil && o.q.Type == nlqast.FlowTop
	},
	"changes": func(o phrasingObs) bool { return o.arm == ai.ArmData && o.q != nil && o.q.Type == nlqast.ChangeList },
	"rca": func(o phrasingObs) bool {
		return o.arm == ai.ArmClassic && (o.intent == "problem_explanation" || o.intent == "top_incident" || o.intent == "noc_focus") ||
			o.arm == ai.ArmData && o.q != nil && o.q.Type == nlqast.IncidentExplain
	},
	"history": func(o phrasingObs) bool {
		return o.arm == ai.ArmClassic && o.intent == "time_range_summary" ||
			o.arm == ai.ArmData && o.q != nil && o.q.Type == nlqast.IncidentList && o.q.Time.Kind != ""
	},
	"shift": func(o phrasingObs) bool { return o.arm == ai.ArmClassic && o.intent == "shift_handoff" },
	"product_help": func(o phrasingObs) bool {
		return o.arm == ai.ArmPageHelp || o.arm == ai.ArmExplain ||
			o.arm == ai.ArmClassic && (o.intent == "product_question" || o.intent == "product_navigation")
	},
	"troubleshoot": func(o phrasingObs) bool {
		return o.arm == ai.ArmSkill || o.arm == ai.ArmClassic && o.intent == "network_kb"
	},
	// compound: a multi-part question every part of which is answered on the
	// deterministic path (route_policy.go), in one answer.
	"compound": func(o phrasingObs) bool { return o.arm == ai.ArmData && o.intent == ai.IntentMultiQuestion },
}

// slotsHold checks the case's slots against the observation; "" = all hold.
func (c phrasingCase) slotsHold(o phrasingObs) string {
	sl := c.Slots
	if sl.Skill != "" && o.skill != sl.Skill {
		return "skill " + o.skill + " ≠ " + sl.Skill
	}
	needQ := sl.Metric != "" || sl.Device != "" || sl.State != "" || sl.AllDevices || sl.MinWindow != "" || sl.Limit > 0 || sl.Target != "" || sl.Verdict != ""
	if !needQ {
		return ""
	}
	if o.q == nil {
		if sl.Skill != "" && sl.Metric == "" && sl.Device == "" {
			return ""
		}
		return "no query to check slots against"
	}
	if sl.Metric != "" && o.q.Metric != sl.Metric {
		return "metric " + o.q.Metric + " ≠ " + sl.Metric
	}
	if sl.Device != "" {
		id := phrasingFixtureDevices[sl.Device]
		found := false
		for _, r := range o.q.Refs {
			if r.ID == "device:"+id || strings.HasPrefix(r.ID, r.Type+":"+id+"/") {
				found = true
			}
		}
		if !found {
			return "device " + sl.Device + " not in scope of the query"
		}
	}
	if sl.AllDevices {
		for _, r := range o.q.Refs {
			if r.Type == "device" || r.Type == "site" || r.Type == "interface" || r.Type == "bgp_peer" {
				return "narrowed to " + r.ID + " instead of every device"
			}
		}
	}
	if sl.State != "" && !phrasingHasState(o.q, sl.State) {
		return "state " + sl.State + " not asked for"
	}
	if sl.MinWindow != "" {
		want, _ := time.ParseDuration(sl.MinWindow)
		got := phrasingWindow(o.q.Time)
		if got < want {
			return fmt.Sprintf("window %v shorter than %v", got, want)
		}
	}
	if sl.Limit > 0 && o.q.Limit != sl.Limit {
		return fmt.Sprintf("limit %d ≠ %d", o.q.Limit, sl.Limit)
	}
	if sl.Target != "" && o.q.Target != sl.Target && !(len(o.q.GroupBy) == 1 && o.q.GroupBy[0] == sl.Target) {
		return "target " + o.q.Target + " ≠ " + sl.Target
	}
	if sl.Verdict != "" && !phrasingHasVerdict(o.q, sl.Verdict) {
		return "verdict " + sl.Verdict + " not filtered"
	}
	return ""
}

// phrasingHasVerdict: the incident list is filtered to exactly that verdict.
func phrasingHasVerdict(q *nlqast.AST, verdict string) bool {
	for _, f := range q.Filters {
		if f.Field == "verdict_tier" && len(f.Values) == 1 && f.Values[0] == verdict {
			return true
		}
	}
	return false
}

// phrasingHasState: the query asks for that up/down state — a reachability
// filter on a device list, or a state predicate on a state metric.
func phrasingHasState(q *nlqast.AST, state string) bool {
	for _, f := range q.Filters {
		if f.Field == "reachability" {
			for _, v := range f.Values {
				if v == state {
					return true
				}
			}
		}
	}
	return q.Predicate != nil && (q.Metric == "bgp_session_state" || q.Metric == "if_oper_status")
}

// phrasingWindow reads a relative window ("24h", "7d", "30m").
func phrasingWindow(tr nlqast.TimeRange) time.Duration {
	if tr.Kind == nlqast.TimeAbsolute && tr.From != nil && tr.To != nil {
		return tr.To.Sub(*tr.From)
	}
	l := strings.TrimSpace(tr.Last)
	if l == "" {
		return 0
	}
	if strings.HasSuffix(l, "d") {
		var n int
		if _, err := fmt.Sscanf(l, "%dd", &n); err == nil {
			return time.Duration(n) * 24 * time.Hour
		}
	}
	if strings.HasSuffix(l, "w") {
		var n int
		if _, err := fmt.Sscanf(l, "%dw", &n); err == nil {
			return time.Duration(n) * 7 * 24 * time.Hour
		}
	}
	d, _ := time.ParseDuration(l)
	return d
}

func loadPhrasingCases(t *testing.T) []phrasingCase {
	t.Helper()
	raw, err := os.ReadFile("ai/testdata/phrasing_golden.json")
	if err != nil {
		t.Fatal(err)
	}
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	var set struct {
		Description string         `json:"description"`
		Items       []phrasingCase `json:"items"`
	}
	if err := dec.Decode(&set); err != nil {
		t.Fatalf("phrasing set: %v", err)
	}
	seen := map[string]bool{}
	for _, c := range set.Items {
		if c.ID == "" || strings.TrimSpace(c.Q) == "" || seen[c.ID] {
			t.Fatalf("phrasing case %q: empty or duplicate", c.ID)
		}
		seen[c.ID] = true
		if _, err := evalsplit.ParseSource(c.Source); err != nil {
			t.Fatalf("%s: %v", c.ID, err)
		}
		for _, l := range append([]string{c.Expect}, c.Alt...) {
			if phrasingLabels[l] == nil {
				t.Fatalf("%s: unknown label %q", c.ID, l)
			}
		}
		if d := c.Slots.Device; d != "" && phrasingFixtureDevices[d] == "" {
			t.Fatalf("%s: device %q is not in the fixture", c.ID, d)
		}
	}
	return set.Items
}

// phrasingFixture is nlqAPIFixture plus the lab-shaped devices, no model.
func phrasingFixture(t *testing.T) (*server, jwtClaims) {
	t.Helper()
	t.Setenv("FEATURE_AI", "true")
	s, a, _ := nlqAPIFixture(t)
	s.copilotCfg = newCopilotConfigStore(t.TempDir()+"/copilot_config.json", nil) // no key: the deterministic path
	for name, id := range phrasingFixtureDevices {
		if id == "dev-a" {
			continue
		}
		if err := s.discovery.Upsert(models.Device{ID: id, Name: name, TenantID: "t-a"}); err != nil {
			t.Fatal(err)
		}
	}
	return s, a
}

// observePhrasingIn asks one question through the router and reports its first
// claim. Downstream reads are cut off the moment the claim is made.
// uiContext is the UI context the question is asked with (nil = none).
func observePhrasingIn(t *testing.T, s *server, a jwtClaims, q string, uiContext map[string]string) phrasingObs {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	r := httptest.NewRequest(http.MethodPost, "/api/ai/ask", nil).WithContext(context.WithValue(ctx, userCtxKey, a))
	var obs phrasingObs
	o := s.newOrchestrator(r, a)
	o.NLQuery = s.aiNLQueryRunning(r, a, nil, "", nil, func(_ *http.Request, _ jwtClaims, checked *nlqast.AST, _ validate.Result) (*plan.ResultSet, error) {
		obs.q = checked
		return &plan.ResultSet{QueryID: "phrasing-eval"}, nil
	})
	var claim ai.RouteDecision
	o.Routed = func(d ai.RouteDecision) {
		claim = d
		if d.Arm != ai.ArmData {
			cancel() // the claim is the measurement; nothing downstream is read
		}
	}
	ans, _ := o.Ask(r.Context(), s.aiPrincipal(a), q, uiContext) // a downstream error after the claim is not the router's
	obs.arm, obs.mode = claim.Arm, string(claim.Mode)
	var pl ai.Plan
	if ai.ProblemInView(q, uiContext) != "" {
		pl = ai.Classify(q, uiContext)
	} else {
		pl = ai.Classify(q, nil)
	}
	obs.intent = pl.Intent
	if claim.Arm == ai.ArmData {
		obs.intent = ans.Intent
	} else {
		obs.q = nil
	}
	if claim.Arm == ai.ArmSkill {
		if m, ok := ai.SelectSkill(aiSkills, q, pl); ok && m.Skill != nil {
			obs.skill = m.Skill.Name
		}
	}
	return obs
}

type phrasingTally struct{ ok, total int }

func (t phrasingTally) rate() float64 {
	if t.total == 0 {
		return 1
	}
	return float64(t.ok) / float64(t.total)
}

func TestIrisPhrasingEval(t *testing.T) {
	cases := loadPhrasingCases(t)
	s, a := phrasingFixture(t)
	showHeld := os.Getenv("IRIS_PHRASING_SHOW_HELDOUT") == "1"

	bySplit := map[evalsplit.Split]*phrasingTally{evalsplit.Dev: {}, evalsplit.HeldOut: {}}
	byLabel := map[string]map[evalsplit.Split]*phrasingTally{}
	var misses []string
	for _, c := range cases {
		o := observePhrasingIn(t, s, a, c.Q, c.Context)
		ok, why := false, ""
		for _, l := range append([]string{c.Expect}, c.Alt...) {
			if phrasingLabels[l](o) {
				ok = true
				break
			}
		}
		if ok {
			if why = c.slotsHold(o); why != "" {
				ok = false
			}
		}
		sp := c.split()
		bySplit[sp].total++
		if byLabel[c.Expect] == nil {
			byLabel[c.Expect] = map[evalsplit.Split]*phrasingTally{evalsplit.Dev: {}, evalsplit.HeldOut: {}}
		}
		byLabel[c.Expect][sp].total++
		if ok {
			bySplit[sp].ok++
			byLabel[c.Expect][sp].ok++
			continue
		}
		if sp == evalsplit.Dev || showHeld {
			misses = append(misses, fmt.Sprintf("[%s] %s %q want %s: got %s %s", sp, c.ID, c.Q, c.Expect, o, why))
		}
		if c.Source == string(evalsplit.SourceLab) {
			// A wording that failed live in the owner's lab and was fixed
			// against must never fail again.
			t.Errorf("LAB REGRESSION %s %q: want %s, got %s %s", c.ID, c.Q, c.Expect, o, why)
		}
	}

	labels := make([]string, 0, len(byLabel))
	for l := range byLabel {
		labels = append(labels, l)
	}
	sort.Strings(labels)
	var b strings.Builder
	fmt.Fprintf(&b, "| Label | Dev | Held-out |\n|---|---|---|\n")
	for _, l := range labels {
		d, h := byLabel[l][evalsplit.Dev], byLabel[l][evalsplit.HeldOut]
		fmt.Fprintf(&b, "| %s | %d/%d | %d/%d |\n", l, d.ok, d.total, h.ok, h.total)
	}
	d, h := bySplit[evalsplit.Dev], bySplit[evalsplit.HeldOut]
	fmt.Fprintf(&b, "| **all** | %d/%d (%.2f) | %d/%d (%.2f) |\n", d.ok, d.total, d.rate(), h.ok, h.total, h.rate())
	t.Log("\n" + b.String())
	if p := os.Getenv("GITHUB_STEP_SUMMARY"); p != "" {
		if f, err := os.OpenFile(p, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o600); err == nil {
			_, _ = f.WriteString("### Iris phrasing eval (deterministic path)\n\n" + b.String() + "\n") // best-effort summary
			_ = f.Close()                                                                               // best-effort summary
		}
	}
	for _, m := range misses {
		t.Log("MISS " + m)
	}
	if d.rate() < minPhrasingDev {
		t.Errorf("phrasing dev accuracy %.3f fell below the floor %.3f", d.rate(), minPhrasingDev)
	}
	if h.rate() < minPhrasingHeldOut {
		t.Errorf("phrasing held-out accuracy %.3f fell below the floor %.3f", h.rate(), minPhrasingHeldOut)
	}
}

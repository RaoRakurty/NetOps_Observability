package experience

// flow_test.go — the passive-flow producer (tracker 252).
//
// The load-bearing test in this file is TestConfirmedIsReachableWithSyntheticAndFlow
// / TestFlowAloneCannotConfirm: they are the mechanical statement of WHY this
// slice exists. Before it, a live tenant had one anchor-capable instrument and
// could never honestly reach `confirmed`; the pair below proves that two
// instruments now can, and that one still cannot — which is the property that
// would rot silently if only the happy case were tested.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"netops/backend/internal/dem"
)

// ── subject mapping ─────────────────────────────────────────────────────────

func TestFlowSubjectIDIsTheDeclaredIdentity(t *testing.T) {
	cases := []struct{ app, site, want string }{
		{"checkout", "branch-1", "checkout@branch-1"},
		{"Checkout", "Branch-1", "checkout@branch-1"},
		{"checkout", "", "checkout"},
		{"", "branch-1", ""},
		{"  ", " ", ""},
	}
	for _, c := range cases {
		if got := FlowSubjectID(c.app, c.site); got != c.want {
			t.Errorf("FlowSubjectID(%q,%q) = %q, want %q", c.app, c.site, got, c.want)
		}
	}
}

func TestFlowSubjectsForFoldsTheCatalogue(t *testing.T) {
	targets := []dem.Target{
		{ID: "dem-1", TenantID: "acme", Kind: dem.KindTCP, Host: "10.1.1.10:443", App: "checkout", Site: "branch-1"},
		{ID: "dem-2", TenantID: "acme", Kind: dem.KindICMP, Host: "10.1.1.11", App: "checkout", Site: "branch-1"},
		{ID: "dem-3", TenantID: "acme", Kind: dem.KindHTTP, Host: "https://10.2.2.20/health", App: "checkout", Site: "branch-7"},
		// Excluded, each for its own stated reason.
		{ID: "dem-4", TenantID: "acme", Kind: dem.KindHTTP, Host: "https://shop.example.com/", App: "checkout", Site: "branch-1"},
		{ID: "dem-5", TenantID: "acme", Kind: dem.KindICMP, Host: "10.1.1.99", Site: "branch-1"},
		{ID: "dem-6", TenantID: "acme", Kind: dem.KindICMP, Host: "10.1.1.12", App: "checkout", Site: "branch-1", Paused: true},
	}
	subs := FlowSubjectsFor(targets)
	if len(subs) != 2 {
		t.Fatalf("expected two (app, site) subjects, got %d: %+v", len(subs), subs)
	}
	if subs[0].Subject != "checkout@branch-1" || subs[1].Subject != "checkout@branch-7" {
		t.Fatalf("subjects are not the declared identities, sorted: %+v", subs)
	}
	b1 := subs[0]
	if len(b1.Endpoints) != 2 {
		t.Fatalf("branch-1 folded %d endpoints, want the two IP-literal ones: %+v", len(b1.Endpoints), b1.Endpoints)
	}
	if b1.Endpoints[0] != (FlowEndpoint{Addr: "10.1.1.10", Port: 443}) {
		t.Errorf("the tcp target's host:port was not peeled: %+v", b1.Endpoints[0])
	}
	if b1.Endpoints[1] != (FlowEndpoint{Addr: "10.1.1.11"}) {
		t.Errorf("an icmp target must name a host with ANY port, not port 0 as a real port: %+v", b1.Endpoints[1])
	}
	if len(b1.TargetIDs) != 2 || b1.TargetIDs[0] != "dem-1" {
		t.Errorf("the subject did not carry the declarations it was folded from: %+v", b1.TargetIDs)
	}
	if subs[1].Endpoints[0] != (FlowEndpoint{Addr: "10.2.2.20"}) {
		t.Errorf("the http URL's IP literal was not peeled: %+v", subs[1].Endpoints)
	}
	// The identity a flow measurement is stamped with must be the SAME shape
	// the synthetic source writes, with only `source` differing.
	id := b1.FlowIdentity("acme")
	if id.Source != dem.SourceFlow || id.Kind != dem.KindFlowApp || id.App != "checkout" || id.Site != "branch-1" {
		t.Fatalf("the flow identity is not the reserved DEM identity: %+v", id)
	}
}

func TestFlowSubjectsForRefusesToInventAnEndpoint(t *testing.T) {
	// A hostname is not an address. Resolving it HERE would measure whatever it
	// resolves to on the API host, which is not what a user reached.
	subs := FlowSubjectsFor([]dem.Target{
		{ID: "dem-1", Kind: dem.KindHTTP, Host: "https://shop.example.com/checkout", App: "checkout", Site: "branch-1"},
	})
	if len(subs) != 0 {
		t.Fatalf("a hostname target produced a flow subject: %+v", subs)
	}
}

func TestFlowSubjectsForIsBounded(t *testing.T) {
	targets := make([]dem.Target, 0, MaxFlowSubjects+50)
	for i := 0; i < MaxFlowSubjects+50; i++ {
		targets = append(targets, dem.Target{
			ID: "dem-" + itoaTest(i), Kind: dem.KindICMP, Host: "10.0.0.1",
			App: "app" + itoaTest(i), Site: "s",
		})
	}
	if got := len(FlowSubjectsFor(targets)); got > MaxFlowSubjects {
		t.Fatalf("the subject fold is unbounded: %d subjects", got)
	}
}

// ── the maths, and every not-measured branch ────────────────────────────────

func TestResetRatioBranches(t *testing.T) {
	cases := []struct {
		name     string
		st       FlowStats
		measured bool
		ratio    float64
		reason   string
		says     string
	}{
		{
			name: "no TCP at all", st: FlowStats{Flows: 900},
			reason: dem.ReasonNoSamples, says: "crossed a flow exporter",
		},
		{
			// THE TRAP: 0 resets out of 1000 flows means "the exporter does not
			// report control bits", not "nothing was aborted".
			name: "exporter reports no control bits", st: FlowStats{Flows: 1000, TCPFlows: 1000},
			reason: MissingNotSupported, says: "tcpControlBits",
		},
		{
			name:   "too few graded flows",
			st:     FlowStats{Flows: 40, TCPFlows: 40, FlagBearingFlows: MinFlowSamples - 1, ResetFlows: 9},
			reason: dem.ReasonNoSamples, says: "below the",
		},
		{
			name:     "measured",
			st:       FlowStats{Flows: 400, TCPFlows: 400, FlagBearingFlows: 200, ResetFlows: 25},
			measured: true, ratio: 12.5,
		},
		{
			name:     "measured, clean",
			st:       FlowStats{Flows: 400, TCPFlows: 400, FlagBearingFlows: 200, ResetFlows: 0},
			measured: true, ratio: 0,
		},
	}
	for _, c := range cases {
		got := c.st.ResetRatio()
		if got.Measured != c.measured {
			t.Errorf("%s: measured = %v, want %v (%+v)", c.name, got.Measured, c.measured, got)
			continue
		}
		if c.measured {
			if got.RatioPct != c.ratio {
				t.Errorf("%s: ratio = %v, want %v", c.name, got.RatioPct, c.ratio)
			}
			if got.Samples != c.st.FlagBearingFlows {
				t.Errorf("%s: the denominator must be the flag-bearing flows, got %d", c.name, got.Samples)
			}
			continue
		}
		if got.Reason != c.reason {
			t.Errorf("%s: reason = %q, want %q", c.name, got.Reason, c.reason)
		}
		if !strings.Contains(got.Detail, c.says) {
			t.Errorf("%s: the sentence does not say why: %q", c.name, got.Detail)
		}
	}
}

func TestFlowObserverIsTheExporterNotTheProber(t *testing.T) {
	if got := FlowObserver([]string{"10.0.0.2", "10.0.0.1", "10.0.0.1"}); got != "flow@10.0.0.1" {
		t.Fatalf("observer = %q, want a deterministic flow@<lowest exporter>", got)
	}
	if got := FlowObserver(nil); got != "flow" {
		t.Fatalf("an exporterless observation named %q; it must still name a vantage", got)
	}
}

// ── the adapter ─────────────────────────────────────────────────────────────

func flowInput(stats []FlowStats) AssembleInput {
	return AssembleInput{
		TenantID: "acme", Window: "1h", WindowDuration: time.Hour, Now: testNow,
		FeatureEnabled: true, MetricsAvailable: true,
		FlowsConfigured: true, FlowsAvailable: true,
		FlowSubjects: []FlowSubject{{
			Subject: "checkout@branch-1", App: "checkout", Site: "branch-1",
			Endpoints: []FlowEndpoint{{Addr: "10.1.1.10", Port: 443}},
		}},
		Flows: stats,
	}
}

func TestFlowEvidenceAboveThresholdIsAnchorCapableSupport(t *testing.T) {
	items := flowEvidence(flowInput([]FlowStats{{
		Subject: "checkout@branch-1", Flows: 900, TCPFlows: 800,
		FlagBearingFlows: 800, ResetFlows: 96,
		Exporters: []string{"10.0.0.7"}, LastSeen: testNow.Add(-2 * time.Minute),
	}}))
	if len(items) != 1 {
		t.Fatalf("expected one item, got %d: %+v", len(items), items)
	}
	it := items[0]
	if it.Stance != StanceSupports {
		t.Fatalf("a breached abort rate is supporting evidence, got %q", it.Stance)
	}
	if it.IndependenceGroup != ModalityPassiveFlow {
		t.Fatalf("modality = %q, want passive_flow", it.IndependenceGroup)
	}
	if !MayAnchorVerdict(it.IndependenceGroup) {
		t.Fatal("the flow class is not anchor-capable, so this slice bought nothing")
	}
	if it.Observer != "flow@10.0.0.7" {
		t.Fatalf("observer = %q; a flow observation's vantage is the exporter", it.Observer)
	}
	if it.Source != SourceFlow || it.Observation != ObservationObserved || it.DataClass != DataClassCustomerMetadata {
		t.Fatalf("provenance is not a flow observation: %+v", it.Provenance)
	}
	if it.EventAt != testNow.Add(-2*time.Minute) {
		t.Fatalf("event_at = %v, want the last flow seen", it.EventAt)
	}
	if it.CauseClass != "" {
		t.Fatalf("the adapter named a cause (%q) an aborted conversation does not identify", it.CauseClass)
	}
	if it.Value == nil || *it.Value != 12 || it.Baseline == nil || *it.Baseline != FlowResetRatioThresholdPct {
		t.Fatalf("the measurement and the bar were not carried: %+v", it)
	}
	if !strings.Contains(it.Detail, "no timing field") {
		t.Fatalf("the item does not state that flow says nothing about speed: %q", it.Detail)
	}
	if err := it.Validate(); err != nil {
		t.Fatalf("the adapter produced an inadmissible item: %v", err)
	}
}

func TestFlowEvidenceHealthyIsContextNotContradiction(t *testing.T) {
	items := flowEvidence(flowInput([]FlowStats{{
		Subject: "checkout@branch-1", Flows: 900, TCPFlows: 800,
		FlagBearingFlows: 800, ResetFlows: 4, Exporters: []string{"10.0.0.7"},
	}}))
	if len(items) != 1 {
		t.Fatalf("expected one item, got %d", len(items))
	}
	// An unattached CONTRADICTION bears on every hypothesis (selectEvidence),
	// so rendering "few resets" as a refutation would quietly make nothing
	// confirmable anywhere. It is context.
	if items[0].Stance != StanceNeutral {
		t.Fatalf("a low abort rate was graded %q; it is context, not a refutation", items[0].Stance)
	}
	if items[0].Weight(testNow) != 0 {
		t.Fatal("a neutral item carried weight into the score")
	}
}

func TestFlowEvidenceProducesNothingWhenNotMeasured(t *testing.T) {
	for _, st := range []FlowStats{
		{Subject: "checkout@branch-1", Flows: 900},
		{Subject: "checkout@branch-1", Flows: 900, TCPFlows: 900},
		{Subject: "checkout@branch-1", Flows: 10, TCPFlows: 10, FlagBearingFlows: 3, ResetFlows: 3},
		{Subject: "somebody-elses-subject", Flows: 900, TCPFlows: 900, FlagBearingFlows: 900, ResetFlows: 900},
	} {
		if got := flowEvidence(flowInput([]FlowStats{st})); len(got) != 0 {
			t.Errorf("an ungradeable aggregate produced evidence: %+v -> %+v", st, got)
		}
	}
	// A store that did not answer produces nothing here either; the absence is
	// carried by Data Health with its reason, never by an invented item.
	in := flowInput(nil)
	in.FlowsAvailable = false
	if got := flowEvidence(in); len(got) != 0 {
		t.Fatalf("an unanswered flow store produced evidence: %+v", got)
	}
}

// ── data health ─────────────────────────────────────────────────────────────

func TestFlowSourceHealthStatesAreFourDifferentSentences(t *testing.T) {
	base := flowInput([]FlowStats{{
		Subject: "checkout@branch-1", Flows: 900, TCPFlows: 800,
		FlagBearingFlows: 800, ResetFlows: 96, Exporters: []string{"10.0.0.7"},
	}})

	cases := []struct {
		name  string
		mut   func(in *AssembleInput)
		state string
		says  string
	}{
		{"flowing", func(*AssembleInput) {}, StateFlowing, "Responsiveness is NOT measured"},
		{"no store wired", func(in *AssembleInput) { in.FlowsConfigured = false; in.FlowsAvailable = false; in.Flows = nil },
			StateOff, "no flow store is wired"},
		{"nothing to attribute to", func(in *AssembleInput) { in.FlowSubjects = nil; in.Flows = nil },
			StateOff, "no subject a flow record could be attributed to"},
		{"store did not answer", func(in *AssembleInput) { in.FlowsAvailable = false; in.Flows = nil; in.FlowError = errTest },
			StateMisconfigured, "did not answer"},
		{"nothing on the wire", func(in *AssembleInput) { in.Flows = nil }, StateNoData, "no flow record touched"},
		{"nothing gradeable", func(in *AssembleInput) {
			in.Flows = []FlowStats{{Subject: "checkout@branch-1", Flows: 900, TCPFlows: 900}}
		}, StateNoData, "none could be graded"},
		{"feature off", func(in *AssembleInput) { in.FeatureEnabled = false }, StateOff, "switched off"},
	}
	for _, c := range cases {
		in := base
		in.Flows = append([]FlowStats(nil), base.Flows...)
		in.FlowSubjects = append([]FlowSubject(nil), base.FlowSubjects...)
		c.mut(&in)
		h := flowSourceHealth(in, 0, time.Time{})
		if h.State != c.state {
			t.Errorf("%s: state = %q, want %q (%q)", c.name, h.State, c.state, h.Detail)
		}
		if !strings.Contains(h.Detail, c.says) {
			t.Errorf("%s: the sentence does not say what happened: %q", c.name, h.Detail)
		}
		// Every branch must state the standing limitation of the lane.
		if !strings.Contains(h.Detail, "no server-response-time") {
			t.Errorf("%s: the source does not disclose that it cannot measure responsiveness: %q", c.name, h.Detail)
		}
	}
}

func TestAssembleGradesTheFlowSourceOnTheDataHealthSurface(t *testing.T) {
	in := flowInput([]FlowStats{{
		Subject: "checkout@branch-1", Flows: 900, TCPFlows: 800,
		FlagBearingFlows: 800, ResetFlows: 96, Exporters: []string{"10.0.0.7"},
		LastSeen: testNow.Add(-time.Minute),
	}})
	a := Assemble(in, testPolicy(t))
	var flow *SourceHealth
	for i := range a.DataHealth.Sources {
		if a.DataHealth.Sources[i].Source == SourceFlow {
			flow = &a.DataHealth.Sources[i]
		}
	}
	if flow == nil {
		t.Fatal("the flow source is missing from the Data Health surface")
	}
	if flow.State != StateFlowing {
		t.Fatalf("flow graded %q with a graded subject: %q", flow.State, flow.Detail)
	}
	if !flow.AnchorCapable || flow.IndependenceGroup != ModalityPassiveFlow {
		t.Fatalf("the flow source is not declared anchor-capable: %+v", flow)
	}
	if flow.EventsInWindow != 1 {
		t.Fatalf("the source did not count the evidence it produced: %d", flow.EventsInWindow)
	}
	if flow.LastSeen == nil {
		t.Fatal("the flow source reported no last-seen despite producing an observation")
	}
	if flow.Coverage == nil || *flow.Coverage != 1 {
		t.Fatalf("coverage was not computed over the declared subjects: %+v", flow.Coverage)
	}
}

// ── THE POINT OF THE SLICE ──────────────────────────────────────────────────

// rumlessBundle is a RUM-less scenario: the synthetic prober sees the path to
// the app degrade from three vantages (which names transit as a cause), and
// there is no browser telemetry anywhere. `flow` decides whether it can be
// CONFIRMED — that is the whole question tracker 252 exists to answer.
func rumlessBundle(flowItems []EvidenceItem) Bundle {
	items := []EvidenceItem{
		{
			ID: "path-isp-a", TenantID: "acme", Kind: KindPathDegradation,
			Entity: "hop-7", EntityKind: "hop",
			Summary:           "hop 7 (AS3356, ISP-A transit) lost 8% of probes and added 180 ms",
			Stance:            StanceSupports,
			IndependenceGroup: ModalityActiveProbe, Observer: "prober@branch-1",
			Reliability: 0.9, App: "checkout", Site: "branch-1",
			CauseClass: CauseTransitDegradation, CauseEntity: "AS3356 (ISP-A transit)",
			Seam: "wan-isp-a", Owner: "ISP A / carrier",
			Provenance: prov(SourcePathGraph, -5*time.Minute),
		},
		ev("syn-branch-2", ModalityActiveProbe, "prober@branch-2", -5*time.Minute),
		ev("syn-branch-3", ModalityActiveProbe, "prober@branch-3", -5*time.Minute),
	}
	items = append(items, flowItems...)
	return Bundle{
		TenantID: "acme", Window: testWindow(), Now: testNow,
		Evidence: items,
		Missing: []MissingEvidence{
			{Source: SourceRUM, IndependenceGroup: ModalityRealUser, Reason: MissingNotConfigured,
				Detail: "no first-party real-user telemetry is collected"},
		},
		Reliability: map[string]SyntheticReliability{},
	}
}

func supportingFlowItems(t *testing.T) []EvidenceItem {
	t.Helper()
	items := flowEvidence(flowInput([]FlowStats{{
		Subject: "checkout@branch-1", Flows: 900, TCPFlows: 800,
		FlagBearingFlows: 800, ResetFlows: 96, Exporters: []string{"10.0.0.7"},
		LastSeen: testNow.Add(-3 * time.Minute),
	}}))
	if len(items) != 1 || items[0].Stance != StanceSupports {
		t.Fatalf("the fixture did not produce the supporting flow item: %+v", items)
	}
	return items
}

// TestConfirmedIsReachableWithSyntheticAndFlow is tracker 252's acceptance:
// with NO real-user telemetry, two independent anchor-capable instruments —
// the prober and the wire — reach CONFIRMED. Its second half is the control
// that makes the first half mean something: the SAME evidence minus the flow
// item does NOT confirm, however many prober vantages agree with each other.
func TestConfirmedIsReachableWithSyntheticAndFlow(t *testing.T) {
	incidents := Detect(rumlessBundle(supportingFlowItems(t)))
	if len(incidents) != 1 {
		t.Fatalf("expected one incident, got %d", len(incidents))
	}
	lead, ok := leadOf(incidents[0])
	if !ok {
		t.Fatal("no leading hypothesis was reached")
	}
	if lead.State != StateConfirmed || lead.VerdictTier != TierConfirmed {
		t.Fatalf("synthetic + flow did not reach CONFIRMED (%s / %s). Gate: %v; independence: %+v; confidence %v",
			lead.State, lead.VerdictTier, lead.GateReasons, lead.Independence, lead.Confidence)
	}
	got := lead.Independence.AnchorModalities
	if len(got) != 2 || got[0] != ModalityActiveProbe || got[1] != ModalityPassiveFlow {
		t.Fatalf("confirmation did not come from the two expected classes: %v", got)
	}
	if len(lead.Independence.IndependentPair) != 2 {
		t.Fatalf("no independent pair was named: %+v", lead.Independence)
	}
	if lead.Confidence >= 1 {
		t.Fatalf("confidence reached %v with RUM missing — a missing source must still cost something", lead.Confidence)
	}

	// The control: three prober vantages, no wire. One kind of instrument
	// agreeing with itself is one opinion.
	withoutFlow := Detect(rumlessBundle(nil))
	if len(withoutFlow) != 1 {
		t.Fatalf("the control produced %d incidents", len(withoutFlow))
	}
	ctl, ok := leadOf(withoutFlow[0])
	if !ok {
		t.Fatal("the control reached no leading hypothesis")
	}
	if ctl.State == StateConfirmed {
		t.Fatalf("three vantages of ONE modality confirmed on their own: %+v", ctl.Independence)
	}
	if len(ctl.Independence.AnchorModalities) != 1 {
		t.Fatalf("the control was not single-class: %v", ctl.Independence.AnchorModalities)
	}
}

// TestFlowAloneCannotConfirm is the other half, and the one that would rot
// silently: the wire says the application is aborting conversations, every
// synthetic check of the same path succeeded, and a deploy happened just
// before. One anchor-capable class supports it, so it stays short of the gate.
func TestFlowAloneCannotConfirm(t *testing.T) {
	items := supportingFlowItems(t)
	items = append(items,
		contra("syn-healthy-1", ModalityActiveProbe, "prober@branch-1",
			[]string{CauseTransitDegradation}, -5*time.Minute),
	)
	b := Bundle{
		TenantID: "acme", Window: testWindow(), Now: testNow,
		Evidence: items,
		Changes: []ChangeEvent{{
			ID: "chg-" + "0000000000000000000000000000000f", TenantID: "acme",
			Type: ChangeApplicationDeploy, Actor: "ci", Object: "checkout-api",
			ObjectKind: "service", Summary: "checkout-api v43 deployed to production",
			ReleaseID: "v43", App: "checkout",
			Provenance: prov(SourceConfigDrift, -40*time.Minute),
		}},
		Missing: []MissingEvidence{
			{Source: SourceRUM, IndependenceGroup: ModalityRealUser, Reason: MissingNotConfigured,
				Detail: "no first-party real-user telemetry is collected"},
		},
		Reliability: map[string]SyntheticReliability{},
	}
	incidents := Detect(b)
	if len(incidents) == 0 {
		t.Fatal("the wire reported an aborting application and nothing was raised at all")
	}
	for _, inc := range incidents {
		for _, h := range inc.Hypotheses {
			if h.State == StateConfirmed || h.VerdictTier == TierConfirmed {
				t.Fatalf("a single modality class confirmed %q: independence %+v", h.CauseClass, h.Independence)
			}
			if len(h.Independence.AnchorModalities) > 1 {
				t.Fatalf("the fixture is not single-class after all: %v", h.Independence.AnchorModalities)
			}
		}
	}
}

// The Go anchor set must never claim more than the Python engine's rules allow
// (evidence.go's one-directional relation). passive_flow is an ordinary trusted
// modality in src/correlation/verdicts.py — Witness.trusted returns True
// whenever probe_authority is None, which it is for every class that is not
// active_probe, and coverage() will pair it with a trusted active_probe witness
// of a different modality — so a flow witness may anchor a confirming pair
// there, and may here.
//
// This is checked against the SOURCE rather than asserted in a comment: a
// modality that quietly disappeared from signals.py, or gained a support-only
// rule in verdicts.py, would silently make DEM the more confident of the two
// graders — the one direction the design forbids.
func TestPassiveFlowIsAnchorCapableInBothGraders(t *testing.T) {
	if !MayAnchorVerdict(ModalityPassiveFlow) {
		t.Fatal("passive_flow is not anchor-capable in DEM, so tracker 252 cannot close")
	}
	// The DEM set stays a SUBSET of what the engine trusts: the classes DEM
	// refuses as anchors must remain refused.
	for _, m := range []string{ModalityManagementPlane, ModalityActiveVerification, ModalitySecurity,
		ModalityChangeRecord, ModalityBusiness} {
		if MayAnchorVerdict(m) {
			t.Fatalf("%s became anchor-capable; DEM must never be MORE confident than the engine", m)
		}
	}

	signals := readRepoFile(t, "src/correlation/signals.py")
	if !strings.Contains(signals, `PASSIVE_FLOW = "passive_flow"`) {
		t.Fatal("src/correlation/signals.py no longer declares PASSIVE_FLOW — the two graders have drifted on what a modality class is")
	}
	// Every DEM anchor modality except the declared DEM-only additions must be
	// a real ModalityClass member in the engine.
	demOnly := map[string]bool{ModalityRealUser: true}
	for m := range anchorModalities {
		if demOnly[m] {
			continue
		}
		if !strings.Contains(signals, `= "`+m+`"`) {
			t.Errorf("DEM anchors on %q but signals.py does not declare it", m)
		}
	}

	verdicts := readRepoFile(t, "src/correlation/verdicts.py")
	// The only support-only rules in the engine are the low-authority probe and
	// the non-ssh/snmp active-verification witness. If a THIRD one appears,
	// this test must be revisited before the flow class is trusted to anchor.
	if strings.Count(verdicts, "support_only = ") != 2 {
		t.Fatal("verdicts.py changed how support_only is assigned — re-check that passive_flow can still anchor a confirming pair before trusting it here")
	}
	if strings.Contains(verdicts, "ModalityClass.PASSIVE_FLOW") {
		t.Fatal("verdicts.py now special-cases PASSIVE_FLOW — DEM's anchor set must be re-derived from that rule rather than from 'non-probe evidence is trusted'")
	}
}

// readRepoFile reads a file relative to the project root, located by walking up
// to the ancestor that owns deployment/docker.
func readRepoFile(t *testing.T, rel string) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for i := 0; i < 12; i++ {
		if _, serr := os.Stat(filepath.Join(dir, "deployment", "docker")); serr == nil {
			b, rerr := os.ReadFile(filepath.Join(dir, rel)) // #nosec G304 — a fixed, in-repo path in a test
			if rerr != nil {
				t.Fatalf("read %s: %v", rel, rerr)
			}
			return string(b)
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Fatalf("could not locate the project root from %s", dir)
	return ""
}

// ── local helpers ───────────────────────────────────────────────────────────

var errTest = errTestType{}

type errTestType struct{}

func (errTestType) Error() string { return "the flow store did not answer" }

func itoaTest(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

func testPolicy(t *testing.T) ScorePolicy {
	t.Helper()
	p, err := EmbeddedScorePolicy()
	if err != nil {
		t.Fatalf("the embedded score policy does not parse: %v", err)
	}
	return p
}

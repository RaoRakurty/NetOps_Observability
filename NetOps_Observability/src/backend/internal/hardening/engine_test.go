package hardening

import (
	"context"
	"reflect"
	"strings"
	"testing"
	"time"

	"netops/backend/internal/secfindings"
)

func fixedClock() func() time.Time {
	t := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	return func() time.Time { return t }
}

// findingFor returns the finding for a given RawRuleID (test helper).
func findingFor(fs []secfindings.Finding, ruleID string) (secfindings.Finding, bool) {
	for _, f := range fs {
		if f.RawRuleID == ruleID {
			return f, true
		}
	}
	return secfindings.Finding{}, false
}

// A config that has Telnet on VTY with NO access-class — the exposed case when
// the device faces an untrusted seam.
const cfgTelnetNoACL = `hostname edge-01
line vty 0 4
 transport input telnet
`

// The SAME service, but restricted by an access-class — the informational case.
const cfgTelnetWithACL = `hostname edge-01
line vty 0 4
 transport input telnet
 access-class MGMT-IN in
`

// TestSeamAwareExposureVerdictDiffers is THE differentiator test: identical
// service, two contexts. Untrusted seam + no ACL → critical EXPOSED (Fail);
// mgmt seam + ACL → informational (Pass). The verdict MUST differ.
func TestSeamAwareExposureVerdictDiffers(t *testing.T) {
	dev := Device{ID: "d1", Hostname: "edge-01", Platform: "Cisco IOS-XE 17.9", TenantID: "acme"}

	// Case A: telnet reachable from the ISP (untrusted) seam, no ACL.
	engA := NewEngine(DefaultCatalog(),
		MemConfigSource{"d1": cfgTelnetNoACL},
		MemSeamResolver{"d1": {{SeamID: "seam-isp", SeamType: "ISP", Interface: "Gi0/0", Untrusted: true}}},
		WithClock(fixedClock()))
	fsA, err := engA.Evaluate(context.Background(), dev)
	if err != nil {
		t.Fatalf("evaluate A: %v", err)
	}
	expA, ok := findingFor(fsA, "exposure-telnet")
	if !ok {
		t.Fatal("no exposure-telnet finding in case A")
	}

	// Case B: telnet restricted by ACL, only a mgmt seam.
	engB := NewEngine(DefaultCatalog(),
		MemConfigSource{"d1": cfgTelnetWithACL},
		MemSeamResolver{"d1": {{SeamID: "seam-mgmt", SeamType: "mgmt", Interface: "Gi0/1", Untrusted: false}}},
		WithClock(fixedClock()))
	fsB, err := engB.Evaluate(context.Background(), dev)
	if err != nil {
		t.Fatalf("evaluate B: %v", err)
	}
	expB, ok := findingFor(fsB, "exposure-telnet")
	if !ok {
		t.Fatal("no exposure-telnet finding in case B")
	}

	// The core assertion: the verdicts differ.
	if expA.StatusID == expB.StatusID {
		t.Fatalf("seam-aware check did not differentiate: both %v", expA.StatusID)
	}
	if expA.StatusID != secfindings.StatusFail || expA.Severity != secfindings.SeverityCritical {
		t.Errorf("exposed case = %v/%s, want Fail/critical", expA.StatusID, expA.Severity)
	}
	if expA.EvidenceClass != secfindings.EvidenceExposure {
		t.Errorf("exposed finding evidence class = %q, want exposure", expA.EvidenceClass)
	}
	if expA.SeamContext == nil || !expA.SeamContext.InternetFacing || expA.SeamContext.SeamID != "seam-isp" {
		t.Errorf("exposed finding lacks the untrusted seam context: %+v", expA.SeamContext)
	}
	if expA.Remediation == "" {
		t.Error("exposed finding has no remediation")
	}
	if expB.StatusID != secfindings.StatusPass || expB.Severity != secfindings.SeverityInfo {
		t.Errorf("mgmt+ACL case = %v/%s, want Pass/info", expB.StatusID, expB.Severity)
	}
}

// TestExposureUntrustedButRestricted: an untrusted seam does NOT make an
// ACL-restricted service critical — the ACL is the mitigation.
func TestExposureUntrustedButRestricted(t *testing.T) {
	dev := Device{ID: "d1", Platform: "Cisco IOS-XE", TenantID: "acme"}
	eng := NewEngine(DefaultCatalog(),
		MemConfigSource{"d1": cfgTelnetWithACL},
		MemSeamResolver{"d1": {{SeamID: "seam-isp", SeamType: "ISP", Untrusted: true}}},
		WithClock(fixedClock()))
	fs, _ := eng.Evaluate(context.Background(), dev)
	exp, _ := findingFor(fs, "exposure-telnet")
	if exp.StatusID != secfindings.StatusPass {
		t.Fatalf("restricted service on untrusted seam = %v, want Pass (ACL mitigates)", exp.StatusID)
	}
}

// TestFailClosedNoConfig: config unavailable → every check is Unknown, NEVER a
// Pass (§5e fail-closed: never a false green).
func TestFailClosedNoConfig(t *testing.T) {
	dev := Device{ID: "ghost", Platform: "Cisco IOS-XE", TenantID: "acme"}
	eng := NewEngine(DefaultCatalog(),
		MemConfigSource{}, // ghost is absent → ok=false
		MemSeamResolver{"ghost": {{SeamID: "s", SeamType: "ISP", Untrusted: true}}},
		WithClock(fixedClock()))
	fs, err := eng.Evaluate(context.Background(), dev)
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) == 0 {
		t.Fatal("expected findings even with no config (honest Unknowns)")
	}
	for _, f := range fs {
		if f.StatusID == secfindings.StatusPass {
			t.Errorf("rule %q is Pass with no config — must never false-green", f.RawRuleID)
		}
		if f.StatusID != secfindings.StatusUnknown {
			t.Errorf("rule %q = %v with no config, want Unknown", f.RawRuleID, f.StatusID)
		}
	}
}

// TestFailClosedNoSeamData: config present, service ON, but the seam model has
// no data → the exposure verdict is Unknown, not Pass.
func TestFailClosedNoSeamData(t *testing.T) {
	dev := Device{ID: "d1", Platform: "Cisco IOS-XE", TenantID: "acme"}
	eng := NewEngine(DefaultCatalog(),
		MemConfigSource{"d1": cfgTelnetNoACL},
		MemSeamResolver{}, // no seam data for d1
		WithClock(fixedClock()))
	fs, _ := eng.Evaluate(context.Background(), dev)
	exp, _ := findingFor(fs, "exposure-telnet")
	if exp.StatusID != secfindings.StatusUnknown {
		t.Fatalf("enabled service + no seam data = %v, want Unknown (fail-closed)", exp.StatusID)
	}
	if exp.StatusID == secfindings.StatusPass {
		t.Fatal("must not false-green when seam model is unavailable")
	}
}

// TestServiceOffIsPassNotExposed: telnet off means not exposed even on an
// untrusted seam.
func TestServiceOffIsPassNotExposed(t *testing.T) {
	dev := Device{ID: "d1", Platform: "Cisco IOS-XE", TenantID: "acme"}
	eng := NewEngine(DefaultCatalog(),
		MemConfigSource{"d1": "line vty 0 4\n transport input ssh\n access-class MGMT-IN in\n"},
		MemSeamResolver{"d1": {{SeamID: "s", SeamType: "ISP", Untrusted: true}}},
		WithClock(fixedClock()))
	fs, _ := eng.Evaluate(context.Background(), dev)
	exp, _ := findingFor(fs, "exposure-telnet")
	if exp.StatusID != secfindings.StatusPass {
		t.Fatalf("telnet-off exposure = %v, want Pass", exp.StatusID)
	}
}

// TestUnresolvedPlatformYieldsExactlyOneUnassessedFinding: a platform label no
// vendor profile recognizes evaluates NOTHING. Before the 2026-09-03 fix an
// unresolvable device was scored against the WHOLE catalog (the Cisco IOS rule
// ids among them) and answered NotApplicable 32 times; a lab SR Linux spine with
// no config on file got the same treatment as 32 Unknowns. The honest answer is
// one finding that says the platform is unresolved and names the label.
func TestUnresolvedPlatformYieldsExactlyOneUnassessedFinding(t *testing.T) {
	dev := Device{ID: "d1", Platform: "Acme WidgetOS 1.0", TenantID: "acme"}
	eng := NewEngine(DefaultCatalog(),
		MemConfigSource{"d1": "some config\n"},
		MemSeamResolver{"d1": {{SeamID: "s", SeamType: "ISP", Untrusted: true}}},
		WithClock(fixedClock()))
	fs, err := eng.Evaluate(context.Background(), dev)
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 1 {
		ids := make([]string, 0, len(fs))
		for _, f := range fs {
			ids = append(ids, f.RawRuleID)
		}
		t.Fatalf("unresolved platform produced %d findings (%v), want exactly 1", len(fs), ids)
	}
	f := fs[0]
	if f.RawRuleID != RulePlatformUnresolved || f.ControlID != RulePlatformUnresolved {
		t.Errorf("rule id = %q/%q, want %q", f.RawRuleID, f.ControlID, RulePlatformUnresolved)
	}
	if f.StatusID != secfindings.StatusUnknown {
		t.Errorf("status = %v, want Unknown (unassessed, never a verdict)", f.StatusID)
	}
	if !strings.Contains(f.Detail, "unassessed: platform unresolved") {
		t.Errorf("detail %q does not carry the unassessed reason", f.Detail)
	}
	if !strings.Contains(f.Detail, "Acme WidgetOS 1.0") {
		t.Errorf("detail %q does not name the platform label that failed to resolve", f.Detail)
	}
	if f.Category != CategoryCoverage {
		t.Errorf("category = %q, want %q — a coverage gap is not a hardening plane", f.Category, CategoryCoverage)
	}
	if len(f.Standards) != 0 {
		t.Errorf("an unresolved platform must claim no standards tag, got %v", f.Standards)
	}
	if f.Severity != secfindings.SeverityInfo {
		t.Errorf("severity = %q, want info", f.Severity)
	}
}

// TestUnresolvedPlatformNeverBorrowsAnotherDialectsRules is the false-clear leg
// of the same defect: the emitted set must contain NOTHING from the IOS
// catalogue, however the label is shaped (including an empty one).
func TestUnresolvedPlatformNeverBorrowsAnotherDialectsRules(t *testing.T) {
	iosOnly := []string{"cdp-run-global", "pad-service", "vty-no-access-class", "no-aaa-new-model",
		"tcp-small-servers", "exposure-telnet", "exposure-ssh", "exposure-snmp", "exposure-http"}
	for _, platform := range []string{"Acme WidgetOS 1.0", "", "   ", "switch"} {
		dev := Device{ID: "d1", Platform: platform, TenantID: "acme"}
		eng := NewEngine(DefaultCatalog(),
			MemConfigSource{"d1": "cdp run\nservice pad\nline vty 0 4\n transport input telnet\n"},
			MemSeamResolver{"d1": {{SeamID: "s", SeamType: "ISP", Untrusted: true}}},
			WithClock(fixedClock()))
		fs, err := eng.Evaluate(context.Background(), dev)
		if err != nil {
			t.Fatal(err)
		}
		for _, rule := range iosOnly {
			if _, ok := findingFor(fs, rule); ok {
				t.Errorf("platform %q produced the IOS rule %q — a foreign dialect was applied", platform, rule)
			}
		}
		if _, ok := findingFor(fs, RulePlatformUnresolved); !ok {
			t.Errorf("platform %q produced no %q finding — silence reads as clear", platform, RulePlatformUnresolved)
		}
	}
}

// TestOnlyBoundRulesAreEvaluated: a device evaluates ITS OWN control set and
// nothing else. The set is derived from the catalog's bindings, so a new rule or
// a new binding updates the expectation automatically — what is pinned is the
// INVARIANT (emitted == bound), which is exactly what broke on the lab fabric.
func TestOnlyBoundRulesAreEvaluated(t *testing.T) {
	cat := DefaultCatalog()
	for _, tc := range []struct {
		name     string
		platform string
		vendor   Vendor
	}{
		// The CORE dialect only. The dialects that arrive through a DialectPack
		// are the `security_dialects` entitlement and live in
		// enterprise/dialects, which core must never import; that package runs
		// the SAME invariant over its own packs
		// (TestOnlyBoundRulesAreEvaluatedForPackDialects).
		{"cisco", "Cisco IOS-XE 17.9", VendorCiscoIOSXE},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := VendorFromPlatform(tc.platform); got != tc.vendor {
				t.Fatalf("VendorFromPlatform(%q) = %q, want %q", tc.platform, got, tc.vendor)
			}
			want := map[string]bool{}
			for _, r := range cat.Rules() {
				if _, ok := r.Binding(tc.vendor); ok {
					want[r.ID] = true
				}
			}
			for _, p := range cat.Probes() {
				if _, ok := p.Binding(tc.vendor); ok {
					want[p.ID] = true
				}
			}
			if len(want) == 0 {
				t.Fatalf("%s has no bindings at all — the fixture is wrong", tc.vendor)
			}
			// Both with and without a config on file: the emitted SET is the
			// binding set either way, only the verdicts differ.
			for _, cfg := range []ConfigSource{
				MemConfigSource{"d1": "hostname lab\n"},
				MemConfigSource{}, // fail-closed leg
			} {
				eng := NewEngine(cat, cfg, MemSeamResolver{"d1": {{SeamID: "s", SeamType: "mgmt"}}},
					WithClock(fixedClock()))
				fs, err := eng.Evaluate(context.Background(), Device{ID: "d1", Platform: tc.platform, TenantID: "acme"})
				if err != nil {
					t.Fatal(err)
				}
				got := map[string]bool{}
				for _, f := range fs {
					got[f.RawRuleID] = true
				}
				for id := range want {
					if !got[id] {
						t.Errorf("bound rule %q was NOT evaluated", id)
					}
				}
				for id := range got {
					if !want[id] {
						t.Errorf("rule %q was evaluated with NO binding for %q — a foreign dialect leaked in", id, tc.vendor)
					}
				}
			}
		})
	}
}

// TestTenantStampedFromDevice: TenantID is stamped from the device record onto
// every finding (§3a), and never left blank when the device has a tenant.
func TestTenantStampedFromDevice(t *testing.T) {
	dev := Device{ID: "d1", Platform: "Cisco IOS-XE", TenantID: "tenant-xyz"}
	eng := NewEngine(DefaultCatalog(),
		MemConfigSource{"d1": cfgTelnetNoACL},
		MemSeamResolver{"d1": {{SeamID: "s", SeamType: "ISP", Untrusted: true}}},
		WithClock(fixedClock()))
	fs, _ := eng.Evaluate(context.Background(), dev)
	for _, f := range fs {
		if f.TenantID != "tenant-xyz" {
			t.Fatalf("finding %q TenantID=%q, want tenant-xyz", f.RawRuleID, f.TenantID)
		}
	}
}

// TestDeterministicOrdering: two evaluations of the same input produce byte-for
// -byte identical ordered output (§11 stable output).
func TestDeterministicOrdering(t *testing.T) {
	dev := Device{ID: "d1", Platform: "Cisco IOS-XE", TenantID: "acme"}
	newEng := func() *Engine {
		return NewEngine(DefaultCatalog(),
			MemConfigSource{"d1": cfgTelnetNoACL},
			MemSeamResolver{"d1": {
				{SeamID: "seam-isp", SeamType: "ISP", Untrusted: true},
				{SeamID: "seam-mgmt", SeamType: "mgmt", Untrusted: false},
			}},
			WithClock(fixedClock()))
	}
	fs1, _ := newEng().Evaluate(context.Background(), dev)
	fs2, _ := newEng().Evaluate(context.Background(), dev)
	if !reflect.DeepEqual(fs1, fs2) {
		t.Fatal("evaluation output is not deterministic across runs")
	}
	// Ordering key is (evidence class, rule id): exposure sorts before posture.
	for i := 1; i < len(fs1); i++ {
		a, b := fs1[i-1], fs1[i]
		if a.EvidenceClass > b.EvidenceClass ||
			(a.EvidenceClass == b.EvidenceClass && a.RawRuleID > b.RawRuleID) {
			t.Fatalf("findings not in stable order at %d: %q/%q then %q/%q",
				i, a.EvidenceClass, a.RawRuleID, b.EvidenceClass, b.RawRuleID)
		}
	}
}

// TestPostureFailCarriesRemediationAndEvidenceRef: a tripped posture rule emits
// Fail with remediation, observed evidence, control tags, and a version-pinned
// by-reference EvidenceRef (§5c).
func TestPostureFailCarriesRemediationAndEvidenceRef(t *testing.T) {
	dev := Device{ID: "d1", Platform: "Cisco IOS-XE", TenantID: "acme"}
	eng := NewEngine(DefaultCatalog(),
		MemConfigSource{"d1": "snmp-server community public RO\n"},
		MemSeamResolver{"d1": {{SeamID: "s", SeamType: "mgmt"}}},
		WithClock(fixedClock()))
	fs, _ := eng.Evaluate(context.Background(), dev)
	f, ok := findingFor(fs, "snmp-default-community")
	if !ok {
		t.Fatal("no snmp-default-community finding")
	}
	if f.StatusID != secfindings.StatusFail || f.Severity != secfindings.SeverityCritical {
		t.Errorf("default-community = %v/%s, want Fail/critical", f.StatusID, f.Severity)
	}
	if f.Remediation == "" {
		t.Error("Fail finding has no remediation")
	}
	if f.Observed == "" {
		t.Error("Fail finding has no observed evidence")
	}
	if f.ControlID != "IA-5" || len(f.Standards) == 0 {
		t.Errorf("control tags missing: control=%q standards=%v", f.ControlID, f.Standards)
	}
	if f.EvidenceRef == nil || f.EvidenceRef.RulesetVersion != RulesetVersion {
		t.Errorf("EvidenceRef not version-pinned: %+v", f.EvidenceRef)
	}
	if f.EvidenceClass != secfindings.EvidencePosture {
		t.Errorf("posture finding evidence class = %q", f.EvidenceClass)
	}
}

// TestConfigSourceErrorPropagates: a transport error from the config source is
// returned, not swallowed (§16.1 / §5 no ignored errors).
func TestConfigSourceErrorPropagates(t *testing.T) {
	dev := Device{ID: "d1", Platform: "Cisco IOS-XE", TenantID: "acme"}
	eng := NewEngine(DefaultCatalog(), errConfigSource{}, MemSeamResolver{}, WithClock(fixedClock()))
	if _, err := eng.Evaluate(context.Background(), dev); err == nil {
		t.Fatal("expected the config-source error to propagate")
	}
}

type errConfigSource struct{}

func (errConfigSource) RunningConfig(_ context.Context, _ string) (string, bool, error) {
	return "", false, context.DeadlineExceeded
}

// TestExposureDetailWellFormed (#13): the informational detail string must be
// well-formed in EVERY clause combination. The untrusted-only + ACL case used
// to render "telnet enabled but not exposed (; restricted by ACL)" — an empty
// first clause — because the string was built by blind concatenation.
func TestExposureDetailWellFormed(t *testing.T) {
	cases := []struct {
		name   string
		cfg    string
		seams  []SeamInfo
		detail string
	}{
		{
			// Only untrusted seams exist, service ACL-restricted: no trusted
			// seam to attribute to — single-clause parenthetical.
			name:   "untrusted-only, restricted by ACL",
			cfg:    cfgTelnetWithACL,
			seams:  []SeamInfo{{SeamID: "seam-isp", SeamType: "ISP", Untrusted: true}},
			detail: "telnet enabled but not exposed (restricted by ACL)",
		},
		{
			// Trusted seam + ACL: both clauses (the pre-fix golden output —
			// pins that the rework changed nothing for the healthy paths).
			name:   "trusted seam, restricted by ACL",
			cfg:    cfgTelnetWithACL,
			seams:  []SeamInfo{{SeamID: "seam-mgmt", SeamType: "mgmt", Untrusted: false}},
			detail: "telnet enabled but not exposed (attributed to the mgmt seam; restricted by ACL)",
		},
		{
			// Trusted seam, no ACL, no untrusted seam reaches the service.
			name:   "trusted seam, no ACL",
			cfg:    cfgTelnetNoACL,
			seams:  []SeamInfo{{SeamID: "seam-mgmt", SeamType: "mgmt", Untrusted: false}},
			detail: "telnet enabled but not exposed (attributed to the mgmt seam; no untrusted seam reaches it)",
		},
	}
	dev := Device{ID: "d1", Platform: "Cisco IOS-XE", TenantID: "acme"}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			eng := NewEngine(DefaultCatalog(),
				MemConfigSource{"d1": tc.cfg},
				MemSeamResolver{"d1": tc.seams},
				WithClock(fixedClock()))
			fs, err := eng.Evaluate(context.Background(), dev)
			if err != nil {
				t.Fatal(err)
			}
			exp, ok := findingFor(fs, "exposure-telnet")
			if !ok {
				t.Fatal("no exposure-telnet finding")
			}
			if exp.StatusID != secfindings.StatusPass {
				t.Fatalf("status = %v, want Pass (informational)", exp.StatusID)
			}
			if exp.Detail != tc.detail {
				t.Errorf("detail = %q, want %q", exp.Detail, tc.detail)
			}
			for _, malformed := range []string{"(;", "( ;", "(  "} {
				if strings.Contains(exp.Detail, malformed) {
					t.Errorf("detail %q contains malformed fragment %q", exp.Detail, malformed)
				}
			}
		})
	}
}

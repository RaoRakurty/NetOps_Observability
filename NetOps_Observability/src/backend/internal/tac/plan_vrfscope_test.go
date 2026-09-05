package tac

// plan_vrfscope_test.go — the NO-REGRESSION gate for the `{vrf-scope}` rendering
// after the keyword moved OUT OF CODE AND INTO PROFILE DATA (tracker row 248).
//
// Until this change internal/tac carried its own four-armed switch on the
// dialect id ("juniper…" → `instance X`, "huawei…" → `vpn-instance X`,
// "nokia…" → bare name, everything else → `vrf X`) — a second vendor vocabulary
// beside the registry, carried on internal/vendorprofile's vocabulary-guard
// allowlist with exactly that reason. The keyword is now a field on
// vendorprofile.Dialect (`vrf_scope_keyword`), authored per vendor and resolved
// onto the DialectPlan at load from the `profile:` the plan already declares,
// so a new dialect arrives as profile data instead of a code edit.
//
// testdata/vrf_scope_parity.json was captured from the RETIRED SWITCH, before
// the move: every plan command carrying `{vrf-scope}`, rendered both with a VRF
// (`CUST-A`) and without one. Every row must still render byte-identically —
//
// FOUR ROWS WERE DELIBERATELY CHANGED, all of them PAN-OS, and they are listed
// in panosDeliberateChanges below because a golden that changes silently is not
// a gate. The retired switch had no PAN-OS arm, so PAN-OS fell into the Cisco
// default and emitted `vrf` — a token PAN-OS does not have in that position. Its
// plan templates already carry the platform's own scoping keyword
// (`logical-router <name>`, `virtual-router <name>`), so the honest authored
// value is the EMPTY keyword (bare instance name), and authoring `vrf` for
// Palo Alto to preserve the old bytes would have written a false vendor fact
// into the registry every other module reads. The change removes one invalid
// token from four commands; each is pinned here with its before and after.
//
// KNOWN, NOT FIXED HERE (reported with the row, not silently preserved): many
// plan templates spell the vendor's scoping keyword themselves AND take a
// keyword-emitting `{vrf-scope}` after it, so they render a doubled token —
// `show ip route vrf vrf CUST-A`, `show ospf neighbor instance instance CUST-A`,
// `display ip routing-table vpn-instance vpn-instance CUST-A`. That is a defect
// in the MERGED PLAN DATA (the same corpus also uses `{vrf-scope}` for an
// EIGRP instance tag and an MST instance id on NX-OS), not in the keyword, and
// no single per-vendor keyword can make both template shapes correct. This test
// preserves that rendering byte-for-byte so the data fix is a separate, visible
// change.

import (
	"encoding/json"
	"os"
	"sort"
	"strings"
	"testing"

	"netops/backend/internal/protocoldiag"
	"netops/backend/internal/vendorprofile"
)

// vrfScopeGolden is testdata/vrf_scope_parity.json: the pre-move rendering.
type vrfScopeGolden struct {
	Note string `json:"note"`
	Rows []struct {
		Dialect  string `json:"dialect"`
		Intent   string `json:"intent"`
		Template string `json:"template"`
		Scoped   string `json:"scoped"`
		Unscoped string `json:"unscoped"`
	} `json:"rows"`
}

// vrfScopeGoldenTarget is the target the golden was captured with. It must stay
// exactly this, or the goldens describe a different rendering.
var vrfScopeGoldenTarget = Target{
	Interface: "Ethernet1/1", Peer: "10.1.1.1", Prefix: "10.0.0.0/24",
	RouterID: "1.1.1.1", Area: "0", VRF: "CUST-A",
}

// panosDeliberateChanges are the only rows whose rendering CHANGED with the
// move, keyed by "<dialect>|<intent>", value = the new scoped rendering. Each
// one drops the `vrf` token the retired default arm emitted into a command that
// already carried PAN-OS's own scoping keyword.
var panosDeliberateChanges = map[string]string{
	"paloalto-panos|bgp.peer.detail":     "show advanced-routing bgp peer status peer-name 10.1.1.1 logical-router CUST-A",
	"paloalto-panos|bgp.summary":         "show advanced-routing bgp summary logical-router CUST-A",
	"paloalto-panos|route.fib.lookup":    "show routing fib virtual-router CUST-A | match 10.0.0.0/24",
	"paloalto-panos|route.logicalrouter": "show advanced-routing logical-router CUST-A",
}

func loadVRFScopeGolden(t *testing.T) vrfScopeGolden {
	t.Helper()
	b, err := os.ReadFile("testdata/vrf_scope_parity.json")
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	var g vrfScopeGolden
	if err := json.Unmarshal(b, &g); err != nil {
		t.Fatalf("decode golden: %v", err)
	}
	if len(g.Rows) == 0 {
		t.Fatal("golden carries no rows")
	}
	return g
}

// scopedCommands returns every authored command carrying {vrf-scope}, keyed by
// "<dialect>|<intent>", in the catalog as it stands.
func scopedCommands(t *testing.T, c *Catalog) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, d := range c.Dialects() {
		dp := c.plans[d]
		for intent, b := range dp.Bindings {
			if strings.Contains(b.Command, "{vrf-scope}") {
				out[d+"|"+intent] = b.Command
			}
		}
	}
	return out
}

// TestVRFScopeRenderingMatchesTheRetiredSwitch is the byte-parity gate: the
// data-driven keyword renders every authored command exactly as the retired
// dialect switch did, except the four pinned PAN-OS rows.
func TestVRFScopeRenderingMatchesTheRetiredSwitch(t *testing.T) {
	cat, err := Default()
	if err != nil {
		t.Fatalf("load catalog: %v", err)
	}
	g := loadVRFScopeGolden(t)
	unscoped := vrfScopeGoldenTarget
	unscoped.VRF = ""

	changed := 0
	for _, row := range g.Rows {
		key := row.Dialect + "|" + row.Intent
		dp, ok := cat.plans[row.Dialect]
		if !ok {
			t.Errorf("%s: the golden's dialect is no longer in the catalog", key)
			continue
		}
		b, ok := dp.Bindings[row.Intent]
		if !ok {
			t.Errorf("%s: the golden's intent is no longer bound on this dialect", key)
			continue
		}
		if b.Command != row.Template {
			t.Errorf("%s: template changed under the golden:\n  now %q\n  was %q\n"+
				"Re-capture the golden deliberately if the plan data was meant to change.",
				key, b.Command, row.Template)
			continue
		}
		wantScoped := row.Scoped
		if pinned, deliberate := panosDeliberateChanges[key]; deliberate {
			wantScoped = pinned
			changed++
		}
		if got := renderCommand(b.Command, dp.vrfScopeKeyword, vrfScopeGoldenTarget); got != wantScoped {
			t.Errorf("%s scoped rendering:\n  got  %q\n  want %q", key, got, wantScoped)
		}
		// An empty VRF must collapse the placeholder to nothing — the keyword
		// is never emitted on its own, or every unscoped command would carry a
		// dangling qualifier.
		if got := renderCommand(b.Command, dp.vrfScopeKeyword, unscoped); got != row.Unscoped {
			t.Errorf("%s unscoped rendering:\n  got  %q\n  want %q", key, got, row.Unscoped)
		}
	}
	if changed != len(panosDeliberateChanges) {
		t.Errorf("%d of the %d pinned deliberate changes were exercised — the pin list has drifted from the golden",
			changed, len(panosDeliberateChanges))
	}
	// The golden must cover the corpus exactly: a NEW scoped command has to be
	// added to it deliberately, or it would ship unproven.
	have := scopedCommands(t, cat)
	if len(have) != len(g.Rows) {
		inGolden := map[string]bool{}
		for _, row := range g.Rows {
			inGolden[row.Dialect+"|"+row.Intent] = true
		}
		missing := make([]string, 0, 4)
		for key := range have {
			if !inGolden[key] {
				missing = append(missing, key)
			}
		}
		sort.Strings(missing)
		t.Errorf("catalog carries %d {vrf-scope} commands, the golden %d; not in the golden: %v",
			len(have), len(g.Rows), missing)
	}
}

// TestVRFScopeKeywordIsTheProfileData proves the plan's keyword IS the vendor
// profile's field — no copy, no default, no second table.
func TestVRFScopeKeywordIsTheProfileData(t *testing.T) {
	cat, err := Default()
	if err != nil {
		t.Fatalf("load catalog: %v", err)
	}
	reg := vendorprofile.Default()
	for _, d := range cat.Dialects() {
		dp := cat.plans[d]
		prof, ok := reg.Lookup(dp.Profile)
		if !ok {
			t.Fatalf("%s: plan profile %q is not a registry profile", d, dp.Profile)
		}
		if dp.vrfScopeKeyword != prof.Dialect.VRFScopeKeyword {
			t.Errorf("%s: plan keyword %q, profile %s authors %q",
				d, dp.vrfScopeKeyword, dp.Profile, prof.Dialect.VRFScopeKeyword)
		}
	}
}

// TestVRFScopeKeywordsArePinnedPerDialect pins the keyword every shipped TAC
// dialect resolves to. It is the row-level statement of what moved into data:
// if a profile edit changes one of these, the command text at a device changes.
func TestVRFScopeKeywordsArePinnedPerDialect(t *testing.T) {
	want := map[string]string{
		"arista-eos":       "vrf",          // EOS: show ip ospf vrf <name>
		"cisco-asa":        "vrf",          // Cisco family keyword (the ASA plan scopes nothing)
		"cisco-ios":        "vrf",          // show ip route vrf <name>
		"cisco-iosxe":      "vrf",          // show ip route vrf <name>
		"cisco-iosxr":      "vrf",          // show route vrf <name> ipv4 unicast
		"cisco-nxos":       "vrf",          // show ip route <prefix> vrf <name>
		"fortinet-fortios": "",             // no authored FortiOS command is VRF-scoped
		"huawei-vrp":       "vpn-instance", // display ip routing-table vpn-instance <name>
		"juniper-junos":    "instance",     // show ospf neighbor instance <name>
		"nokia-srlinux":    "",             // show network-instance <name> … (keyword in the template)
		"nokia-sros":       "",             // show router <name> … (keyword in the template)
		"paloalto-panos":   "",             // logical-router / virtual-router <name> (keyword in the template)
	}
	cat, err := Default()
	if err != nil {
		t.Fatalf("load catalog: %v", err)
	}
	dialects := cat.Dialects()
	if len(dialects) != len(want) {
		t.Errorf("catalog ships %d dialects, %d are pinned here — pin the new one with its citation",
			len(dialects), len(want))
	}
	for _, d := range dialects {
		kw, pinned := want[d]
		if !pinned {
			t.Errorf("%s: dialect is not pinned in this test", d)
			continue
		}
		if got := cat.plans[d].vrfScopeKeyword; got != kw {
			t.Errorf("%s: vrf scope keyword %q, pinned %q", d, got, kw)
		}
	}
}

// TestEveryAuthoredVRFScopeKeywordIsAGateQualifier keeps the closed command
// table and the profile data in step: the gate matches a rendered scope as the
// two tokens `<qualifier> <name>`, so a keyword the qualifier set does not carry
// would render commands the gate then refuses to run.
func TestEveryAuthoredVRFScopeKeywordIsAGateQualifier(t *testing.T) {
	cat, err := Default()
	if err != nil {
		t.Fatalf("load catalog: %v", err)
	}
	for _, d := range cat.Dialects() {
		kw := cat.plans[d].vrfScopeKeyword
		if kw == "" {
			continue
		}
		if _, ok := vrfQualifiers[kw]; !ok {
			t.Errorf("%s: authored vrf scope keyword %q is not in vrfQualifiers — the gate would refuse every scoped command it renders", d, kw)
		}
	}
}

// TestGateAdmitsEveryScopedRendering is the end-to-end statement of the same
// thing: every command the plans render WITH a VRF is admitted by the closed
// table, both in its scoped and its unscoped form.
func TestGateAdmitsEveryScopedRendering(t *testing.T) {
	cat, err := Default()
	if err != nil {
		t.Fatalf("load catalog: %v", err)
	}
	gate := NewGate(cat)
	unscoped := vrfScopeGoldenTarget
	unscoped.VRF = ""
	for key, tmpl := range scopedCommands(t, cat) {
		dialect, _, _ := strings.Cut(key, "|")
		dp := cat.plans[dialect]
		for _, tgt := range []Target{vrfScopeGoldenTarget, unscoped} {
			cmd := renderCommand(tmpl, dp.vrfScopeKeyword, tgt)
			// A bounded probe whose destination did not render is reported as
			// UNBOUND by Plan and never runs, so the gate is right to refuse
			// it; it is not a rendering this test is about.
			if protocoldiag.IsProbeCommand(cmd) && protocoldiag.ValidateBoundedProbe(cmd) != nil {
				continue
			}
			if !gate.AllowsDialect(dialect, cmd) {
				t.Errorf("%s: the closed table refuses its own rendering %q", key, cmd)
			}
		}
	}
}

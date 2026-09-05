package tac

// plan_vrfscope_test.go — the gate on how a TAC plan command is scoped to a VRF.
//
// THE CONTRACT (ai/tac/README.md §2 "The VRF-scoping contract"):
//
//   {vrf-scope}  renders `<keyword> <name>`, where the keyword is the vendor's
//                own scoping word read from vendorprofile.Dialect.VRFScopeKeyword
//                (`vrf`, `instance`, `vpn-instance`; EMPTY for the vendors whose
//                CLI carries its own word, which render the bare name).
//                A TEMPLATE MUST NOT SPELL THAT KEYWORD ITSELF.
//   {vrf-name}   renders the SAME name BARE, for the commands whose CLI puts it
//                after a word that is not the scoping keyword
//                (`show ip vrf detail <name>`, `show route extensive table <name>`).
//
// Both collapse to nothing when the incident supplied no VRF, so the unscoped
// form of the command is what renders.
//
// HISTORY. Tracker row 248 moved the keyword out of a four-armed switch in
// plan.go and into profile data. Closing it exposed row 261: most merged
// templates SPELLED the keyword and then took the keyword-emitting placeholder,
// so a scoped collection rendered `show ip route vrf vrf CUST-A`,
// `show ospf neighbor instance instance CUST-A` and
// `display ip routing-table vpn-instance vpn-instance CUST-A` — commands the
// device rejects — and, on NX-OS, bent the VRF onto an EIGRP instance tag and an
// MST instance id, which are not VRFs at all. Row 261 fixed the DATA (and the
// merge script that shaped it); testdata/vrf_scope_rendering.json is the golden
// re-captured from the FIXED rendering. The retired golden it replaces
// (testdata/vrf_scope_parity.json, deleted in the same change) pinned the defect
// byte-for-byte.
//
// TO RE-CAPTURE the golden after a REVIEWED plan-data change: render every
// binding carrying {vrf-scope} or {vrf-name} with vrfScopeGoldenTarget and with
// its VRF cleared, sorted by dialect then intent, into the same JSON shape.
// Every "scoped" line in that file is a command that will be typed at someone's
// device: read them, do not bless them.

import (
	"encoding/json"
	"os"
	"sort"
	"strings"
	"testing"

	"netops/backend/internal/protocoldiag"
	"netops/backend/internal/vendorprofile"
)

// vrfScopeGolden is testdata/vrf_scope_rendering.json: the reviewed rendering
// of every VRF-scoped command, with a VRF and without one.
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

func loadVRFScopeGolden(t *testing.T) vrfScopeGolden {
	t.Helper()
	b, err := os.ReadFile("testdata/vrf_scope_rendering.json")
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

// scopedCommands returns every authored command that takes a VRF — through
// either placeholder — keyed by "<dialect>|<intent>", in the catalog as it
// stands.
func scopedCommands(t *testing.T, c *Catalog) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, d := range c.Dialects() {
		dp := c.plans[d]
		for intent, b := range dp.Bindings {
			if strings.Contains(b.Command, "{vrf-scope}") || strings.Contains(b.Command, "{vrf-name}") {
				out[d+"|"+intent] = b.Command
			}
		}
	}
	return out
}

// TestVRFScopeRenderingMatchesTheReviewedGolden is the byte gate on the corpus:
// every VRF-scoped command renders, with a VRF and without one, exactly the two
// lines a human reviewed in testdata/vrf_scope_rendering.json. A plan-data edit
// that changes a rendering fails here and must be re-reviewed and re-captured,
// because each of those lines is a command that will be typed at a device.
func TestVRFScopeRenderingMatchesTheReviewedGolden(t *testing.T) {
	cat, err := Default()
	if err != nil {
		t.Fatalf("load catalog: %v", err)
	}
	g := loadVRFScopeGolden(t)
	unscoped := vrfScopeGoldenTarget
	unscoped.VRF = ""

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
		if got := renderCommand(b.Command, dp.vrfScopeKeyword, vrfScopeGoldenTarget); got != row.Scoped {
			t.Errorf("%s scoped rendering:\n  got  %q\n  want %q", key, got, row.Scoped)
		}
		// An empty VRF must collapse the placeholder to nothing — the keyword
		// is never emitted on its own, or every unscoped command would carry a
		// dangling qualifier.
		if got := renderCommand(b.Command, dp.vrfScopeKeyword, unscoped); got != row.Unscoped {
			t.Errorf("%s unscoped rendering:\n  got  %q\n  want %q", key, got, row.Unscoped)
		}
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
		t.Errorf("catalog carries %d VRF-scoped commands, the golden %d; not in the golden: %v",
			len(have), len(g.Rows), missing)
	}
}

// TestNoTemplateSpellsTheVRFScopeKeywordItself is the row-261 guard, and it is
// the one test that fails on the DEFECT ITSELF rather than on a golden that has
// drifted: `{vrf-scope}` EMITS the dialect's scoping keyword, so a template that
// also spells a scoping word in front of it renders a doubled token
// (`show ip route vrf vrf CUST-A`) the device rejects.
//
// It checks the templates AND the renderings, because those are two different
// mistakes: a template can spell the keyword (caught by the first block), and a
// dialect can be authored a keyword that duplicates a word the template already
// carries elsewhere (caught by the second).
func TestNoTemplateSpellsTheVRFScopeKeywordItself(t *testing.T) {
	cat, err := Default()
	if err != nil {
		t.Fatalf("load catalog: %v", err)
	}
	scoped := vrfScopeGoldenTarget
	for _, d := range cat.Dialects() {
		dp := cat.plans[d]
		for _, intent := range sortedIntents(dp.Bindings) {
			b := dp.Bindings[intent]
			toks := strings.Fields(b.Command)
			for i, tok := range toks {
				if i == 0 {
					continue
				}
				prev := strings.ToLower(toks[i-1])
				if _, isQualifier := vrfQualifiers[prev]; !isQualifier {
					continue
				}
				switch tok {
				case "{vrf-scope}":
					t.Errorf("%s|%s: template spells the scoping word %q in front of {vrf-scope}, "+
						"which emits the dialect's own keyword — it renders a doubled token:\n  %q\n"+
						"Drop the literal (the placeholder supplies it), or take {vrf-name} if this "+
						"word is part of the command rather than the qualifier. See ai/tac/README.md "+
						"\"The VRF-scoping contract\".", d, intent, prev, b.Command)
				case "{vrf-name}":
					if prev == dp.vrfScopeKeyword {
						t.Errorf("%s|%s: template spells this dialect's own keyword %q in front of the "+
							"BARE {vrf-name}, so an unscoped rendering leaves the qualifier dangling: %q\n"+
							"Use {vrf-scope}, which emits the keyword and collapses with the name.",
							d, intent, prev, b.Command)
					}
				}
			}
			// The rendering itself: no two adjacent scoping words, whatever
			// produced them.
			out := strings.Fields(renderCommand(b.Command, dp.vrfScopeKeyword, scoped))
			for i := 1; i < len(out); i++ {
				_, a := vrfQualifiers[strings.ToLower(out[i-1])]
				_, bb := vrfQualifiers[strings.ToLower(out[i])]
				if a && bb {
					t.Errorf("%s|%s renders a doubled scoping token: %q", d, intent,
						strings.Join(out, " "))
					break
				}
			}
		}
	}
}

// TestTheVRFPlaceholdersNeverStandInForANonVRFInstanceID is the second half of
// row 261. An EIGRP instance tag and an MST instance id are NOT VRFs — the
// merged NX-OS templates put `{vrf-scope}` in both slots because the research
// spells each of them `<instance>`, so a VRF-scoped collection asked the device
// for EIGRP process "CUST-A". Correlix has no source for either value, so those
// commands are authored UNSCOPED; the merge script refuses `<instance>` outright
// for the same reason.
func TestTheVRFPlaceholdersNeverStandInForANonVRFInstanceID(t *testing.T) {
	// Words after which the next token is an instance id of some protocol, never
	// a VRF. Deliberately short and literal: these are the two the corpus got
	// wrong, not a guess at what a vendor might mean.
	notAVRFAfter := map[string]string{
		"eigrp": "an EIGRP instance tag",
		"mst":   "an MST instance id",
	}
	cat, err := Default()
	if err != nil {
		t.Fatalf("load catalog: %v", err)
	}
	for _, d := range cat.Dialects() {
		dp := cat.plans[d]
		for _, intent := range sortedIntents(dp.Bindings) {
			toks := strings.Fields(dp.Bindings[intent].Command)
			for i, tok := range toks {
				if i == 0 || (tok != "{vrf-scope}" && tok != "{vrf-name}") {
					continue
				}
				if what, bad := notAVRFAfter[strings.ToLower(toks[i-1])]; bad {
					t.Errorf("%s|%s: %s stands where %s belongs, and Correlix has no source for it: %q",
						d, intent, tok, what, dp.Bindings[intent].Command)
				}
			}
		}
	}
}

// TestVRFNameRendersTheBareInstanceName pins the second placeholder's whole
// contract: the same value as {vrf-scope}, with no keyword in front, collapsing
// to nothing when no VRF was supplied — on a dialect whose keyword is NOT empty,
// where the two would otherwise be indistinguishable.
func TestVRFNameRendersTheBareInstanceName(t *testing.T) {
	tgt := Target{VRF: "CUST-A"}
	for _, tc := range []struct {
		keyword, tmpl, scoped, unscoped string
	}{
		{"vrf", "show ip vrf detail {vrf-name}", "show ip vrf detail CUST-A", "show ip vrf detail"},
		{"instance", "show route extensive table {vrf-name}", "show route extensive table CUST-A", "show route extensive table"},
		{"vrf", "show ip route {vrf-scope}", "show ip route vrf CUST-A", "show ip route"},
		{"", "show network-instance {vrf-scope} interfaces", "show network-instance CUST-A interfaces", "show network-instance interfaces"},
	} {
		if got := renderCommand(tc.tmpl, tc.keyword, tgt); got != tc.scoped {
			t.Errorf("keyword %q, %q scoped:\n  got  %q\n  want %q", tc.keyword, tc.tmpl, got, tc.scoped)
		}
		if got := renderCommand(tc.tmpl, tc.keyword, Target{}); got != tc.unscoped {
			t.Errorf("keyword %q, %q unscoped:\n  got  %q\n  want %q", tc.keyword, tc.tmpl, got, tc.unscoped)
		}
	}
}

// sortedIntents keeps the two guards above deterministic: a map iteration would
// report the same corpus in a different order on every run.
func sortedIntents(bindings map[string]Binding) []string {
	out := make([]string, 0, len(bindings))
	for intent := range bindings {
		out = append(out, intent)
	}
	sort.Strings(out)
	return out
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

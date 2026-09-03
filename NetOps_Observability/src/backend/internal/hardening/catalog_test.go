package hardening

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"regexp"
	"strings"
	"testing"

	"netops/backend/internal/secfindings"
)

// ruleByID fetches a catalog rule by id (test helper).
func ruleByID(t *testing.T, cat *Catalog, id string) Rule {
	t.Helper()
	for _, r := range cat.Rules() {
		if r.ID == id {
			return r
		}
	}
	t.Fatalf("rule %q not in catalog", id)
	return Rule{}
}

// TestCatalogRulesCiscoDetection is the per-rule table: for every Cisco IOS-XE
// rule, a config that TRIPS it, a config that does NOT, and the assertion that a
// remediation snippet is present (§5e: a finding is never just "X is on").
func TestCatalogRulesCiscoDetection(t *testing.T) {
	cat := DefaultCatalog()
	cases := []struct {
		id    string
		trip  string
		clean string
	}{
		{"telnet-vty-enabled",
			"line vty 0 4\n transport input telnet\n",
			"line vty 0 4\n transport input ssh\n"},
		{"ftp-server-enabled", "ftp-server enable\n", "hostname r1\n"},
		{"tftp-server-enabled", "tftp-server flash:startup\n", "hostname r1\n"},
		{"http-server-nontls", "ip http server\n", "no ip http server\nip http secure-server\n"},
		{"ssh-not-v2", "hostname r1\n", "ip ssh version 2\n"},
		{"snmp-v1v2c-community", "snmp-server community s3cr3t RO\n", "hostname r1\n"},
		{"snmp-default-community", "snmp-server community public RO\n", "snmp-server community s3cr3t RO\n"},
		{"tcp-small-servers", "service tcp-small-servers\n", "hostname r1\n"},
		{"udp-small-servers", "service udp-small-servers\n", "hostname r1\n"},
		{"finger-service", "ip finger\n", "hostname r1\n"},
		{"bootp-server", "ip bootp server\n", "no ip bootp server\n"},
		{"pad-service", "service pad\n", "no service pad\n"},
		{"cdp-run-global", "cdp run\n", "no cdp run\n"},
		{"vty-no-access-class",
			"line vty 0 4\n transport input ssh\n",
			"line vty 0 4\n transport input ssh\n access-class MGMT-IN in\n"},
		{"snmp-no-source-acl",
			"snmp-server community s3cr3t RO\n",
			"snmp-server community s3cr3t RO SNMP-IN\n"},
		{"http-no-source-acl", "ip http server\n", "ip http server\nip http access-class MGMT-IN\n"},
		{"no-service-password-encryption", "hostname r1\n", "service password-encryption\n"},
		{"weak-enable-password", "enable password 0 cisco\n", "enable secret 5 $1$ab$xyz\n"},
		{"no-aaa-new-model", "hostname r1\n", "aaa new-model\n"},
		{"no-central-logging", "logging trap informational\n", "logging host 10.0.0.10\n"},
		{"ntp-no-authentication", "ntp server 10.0.0.20\n", "ntp server 10.0.0.20 key 1\nntp authenticate\n"},
		{"no-control-plane-protection", "hostname r1\n", "control-plane\n service-policy input COPP\n"},
	}

	seen := map[string]bool{}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.id, func(t *testing.T) {
			seen[tc.id] = true
			rule := ruleByID(t, cat, tc.id)
			b, ok := rule.Binding(VendorCiscoIOSXE)
			if !ok {
				t.Fatalf("rule %q has no Cisco IOS-XE binding", tc.id)
			}
			if strings.TrimSpace(b.Remediation) == "" {
				t.Errorf("rule %q has an empty remediation — every finding must carry a fix", tc.id)
			}
			if got := b.Detect(NewConfig(VendorCiscoIOSXE, tc.trip)); !got.Tripped {
				t.Errorf("rule %q did NOT trip on its insecure config; evidence=%q", tc.id, got.Evidence)
			}
			if got := b.Detect(NewConfig(VendorCiscoIOSXE, tc.clean)); got.Tripped {
				t.Errorf("rule %q FALSELY tripped on its secure config; evidence=%q", tc.id, got.Evidence)
			}
		})
	}

	// Guard: every Cisco-bound rule is covered by the table (no silent gaps).
	for _, r := range cat.Rules() {
		if _, ok := r.Binding(VendorCiscoIOSXE); ok && !seen[r.ID] {
			t.Errorf("Cisco-bound rule %q is not covered by the detection table", r.ID)
		}
	}
}

// TestCatalogShape asserts catalog size and hygiene: rule count in the §5e
// band, every rule tagged with a control and a severity, every binding carrying
// a remediation, and the canonical control being 800-53-shaped.
//
// The upper bound moved 30 → 40 when the fabric dialects landed. §5e specified
// a 20-30 STARTER set for one dialect; the five rules Arista EOS and Nokia SR
// Linux added (dialect_fabric.go) are controls the IOS-centric set cannot
// express at all — a model-driven management API's TLS posture, a TLS profile's
// client authentication, credential storage on a platform with no global
// encryption switch, remote AAA, and an NTP source — not padding. The band
// still exists so the catalog cannot grow unnoticed.
func TestCatalogShape(t *testing.T) {
	cat := DefaultCatalog()
	rules := cat.Rules()
	total := cat.Len()
	if total < 20 || total > 40 {
		t.Errorf("catalog has %d checks; the §5e band is 20-40", total)
	}
	validSev := map[string]bool{
		secfindings.SeverityCritical: true, secfindings.SeverityHigh: true,
		secfindings.SeverityMedium: true, secfindings.SeverityLow: true,
		secfindings.SeverityInfo: true,
	}
	ids := map[string]bool{}
	for _, r := range rules {
		if ids[r.ID] {
			t.Errorf("duplicate rule id %q", r.ID)
		}
		ids[r.ID] = true
		if len(r.Controls) == 0 {
			t.Errorf("rule %q has no control tags (§5d requires 800-53/CIS/PCI tags)", r.ID)
		}
		if !validSev[r.Severity] {
			t.Errorf("rule %q has invalid severity %q", r.ID, r.Severity)
		}
		if strings.TrimSpace(r.Intended) == "" {
			t.Errorf("rule %q has no Intended end-state", r.ID)
		}
		for v, b := range r.bindings {
			if strings.TrimSpace(b.Remediation) == "" {
				t.Errorf("rule %q vendor %q has empty remediation", r.ID, v)
			}
			if b.Detect == nil {
				t.Errorf("rule %q vendor %q has nil Detect", r.ID, v)
			}
		}
	}
	for _, p := range cat.Probes() {
		if len(p.Controls) == 0 {
			t.Errorf("probe %q has no control tags", p.ID)
		}
		for v, b := range p.bindings {
			if strings.TrimSpace(b.Remediation) == "" {
				t.Errorf("probe %q vendor %q empty remediation", p.ID, v)
			}
			if b.Enabled == nil || b.Restricted == nil {
				t.Errorf("probe %q vendor %q has nil Enabled/Restricted", p.ID, v)
			}
		}
	}
}

// TestMultiVendorBindingsDeclarative proves adding a vendor is declarative: at
// least the telnet concept is bound across all three vendors, and each non-Cisco
// binding both detects its dialect and carries a remediation.
func TestMultiVendorBindingsDeclarative(t *testing.T) {
	cat := DefaultCatalog()
	telnet := ruleByID(t, cat, "telnet-vty-enabled")
	for _, v := range []Vendor{VendorCiscoIOSXE, VendorJuniper, VendorNokia} {
		if _, ok := telnet.Binding(v); !ok {
			t.Errorf("telnet rule missing a binding for %q — multi-vendor seam not declarative", v)
		}
	}
	// Juniper set-format detection.
	jb, _ := telnet.Binding(VendorJuniper)
	if !jb.Detect(NewConfig(VendorJuniper, "set system services telnet\n")).Tripped {
		t.Error("Juniper telnet detection did not trip on `set system services telnet`")
	}
	if jb.Detect(NewConfig(VendorJuniper, "set system services ssh\n")).Tripped {
		t.Error("Juniper telnet detection falsely tripped without telnet")
	}
}

// ─── tracker 208d (ultra-review #45): no regexp is compiled per call ─────────

// TestNoRegexpIsCompiledInsideAFunctionLiteral is a STRUCTURAL guard, and it is
// structural on purpose: "this regexp is compiled once" is not observable from
// outside the closure that holds it, so a behavioural test cannot pin it.
//
// This package's contract (stated at the top of catalog.go) is that every
// pattern is compiled ONCE — either at package scope, or in a builder function
// that returns a closure capturing the compiled value. Two exposure bindings had
// drifted from it: exposure-ssh and exposure-snmp each called
// regexp.MustCompile INSIDE their `Enabled` closure, so the same two fixed
// patterns were re-parsed on every evaluation of every device. Compilation costs
// orders of magnitude more than the match it enables, and it is invisible in
// review — which is exactly why it is worth a guard rather than a comment.
//
// The rule the test enforces: a regexp.MustCompile call may not appear inside a
// function LITERAL. A literal is the thing that gets called repeatedly; a named
// builder function runs once, at catalog-build time.
func TestNoRegexpIsCompiledInsideAFunctionLiteral(t *testing.T) {
	// Parsed file-by-file rather than with parser.ParseDir: that helper is
	// deprecated (it ignores build tags when grouping files into packages), and
	// this guard only ever wanted "every non-test .go file in this directory".
	fset := token.NewFileSet()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	var files []*ast.File
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		files = append(files, f)
	}
	if len(files) == 0 {
		t.Fatal("parsed no files — the guard would pass vacuously")
	}
	compiled := 0
	for _, file := range files {
		ast.Inspect(file, func(n ast.Node) bool {
			lit, ok := n.(*ast.FuncLit)
			if !ok {
				return true
			}
			ast.Inspect(lit.Body, func(inner ast.Node) bool {
				call, ok := inner.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				ident, ok := sel.X.(*ast.Ident)
				if !ok || ident.Name != "regexp" {
					return true
				}
				if sel.Sel.Name == "MustCompile" || sel.Sel.Name == "Compile" {
					t.Errorf("%s: regexp.%s inside a function literal — the pattern is "+
						"recompiled on EVERY call. Hoist it to a package-level var or to the "+
						"enclosing builder, as the rest of this package does.",
						fset.Position(call.Pos()), sel.Sel.Name)
				}
				return true
			})
			return true
		})
		// Sanity: the guard must be scanning a file that actually holds
		// regexps, or it proves nothing.
		ast.Inspect(file, func(n ast.Node) bool {
			if call, ok := n.(*ast.CallExpr); ok {
				if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
					if id, ok := sel.X.(*ast.Ident); ok && id.Name == "regexp" {
						compiled++
					}
				}
			}
			return true
		})
	}
	if compiled == 0 {
		t.Fatal("found no regexp compilations at all — the guard is not scanning this package")
	}
}

// TestExposureProbesUseThePackageLevelMatchers pins the two hoisted patterns
// themselves: the behaviour must be exactly what the inline compiles produced.
func TestExposureProbesUseThePackageLevelMatchers(t *testing.T) {
	for _, tc := range []struct {
		name string
		re   *regexp.Regexp
		hit  []string
		miss []string
	}{
		{
			name: "ssh",
			re:   reIOSSSHEnabled,
			hit:  []string{"ip ssh version 2", "transport input ssh", "transport input telnet ssh"},
			miss: []string{"transport input telnet", "no ip ssh", "line vty 0 15"},
		},
		{
			name: "snmp",
			re:   reIOSSNMPEnabled,
			hit:  []string{"snmp-server community public RO", "snmp-server host 10.0.0.1", "snmp-server user u g v3", "snmp-server group g v3 priv"},
			miss: []string{"snmp-server enable traps", "no snmp-server", "ip snmp-server community x"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, s := range tc.hit {
				if !tc.re.MatchString(s) {
					t.Errorf("%q must match %s", s, tc.re)
				}
			}
			for _, s := range tc.miss {
				if tc.re.MatchString(s) {
					t.Errorf("%q must NOT match %s", s, tc.re)
				}
			}
		})
	}
}

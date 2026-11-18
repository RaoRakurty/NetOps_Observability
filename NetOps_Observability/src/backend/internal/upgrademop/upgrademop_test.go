// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package upgrademop_test

import (
	"regexp"
	"strings"
	"testing"

	"netops/backend/internal/protocoldiag"
	"netops/backend/internal/upgrademop"
)

// Every read-only check a procedure names passes the device gateway's read
// guard: the procedures carry no command Iris could use to change a device.
func TestEveryCheckPassesTheGatewayReadGuard(t *testing.T) {
	for _, tpl := range upgrademop.All() {
		if len(tpl.Checks()) == 0 {
			t.Errorf("%s names no read-only check at all", tpl.Name)
		}
		for _, c := range tpl.Checks() {
			if err := protocoldiag.ValidateReadOnly(c); err != nil {
				t.Errorf("%s: check %q fails the read guard: %v", tpl.Name, c, err)
			}
		}
	}
}

// The checks are the only device text: a step's own wording never carries a
// command line a device would accept as a change, and every step says the
// engineer performs it.
func TestStepsAreForAPersonAndCarryNoChangeCommand(t *testing.T) {
	changeVerb := regexp.MustCompile(`(?i)(^|[\s:])(install add|request system software|configure terminal|conf t|boot system|write mem|copy run|reload in)\b`)
	for _, tpl := range upgrademop.All() {
		if len(tpl.Steps) == 0 || len(tpl.Steps) > 30 {
			t.Errorf("%s: %d steps (a MOP carries 1-30)", tpl.Name, len(tpl.Steps))
		}
		for i, s := range tpl.Steps {
			line := s.StepLine()
			if !strings.HasPrefix(line, "Performed by the engineer: ") {
				t.Errorf("%s step %d does not say the engineer performs it: %q", tpl.Name, i+1, line)
			}
			if changeVerb.MatchString(s.Do) {
				t.Errorf("%s step %d quotes a change command in its wording: %q", tpl.Name, i+1, s.Do)
			}
			if strings.ContainsAny(s.Do, "<>`$") {
				t.Errorf("%s step %d carries a placeholder or shell character: %q", tpl.Name, i+1, s.Do)
			}
		}
	}
}

// Every procedure cites the public document it was written from, with the
// edition read and when; no image or download link appears anywhere.
func TestEveryProcedureCitesItsPublicSource(t *testing.T) {
	vendorHost := map[string]string{"Cisco": "www.cisco.com", "Juniper": "www.juniper.net", "Arista": "www.arista.com"}
	readOn := regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)
	for _, tpl := range upgrademop.All() {
		d := tpl.Doc
		if d.Title == "" || d.Version == "" || !readOn.MatchString(d.Read) {
			t.Errorf("%s: incomplete citation %+v", tpl.Name, d)
		}
		if host := vendorHost[tpl.Vendor]; !strings.HasPrefix(d.URL, "https://"+host+"/") {
			t.Errorf("%s: source %q is not on the vendor's public site %s", tpl.Name, d.URL, host)
		}
		md := tpl.SkillMD()
		for _, bad := range []string{"http://", "https://", ".bin", ".swi", ".tgz", "ftp:", "scp:"} {
			if strings.Contains(md, bad) {
				t.Errorf("%s: the runbook text carries %q — a runbook names no link or image", tpl.Name, bad)
			}
		}
		if !strings.Contains(md, "kind: mop") || !strings.Contains(md, d.Title) {
			t.Errorf("%s: the runbook text is not a MOP naming its source", tpl.Name)
		}
	}
}

func TestMatchByQuestionThenDialect(t *testing.T) {
	cases := map[string]string{
		"how do I upgrade a Catalyst 9300":          "upgrade-cisco-iosxe-install",
		"show me the IOS-XE upgrade steps":          "upgrade-cisco-iosxe-install",
		"upgrade procedure for an isr 4451":         "upgrade-cisco-iosxe-install",
		"what are the steps to upgrade nx-os":       "upgrade-cisco-nxos",
		"upgrade our nexus 9300 switches":           "upgrade-cisco-nxos",
		"how do we upgrade junos on the mx480":      "upgrade-juniper-junos",
		"juniper software upgrade procedure":        "upgrade-juniper-junos",
		"how to upgrade an arista switch":           "upgrade-arista-eos",
		"eos upgrade steps":                         "upgrade-arista-eos",
		"upgrade the catalyst 9500 in install mode": "upgrade-cisco-iosxe-install",
	}
	for q, want := range cases {
		got, ok := upgrademop.Match(q, "")
		if !ok || got.Name != want {
			t.Errorf("Match(%q) = %q, %v; want %q", q, got.Name, ok, want)
		}
	}
	if got, ok := upgrademop.Match("how do I upgrade this device", "juniper/junos"); !ok || got.Name != "upgrade-juniper-junos" {
		t.Errorf("a device's dialect picks its procedure: %q %v", got.Name, ok)
	}
	for _, q := range []string{"how do I upgrade this device", "upgrade the firewall", "how do I upgrade a palo alto"} {
		if got, ok := upgrademop.Match(q, ""); ok {
			t.Errorf("Match(%q) guessed %q; an unnamed platform is asked, never guessed", q, got.Name)
		}
	}
	if _, ok := upgrademop.Match("how do I upgrade this device", "cisco/ios_xr"); ok {
		t.Error("a dialect with no procedure must not match one")
	}
}

func TestNamesAreRunbookShaped(t *testing.T) {
	shape := regexp.MustCompile(`^[a-z][a-z0-9-]{0,47}$`)
	seen := map[string]bool{}
	for _, n := range upgrademop.Names() {
		if !shape.MatchString(n) || seen[n] {
			t.Errorf("name %q is not a unique runbook name", n)
		}
		seen[n] = true
		if _, ok := upgrademop.Get(n); !ok {
			t.Errorf("Get(%q) failed", n)
		}
	}
	if len(seen) != 4 {
		t.Errorf("%d procedures, want the four vendor families", len(seen))
	}
}

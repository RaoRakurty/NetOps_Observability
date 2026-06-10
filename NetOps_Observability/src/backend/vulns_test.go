package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCompareVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"4.33.1F", "4.33.1F", 0},
		{"4.33", "4.33.1", -1},
		{"4.33.2F", "4.33.1F", 1},
		{"15.2(4)E10", "15.2(4)E9", 1},  // numeric, not lexical: 10 > 9
		{"15.2(4)E10", "15.2(5)E1", -1}, // inner release wins over suffix
		{"15.2", "15.2e", -1},           // lettered train extends the base
		{"21.4R3-S4.9", "21.4R3-S4", 1}, // build suffix sorts above its base
		{"21.4R3-S4", "21.4R3-S10", -1}, // S4 < S10 numerically
		{"7.5.2", "7.10.1", -1},         // 5 < 10 numerically
		{"9.3(10)", "9.3(2)", 1},
		{"17.9.4", "17.9.4a", -1},
	}
	for _, c := range cases {
		if got := compareVersions(c.a, c.b); got != c.want {
			t.Errorf("compareVersions(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
		if got := compareVersions(c.b, c.a); got != -c.want {
			t.Errorf("compareVersions(%q, %q) = %d, want %d (antisymmetry)", c.b, c.a, got, -c.want)
		}
	}
}

func TestVersionMatches(t *testing.T) {
	rng := func(si, se, ei, ee string) vulnEntry {
		return vulnEntry{StartIncl: si, StartExcl: se, EndIncl: ei, EndExcl: ee}
	}
	cases := []struct {
		name string
		v    string
		e    vulnEntry
		want bool
	}{
		{"exact hit", "4.33.1F", vulnEntry{Exact: "4.33.1f"}, true},
		{"exact miss", "4.33.2F", vulnEntry{Exact: "4.33.1f"}, false},
		{"exact + numeric build suffix", "21.4R3-S4.9", vulnEntry{Exact: "21.4r3-s4"}, true},
		{"exact rejects lettered suffix", "17.9.4a", vulnEntry{Exact: "17.9.4"}, false},
		{"range end-excl inside", "7.2.8", rng("", "", "", "7.4.0"), true},
		{"range end-excl boundary", "7.4.0", rng("", "", "", "7.4.0"), false},
		{"range end-incl boundary", "7.4.0", rng("", "", "7.4.0", ""), true},
		{"range start-incl below", "7.0.1", rng("7.2.0", "", "", "7.4.0"), false},
		{"range both bounds inside", "7.2.5", rng("7.2.0", "", "", "7.4.0"), true},
		{"unconstrained row matches nothing", "7.2.5", vulnEntry{}, false},
		{"empty device version never matches", "", vulnEntry{Exact: "7.2.5"}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := versionMatches(c.v, c.e); got != c.want {
				t.Fatalf("versionMatches(%q, %+v) = %v, want %v", c.v, c.e, got, c.want)
			}
		})
	}
}

func TestNormProduct(t *testing.T) {
	cases := map[string]string{
		"ios_xe":                               "iosxe",
		"IOS-XE":                               "iosxe",
		"nx-os":                                "nxos",
		"pan-os":                               "panos",
		"sr_os":                                "sros", // alias fold
		"timos":                                "sros",
		"adaptive_security_appliance_software": "asa",
		"junos":                                "junos",
	}
	for in, want := range cases {
		if got := normProduct(in); got != want {
			t.Errorf("normProduct(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestVulnFeedLoadAndMatch(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "advisories.csv")
	csvData := `vendor,product,cve,severity,cvss,ver_start_incl,ver_start_excl,ver_end_incl,ver_end_excl,ver_exact,kev,published,summary
juniper,junos,CVE-2023-0001,critical,9.8,,,,,21.4r3-s4,1,2023-01-10,Exact-version RCE
arista,eos,CVE-2024-0002,high,8.1,4.30.0,,,4.33.2,,0,2024-02-20,Range DoS
cisco,ios_xe,CVE-2023-20198,critical,10.0,,,,17.9.4,,1,2023-10-16,Web UI privilege escalation
acme,,CVE-2024-9999,low,2.0,,,,,1.0,0,2024-01-01,Malformed row (no product) must be skipped
cisco,ios_xe,not-a-cve,high,8.0,,,,,1.0,0,2024-01-01,Malformed row (bad CVE id) must be skipped
`
	if err := os.WriteFile(path, []byte(csvData), 0o600); err != nil {
		t.Fatal(err)
	}
	f := newVulnFeed(path)
	if !f.ensure() {
		t.Fatal("ensure() = false for a valid feed file")
	}
	if entries, kev, _ := f.info(); entries != 3 || kev != 2 {
		t.Fatalf("info() = %d entries / %d kev, want 3 / 2", entries, kev)
	}

	// Exact + build suffix (JunOS build of the advisory release).
	if hits := f.match("juniper", "junos", "21.4R3-S4.9"); len(hits) != 1 || hits[0].CVE != "CVE-2023-0001" {
		t.Fatalf("junos match = %+v, want CVE-2023-0001", hits)
	}
	// Range hit, punctuation-insensitive product key (ios_xe vs ios-xe).
	if hits := f.match("cisco", "ios-xe", "17.9.3"); len(hits) != 1 || hits[0].CVE != "CVE-2023-20198" {
		t.Fatalf("ios-xe match = %+v, want CVE-2023-20198", hits)
	}
	// Above the inclusive end bound → no hit.
	if hits := f.match("cisco", "ios_xe", "17.12.1"); len(hits) != 0 {
		t.Fatalf("ios_xe 17.12.1 match = %+v, want none", hits)
	}
	// Range with both bounds.
	if hits := f.match("arista", "eos", "4.33.1F"); len(hits) != 1 || hits[0].CVE != "CVE-2024-0002" {
		t.Fatalf("eos match = %+v, want CVE-2024-0002", hits)
	}
	if hits := f.match("arista", "eos", "4.29.0F"); len(hits) != 0 {
		t.Fatalf("eos 4.29.0F match = %+v, want none", hits)
	}

	// Missing file → not provisioned.
	missing := newVulnFeed(filepath.Join(dir, "nope.csv"))
	if missing.ensure() {
		t.Fatal("ensure() = true for a missing file")
	}
}

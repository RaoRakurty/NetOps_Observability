package collectors

import (
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"netops/backend/internal/vendorprofile"
)

// vendorprofile_parity_test.go — the T9 NO-REGRESSION gate.
//
// testdata/vendorprofile_parity.json was captured from the PRE-migration code
// (the hand-written enterpriseVendor map, the vendorFromDescr switch and the
// per-vendor ParseOS regexps) before any of it moved into
// internal/vendorprofile. Every row here must still produce the byte-identical
// answer now that those three tables are declarative profile data.
//
// ONE ROW HAS BEEN DELIBERATELY RE-BASELINED (2026-09-03, defect D-06):
// ParseOS("nokia", "Nokia SR Linux srlinux 24.10.1") used to answer product
// "sros" because nokia.json declared os_parse for the SR OS product only, and
// every SR Linux box therefore resolved to a DIFFERENT operating system with an
// empty version — which made advisory assessment structurally impossible for
// the whole platform (measured live: assessed 0/2, "OS version not present in
// sysDescr", even against an unbounded sros feed row). The pre-migration answer
// was the defect, so preserving it would have pinned the bug. The row now reads
// product "srlinux"; the version stays "" for THIS string because it carries no
// SRLinux-v<version> token. Every other row is untouched, and the corpus is
// still the byte-parity gate for them.

type parityCorpus struct {
	ParseOS []struct {
		Vendor   string
		SysDescr string
		Product  string
		Version  string
	} `json:"parse_os"`
	VendorFromDescr []struct {
		SysDescr string
		Vendor   string
	} `json:"vendor_from_descr"`
	EnterpriseVendor map[string]string `json:"enterprise_vendor"`
}

func loadParityCorpus(t *testing.T) parityCorpus {
	t.Helper()
	b, err := os.ReadFile("testdata/vendorprofile_parity.json")
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	var c parityCorpus
	if err := json.Unmarshal(b, &c); err != nil {
		t.Fatalf("decode golden: %v", err)
	}
	return c
}

// TestParseOSMatchesPreMigrationGolden replays every (vendor, sysDescr) pair in
// the golden corpus — 21 vendors x 34 real-world sysDescr shapes — through the
// registry-backed ParseOS.
func TestParseOSMatchesPreMigrationGolden(t *testing.T) {
	c := loadParityCorpus(t)
	if len(c.ParseOS) == 0 {
		t.Fatal("golden corpus carries no parse_os rows")
	}
	for _, row := range c.ParseOS {
		got := ParseOS(row.Vendor, row.SysDescr)
		if got.Product != row.Product || got.Version != row.Version {
			t.Errorf("ParseOS(%q, %q) = {%q %q}, pre-migration golden {%q %q}",
				row.Vendor, row.SysDescr, got.Product, got.Version, row.Product, row.Version)
		}
	}
}

// TestVendorFromDescrMatchesPreMigrationGolden pins the sysDescr text backstop,
// INCLUDING its ordering: the golden contains the BIG-IP sysDescr that embeds
// "Linux" and must still resolve to f5.
func TestVendorFromDescrMatchesPreMigrationGolden(t *testing.T) {
	c := loadParityCorpus(t)
	if len(c.VendorFromDescr) == 0 {
		t.Fatal("golden corpus carries no vendor_from_descr rows")
	}
	for _, row := range c.VendorFromDescr {
		if got := vendorFromDescr(row.SysDescr); got != row.Vendor {
			t.Errorf("vendorFromDescr(%q) = %q, pre-migration golden %q", row.SysDescr, got, row.Vendor)
		}
	}
}

// TestEnterpriseVendorMatchesPreMigrationGolden asserts the sysObjectID
// enterprise table is unchanged in BOTH directions: every golden entry still
// resolves, and the profiles introduce no enterprise number that was not there
// before (a silently widened detection table is a behaviour change too).
func TestEnterpriseVendorMatchesPreMigrationGolden(t *testing.T) {
	c := loadParityCorpus(t)
	if len(c.EnterpriseVendor) == 0 {
		t.Fatal("golden corpus carries no enterprise_vendor rows")
	}
	reg := vendorprofile.Default()
	golden := map[int]string{}
	for k, v := range c.EnterpriseVendor {
		var ent int
		if _, err := fmt.Sscanf(k, "%d", &ent); err != nil {
			t.Fatalf("golden enterprise key %q: %v", k, err)
		}
		golden[ent] = v
		if got := vendorForEnterprise(ent); got != v {
			t.Errorf("vendorForEnterprise(%d) = %q, pre-migration golden %q", ent, got, v)
		}
	}
	declared := 0
	for _, id := range reg.VendorIDs() {
		rec, _ := reg.Vendor(id)
		for range rec.Detection.SysObjectIDPrefixes {
			declared++
		}
	}
	if declared != len(golden) {
		t.Errorf("profiles declare %d sysObjectID enterprise prefixes, pre-migration table had %d — "+
			"the migration must neither add nor drop a detection entry", declared, len(golden))
	}
}

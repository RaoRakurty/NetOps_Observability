package ticketing

// caseconn_registry_test.go — the capability matrix W1's CaseOpener list is
// built from. The assertions mirror the research's §6 table row by row, so a
// silent capability drift (declaring a create we cannot do, or losing the
// attach-only mode) fails here rather than in front of an operator.

import (
	"testing"
)

func TestDefaultRegistryMatchesTheResearchCapabilityMatrix(t *testing.T) {
	r := DefaultCaseConnectorRegistry()

	type row struct {
		vendor               string
		tier                 ConnectorTier
		create, attach, poll bool
		attachOnly           bool
		maxAttach            int64
	}
	want := map[string]row{
		"servicenow":          {"servicenow", TierITSM, true, true, true, false, SnowDefaultMaxAttachBytes},
		"jira":                {"jira", TierITSM, true, true, true, false, JiraCloudDefaultMaxAttachBytes},
		"email-arista":        {"arista", TierITSM, true, true, false, false, EmailProfileMaxBytes},
		"email-cisco":         {"cisco", TierITSM, false, true, false, true, 0},
		"cisco-cxd":           {"cisco", TierVendorAPI, false, true, false, true, 0},
		"cisco-smart-bonding": {"cisco", TierVendorAPI, true, true, true, false, 0},
		"juniper":             {"juniper", TierVendorAPI, true, true, true, false, 0},
		"portal-fortinet":     {"fortinet", TierPortal, false, false, false, false, 0},
		"portal-paloalto":     {"paloalto", TierPortal, false, false, false, false, 0},
		"portal-nokia":        {"nokia", TierPortal, false, false, false, false, 0},
		"portal-huawei":       {"huawei", TierPortal, false, false, false, false, 0},
	}
	matrix := r.Matrix()
	if len(matrix) != len(want) {
		t.Fatalf("registry has %d rows, want %d: %v", len(matrix), len(want), r.Vendors())
	}
	for _, e := range matrix {
		w, ok := want[e.ID]
		if !ok {
			t.Errorf("unexpected connector %q", e.ID)
			continue
		}
		if e.Vendor != w.vendor || e.Tier != w.tier {
			t.Errorf("%s: vendor/tier = %s/%d, want %s/%d", e.ID, e.Vendor, e.Tier, w.vendor, w.tier)
		}
		if e.Caps.Create != w.create || e.Caps.Attach != w.attach || e.Caps.Poll != w.poll {
			t.Errorf("%s: create/attach/poll = %v/%v/%v, want %v/%v/%v",
				e.ID, e.Caps.Create, e.Caps.Attach, e.Caps.Poll, w.create, w.attach, w.poll)
		}
		if e.Caps.AttachToExistingOnly != w.attachOnly {
			t.Errorf("%s: AttachToExistingOnly = %v, want %v", e.ID, e.Caps.AttachToExistingOnly, w.attachOnly)
		}
		// email-cisco's ceiling is derived from the 20 MB mailbox, so it is
		// asserted separately; 0 in the table means "not pinned here".
		if w.maxAttach != 0 && e.Caps.MaxAttachBytes != w.maxAttach {
			t.Errorf("%s: MaxAttachBytes = %d, want %d", e.ID, e.Caps.MaxAttachBytes, w.maxAttach)
		}
	}
}

func TestRegistryOrdersCiscoAttachBeforeCreate(t *testing.T) {
	r := DefaultCaseConnectorRegistry()
	got := r.ForVendor("cisco")
	if len(got) != 3 {
		t.Fatalf("cisco connectors = %d, want 3 (email attach, CXD, Smart Bonding)", len(got))
	}
	// Tier 1 (email) first, then the vendor API tier. Within the vendor tier,
	// CXD must come before Smart Bonding: attach-to-existing needs only an SR
	// number and a token, while create needs a whole onboarding project.
	if got[0].ID != "email-cisco" {
		t.Errorf("first cisco connector = %q, want the email attach path", got[0].ID)
	}
	if got[1].ID != "cisco-cxd" || got[2].ID != "cisco-smart-bonding" {
		t.Errorf("vendor-tier order = %q, %q; want CXD before Smart Bonding", got[1].ID, got[2].ID)
	}
}

func TestRegistryRefusesADuplicateID(t *testing.T) {
	r := NewCaseConnectorRegistry()
	if err := r.Register("servicenow", TierITSM, NewServiceNowCaseConnector(nil)); err != nil {
		t.Fatal(err)
	}
	if err := r.Register("servicenow", TierITSM, NewServiceNowCaseConnector(nil)); err == nil {
		t.Fatal("a duplicate id must be refused: two connectors on one id makes the matrix a lie")
	}
	if err := r.Register("x", TierITSM, nil); err == nil {
		t.Fatal("a nil connector must be refused")
	}
}

func TestRegistryCoversEveryVendorInTheStudy(t *testing.T) {
	r := DefaultCaseConnectorRegistry()
	// Every vendor the research examined must be REPRESENTED, even the ones
	// with no API — an absent vendor is indistinguishable from a broken one.
	for _, v := range []string{"cisco", "juniper", "arista", "nokia", "huawei", "fortinet", "paloalto", "servicenow", "jira"} {
		if len(r.ForVendor(v)) == 0 {
			t.Errorf("vendor %q has no connector row", v)
		}
	}
}

func TestRegistryGetIsCaseInsensitiveAndClosed(t *testing.T) {
	r := DefaultCaseConnectorRegistry()
	if _, ok := r.Get("  Cisco-CXD "); !ok {
		t.Error("lookup should normalize the id")
	}
	if _, ok := r.Get("cisco-support-case-api-v3"); ok {
		t.Error("the read-only v3 Support Case API is NOT a create path and must not be registered")
	}
}

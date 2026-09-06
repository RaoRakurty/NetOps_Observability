package discovery

// os_version_test.go — tracker 231: the inventory row must be able to CARRY the
// device's software version, whatever transport learned it.
//
// The reference lab's two SR Linux spines are hand-authored rows: the platform's
// ACL refuses the collector host, so there is no sysDescr to parse, and the row
// says `os: "SR Linux"` — a product label with no version. Advisory assessment
// needs a version or it must report the device UNASSESSED, so those two devices
// were unassessable by construction until the row could hold the version leaf.

import (
	"testing"

	"netops/backend/models"
)

// srlVersionLeaf is the version string lab spine1/spine2 actually report (read
// over gNMI /system/information 2026-09-03, byte-identical on both).
const srlVersionLeaf = "SRLinux-v26.3.2-426-g2b38957bbca"

func TestStaticInventoryCarriesTheOSVersionLeaf(t *testing.T) {
	devices, err := parseStaticDevicesYAML(`devices:
  spine1:
    address: 172.40.40.11
    vendor: nokia
    os: "SR Linux"
    os_version: "` + srlVersionLeaf + `"
    labels:
      site: dc1
  spine2:
    address: 172.40.40.12
    vendor: nokia
    os: "SR Linux"
`)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(devices) != 2 {
		t.Fatalf("parsed %d devices, want 2", len(devices))
	}
	byID := map[string]models.Device{}
	for _, d := range devices {
		byID[d.ID] = d
	}
	if got := byID["spine1"].OSVersion; got != srlVersionLeaf {
		t.Errorf("spine1 os_version = %q, want %q", got, srlVersionLeaf)
	}
	// The OS label must NOT be clobbered by the new key, and a row without the
	// key must not acquire one.
	if got := byID["spine1"].OS; got != "SR Linux" {
		t.Errorf("spine1 os = %q, want the operator's label untouched", got)
	}
	if got := byID["spine2"].OSVersion; got != "" {
		t.Errorf("spine2 acquired an os_version out of nowhere: %q", got)
	}
}

// TestMergeKeepsTheOSVersionLeaf — dedupe folds two records for one physical
// device. A version learned by one source must survive the fold, or the leaf
// would silently disappear the moment a second source reported the device.
func TestMergeKeepsTheOSVersionLeaf(t *testing.T) {
	netbox := models.Device{ID: "spine1", Name: "spine1", Source: "netbox", Vendor: "nokia", OS: "SR Linux"}
	live := models.Device{ID: "spine1", Name: "spine1", Source: "static", OSVersion: srlVersionLeaf}

	if got := mergeDevices(netbox, live).OSVersion; got != srlVersionLeaf {
		t.Errorf("netbox-base merge lost the version leaf: %q", got)
	}
	if got := mergeDevices(live, netbox).OSVersion; got != srlVersionLeaf {
		t.Errorf("other-base merge lost the version leaf: %q", got)
	}
	// A leaf already on the base is never replaced by another source's.
	held := models.Device{ID: "spine1", Source: "netbox", OSVersion: srlVersionLeaf}
	stale := models.Device{ID: "spine1", Source: "static", OSVersion: "SRLinux-v25.10.1-1-gdeadbeef"}
	if got := mergeDevices(held, stale).OSVersion; got != srlVersionLeaf {
		t.Errorf("the base's own version leaf was overwritten by another source: %q", got)
	}
}

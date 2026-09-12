// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// devicetype_parity_test.go — the PARITY GOLDEN for the move of the device-type
// inference hints into the Vendor Profile registry (tracker 221).
//
// Until this change inferDeviceType carried the whole hint table inline as a
// switch of hasAny(…) calls. The hints now live in the profile documents
// (device_type.text_hints, plus the vendor-neutral document for role words that
// belong to no vendor) and the registry evaluates them in DeviceTypeOrder. The
// device type drives what an operator SEES on the topology and which rule
// families a device is judged by, so the move has to be a move.
//
// The deleted switch is preserved HERE, verbatim, as the golden, and compared
// over a corpus built from real vendor/model/OS/name shapes.

import (
	"strings"
	"testing"

	"netops/backend/models"
)

// handWrittenInferDeviceType is the classification the switch performed,
// verbatim (minus the operator-override branch, which did not move).
func handWrittenInferDeviceType(d models.Device) string {
	h := strings.ToLower(d.Vendor + " " + d.Model + " " + d.OS + " " + d.Name)
	switch {
	case goldenHasAny(h, "fortigate", "fortios", "firewall", "asa", "palo alto", "pan-os", "panos", "checkpoint", "check point", "srx", "ngfw", "firepower", "fpr-", "ftd"):
		return "firewall"
	case goldenHasAny(h, "big-ip", "bigip", "f5 ", "load-balanc", "loadbalanc", "netscaler", "citrix adc", "avi vantage"):
		return "load-balancer"
	case goldenHasAny(h, "wlc", "wireless lan controller", "wism", "9800", "mobility express", "wireless controller"):
		return "wlc"
	case goldenHasAny(h, "aironet", "access point", "accesspoint", "air-ap", "air-cap", "meraki mr", "wifi", "wireless ap", "uap-"):
		return "ap"
	case goldenHasAny(h, "vgw", "tgw", "transit gateway", "vpn gateway", "cloud gateway", "cloudgw", "cloud-gw", "csr1000v", "c8000v cloud", "vmx cloud"):
		return "cloud-gw"
	case goldenHasAny(h, "catalyst", "nexus", "qfx", " ex2", " ex3", " ex4", "arista", " eos", "dcs-", "icx", "powerconnect", "ws-c", "switch"):
		return "switch"
	case goldenHasAny(h, "router", "asr", "isr", "ncs", " mx", "ptx", "crs", "gsr", "7750", "7250", "csr", "c8000v", "vmx", "vsr"):
		return "router"
	}
	return "generic"
}

func goldenHasAny(hay string, needles ...string) bool {
	for _, n := range needles {
		if strings.Contains(hay, n) {
			return true
		}
	}
	return false
}

// deviceTypeCorpus crosses the vendor, model, OS and name shapes discovery
// actually produces — including the ones where two hints of different types
// collide in one string, which is where an order change would show.
func deviceTypeCorpus() []models.Device {
	vendors := []string{"", "cisco", "Cisco", "arista", "juniper", "fortinet", "paloalto",
		"f5", "checkpoint", "ubiquiti", "ruckus", "dell", "nokia", "huawei", "acme"}
	models_ := []string{"", "ASR1000", "ISR4451", "Catalyst 9300", "Catalyst 9800-CL",
		"Nexus 93180YC", "WS-C3750", "DCS-7050", "MX240", "QFX5100", "EX2300",
		"BIG-IP i4800", "FortiGate 1000D", "UAP-AC-Pro", "AIR-AP2802", "PowerConnect 5548",
		"7750 SR-7", "ICX7150", "CSR1000V", "C8000V", "widget", "vSRX", "FPR-2110"}
	oses := []string{"", "IOS-XE 17.9", "NX-OS 9.3", "EOS 4.30", "Junos 21.4", "PAN-OS 10.2",
		"FortiOS 7.2", "VRP V800", "Ruckus R610 Multimedia Hotzone Wireless AP", "SomeOS"}
	names := []string{"", "edge-fw-01", "core-sw-01", "wan-r2", "aws-transit gateway",
		"dc1-wlc-01", "lb-01", "ap-lobby", "firewall-dmz"}
	var out []models.Device
	for _, v := range vendors {
		for _, m := range models_ {
			out = append(out, models.Device{Vendor: v, Model: m})
		}
	}
	for _, v := range vendors {
		for _, o := range oses {
			for _, n := range names {
				out = append(out, models.Device{Vendor: v, OS: o, Name: n})
			}
		}
	}
	for _, m := range models_ {
		for _, n := range names {
			out = append(out, models.Device{Vendor: "cisco", Model: m, Name: n})
		}
	}
	return out
}

// TestInferDeviceTypeIsIdenticalToTheHandWrittenTable — the hints moved, and
// every device is called exactly what it was called before.
func TestInferDeviceTypeIsIdenticalToTheHandWrittenTable(t *testing.T) {
	corpus := deviceTypeCorpus()
	if len(corpus) < 500 {
		t.Fatalf("only %d devices in the corpus — the comparison is not exercising the hints", len(corpus))
	}
	seen := map[string]int{}
	for _, d := range corpus {
		got := inferDeviceType(d)
		want := handWrittenInferDeviceType(d)
		if got != want {
			t.Fatalf("TYPE DRIFT for vendor=%q model=%q os=%q name=%q: registry = %q, golden = %q",
				d.Vendor, d.Model, d.OS, d.Name, got, want)
		}
		seen[got]++
	}
	// The corpus must reach every type, or "identical" proves nothing about the
	// types it never produced.
	for _, kind := range []string{"firewall", "load-balancer", "wlc", "ap", "cloud-gw", "switch", "router", "generic"} {
		if seen[kind] == 0 {
			t.Errorf("the corpus never classified a device as %q", kind)
		}
	}
	t.Logf("compared %d devices: %v", len(corpus), seen)
}

// TestInferDeviceTypeOperatorOverrideStillWins — the half that did NOT move.
func TestInferDeviceTypeOperatorOverrideStillWins(t *testing.T) {
	d := models.Device{Vendor: "cisco", Model: "ASR1000", Labels: map[string]string{"device_type": "load-balancer"}}
	if got := inferDeviceType(d); got != "load-balancer" {
		t.Errorf("operator override lost: got %q", got)
	}
	d.Labels["device_type"] = "   "
	if got := inferDeviceType(d); got != "router" {
		t.Errorf("a blank override must fall through to inference: got %q", got)
	}
}

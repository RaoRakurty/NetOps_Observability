package collectors

import (
	"os"
	"reflect"
	"testing"
)

func TestParseDottedOID(t *testing.T) {
	if got := parseDottedOID("1.3.6.1.2.1.1.3"); !reflect.DeepEqual(got, []int{1, 3, 6, 1, 2, 1, 1, 3}) {
		t.Errorf("got %v", got)
	}
	if got := parseDottedOID(" 1.3.6 "); !reflect.DeepEqual(got, []int{1, 3, 6}) {
		t.Errorf("trim: got %v", got)
	}
	if parseDottedOID("1.3.x.4") != nil {
		t.Error("non-numeric arc should be nil")
	}
	if parseDottedOID("9") != nil {
		t.Error("single arc should be nil")
	}
}

func TestSelectProfiles(t *testing.T) {
	profs := builtinProfiles()
	names := func(ps []SNMPProfile) []string {
		out := make([]string, len(ps))
		for i, p := range ps {
			out[i] = p.Name
		}
		return out
	}

	// Cisco (ent 9): generic + cisco, not juniper.
	got := names(selectProfiles(profs, 9, true))
	if !reflect.DeepEqual(got, []string{"generic", "cisco"}) {
		t.Errorf("cisco selection=%v", got)
	}
	// Juniper (ent 2636): generic + juniper.
	got = names(selectProfiles(profs, 2636, true))
	if !reflect.DeepEqual(got, []string{"generic", "juniper"}) {
		t.Errorf("juniper selection=%v", got)
	}
	// F5 (ent 3375): generic + f5 (the LB-health profile that feeds the
	// lb-target-health signatures).
	if got = names(selectProfiles(profs, 3375, true)); !reflect.DeepEqual(got, []string{"generic", "f5"}) {
		t.Errorf("f5 selection=%v", got)
	}
	// Palo Alto (ent 25461): generic + paloalto.
	if got = names(selectProfiles(profs, 25461, true)); !reflect.DeepEqual(got, []string{"generic", "paloalto"}) {
		t.Errorf("paloalto selection=%v", got)
	}
	// Vendor fleet added 2026-07-03: each selects generic + its own.
	for ent, name := range map[int]string{
		12356: "fortinet", 2620: "checkpoint", 14988: "mikrotik", 21067: "sophos",
		41112: "ubiquiti", 2011: "huawei", 1916: "extreme", 30065: "arista", 674: "dell",
	} {
		if got = names(selectProfiles(profs, ent, true)); !reflect.DeepEqual(got, []string{"generic", name}) {
			t.Errorf("%s (ent %d) selection=%v", name, ent, got)
		}
	}
	// Unknown enterprise / detection failed: generic only (the floor covers it).
	if got = names(selectProfiles(profs, 99999, true)); !reflect.DeepEqual(got, []string{"generic"}) {
		t.Errorf("unknown enterprise selection=%v", got)
	}
	if got = names(selectProfiles(profs, 0, false)); !reflect.DeepEqual(got, []string{"generic"}) {
		t.Errorf("no-detection selection=%v", got)
	}
}

func TestVendorLabel(t *testing.T) {
	if got := vendorLabel(9, true); got != "cisco" {
		t.Errorf("cisco=%q", got)
	}
	if got := vendorLabel(2636, true); got != "juniper" {
		t.Errorf("juniper=%q", got)
	}
	if got := vendorLabel(99999, true); got != "unknown" {
		t.Errorf("unknown ent=%q", got)
	}
	if got := vendorLabel(0, false); got != "generic" {
		t.Errorf("no detection=%q", got)
	}
}

func TestValueInt(t *testing.T) {
	if v := valueInt(berVal{tag: 0x02, raw: []byte{0xFF}}); v != -1 {
		t.Errorf("INTEGER -1 => %d", v)
	}
	if v := valueInt(berVal{tag: 0x42, raw: []byte{0x01, 0x00}}); v != 256 {
		t.Errorf("Gauge32 256 => %d", v)
	}
	if v := valueInt(berVal{tag: 0x46, raw: []byte{0x01, 0x00, 0x00}}); v != 65536 {
		t.Errorf("Counter64 65536 => %d", v)
	}
}

// Single-contract ownership: a gNMI-owned metric is withheld on a gNMI device but
// emitted (the floor) on an SNMP-only one. Default-closed otherwise.
func TestMetricOwnershipGate(t *testing.T) {
	bgp := SNMPMetric{Name: "device_bgp_peer_state", Owner: "gnmi", IndexLabel: "peer"}
	ospf := SNMPMetric{Name: "device_ospf_nbr_state", IndexLabel: "neighbor"} // SNMP-owned
	iface := SNMPMetric{Name: "device_if_in_octets"}                          // no owner

	gnmiDev := Target{ID: "leaf1", GNMICapable: true}
	snmpDev := Target{ID: "edge-rtr", GNMICapable: false} // agentless BGP router

	// gNMI-owned BGP: withheld on a gNMI device, emitted on an SNMP-only device.
	if !bgp.ownedElsewhere(gnmiDev) {
		t.Error("BGP must be withheld on a gNMI-capable device (gNMI owns it)")
	}
	if bgp.ownedElsewhere(snmpDev) {
		t.Error("BGP must be EMITTED on an SNMP-only device (the floor/fallback)")
	}
	// SNMP-owned + unowned families are never withheld, on either device.
	for _, m := range []SNMPMetric{ospf, iface} {
		for _, tg := range []Target{gnmiDev, snmpDev} {
			if m.ownedElsewhere(tg) {
				t.Errorf("%s must never be withheld (owner=%q) on %s", m.Name, m.Owner, tg.ID)
			}
		}
	}
	// hasTransport only knows gNMI today; an unknown transport never matches.
	if (SNMPMetric{Owner: "netconf"}).ownedElsewhere(gnmiDev) {
		t.Error("a device is not netconf-capable just by being gNMI-capable")
	}
}

func TestMetricIndexLabel(t *testing.T) {
	if got := (SNMPMetric{IndexLabel: "peer"}).indexLabel(); got != "peer" {
		t.Errorf("index label = %q, want peer", got)
	}
	if got := (SNMPMetric{}).indexLabel(); got != "index" {
		t.Errorf("default index label = %q, want index", got)
	}
}

// The JSON override carries owner + index_label through to the loaded profile.
func TestLoadProfiles_OwnerIndexLabel(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/p.json"
	js := `[{"name":"generic","enterprise":0,"metrics":[
	  {"name":"device_bgp_peer_state","oid":"1.3.6.1.2.1.15.3.1.2","table":true,"owner":"gnmi","index_label":"peer"}]}]`
	if err := os.WriteFile(path, []byte(js), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SNMP_PROFILES_FILE", path)
	for _, p := range loadProfiles() {
		if p.Name != "generic" {
			continue
		}
		for _, m := range p.Metrics {
			if m.Name == "device_bgp_peer_state" {
				if m.Owner != "gnmi" || m.IndexLabel != "peer" {
					t.Fatalf("owner/index_label not loaded: %+v", m)
				}
				return
			}
		}
	}
	t.Fatal("device_bgp_peer_state not found in loaded generic profile")
}

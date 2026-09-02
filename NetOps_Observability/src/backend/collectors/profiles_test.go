package collectors

import (
	"os"
	"reflect"
	"strings"
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
		// Wireless AP vendors (#94): registered for labelling + the generic
		// port floor; wireless metric family is a separate owner-gated design.
		14823: "aruba", 25053: "ruckus",
	} {
		if got = names(selectProfiles(profs, ent, true)); !reflect.DeepEqual(got, []string{"generic", name}) {
			t.Errorf("%s (ent %d) selection=%v", name, ent, got)
		}
	}
	// PoE port status (RFC 3621) rides the GENERIC floor — switch-side port
	// enrichment for powered endpoints (APs/phones). Table metrics, standard MIB.
	for _, p := range profs {
		if p.Name != "generic" {
			continue
		}
		poe := map[string]bool{
			"device_poe_port_detection_status": false,
			"device_poe_port_power_class":      false,
			"device_poe_pse_consumption_watts": false,
		}
		for _, m := range p.Metrics {
			if _, ok := poe[m.Name]; ok {
				poe[m.Name] = true
				if !m.Table {
					t.Errorf("%s must be a table walk", m.Name)
				}
			}
		}
		for name, found := range poe {
			if !found {
				t.Errorf("generic profile missing %s", name)
			}
		}
	}

	// F5 trunk (LAG) membership — the Port-Intelligence lane: the profile must
	// carry trunk status + configured/working member counts, all trunk-indexed
	// tables (a working<configured delta is a degraded bundle).
	for _, p := range profs {
		if p.Name != "f5" {
			continue
		}
		want := map[string]bool{
			"device_lb_trunk_status":          false,
			"device_lb_trunk_cfg_members":     false,
			"device_lb_trunk_working_members": false,
		}
		for _, m := range p.Metrics {
			if _, ok := want[m.Name]; ok {
				want[m.Name] = true
				if !m.Table || m.IndexLabel != "trunk" {
					t.Errorf("%s: Table=%v IndexLabel=%q, want table indexed by trunk", m.Name, m.Table, m.IndexLabel)
				}
			}
		}
		for name, found := range want {
			if !found {
				t.Errorf("f5 profile missing %s", name)
			}
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

// TestGenericProfileCarriesOSPFDepth pins the frontend-wave #11 "OSPF advanced"
// rows on the generic (standard-MIB) floor.
//
// Every OID is asserted as a literal against the OSPF-MIB, because the whole
// value of this profile is that the numbers are right: a transposed digit polls
// a different object and the panel fills with a plausible wrong number, which is
// worse than an empty one. The expected values below were resolved through the
// vendored MIB index (collectors/mibs/index/oididx.json), not transcribed.
//
// The index labels are part of the contract too: the three ospfAreaTable rows
// MUST be labelled {area} (the table is indexed by ospfAreaId) and the two
// ospfIfTable rows MUST keep the default {index} so they join
// device_ospf_if_state, which is labelled the same way.
func TestGenericProfileCarriesOSPFDepth(t *testing.T) {
	want := map[string]struct {
		oid   []int
		index string
	}{
		"device_ospf_lsdb_count":       {[]int{1, 3, 6, 1, 2, 1, 14, 2, 1, 7}, "area"},   // ospfAreaLsaCount
		"device_ospf_area":             {[]int{1, 3, 6, 1, 2, 1, 14, 2, 1, 10}, "area"},  // ospfAreaStatus
		"device_ospf_spf_runs_total":   {[]int{1, 3, 6, 1, 2, 1, 14, 2, 1, 4}, "area"},   // ospfSpfRuns
		"device_ospf_if_hello_seconds": {[]int{1, 3, 6, 1, 2, 1, 14, 7, 1, 9}, "index"},  // ospfIfHelloInterval
		"device_ospf_if_dead_seconds":  {[]int{1, 3, 6, 1, 2, 1, 14, 7, 1, 10}, "index"}, // ospfIfRtrDeadInterval
	}
	got := map[string]SNMPMetric{}
	for _, p := range builtinProfiles() {
		if p.Name != "generic" {
			continue
		}
		for _, m := range p.Metrics {
			if _, ok := want[m.Name]; ok {
				got[m.Name] = m
			}
		}
	}
	for name, w := range want {
		m, ok := got[name]
		if !ok {
			t.Errorf("%s missing from the generic profile", name)
			continue
		}
		if !reflect.DeepEqual(m.OID, w.oid) {
			t.Errorf("%s OID = %v, want %v", name, m.OID, w.oid)
		}
		if m.indexLabel() != w.index {
			t.Errorf("%s index label = %q, want %q", name, m.indexLabel(), w.index)
		}
		if !m.Table {
			t.Errorf("%s must be a table walk (ospfAreaTable / ospfIfTable)", name)
		}
		// SNMP-owned: gNMI carries IS-IS on this fabric, not OSPF. An owner here
		// would silently withhold the family on every gNMI-capable device.
		if m.Owner != "" {
			t.Errorf("%s must stay SNMP-owned, got owner %q", name, m.Owner)
		}
	}
}

// The OSPF-MIB has NO per-neighbour hello or dead-interval column: ospfNbrTable
// (1.3.6.1.2.1.14.10.1.x) is addr/index/rtrId/options/priority/state/events/
// retransQLen/nbmaStatus/permanence/helloSuppressed + the three restart-helper
// columns, and that is the whole table. The timers therefore come from
// ospfIfTable and are PER INTERFACE. This test exists so nobody "fixes" the
// profile later by inventing a neighbour-scoped timer OID under ospfNbrTable.
func TestNoPerNeighbourOSPFTimerIsClaimed(t *testing.T) {
	nbrTable := []int{1, 3, 6, 1, 2, 1, 14, 10}
	underNbrTable := func(oid []int) bool {
		if len(oid) < len(nbrTable) {
			return false
		}
		return reflect.DeepEqual(oid[:len(nbrTable)], nbrTable)
	}
	for _, p := range builtinProfiles() {
		for _, m := range p.Metrics {
			isTimer := strings.Contains(m.Name, "hello") || strings.Contains(m.Name, "dead")
			if isTimer && underNbrTable(m.OID) {
				t.Errorf("%s polls %v under ospfNbrTable, which has no timer column", m.Name, m.OID)
			}
		}
	}
}

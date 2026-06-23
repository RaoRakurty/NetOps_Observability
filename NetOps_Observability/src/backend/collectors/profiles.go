package collectors

import (
	"encoding/json"
	"os"
	"strconv"
	"strings"
)

// profiles.go — vendor SNMP metric profiles, the multivendor lever (the same
// idea as leading NMS platforms "profiles"). A profile is a set of OID→metric definitions
// selected by the device's sysObjectID enterprise number. The generic profile
// (Enterprise 0) applies to every device using standard MIBs; vendor profiles
// layer vendor-specific health OIDs on top. Built-ins ship in code; an operator
// can extend/override them with a JSON file (SNMP_PROFILES_FILE) — no recompile,
// no MIB compiler, exactly the curated OID-catalog approach we settled on.

// SNMPMetric is one pollable object. For a scalar the instance ".0" is appended
// at poll time; for a table the column is walked and each row labelled by index.
type SNMPMetric struct {
	Name  string
	OID   []int
	Table bool
	// Owner is the transport that OWNS this canonical metric when the device has
	// it — "gnmi" / "netconf" / "" (=SNMP, the default/universal floor). The SNMP
	// collector withholds an owned metric on a device that actually has that
	// transport (so it never double-emits a richer source's series), but still
	// polls it on devices that DON'T (the agentless fallback). The other transport's
	// canonical lane mirrors the gate (see gnmic ownership-gate). Single-contract:
	// exactly one transport per (device, family).
	Owner string
	// IndexLabel renames a table row's index label so an SNMP-owned series matches
	// the canonical contract the richer transport uses (e.g. bgpPeerTable index →
	// "peer", ospfNbrTable → "neighbor"). Empty → "index".
	IndexLabel string
}

// ownedElsewhere reports whether the SNMP collector should YIELD this metric to
// another transport on `tg` (single-contract ownership). True only when the metric
// declares a non-SNMP Owner AND the device actually has that transport — so a
// gNMI-owned family is withheld on a gNMI device but still emitted on an agentless
// one. Default-closed: no owner / SNMP owner / device lacks the transport ⇒ false.
func (m SNMPMetric) ownedElsewhere(tg Target) bool {
	return m.Owner != "" && !strings.EqualFold(m.Owner, "snmp") && tg.hasTransport(m.Owner)
}

// indexLabel is the table row's index label, defaulting to "index".
func (m SNMPMetric) indexLabel() string {
	if m.IndexLabel == "" {
		return "index"
	}
	return m.IndexLabel
}

// SNMPProfile is a named OID set matched by sysObjectID enterprise number.
type SNMPProfile struct {
	Name       string
	Enterprise int // 0 = generic (matches every device)
	Metrics    []SNMPMetric
}

// builtinProfiles is the shipped catalog. OIDs are numeric (no MIB files
// needed) and follow published standard/vendor MIBs; verify against a given
// platform and extend via the JSON override when needed.
func builtinProfiles() []SNMPProfile {
	return []SNMPProfile{
		{
			Name:       "generic",
			Enterprise: 0,
			Metrics: []SNMPMetric{
				{Name: "device_sysuptime", OID: []int{1, 3, 6, 1, 2, 1, 1, 3}},                           // sysUpTime
				{Name: "device_if_oper_status", OID: []int{1, 3, 6, 1, 2, 1, 2, 2, 1, 8}, Table: true},   // ifOperStatus
				{Name: "device_if_admin_status", OID: []int{1, 3, 6, 1, 2, 1, 2, 2, 1, 7}, Table: true},  // ifAdminStatus
				// ifLastChange (sysUpTime when the interface entered its current
				// state) — the interface flap timestamp. A change in this value IS a
				// flap; correlation can pin "this port flapped at T" against other
				// signals. VM-only (its step-on-flap shape is not a CUSUM level).
				{Name: "device_if_last_change", OID: []int{1, 3, 6, 1, 2, 1, 2, 2, 1, 9}, Table: true},
				{Name: "device_if_in_octets", OID: []int{1, 3, 6, 1, 2, 1, 31, 1, 1, 1, 6}, Table: true}, // ifHCInOctets
				{Name: "device_if_out_octets", OID: []int{1, 3, 6, 1, 2, 1, 31, 1, 1, 1, 10}, Table: true},
				// ifHighSpeed (Mbps) — denominator for the utilization panels;
				// without it inbound/outbound utilization % is empty.
				{Name: "device_if_speed", OID: []int{1, 3, 6, 1, 2, 1, 31, 1, 1, 1, 15}, Table: true},
				// Error/discard counters — the "interfaces with most errors" and
				// the four error/discard graphs read these.
				{Name: "device_if_in_errors", OID: []int{1, 3, 6, 1, 2, 1, 2, 2, 1, 14}, Table: true},    // ifInErrors
				{Name: "device_if_out_errors", OID: []int{1, 3, 6, 1, 2, 1, 2, 2, 1, 20}, Table: true},   // ifOutErrors
				{Name: "device_if_in_discards", OID: []int{1, 3, 6, 1, 2, 1, 2, 2, 1, 13}, Table: true},  // ifInDiscards
				{Name: "device_if_out_discards", OID: []int{1, 3, 6, 1, 2, 1, 2, 2, 1, 19}, Table: true}, // ifOutDiscards
				// EtherLike-MIB dot3StatsFCSErrors (RFC 3635, dot3StatsTable indexed
				// by ifIndex). The L1 fault discriminator: FCS errors point at a
				// physical-layer fault (bad cable/SFP/CRC) distinct from L2/L3 drops,
				// so correlation can separate a dirty link from a congestion drop.
				{Name: "device_if_fcs_errors", OID: []int{1, 3, 6, 1, 2, 1, 10, 7, 2, 1, 3}, Table: true},
				// HC packet-mix counters (ifXTable) — the unicast/multicast/broadcast panels.
				{Name: "device_if_in_ucast_pkts", OID: []int{1, 3, 6, 1, 2, 1, 31, 1, 1, 1, 7}, Table: true},
				{Name: "device_if_in_mcast_pkts", OID: []int{1, 3, 6, 1, 2, 1, 31, 1, 1, 1, 8}, Table: true},
				{Name: "device_if_in_bcast_pkts", OID: []int{1, 3, 6, 1, 2, 1, 31, 1, 1, 1, 9}, Table: true},
				{Name: "device_if_out_ucast_pkts", OID: []int{1, 3, 6, 1, 2, 1, 31, 1, 1, 1, 11}, Table: true},
				{Name: "device_if_out_mcast_pkts", OID: []int{1, 3, 6, 1, 2, 1, 31, 1, 1, 1, 12}, Table: true},
				{Name: "device_if_out_bcast_pkts", OID: []int{1, 3, 6, 1, 2, 1, 31, 1, 1, 1, 13}, Table: true},
				{Name: "device_cpu_percent", OID: []int{1, 3, 6, 1, 2, 1, 25, 3, 3, 1, 2}, Table: true},  // hrProcessorLoad (HOST-RESOURCES-MIB)
				{Name: "device_sensor_value", OID: []int{1, 3, 6, 1, 2, 1, 99, 1, 1, 1, 4}, Table: true}, // entPhySensorValue (ENTITY-SENSOR-MIB)
				// BGP4-MIB bgpPeerTable (index = bgpPeerRemoteAddr) — gNMI-OWNED where a
				// device has gNMI (OpenConfig carries richer BGP: per-AFI prefixes, vrf),
				// SNMP is the agentless fallback. IndexLabel "peer" matches gNMI's contract.
				{Name: "device_bgp_peer_state", OID: []int{1, 3, 6, 1, 2, 1, 15, 3, 1, 2}, Table: true, Owner: "gnmi", IndexLabel: "peer"},      // bgpPeerState
				{Name: "device_bgp_fsm_transitions", OID: []int{1, 3, 6, 1, 2, 1, 15, 3, 1, 15}, Table: true, Owner: "gnmi", IndexLabel: "peer"}, // bgpPeerFsmEstablishedTransitions
				{Name: "device_bgp_in_updates", OID: []int{1, 3, 6, 1, 2, 1, 15, 3, 1, 10}, Table: true, Owner: "gnmi", IndexLabel: "peer"},      // bgpPeerInUpdates
				// OSPF-MIB neighbor/interface state — SNMP-owned (gNMI carries IS-IS here,
				// not OSPF). IndexLabel "neighbor" is the canonical adjacency identity.
				{Name: "device_ospf_nbr_state", OID: []int{1, 3, 6, 1, 2, 1, 14, 10, 1, 6}, Table: true, IndexLabel: "neighbor"}, // ospfNbrState
				{Name: "device_ospf_if_state", OID: []int{1, 3, 6, 1, 2, 1, 14, 7, 1, 12}, Table: true},                          // ospfIfState
			},
		},
		{
			Name:       "cisco",
			Enterprise: 9,
			Metrics: []SNMPMetric{
				{Name: "device_cpu_percent", OID: []int{1, 3, 6, 1, 4, 1, 9, 9, 109, 1, 1, 1, 1, 8}, Table: true}, // cpmCPUTotal5minRev
				{Name: "device_mem_used_bytes", OID: []int{1, 3, 6, 1, 4, 1, 9, 9, 48, 1, 1, 1, 5}, Table: true},  // ciscoMemoryPoolUsed
				{Name: "device_temp_celsius", OID: []int{1, 3, 6, 1, 4, 1, 9, 9, 13, 1, 3, 1, 3}, Table: true},    // ciscoEnvMonTemperatureValue
			},
		},
		{
			Name:       "juniper",
			Enterprise: 2636,
			Metrics: []SNMPMetric{
				{Name: "device_cpu_percent", OID: []int{1, 3, 6, 1, 4, 1, 2636, 3, 1, 13, 1, 8}, Table: true},  // jnxOperatingCPU
				{Name: "device_temp_celsius", OID: []int{1, 3, 6, 1, 4, 1, 2636, 3, 1, 13, 1, 7}, Table: true}, // jnxOperatingTemp
				{Name: "device_mem_percent", OID: []int{1, 3, 6, 1, 4, 1, 2636, 3, 1, 13, 1, 11}, Table: true}, // jnxOperatingBuffer
			},
		},
	}
}

// loadProfiles returns the built-in catalog merged with an optional JSON
// override file (SNMP_PROFILES_FILE, default /config/snmp_profiles.json). A
// file profile with the same Name as a built-in replaces it; new names are
// appended. Missing/invalid file → built-ins only.
func loadProfiles() []SNMPProfile {
	profs := builtinProfiles()
	path := os.Getenv("SNMP_PROFILES_FILE")
	if path == "" {
		path = "/config/snmp_profiles.json"
	}
	// #nosec G304 G703 -- path is the operator-configured SNMP_PROFILES_FILE, not user input
	b, err := os.ReadFile(path)
	if err != nil {
		return profs
	}
	var ext []profileJSON
	if json.Unmarshal(b, &ext) != nil {
		return profs
	}
	idxByName := make(map[string]int, len(profs))
	for i, p := range profs {
		idxByName[p.Name] = i
	}
	for _, pj := range ext {
		conv := SNMPProfile{Name: pj.Name, Enterprise: pj.Enterprise}
		for _, m := range pj.Metrics {
			oid := parseDottedOID(m.OID)
			if oid == nil {
				continue
			}
			conv.Metrics = append(conv.Metrics, SNMPMetric{
				Name: m.Name, OID: oid, Table: m.Table, Owner: m.Owner, IndexLabel: m.IndexLabel})
		}
		if i, ok := idxByName[conv.Name]; ok {
			profs[i] = conv
		} else {
			idxByName[conv.Name] = len(profs)
			profs = append(profs, conv)
		}
	}
	return profs
}

type profileJSON struct {
	Name       string `json:"name"`
	Enterprise int    `json:"enterprise"`
	Metrics    []struct {
		Name       string `json:"name"`
		OID        string `json:"oid"`
		Table      bool   `json:"table"`
		Owner      string `json:"owner"`
		IndexLabel string `json:"index_label"`
	} `json:"metrics"`
}

// selectProfiles returns every profile that applies to a device: the generic
// profile always, plus the vendor profile matching the enterprise number.
func selectProfiles(profiles []SNMPProfile, enterprise int, ok bool) []SNMPProfile {
	var out []SNMPProfile
	for _, p := range profiles {
		if p.Enterprise == 0 || (ok && p.Enterprise == enterprise) {
			out = append(out, p)
		}
	}
	return out
}

// parseDottedOID converts "1.3.6.1.2.1.1.3" to arcs, or nil if malformed.
func parseDottedOID(s string) []int {
	parts := strings.Split(strings.TrimSpace(s), ".")
	out := make([]int, 0, len(parts))
	for _, p := range parts {
		if p == "" {
			continue
		}
		n, err := strconv.Atoi(p)
		if err != nil {
			return nil
		}
		out = append(out, n)
	}
	if len(out) < 2 {
		return nil
	}
	return out
}

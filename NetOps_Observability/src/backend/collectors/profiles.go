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
				// POWER-ETHERNET-MIB (RFC 3621) — PoE port status on the SWITCH side,
				// the port-intelligence lane for powered endpoints (APs, phones,
				// cameras): deliveringPower vs fault/otherFault localizes an AP outage
				// to its feed port. Rows exist only on PSE-capable switches; a walk on
				// anything else returns nothing (a cheap no-op). Index is
				// pethPsePortGroupIndex.pethPsePortIndex (group.port).
				{Name: "device_poe_port_detection_status", OID: []int{1, 3, 6, 1, 2, 1, 105, 1, 1, 1, 6}, Table: true},  // pethPsePortDetectionStatus
				{Name: "device_poe_port_power_class", OID: []int{1, 3, 6, 1, 2, 1, 105, 1, 1, 1, 10}, Table: true},      // pethPsePortPowerClassifications
				{Name: "device_poe_pse_consumption_watts", OID: []int{1, 3, 6, 1, 2, 1, 105, 1, 3, 1, 1, 4}, Table: true}, // pethMainPseConsumptionPower (per PSE group)
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
		// F5 BIG-IP (F5-BIGIP-SYSTEM/LOCAL-MIB). Load-balancer health — the
		// pool/VIP/member availability that directly feeds the lb-target-health
		// signatures (#94), plus connection + resource load. OIDs transcribed from
		// the published MIBs; verify against a live BIG-IP before production trust
		// (no F5 in the lab — known-gap policy). Scalars unless Table:true.
		{
			Name:       "f5",
			Enterprise: 3375,
			Metrics: []SNMPMetric{
				{Name: "device_lb_client_conns", OID: []int{1, 3, 6, 1, 4, 1, 3375, 2, 1, 1, 2, 1, 8}},        // sysStatClientCurConns (scalar)
				{Name: "device_lb_mem_used_bytes", OID: []int{1, 3, 6, 1, 4, 1, 3375, 2, 1, 1, 2, 1, 45}},     // sysStatMemoryUsed (scalar)
				{Name: "device_lb_pool_member_avail", OID: []int{1, 3, 6, 1, 4, 1, 3375, 2, 2, 5, 5, 2, 1, 5}, Table: true, IndexLabel: "pool_member"}, // ltmPoolMbrStatusAvailState
				{Name: "device_lb_pool_cur_conns", OID: []int{1, 3, 6, 1, 4, 1, 3375, 2, 2, 5, 2, 3, 1, 8}, Table: true, IndexLabel: "pool"},          // ltmPoolStatServerCurConns
				{Name: "device_lb_vs_avail", OID: []int{1, 3, 6, 1, 4, 1, 3375, 2, 2, 10, 13, 2, 1, 2}, Table: true, IndexLabel: "virtual_server"},    // ltmVsStatusAvailState
				// Trunk (LAG) membership — the Port-Intelligence lane (#94): a trunk
				// whose working-member count drops below its configured count is a
				// degraded port bundle even while the trunk stays "up". sysTrunkTable
				// (F5-BIGIP-SYSTEM-MIB, sysTrunks .12.1.2, indexed by trunk name).
				// Member-count column indices transcribed from the published MIB —
				// verify against a live BIG-IP MIB dump before production trust.
				{Name: "device_lb_trunk_status", OID: []int{1, 3, 6, 1, 4, 1, 3375, 2, 1, 2, 12, 1, 2, 1, 2}, Table: true, IndexLabel: "trunk"},          // sysTrunkStatus
				{Name: "device_lb_trunk_cfg_members", OID: []int{1, 3, 6, 1, 4, 1, 3375, 2, 1, 2, 12, 1, 2, 1, 4}, Table: true, IndexLabel: "trunk"},     // sysTrunkCfgMbrCount
				{Name: "device_lb_trunk_working_members", OID: []int{1, 3, 6, 1, 4, 1, 3375, 2, 1, 2, 12, 1, 2, 1, 5}, Table: true, IndexLabel: "trunk"}, // sysTrunkWorkingMbrCount
			},
		},
		// Palo Alto (PAN-COMMON-MIB). NGFW health — the session table + dataplane
		// utilization + HA state that make a firewall's own health observable
		// (complements the FortiGate onboarding + firewall signatures). CPU rides
		// the generic HOST-RESOURCES floor. Verify against a live PAN-OS device.
		{
			Name:       "paloalto",
			Enterprise: 25461,
			Metrics: []SNMPMetric{
				{Name: "device_fw_session_active", OID: []int{1, 3, 6, 1, 4, 1, 25461, 2, 1, 2, 3, 3}},   // panSessionActive (scalar)
				{Name: "device_fw_session_util_pct", OID: []int{1, 3, 6, 1, 4, 1, 25461, 2, 1, 2, 3, 1}}, // panSessionUtilization (scalar %)
				{Name: "device_fw_session_max", OID: []int{1, 3, 6, 1, 4, 1, 25461, 2, 1, 2, 3, 2}},      // panSessionMax (scalar)
				{Name: "device_fw_ha_state", OID: []int{1, 3, 6, 1, 4, 1, 25461, 2, 1, 2, 1, 11}},        // panSysHAState (scalar enum)
				{Name: "device_fw_gp_tunnels", OID: []int{1, 3, 6, 1, 4, 1, 25461, 2, 1, 2, 5, 1, 3}},    // panGPGWUtilizationActiveTunnels (scalar)
			},
		},
		// FortiGate (FORTINET-FORTIGATE-MIB). Firewall health metrics — complements
		// the existing FortiGate onboarding/syslog lane (which had detection +
		// events but no CPU/session/mem series). Verify against a live FortiOS.
		{
			Name:       "fortinet",
			Enterprise: 12356,
			Metrics: []SNMPMetric{
				{Name: "device_fw_cpu_pct", OID: []int{1, 3, 6, 1, 4, 1, 12356, 101, 4, 1, 3}},      // fgSysCpuUsage (scalar %)
				{Name: "device_fw_mem_pct", OID: []int{1, 3, 6, 1, 4, 1, 12356, 101, 4, 1, 4}},      // fgSysMemUsage (scalar %)
				{Name: "device_fw_session_active", OID: []int{1, 3, 6, 1, 4, 1, 12356, 101, 4, 1, 8}}, // fgSysSesCount (scalar)
			},
		},
		// Check Point (CHECKPOINT-MIB). Gateway health — connections + CPU + memory.
		// Verify against a live Gaia gateway.
		{
			Name:       "checkpoint",
			Enterprise: 2620,
			Metrics: []SNMPMetric{
				{Name: "device_fw_conns", OID: []int{1, 3, 6, 1, 4, 1, 2620, 1, 1, 25, 3}},        // fwNumConn (scalar)
				{Name: "device_fw_cpu_pct", OID: []int{1, 3, 6, 1, 4, 1, 2620, 1, 6, 7, 2, 7}},    // procUsage (scalar %)
				{Name: "device_fw_mem_active_bytes", OID: []int{1, 3, 6, 1, 4, 1, 2620, 1, 6, 7, 4, 6}}, // memActiveReal64 (scalar)
			},
		},
		// MikroTik RouterOS (MIKROTIK-MIB, mtxrHealth). RouterOS exposes CPU/mem via
		// the generic HOST-RESOURCES floor; the vendor niche is hardware health —
		// temperature + voltage. Verify against a live RouterOS device.
		{
			Name:       "mikrotik",
			Enterprise: 14988,
			Metrics: []SNMPMetric{
				{Name: "device_temp_celsius", OID: []int{1, 3, 6, 1, 4, 1, 14988, 1, 1, 3, 10}},   // mtxrHlTemperature (scalar, deci-C on some models)
				{Name: "device_cpu_temp_celsius", OID: []int{1, 3, 6, 1, 4, 1, 14988, 1, 1, 3, 11}}, // mtxrHlProcessorTemperature (scalar)
				{Name: "device_voltage_dv", OID: []int{1, 3, 6, 1, 4, 1, 14988, 1, 1, 3, 8}},        // mtxrHlVoltage (scalar, deci-V)
			},
		},
		// Sophos SFOS / XG firewall. SFOS SNMP is sparse — most health rides the
		// generic IF-MIB/HOST-RESOURCES floor; the identifiable vendor scalars are
		// service/HA-oriented. Registered so Sophos devices are LABELLED (not
		// "unknown") and pick up the floor; extend with SFOS OIDs once verified on
		// a live device (their MIB coverage varies by SFOS version).
		{
			Name:       "sophos",
			Enterprise: 21067,
			Metrics:    []SNMPMetric{
				// SFOS exposes little beyond standard MIBs; the generic profile
				// (also selected) supplies interfaces/CPU/inventory. Left minimal on
				// purpose rather than guessing OIDs that may not exist.
			},
		},
		// Ubiquiti (EdgeRouter/EdgeSwitch/UniFi). EdgeOS is Vyatta-derived and
		// speaks mostly standard MIBs; UniFi health lives in the controller, not
		// device SNMP. Registered for LABELLING + the generic floor; a rich profile
		// would target the controller API, not device OIDs (a separate connector).
		{
			Name:       "ubiquiti",
			Enterprise: 41112,
			Metrics:    []SNMPMetric{},
		},
		// Aruba Networks (wireless: IAP/campus APs + mobility controllers, ent
		// 14823). Registered for LABELLING + the generic IF-MIB/HOST-RESOURCES
		// floor (port intelligence #94: an AP's wired uplink port renders like
		// any other port). Wireless-side metrics (clients, RF/radio health,
		// roaming) are a SEPARATE metric family under owner design — do not add
		// them here.
		{
			Name:       "aruba",
			Enterprise: 14823,
			Metrics:    []SNMPMetric{},
		},
		// Ruckus Wireless (APs + ZoneDirector/SmartZone, ent 25053). Registered
		// for LABELLING + the generic floor, same rationale as Aruba: port-level
		// visibility now, wireless metric family deferred to the owner's design.
		{
			Name:       "ruckus",
			Enterprise: 25053,
			Metrics:    []SNMPMetric{},
		},
		// Huawei VRP (HUAWEI-ENTITY-EXTENT-MIB, hwEntityStateTable). Per-entity
		// CPU / memory / temperature indexed by entPhysicalIndex. Verify against a
		// live VRP device (CE/NE/AR lines vary).
		{
			Name:       "huawei",
			Enterprise: 2011,
			Metrics: []SNMPMetric{
				{Name: "device_cpu_percent", OID: []int{1, 3, 6, 1, 4, 1, 2011, 5, 25, 31, 1, 1, 1, 1, 5}, Table: true},  // hwEntityCpuUsage
				{Name: "device_mem_percent", OID: []int{1, 3, 6, 1, 4, 1, 2011, 5, 25, 31, 1, 1, 1, 1, 7}, Table: true},  // hwEntityMemUsage
				{Name: "device_temp_celsius", OID: []int{1, 3, 6, 1, 4, 1, 2011, 5, 25, 31, 1, 1, 1, 1, 11}, Table: true}, // hwEntityTemperature
			},
		},
		// Extreme EXOS (EXTREME-SYSTEM-MIB). CPU / free memory / temperature.
		// Verify against a live EXOS switch.
		{
			Name:       "extreme",
			Enterprise: 1916,
			Metrics: []SNMPMetric{
				{Name: "device_cpu_percent", OID: []int{1, 3, 6, 1, 4, 1, 1916, 1, 32, 1, 4, 1, 4}, Table: true},      // extremeCpuMonitorTotalUtilization
				{Name: "device_mem_free_kb", OID: []int{1, 3, 6, 1, 4, 1, 1916, 1, 32, 2, 2, 1, 3}, Table: true},      // extremeMemoryMonitorSystemFree
				{Name: "device_temp_celsius", OID: []int{1, 3, 6, 1, 4, 1, 1916, 1, 1, 1, 8}},                          // extremeCurrentTemperature (scalar)
			},
		},
		// Arista EOS — standard-MIB native: CPU/memory via HOST-RESOURCES and
		// temperature via ENTITY-SENSOR are ALL supplied by the generic floor
		// (hrProcessorLoad + entPhySensorValue). A dedicated profile would only
		// duplicate the floor, so this stays registered-only for labelling.
		{
			Name:       "arista",
			Enterprise: 30065,
			Metrics:    []SNMPMetric{},
		},
		// Dell — networking OS is fragmented (OS10 / OS9-Force10 / PowerConnect,
		// each a different enterprise sub-tree, and 674 also covers iDRAC servers).
		// Registered for labelling + the generic floor; a real profile must target
		// the specific Dell OS once identified (do not guess a shared OID tree).
		{
			Name:       "dell",
			Enterprise: 674,
			Metrics:    []SNMPMetric{},
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

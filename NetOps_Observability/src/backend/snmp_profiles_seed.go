// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// snmp_profiles_seed.go — built-in SNMP vendor profiles.
//
// OIDs are grounded in docs/research/snmp-vendor-profiles.md and verified against
// the source MIBs/RFCs (IF-MIB/RFC 2863, HOST-RESOURCES/RFC 2790, ENTITY-MIB/
// RFC 4133, ENTITY-SENSOR/RFC 3433, IP-MIB/RFC 4293, TCP-MIB, UPS-MIB/RFC 1628,
// Printer-MIB/RFC 3805, and each vendor's enterprise MIB). Leaves the research
// flagged as unverified are intentionally excluded so the shipped defaults are
// safe to poll as-is; operators add more via the UI.
//
// Each vendor profile is composed from shared standard-MIB blocks (every major
// vendor supports these) PLUS its enterprise-specific health OIDs, so a profile
// is a realistic 25-40 metric polling template rather than a handful.

func m(name, oid, typ, unit, desc string) SNMPMetric {
	return SNMPMetric{Name: name, OID: oid, Type: typ, Unit: unit, Description: desc}
}

// mc builds a metric carrying its source MIB and functional category, for the
// richer reference-grade profile view (MIB + Category columns).
func mc(name, oid, typ, unit, mib, cat string) SNMPMetric {
	return SNMPMetric{Name: name, OID: oid, Type: typ, Unit: unit, MIB: mib, Category: cat}
}

// paloAltoCloudGenix is a 30-OID profile for Palo Alto CloudGenix SD-WAN edges,
// combining IF-MIB + HOST-RESOURCES + UCD-SNMP/UCD-DISKIO metrics. OIDs supplied
// by the operator; tables are listed by their base/entry OID.
func paloAltoCloudGenix() SNMPProfile {
	return SNMPProfile{
		ID: "paloalto-cloudgenix", Vendor: "Palo Alto Networks — CloudGenix SD-WAN", Category: "firewall",
		SysObjectIDPrefix: "1.3.6.1.4.1.50114", Builtin: true,
		Description: "Palo Alto CloudGenix SD-WAN appliances. Combines interface, host-resources, and UCD metrics for SD-WAN edge monitoring (UCD-SNMP-MIB + UCD-DISKIO-MIB for vendor-specific CPU/memory/disk).",
		Metrics: []SNMPMetric{
			// tables (listed by base/entry OID)
			mc("ifTable", "1.3.6.1.2.1.2.2", "table", "", "IF-MIB", "Capacity"),
			mc("ifXTable", "1.3.6.1.2.1.31.1.1", "table", "", "IF-MIB", "Capacity"),
			mc("hrProcessorTable", "1.3.6.1.2.1.25.3.3", "table", "", "HOST-RESOURCES-MIB", "CPU"),
			mc("hrStorageTable", "1.3.6.1.2.1.25.2.3", "table", "", "HOST-RESOURCES-MIB", "Memory"),
			mc("dskTable", "1.3.6.1.4.1.2021.9.1", "table", "", "UCD-SNMP-MIB", "Memory"),
			mc("diskIOTable", "1.3.6.1.4.1.2021.13.15.1.1", "table", "", "UCD-DISKIO-MIB", "Utilization"),
			// host-resources scalars
			mc("ifNumber", "1.3.6.1.2.1.2.1.0", "gauge", "count", "IF-MIB", "System"),
			mc("hrSystemUptime", "1.3.6.1.2.1.25.1.1.0", "gauge", "timeticks", "HOST-RESOURCES-MIB", "System"),
			mc("hrSystemNumUsers", "1.3.6.1.2.1.25.1.5.0", "gauge", "count", "HOST-RESOURCES-MIB", "System"),
			mc("hrSystemProcesses", "1.3.6.1.2.1.25.1.6.0", "gauge", "count", "HOST-RESOURCES-MIB", "System"),
			mc("hrSystemMaxProcesses", "1.3.6.1.2.1.25.1.7.0", "gauge", "count", "HOST-RESOURCES-MIB", "System"),
			// UCD memory
			mc("memory.total", "1.3.6.1.4.1.2021.4.5.0", "gauge", "KB", "UCD-SNMP-MIB", "Memory"),
			mc("memory.free", "1.3.6.1.4.1.2021.4.6.0", "gauge", "KB", "UCD-SNMP-MIB", "Memory"),
			mc("ucd.memTotalSwap", "1.3.6.1.4.1.2021.4.3.0", "gauge", "KB", "UCD-SNMP-MIB", "Memory"),
			mc("ucd.memAvailSwap", "1.3.6.1.4.1.2021.4.4.0", "gauge", "KB", "UCD-SNMP-MIB", "Memory"),
			mc("ucd.memTotalFree", "1.3.6.1.4.1.2021.4.11.0", "gauge", "KB", "UCD-SNMP-MIB", "Memory"),
			mc("ucd.memMinimumSwap", "1.3.6.1.4.1.2021.4.12.0", "gauge", "KB", "UCD-SNMP-MIB", "Memory"),
			mc("ucd.memShared", "1.3.6.1.4.1.2021.4.13.0", "gauge", "KB", "UCD-SNMP-MIB", "Memory"),
			mc("ucd.memBuffer", "1.3.6.1.4.1.2021.4.14.0", "gauge", "KB", "UCD-SNMP-MIB", "Memory"),
			mc("ucd.memCached", "1.3.6.1.4.1.2021.4.15.0", "gauge", "KB", "UCD-SNMP-MIB", "Memory"),
			// UCD CPU
			mc("cpu.usage", "1.3.6.1.4.1.2021.10.1.5.1", "gauge", "%", "UCD-SNMP-MIB", "CPU"),
			mc("ucd.ssCpuUser", "1.3.6.1.4.1.2021.11.9.0", "gauge", "%", "UCD-SNMP-MIB", "CPU"),
			mc("ucd.ssCpuSystem", "1.3.6.1.4.1.2021.11.10.0", "gauge", "%", "UCD-SNMP-MIB", "CPU"),
			mc("ucd.ssCpuIdle", "1.3.6.1.4.1.2021.11.11.0", "gauge", "%", "UCD-SNMP-MIB", "CPU"),
			mc("ucd.ssCpuRawUser", "1.3.6.1.4.1.2021.11.50.0", "counter", "ticks", "UCD-SNMP-MIB", "CPU"),
			mc("ucd.ssCpuRawNice", "1.3.6.1.4.1.2021.11.51.0", "counter", "ticks", "UCD-SNMP-MIB", "CPU"),
			mc("ucd.ssCpuRawSystem", "1.3.6.1.4.1.2021.11.52.0", "counter", "ticks", "UCD-SNMP-MIB", "CPU"),
			mc("ucd.ssCpuRawIdle", "1.3.6.1.4.1.2021.11.53.0", "counter", "ticks", "UCD-SNMP-MIB", "CPU"),
			mc("ucd.ssCpuRawWait", "1.3.6.1.4.1.2021.11.54.0", "counter", "ticks", "UCD-SNMP-MIB", "CPU"),
			mc("ucd.ssCpuRawKernel", "1.3.6.1.4.1.2021.11.55.0", "counter", "ticks", "UCD-SNMP-MIB", "CPU"),
			mc("ucd.ssCpuRawInterrupt", "1.3.6.1.4.1.2021.11.56.0", "counter", "ticks", "UCD-SNMP-MIB", "CPU"),
		},
	}
}

// ---- shared standard-MIB blocks ----

func blkSystem() []SNMPMetric {
	return []SNMPMetric{
		m("sysDescr", "1.3.6.1.2.1.1.1.0", "string", "", "Vendor/OS/version banner"),
		m("sysObjectID", "1.3.6.1.2.1.1.2.0", "string", "", "Vendor/model fingerprint"),
		m("sysUpTime", "1.3.6.1.2.1.1.3.0", "gauge", "timeticks", "Uptime since reboot"),
		m("sysName", "1.3.6.1.2.1.1.5.0", "string", "", "Hostname"),
		m("sysLocation", "1.3.6.1.2.1.1.6.0", "string", "", "Location"),
		m("sysContact", "1.3.6.1.2.1.1.4.0", "string", "", "Contact"),
	}
}

func blkInterface() []SNMPMetric {
	return []SNMPMetric{
		m("ifName", "1.3.6.1.2.1.31.1.1.1.1", "string", "", "Interface short name"),
		m("ifAlias", "1.3.6.1.2.1.31.1.1.1.18", "string", "", "Interface description"),
		m("ifOperStatus", "1.3.6.1.2.1.2.2.1.8", "enum", "", "Operational status"),
		m("ifAdminStatus", "1.3.6.1.2.1.2.2.1.7", "enum", "", "Admin status"),
		m("ifMtu", "1.3.6.1.2.1.2.2.1.4", "gauge", "bytes", "Interface MTU"), // #85 per-hop MTU
		m("ifHighSpeed", "1.3.6.1.2.1.31.1.1.1.15", "gauge", "Mbps", "Interface speed"),
		m("ifHCInOctets", "1.3.6.1.2.1.31.1.1.1.6", "counter", "bytes", "64-bit ingress bytes"),
		m("ifHCOutOctets", "1.3.6.1.2.1.31.1.1.1.10", "counter", "bytes", "64-bit egress bytes"),
		m("ifHCInUcastPkts", "1.3.6.1.2.1.31.1.1.1.7", "counter", "packets", "64-bit ingress unicast"),
		m("ifHCOutUcastPkts", "1.3.6.1.2.1.31.1.1.1.11", "counter", "packets", "64-bit egress unicast"),
		m("ifInErrors", "1.3.6.1.2.1.2.2.1.14", "counter", "packets", "Ingress errors"),
		m("ifOutErrors", "1.3.6.1.2.1.2.2.1.20", "counter", "packets", "Egress errors"),
		m("ifInDiscards", "1.3.6.1.2.1.2.2.1.13", "counter", "packets", "Ingress discards"),
		m("ifOutDiscards", "1.3.6.1.2.1.2.2.1.19", "counter", "packets", "Egress discards"),
	}
}

func blkEntity() []SNMPMetric {
	return []SNMPMetric{
		m("entPhysicalDescr", "1.3.6.1.2.1.47.1.1.1.1.2", "string", "", "Component description"),
		m("entPhysicalName", "1.3.6.1.2.1.47.1.1.1.1.7", "string", "", "Component name"),
		m("entPhysicalSerialNum", "1.3.6.1.2.1.47.1.1.1.1.11", "string", "", "Serial number"),
		m("entPhysicalModelName", "1.3.6.1.2.1.47.1.1.1.1.13", "string", "", "Model name"),
		m("entPhySensorValue", "1.3.6.1.2.1.99.1.1.1.4", "gauge", "", "Generic sensor reading (temp/volt/rpm)"),
		m("entPhySensorOperStatus", "1.3.6.1.2.1.99.1.1.1.5", "enum", "", "Sensor operational status"),
	}
}

func blkL3() []SNMPMetric {
	return []SNMPMetric{
		m("ipForwarding", "1.3.6.1.2.1.4.1.0", "enum", "", "IP forwarding enabled"),
		m("ipInReceives", "1.3.6.1.2.1.4.3.0", "counter", "datagrams", "IP datagrams received"),
		m("ipInHdrErrors", "1.3.6.1.2.1.4.4.0", "counter", "datagrams", "IP header errors"),
		m("ipInDiscards", "1.3.6.1.2.1.4.8.0", "counter", "datagrams", "IP input discards"),
		m("ipOutDiscards", "1.3.6.1.2.1.4.11.0", "counter", "datagrams", "IP output discards"),
		m("tcpCurrEstab", "1.3.6.1.2.1.6.9.0", "gauge", "connections", "Established TCP connections"),
		m("tcpActiveOpens", "1.3.6.1.2.1.6.5.0", "counter", "connections", "TCP active opens"),
		m("tcpRetransSegs", "1.3.6.1.2.1.6.12.0", "counter", "segments", "TCP retransmitted segments"),
	}
}

func blkHost() []SNMPMetric {
	return []SNMPMetric{
		m("hrProcessorLoad", "1.3.6.1.2.1.25.3.3.1.2", "gauge", "%", "Per-core CPU load (average the walk)"),
		m("hrMemorySize", "1.3.6.1.2.1.25.2.2.0", "gauge", "KB", "Total RAM"),
		m("hrStorageSize", "1.3.6.1.2.1.25.2.3.1.5", "gauge", "units", "Storage size (× alloc unit)"),
		m("hrStorageUsed", "1.3.6.1.2.1.25.2.3.1.6", "gauge", "units", "Storage used (× alloc unit)"),
		m("hrSystemProcesses", "1.3.6.1.2.1.25.1.6.0", "gauge", "count", "Running processes"),
		m("hrSystemNumUsers", "1.3.6.1.2.1.25.1.5.0", "gauge", "count", "Logged-in users"),
	}
}

// std composes the common standard-MIB blocks shared by routers/switches/
// firewalls (system + interfaces + entity inventory/sensors + L3 stats).
func std(extra ...[]SNMPMetric) []SNMPMetric {
	out := append([]SNMPMetric{}, blkSystem()...)
	out = append(out, blkInterface()...)
	out = append(out, blkEntity()...)
	out = append(out, blkL3()...)
	for _, e := range extra {
		out = append(out, e...)
	}
	return out
}

func builtinSNMPProfiles() []SNMPProfile {
	return []SNMPProfile{
		// ---- universal standard MIBs (focused reference profiles) ----
		{ID: "universal-system", Vendor: "Universal — System (SNMPv2-MIB)", Category: "universal", Builtin: true, Metrics: blkSystem()},
		{ID: "universal-interface", Vendor: "Universal — Interfaces (IF-MIB)", Category: "universal", Builtin: true, Metrics: blkInterface()},
		{ID: "universal-host", Vendor: "Universal — Host Resources", Category: "server", Builtin: true,
			Metrics: append(append([]SNMPMetric{}, blkSystem()...), blkHost()...)},
		{ID: "universal-l3", Vendor: "Universal — L3 (IP/TCP)", Category: "universal", Builtin: true, Metrics: blkL3()},

		// ---- routers / switches ----
		{ID: "cisco-ios", Vendor: "Cisco IOS / IOS-XE", Category: "router_switch", SysObjectIDPrefix: "1.3.6.1.4.1.9.1", Builtin: true,
			Metrics: std([]SNMPMetric{
				m("cpmCPUTotal5minRev", "1.3.6.1.4.1.9.9.109.1.1.1.1.8", "gauge", "%", "CPU 5-min average"),
				m("cpmCPUTotal1minRev", "1.3.6.1.4.1.9.9.109.1.1.1.1.7", "gauge", "%", "CPU 1-min average"),
				m("cpmCPUMemoryUsed", "1.3.6.1.4.1.9.9.109.1.1.1.1.12", "gauge", "KB", "Processor memory used"),
				m("ciscoMemoryPoolUsed", "1.3.6.1.4.1.9.9.48.1.1.1.5", "gauge", "bytes", "Memory pool used"),
				m("ciscoMemoryPoolFree", "1.3.6.1.4.1.9.9.48.1.1.1.6", "gauge", "bytes", "Memory pool free"),
				m("ciscoEnvMonTemperatureValue", "1.3.6.1.4.1.9.9.13.1.3.1.3", "gauge", "C", "Temperature"),
				m("ciscoEnvMonTemperatureState", "1.3.6.1.4.1.9.9.13.1.3.1.6", "enum", "", "Temperature state"),
				m("ciscoEnvMonFanState", "1.3.6.1.4.1.9.9.13.1.4.1.3", "enum", "", "Fan health"),
				m("ciscoEnvMonSupplyState", "1.3.6.1.4.1.9.9.13.1.5.1.3", "enum", "", "PSU health"),
			})},
		{ID: "juniper-junos", Vendor: "Juniper JUNOS", Category: "router_switch", SysObjectIDPrefix: "1.3.6.1.4.1.2636", Builtin: true,
			Metrics: std([]SNMPMetric{
				m("jnxOperatingCPU", "1.3.6.1.4.1.2636.3.1.13.1.8", "gauge", "%", "Operating entity CPU"),
				m("jnxOperatingTemp", "1.3.6.1.4.1.2636.3.1.13.1.7", "gauge", "C", "Operating entity temperature"),
				m("jnxOperatingBuffer", "1.3.6.1.4.1.2636.3.1.13.1.11", "gauge", "%", "Memory buffer utilization"),
				m("jnxOperatingState", "1.3.6.1.4.1.2636.3.1.13.1.6", "enum", "", "Entity state"),
				m("jnxOperatingDescr", "1.3.6.1.4.1.2636.3.1.13.1.5", "string", "", "Operating entity name"),
			})},
		{ID: "arista-eos", Vendor: "Arista EOS", Category: "router_switch", SysObjectIDPrefix: "1.3.6.1.4.1.30065", Builtin: true,
			Metrics: std(blkHost())},
		{ID: "huawei", Vendor: "Huawei", Category: "router_switch", SysObjectIDPrefix: "1.3.6.1.4.1.2011", Builtin: true,
			Metrics: std([]SNMPMetric{
				m("hwEntityCpuUsage", "1.3.6.1.4.1.2011.5.25.31.1.1.1.1.5", "gauge", "%", "Entity CPU usage"),
				m("hwEntityMemUsage", "1.3.6.1.4.1.2011.5.25.31.1.1.1.1.7", "gauge", "%", "Entity memory usage"),
				m("hwEntityTemperature", "1.3.6.1.4.1.2011.5.25.31.1.1.1.1.11", "gauge", "C", "Entity temperature"),
			})},
		{ID: "mikrotik", Vendor: "MikroTik RouterOS", Category: "router_switch", SysObjectIDPrefix: "1.3.6.1.4.1.14988.1", Builtin: true,
			Metrics: std(blkHost(), []SNMPMetric{
				m("mtxrHlTemperature", "1.3.6.1.4.1.14988.1.1.3.10.0", "gauge", "0.1C", "System temperature"),
				m("mtxrHlVoltage", "1.3.6.1.4.1.14988.1.1.3.8.0", "gauge", "0.1V", "Input voltage"),
			})},

		// ---- firewalls ----
		{ID: "fortinet-fortigate", Vendor: "Fortinet FortiGate", Category: "firewall", SysObjectIDPrefix: "1.3.6.1.4.1.12356.101", Builtin: true,
			Metrics: std([]SNMPMetric{
				m("fgSysCpuUsage", "1.3.6.1.4.1.12356.101.4.1.3.0", "gauge", "%", "System CPU usage"),
				m("fgSysMemUsage", "1.3.6.1.4.1.12356.101.4.1.4.0", "gauge", "%", "System memory usage"),
				m("fgSysMemCapacity", "1.3.6.1.4.1.12356.101.4.1.5.0", "gauge", "KB", "Total memory"),
				m("fgSysSesCount", "1.3.6.1.4.1.12356.101.4.1.8.0", "gauge", "sessions", "Active sessions"),
			})},
		{ID: "paloalto-panos", Vendor: "Palo Alto PAN-OS", Category: "firewall", SysObjectIDPrefix: "1.3.6.1.4.1.25461.2", Builtin: true,
			Metrics: std(blkHost(), []SNMPMetric{
				m("panSessionUtilization", "1.3.6.1.4.1.25461.2.1.2.3.1.0", "gauge", "%", "Session table utilization"),
				m("panSessionActive", "1.3.6.1.4.1.25461.2.1.2.3.3.0", "gauge", "sessions", "Active sessions"),
				m("panSessionMax", "1.3.6.1.4.1.25461.2.1.2.3.2.0", "gauge", "sessions", "Max sessions"),
			})},
		paloAltoCloudGenix(),

		// ---- load balancers ----
		// F5 BIG-IP (F5-BIGIP-SYSTEM-MIB + F5-BIGIP-LOCAL-MIB). BIG-IP serves the
		// full standard IF-MIB/ENTITY floor (std blocks cover ports/inventory);
		// the enterprise OIDs add LB health (pool/member/VIP availability,
		// connections, memory) + trunk (LAG) membership for the Port-Intelligence
		// lane. Transceiver DOM is NOT exposed via BIG-IP SNMP (tmsh/iHealth
		// only) — a known, honest gap. Verify enterprise OIDs against a live
		// BIG-IP MIB dump before production trust (no F5 in the lab).
		{ID: "f5-bigip", Vendor: "F5 BIG-IP", Category: "load_balancer", SysObjectIDPrefix: "1.3.6.1.4.1.3375", Builtin: true,
			Description: "F5 BIG-IP (LTM). Standard MIBs cover interfaces/inventory; enterprise OIDs add pool/member/virtual-server availability, client connections, memory, and trunk (LAG) membership. Transceiver DOM is not exposed via SNMP on BIG-IP.",
			Metrics: std([]SNMPMetric{
				mc("sysStatClientCurConns", "1.3.6.1.4.1.3375.2.1.1.2.1.8.0", "gauge", "connections", "F5-BIGIP-SYSTEM-MIB", "Capacity"),
				mc("sysStatMemoryTotal", "1.3.6.1.4.1.3375.2.1.1.2.1.44.0", "gauge", "bytes", "F5-BIGIP-SYSTEM-MIB", "Memory"),
				mc("sysStatMemoryUsed", "1.3.6.1.4.1.3375.2.1.1.2.1.45.0", "gauge", "bytes", "F5-BIGIP-SYSTEM-MIB", "Memory"),
				mc("sysTrunkTable", "1.3.6.1.4.1.3375.2.1.2.12.1.2", "table", "", "F5-BIGIP-SYSTEM-MIB", "Capacity"),
				mc("ltmPoolStatServerCurConns", "1.3.6.1.4.1.3375.2.2.5.2.3.1.8", "table", "connections", "F5-BIGIP-LOCAL-MIB", "Capacity"),
				mc("ltmPoolMbrStatusAvailState", "1.3.6.1.4.1.3375.2.2.5.5.2.1.5", "table", "", "F5-BIGIP-LOCAL-MIB", "System"),
				mc("ltmVsStatusAvailState", "1.3.6.1.4.1.3375.2.2.10.13.2.1.2", "table", "", "F5-BIGIP-LOCAL-MIB", "System"),
			})},

		// ---- additional switch / router / SD-WAN vendors ----
		// Standard-MIB-safe baseline (IF-MIB/ENTITY-SENSOR/HOST-RESOURCES cover
		// interfaces/CPU/mem/sensors on all three); enterprise + controller-API
		// OIDs are flagged in the description to layer in once verified on-device.
		{ID: "extreme-exos", Vendor: "Extreme EXOS / VOSS", Category: "router_switch", SysObjectIDPrefix: "1.3.6.1.4.1.1916", Builtin: true,
			Description: "Extreme Networks EXOS/VOSS. Standard MIBs cover interfaces, CPU, memory and temp/fan/PSU sensors. EXTREME-SOFTWARE-MONITOR-MIB (1.3.6.1.4.1.1916.1.32) adds enterprise CPU/mem — add via the UI once verified against the device.",
			Metrics:     std(blkHost())},
		{ID: "ubiquiti-edgeos", Vendor: "Ubiquiti EdgeOS / EdgeRouter", Category: "router_switch", SysObjectIDPrefix: "1.3.6.1.4.1.41112", Builtin: true,
			Description: "Ubiquiti EdgeOS/EdgeRouter (Vyatta/Linux base) — full HOST-RESOURCES + IF-MIB. For AirMAX/UniFi radios, UBNT-MIB wireless OIDs (signal/noise/CCQ) apply — add when targeting APs (a controller/cloud API is the richer source for UniFi).",
			Metrics:     std(blkHost())},
		{ID: "versa-flexvnf", Vendor: "Versa FlexVNF (SD-WAN / NGFW)", Category: "firewall", SysObjectIDPrefix: "1.3.6.1.4.1.42359", Builtin: true,
			Description: "Versa FlexVNF SD-WAN/NGFW box monitoring via standard MIBs. Deep SD-WAN telemetry (path SLA, traffic steering, overlay/tunnel state) is controller-API-sourced (Versa Director + Analytics), NOT box SNMP — see docs/design/multi-vendor-wifi-expansion.md.",
			Metrics:     std(blkHost())},

		// ---- wireless (identification + port floor ONLY) ----
		// Scope guard (#94): these profiles exist so APs are correctly IDENTIFIED
		// (vendor/model/serial) and their wired ports render with full IF-MIB
		// fidelity. The wireless metric family (client counts, RF/radio health,
		// roaming) is a separate owner-authored design — deliberately NOT here.
		{ID: "aruba-wireless", Vendor: "Aruba Networks (APs / mobility controllers)", Category: "wireless", SysObjectIDPrefix: "1.3.6.1.4.1.14823", Builtin: true,
			Description: "Aruba wireless (Instant/campus APs, mobility controllers). Standard MIBs cover the wired uplink ports, inventory and host resources. RF/client telemetry (AI-MON/WLSX MIBs or controller API) is a separate wireless metric family — add once that design lands.",
			Metrics:     std(blkHost())},
		{ID: "ruckus-wireless", Vendor: "Ruckus Wireless (APs / SmartZone)", Category: "wireless", SysObjectIDPrefix: "1.3.6.1.4.1.25053", Builtin: true,
			Description: "Ruckus wireless (standalone/Unleashed APs, ZoneDirector/SmartZone). Standard MIBs cover wired ports, inventory and host resources. RF/client telemetry (RUCKUS-* MIBs or SmartZone API) is a separate wireless metric family — add once that design lands.",
			Metrics:     std(blkHost())},

		// ---- servers / hosts ----
		{ID: "server-host", Vendor: "Server / Host (net-snmp, Windows)", Category: "server", Builtin: true,
			Metrics: append(append(append([]SNMPMetric{}, blkSystem()...), blkInterface()...), blkHost()...)},

		// ---- printers ----
		{ID: "printer", Vendor: "Printer (Printer-MIB)", Category: "printer", Builtin: true,
			Metrics: append(append([]SNMPMetric{}, blkSystem()...), []SNMPMetric{
				m("hrPrinterStatus", "1.3.6.1.2.1.25.3.5.1.1", "enum", "", "Printer status (idle/printing/…)"),
				m("hrDeviceStatus", "1.3.6.1.2.1.25.3.2.1.5", "enum", "", "Device status (running/warning/down)"),
				m("prtMarkerLifeCount", "1.3.6.1.2.1.43.10.2.1.4.1.1", "counter", "pages", "Lifetime page count"),
				m("prtMarkerSuppliesLevel", "1.3.6.1.2.1.43.11.1.1.9", "gauge", "units", "Toner/supply level"),
				m("prtMarkerSuppliesMaxCapacity", "1.3.6.1.2.1.43.11.1.1.8", "gauge", "units", "Supply max capacity"),
				m("prtInputCurrentLevel", "1.3.6.1.2.1.43.8.2.1.10", "gauge", "units", "Paper tray level"),
			}...)},

		// ---- UPS / power ----
		{ID: "ups", Vendor: "UPS (RFC 1628 UPS-MIB)", Category: "ups", Builtin: true,
			Metrics: append(append([]SNMPMetric{}, blkSystem()...), []SNMPMetric{
				m("upsBatteryStatus", "1.3.6.1.2.1.33.1.2.1.0", "enum", "", "Battery status (normal/low/depleted)"),
				m("upsEstimatedMinutesRemaining", "1.3.6.1.2.1.33.1.2.3.0", "gauge", "minutes", "Runtime remaining"),
				m("upsEstimatedChargeRemaining", "1.3.6.1.2.1.33.1.2.4.0", "gauge", "%", "Battery charge"),
				m("upsBatteryTemperature", "1.3.6.1.2.1.33.1.2.7.0", "gauge", "C", "Battery temperature"),
				m("upsBatteryVoltage", "1.3.6.1.2.1.33.1.2.5.0", "gauge", "0.1V", "Battery voltage"),
				m("upsInputVoltage", "1.3.6.1.2.1.33.1.3.1.3", "gauge", "V", "Input voltage per line"),
				m("upsInputFrequency", "1.3.6.1.2.1.33.1.3.1.2", "gauge", "0.1Hz", "Input frequency per line"),
				m("upsOutputSource", "1.3.6.1.2.1.33.1.4.1.0", "enum", "", "Output source (normal/battery/bypass)"),
				m("upsOutputVoltage", "1.3.6.1.2.1.33.1.4.4.1.2", "gauge", "V", "Output voltage per line"),
				m("upsOutputPercentLoad", "1.3.6.1.2.1.33.1.4.4.1.5", "gauge", "%", "Output load per line"),
				m("upsSecondsOnBattery", "1.3.6.1.2.1.33.1.2.2.0", "gauge", "seconds", "Seconds on battery"),
				m("upsAlarmsPresent", "1.3.6.1.2.1.33.1.6.1.0", "gauge", "count", "Active alarms"),
			}...)},
	}
}

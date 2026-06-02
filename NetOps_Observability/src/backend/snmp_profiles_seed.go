package main

// snmp_profiles_seed.go — built-in SNMP vendor profiles.
//
// OIDs are grounded in docs/research/snmp-vendor-profiles.md and verified against
// the source MIBs/RFCs (IF-MIB/RFC 2863, HOST-RESOURCES/RFC 2790, ENTITY-SENSOR/
// RFC 3433, UPS-MIB/RFC 1628, Printer-MIB/RFC 3805, and each vendor's enterprise
// MIB). Leaves the research flagged as unverified are intentionally excluded so
// the shipped defaults are safe to poll as-is; operators add more via the UI.

func m(name, oid, typ, unit, desc string) SNMPMetric {
	return SNMPMetric{Name: name, OID: oid, Type: typ, Unit: unit, Description: desc}
}

func builtinSNMPProfiles() []SNMPProfile {
	return []SNMPProfile{
		// ---- universal standard MIBs (apply to nearly every device) ----
		{
			ID: "universal-system", Vendor: "Universal — System (SNMPv2-MIB)", Category: "universal", Builtin: true,
			Metrics: []SNMPMetric{
				m("sysDescr", "1.3.6.1.2.1.1.1.0", "string", "", "Vendor/OS/version banner"),
				m("sysObjectID", "1.3.6.1.2.1.1.2.0", "string", "", "Vendor/model fingerprint"),
				m("sysUpTime", "1.3.6.1.2.1.1.3.0", "gauge", "timeticks", "Uptime since reboot"),
				m("sysName", "1.3.6.1.2.1.1.5.0", "string", "", "Hostname"),
				m("sysLocation", "1.3.6.1.2.1.1.6.0", "string", "", "Location"),
			},
		},
		{
			ID: "universal-interface", Vendor: "Universal — Interfaces (IF-MIB)", Category: "universal", Builtin: true,
			Metrics: []SNMPMetric{
				m("ifName", "1.3.6.1.2.1.31.1.1.1.1", "string", "", "Interface short name"),
				m("ifAlias", "1.3.6.1.2.1.31.1.1.1.18", "string", "", "Interface description"),
				m("ifOperStatus", "1.3.6.1.2.1.2.2.1.8", "enum", "", "Operational status"),
				m("ifAdminStatus", "1.3.6.1.2.1.2.2.1.7", "enum", "", "Admin status"),
				m("ifHighSpeed", "1.3.6.1.2.1.31.1.1.1.15", "gauge", "Mbps", "Interface speed"),
				m("ifHCInOctets", "1.3.6.1.2.1.31.1.1.1.6", "counter", "bytes", "64-bit ingress bytes"),
				m("ifHCOutOctets", "1.3.6.1.2.1.31.1.1.1.10", "counter", "bytes", "64-bit egress bytes"),
				m("ifInErrors", "1.3.6.1.2.1.2.2.1.14", "counter", "packets", "Ingress errors"),
				m("ifOutErrors", "1.3.6.1.2.1.2.2.1.20", "counter", "packets", "Egress errors"),
				m("ifInDiscards", "1.3.6.1.2.1.2.2.1.13", "counter", "packets", "Ingress discards"),
				m("ifOutDiscards", "1.3.6.1.2.1.2.2.1.19", "counter", "packets", "Egress discards"),
			},
		},
		{
			ID: "universal-host", Vendor: "Universal — Host Resources", Category: "server", Builtin: true,
			Metrics: []SNMPMetric{
				m("hrProcessorLoad", "1.3.6.1.2.1.25.3.3.1.2", "gauge", "%", "Per-core CPU load (average the walk)"),
				m("hrMemorySize", "1.3.6.1.2.1.25.2.2.0", "gauge", "KB", "Total RAM"),
				m("hrStorageSize", "1.3.6.1.2.1.25.2.3.1.5", "gauge", "units", "Storage size (× alloc unit)"),
				m("hrStorageUsed", "1.3.6.1.2.1.25.2.3.1.6", "gauge", "units", "Storage used (× alloc unit)"),
				m("hrSystemProcesses", "1.3.6.1.2.1.25.1.6.0", "gauge", "count", "Running processes"),
				m("entPhySensorValue", "1.3.6.1.2.1.99.1.1.1.4", "gauge", "", "Generic sensor reading (temp/volt/rpm)"),
			},
		},

		// ---- routers / switches ----
		{
			ID: "cisco-ios", Vendor: "Cisco IOS / IOS-XE", Category: "router_switch", SysObjectIDPrefix: "1.3.6.1.4.1.9.1", Builtin: true,
			Metrics: []SNMPMetric{
				m("cpmCPUTotal5minRev", "1.3.6.1.4.1.9.9.109.1.1.1.1.8", "gauge", "%", "CPU 5-min average"),
				m("cpmCPUTotal1minRev", "1.3.6.1.4.1.9.9.109.1.1.1.1.7", "gauge", "%", "CPU 1-min average"),
				m("ciscoMemoryPoolUsed", "1.3.6.1.4.1.9.9.48.1.1.1.5", "gauge", "bytes", "Memory pool used"),
				m("ciscoMemoryPoolFree", "1.3.6.1.4.1.9.9.48.1.1.1.6", "gauge", "bytes", "Memory pool free"),
				m("ciscoEnvMonTemperatureValue", "1.3.6.1.4.1.9.9.13.1.3.1.3", "gauge", "C", "Temperature"),
				m("ciscoEnvMonFanState", "1.3.6.1.4.1.9.9.13.1.4.1.3", "enum", "", "Fan health"),
				m("ciscoEnvMonSupplyState", "1.3.6.1.4.1.9.9.13.1.5.1.3", "enum", "", "PSU health"),
			},
		},
		{
			ID: "juniper-junos", Vendor: "Juniper JUNOS", Category: "router_switch", SysObjectIDPrefix: "1.3.6.1.4.1.2636", Builtin: true,
			Metrics: []SNMPMetric{
				m("jnxOperatingCPU", "1.3.6.1.4.1.2636.3.1.13.1.8", "gauge", "%", "Operating entity CPU"),
				m("jnxOperatingTemp", "1.3.6.1.4.1.2636.3.1.13.1.7", "gauge", "C", "Operating entity temperature"),
				m("jnxOperatingBuffer", "1.3.6.1.4.1.2636.3.1.13.1.11", "gauge", "%", "Memory buffer utilization"),
				m("jnxOperatingState", "1.3.6.1.4.1.2636.3.1.13.1.6", "enum", "", "Entity state"),
			},
		},
		{
			ID: "arista-eos", Vendor: "Arista EOS", Category: "router_switch", SysObjectIDPrefix: "1.3.6.1.4.1.30065", Builtin: true,
			Metrics: []SNMPMetric{
				m("hrProcessorLoad", "1.3.6.1.2.1.25.3.3.1.2", "gauge", "%", "CPU (HOST-RESOURCES)"),
				m("entPhySensorValue", "1.3.6.1.2.1.99.1.1.1.4", "gauge", "", "Temp/fan/voltage (ENTITY-SENSOR)"),
			},
		},
		{
			ID: "huawei", Vendor: "Huawei", Category: "router_switch", SysObjectIDPrefix: "1.3.6.1.4.1.2011", Builtin: true,
			Metrics: []SNMPMetric{
				m("hwEntityCpuUsage", "1.3.6.1.4.1.2011.5.25.31.1.1.1.1.5", "gauge", "%", "Entity CPU usage"),
				m("hwEntityMemUsage", "1.3.6.1.4.1.2011.5.25.31.1.1.1.1.7", "gauge", "%", "Entity memory usage"),
				m("hwEntityTemperature", "1.3.6.1.4.1.2011.5.25.31.1.1.1.1.11", "gauge", "C", "Entity temperature"),
			},
		},

		// ---- firewalls ----
		{
			ID: "fortinet-fortigate", Vendor: "Fortinet FortiGate", Category: "firewall", SysObjectIDPrefix: "1.3.6.1.4.1.12356.101", Builtin: true,
			Metrics: []SNMPMetric{
				m("fgSysCpuUsage", "1.3.6.1.4.1.12356.101.4.1.3.0", "gauge", "%", "System CPU usage"),
				m("fgSysMemUsage", "1.3.6.1.4.1.12356.101.4.1.4.0", "gauge", "%", "System memory usage"),
				m("fgSysMemCapacity", "1.3.6.1.4.1.12356.101.4.1.5.0", "gauge", "KB", "Total memory"),
				m("fgSysSesCount", "1.3.6.1.4.1.12356.101.4.1.8.0", "gauge", "sessions", "Active sessions"),
			},
		},
		{
			ID: "paloalto-panos", Vendor: "Palo Alto PAN-OS", Category: "firewall", SysObjectIDPrefix: "1.3.6.1.4.1.25461.2", Builtin: true,
			Metrics: []SNMPMetric{
				m("panSessionUtilization", "1.3.6.1.4.1.25461.2.1.2.3.1.0", "gauge", "%", "Session table utilization"),
				m("panSessionActive", "1.3.6.1.4.1.25461.2.1.2.3.3.0", "gauge", "sessions", "Active sessions"),
				m("panSessionMax", "1.3.6.1.4.1.25461.2.1.2.3.2.0", "gauge", "sessions", "Max sessions"),
				m("hrProcessorLoad", "1.3.6.1.2.1.25.3.3.1.2", "gauge", "%", "CPU (HOST-RESOURCES)"),
			},
		},

		// ---- printers ----
		{
			ID: "printer", Vendor: "Printer (Printer-MIB)", Category: "printer", Builtin: true,
			Metrics: []SNMPMetric{
				m("hrPrinterStatus", "1.3.6.1.2.1.25.3.5.1.1", "enum", "", "Printer status (idle/printing/…)"),
				m("hrDeviceStatus", "1.3.6.1.2.1.25.3.2.1.5", "enum", "", "Device status (running/warning/down)"),
				m("prtMarkerLifeCount", "1.3.6.1.2.1.43.10.2.1.4.1.1", "counter", "pages", "Lifetime page count"),
				m("prtMarkerSuppliesLevel", "1.3.6.1.2.1.43.11.1.1.9", "gauge", "units", "Toner/supply level"),
				m("prtMarkerSuppliesMaxCapacity", "1.3.6.1.2.1.43.11.1.1.8", "gauge", "units", "Supply max capacity"),
				m("prtInputCurrentLevel", "1.3.6.1.2.1.43.8.2.1.10", "gauge", "units", "Paper tray level"),
			},
		},

		// ---- UPS / power ----
		{
			ID: "ups", Vendor: "UPS (RFC 1628 UPS-MIB)", Category: "ups", Builtin: true,
			Metrics: []SNMPMetric{
				m("upsBatteryStatus", "1.3.6.1.2.1.33.1.2.1.0", "enum", "", "Battery status (normal/low/depleted)"),
				m("upsEstimatedMinutesRemaining", "1.3.6.1.2.1.33.1.2.3.0", "gauge", "minutes", "Runtime remaining"),
				m("upsEstimatedChargeRemaining", "1.3.6.1.2.1.33.1.2.4.0", "gauge", "%", "Battery charge"),
				m("upsBatteryTemperature", "1.3.6.1.2.1.33.1.2.7.0", "gauge", "C", "Battery temperature"),
				m("upsOutputSource", "1.3.6.1.2.1.33.1.4.1.0", "enum", "", "Output source (normal/battery/bypass)"),
				m("upsOutputPercentLoad", "1.3.6.1.2.1.33.1.4.4.1.5", "gauge", "%", "Output load per line"),
				m("upsSecondsOnBattery", "1.3.6.1.2.1.33.1.2.2.0", "gauge", "seconds", "Seconds on battery"),
			},
		},
	}
}

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package featureflags

// specs.go — the switchable set on the platform-admin Features page.
//
// WHAT IS NOT ON THE PAGE, and why (stated so nobody adds it casually):
//   - controls, not capabilities — FEATURE_SEALED_FIELDS (boot-fatal when
//     custody is missing, and turning it off silently stops encrypting), TLS
//     posture, the store backend, BROKER_URLS, VMALERT_NOTIFIER_FLAG,
//     AI_TOOLS_ALL_TENANTS (cross-tenant reach). No saved switch may stop the
//     api from booting, or the page could not undo it.
//   - flags read by OTHER containers (the correlation engine's CORR_*,
//     ENABLE_FLOW_CORRELATION, gnmic's ENABLE_GNMI_CORRELATION, the prober's
//     FEATURE_TRACEROUTE / ACTIVE_PROBE / STAMP_REFLECTOR / DEM / SYNTHETICS /
//     WAN_ECHO): the api cannot apply them; delivering them to those
//     containers is a follow-up, not a switch that pretends.
//   - settings already managed on their own pages (notification channels,
//     ITSM, SNMP discovery): one place per setting.
//   - ENABLE_REPORT_SCHEDULER: a flag-gated log.Fatalf path at start.
//   - FEATURE_AI / FEATURE_COPILOT / FEATURE_AI_TOOLS: no longer gates. The two
//     console-only AI switches below replace them (owner 2026-11-12/13); the
//     old variables are read once, by the upgrade seed, and nowhere else.
//
// THE AI SWITCHES (owner decisions 2026-11-12 and 2026-11-13): model-backed
// Iris is the `iris_model` licence add-on, and on a licensed install it still
// starts OFF until a platform administrator turns it on and acknowledges that
// questions and evidence go to the configured AI provider. Both are
// console-only (no .env line can set them), risky (acknowledgement) and Live.
// Evidence-only Iris needs neither.

// PlatformSpecs is the switchable set. Apply class and semantics follow how
// each flag is ACTUALLY read (verified 2026-10-11): per request/poll → Live;
// read once at start (pool.Enable, a worker, a bound port, routes registered
// only when a module is built) → Restart. A flag read both ways is Restart,
// so the page never shows a value that is not running.
func PlatformSpecs() []Spec {
	const (
		collect   = "Collection"
		discover  = "Discovery"
		routing   = "Routing"
		access    = "Configuration and device access"
		integrate = "Integrations and automation"
		analytics = "Analytics"
		iris      = "Iris AI"
	)
	live, restart := ApplyLive, ApplyRestart
	return []Spec{
		{Env: "ENABLE_SNMP_COLLECTION", Label: "SNMP polling", Group: collect, Apply: restart, Help: "Poll devices over SNMP v2c and v3."},
		{Env: "ENABLE_SNMP_METRICS", Label: "SNMP metrics", Group: collect, Apply: restart, Help: "Collect interface, CPU, memory and routing metrics over SNMP."},
		{Env: "ENABLE_GNMI_COLLECTION", Label: "gNMI streaming telemetry", Group: collect, Apply: restart, Help: "Subscribe to gNMI telemetry on devices that support it."},
		{Env: "ENABLE_NETCONF_COLLECTION", Label: "NETCONF polling", Group: collect, Apply: restart, Help: "Read device state over NETCONF."},
		{Env: "FEATURE_SNMP_TRAPS", Label: "SNMP traps", Group: collect, Apply: restart, Help: "Receive SNMP traps from devices."},
		{Env: "FEATURE_PORT_DOM", Label: "Optics readings (DOM)", Group: collect, Apply: live, Help: "Read optical power, temperature and voltage per port."},
		{Env: "FEATURE_UNIFI", Label: "UniFi controller", Group: collect, Apply: restart, Risky: true, Help: "Read device health from a Ubiquiti UniFi controller."},

		{Env: "ENABLE_VENDOR_DETECTION", Label: "Vendor detection", Group: discover, Apply: restart, Help: "Identify vendor and OS from each device's system ID."},
		{Env: "ENABLE_LLDP_DISCOVERY", Label: "LLDP neighbors", Group: discover, Apply: restart, Help: "Learn neighbors from LLDP."},
		{Env: "ENABLE_CDP_DISCOVERY", Label: "CDP neighbors", Group: discover, Apply: restart, Help: "Learn neighbors from CDP."},
		{Env: "ENABLE_TUNNEL_DISCOVERY", Label: "Tunnels", Group: discover, Apply: restart, Help: "Discover IPsec, GRE and SD-WAN tunnels."},
		{Env: "ENABLE_SDWAN_OVERLAY", Label: "SD-WAN overlay", Group: discover, Apply: restart, Help: "Read SD-WAN tunnels and transports from SD-WAN edges."},
		{Env: "ENABLE_VRF_COLLECTION", Label: "VRFs and routing instances", Group: discover, Apply: restart, Help: "Read routing instances, their interfaces and the BGP sessions inside them."},
		{Env: "ENABLE_BGPLS_DISCOVERY", Label: "BGP-LS topology", Group: discover, Apply: restart, Help: "Learn topology from BGP-LS."},

		{Env: "FEATURE_BGP_ALERTS", Label: "BGP alerts", Group: routing, Apply: restart, Help: "Watch prefixes and alert on hijacks and leaks."},
		{Env: "FEATURE_BGP_LIVE_FEED", Label: "Live BGP update feed", Group: routing, Apply: restart, Help: "Follow BGP updates in near real time."},
		{Env: "FEATURE_BMP", Label: "BMP listener", Group: routing, Apply: restart, Help: "Receive BGP Monitoring Protocol sessions from routers."},
		{Env: "FEATURE_PATH_GRAPH", Label: "Path graph", Group: routing, Apply: restart, Help: "Build the forwarding-path graph from path measurements."},
		{Env: "FEATURE_PATH_BASELINES", Label: "Path baselines", Group: routing, Apply: restart, Help: "Learn normal latency and loss per path."},

		{Env: "FEATURE_CONFIG_BACKUP", Label: "Configuration backup", Group: access, Apply: restart, Risky: true, Help: "Log in to devices to back up their configuration and detect drift."},
		{Env: "FEATURE_DEVICE_SSH", Label: "SSH to devices", Group: access, Apply: live, Risky: true, Help: "Open an SSH session to a device from the browser."},
		{Env: "FEATURE_PROTOCOL_DIAG_COLLECT", Label: "Run diagnostic commands", Group: access, Apply: live, Risky: true, Help: "Run read-only show commands on devices for troubleshooting."},
		{Env: "FEATURE_WIRELESS_ACTIONS", Label: "Wireless actions", Group: access, Apply: live, Risky: true, Help: "Allow actions that change wireless controllers."},
		{Env: "FEATURE_PACKET_CAPTURE", Label: "Packet capture", Group: access, Apply: restart, Risky: true, Help: "Capture packets on request."},

		{Env: "FEATURE_NMS_INTEGRATIONS", Label: "NMS integrations", Group: integrate, Apply: restart, Semantics: OnUnlessFalse, Help: "Connect other network management systems."},
		{Env: "FEATURE_ITSM_INBOUND", Label: "Ticket updates from ITSM", Group: integrate, Apply: live, Risky: true, Help: "Accept ticket updates sent by your ITSM tool."},
		{Env: "FEATURE_ITSM_RECONCILE", Label: "Ticket reconciliation", Group: integrate, Apply: restart, Help: "Keep tickets and incidents in step."},
		{Env: "FEATURE_RCA_TICKETING", Label: "Tickets from root causes", Group: integrate, Apply: restart, Help: "Open tickets from confirmed root causes."},
		{Env: "FEATURE_PROCESSORS", Label: "Pipeline processors", Group: integrate, Apply: live, Help: "Show the per-tenant log processor editor."},

		{Env: "FEATURE_SECURITY_LANE", Label: "Security findings", Group: analytics, Apply: restart, Help: "Correlate security events with network faults."},
		{Env: "FEATURE_ACTIVE_VERIFICATION", Label: "Active verification", Group: analytics, Apply: restart, Help: "Test a suspected cause with safe, read-only checks."},
		{Env: "FEATURE_SVC_FLOW_ROLLUP", Label: "Service traffic totals", Group: analytics, Apply: restart, Help: "Roll flow traffic up per service every minute."},

		{Env: "IRIS_AI_MODELS", Label: "Iris AI models", Group: iris, Apply: live, Risky: true, ConsoleOnly: true, Requires: "iris_model",
			Help: "Let Iris send questions and the evidence it gathered to your configured AI provider for written answers and chat. Off, Iris answers from Correlix data alone."},
		{Env: "IRIS_AI_INVESTIGATIONS", Label: "AI investigations", Group: iris, Apply: live, Risky: true, ConsoleOnly: true, Requires: "iris_model",
			Help: "Let the AI model run read-only lookups across your network data to investigate a question. Needs Iris AI models on; each workspace still opts in."},
		// N-I5 (D17): read-only MCP. No AI provider call is made by Correlix, so
		// it needs no iris_model licence; it is still risky because the answers
		// leave Correlix for the customer's own AI client.
		{Env: "IRIS_MCP", Label: "Iris over MCP (read-only)", Group: iris, Apply: live, Risky: true, ConsoleOnly: true,
			Help: "Let an external AI assistant use Iris's read-only lookups over the Model Context Protocol with a workspace API key. Data leaves Correlix for that assistant; each workspace still opts in."},
	}
}

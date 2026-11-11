// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// eventFixtures — record shapes for the Event Intelligence panel, shared by the vitest
// suite and the Playwright spec. The CPU trap is the real lab record of 2026-11-10
// (vedge-51, viptelaSystemCpuUsage, Trap-enhance.md §1), shaped by the data contract the
// trap-semantics work emits (tracker 387). The others are one record per lane: what each
// would look like on the Logs page with that contract's fields present.

import type { LogHit } from "./logEvent";

// The literal only exists so the redaction tests can prove it never reaches the page.
export const FIXTURE_SECRET = "s3cr3t-community";

const PIPELINE = { "topic": "netops.snmptrap", partition: 3, offset: 991823, source_type: "kafka", message_key: "abc123" };

const CPU_VARBINDS = [
  { name: "sysUpTime", oid: "1.3.6.1.2.1.1.3.0", type: "TimeTicks", value: "143277415", decoded: "143277415" },
  { name: "eventTime", oid: "1.3.6.1.4.1.41916.100.1.1.0", type: "DateAndTime", value: "0x07ea0b0a04071b052b0000", decoded: "2026-11-10T04:07:27.500Z" },
  { name: "netconfNotificationSeverity", oid: "1.3.6.1.4.1.41916.100.1.2.0", type: "INTEGER", value: "1", decoded: "critical (1)" },
  { name: "viptelaSystemWarning", oid: "1.3.6.1.4.1.41916.100.1.54.0", type: "OCTET", value: "System cpu usage is above 90% (critically high)", decoded: "System cpu usage is above 90% (critically high)" },
  { name: "viptelaSystemCpuUserPercentage", oid: "1.3.6.1.4.1.41916.100.1.190.0", type: "OCTET", value: "4.15", decoded: "4.15" },
  { name: "viptelaSystemCpuSystemPercentage", oid: "1.3.6.1.4.1.41916.100.1.191.0", type: "OCTET", value: "95.85", decoded: "95.85" },
  { name: "viptelaSystemCpuIdlePercentage", oid: "1.3.6.1.4.1.41916.100.1.192.0", type: "OCTET", value: "0.00", decoded: "0.00" },
];

/** The golden fixture: the real critical CPU trap from vedge-51. */
export const CPU_GOLDEN: LogHit = {
  _index: "netops-snmptrap-global-2026.11.10",
  _id: "golden-cpu-1",
  _source: {
    timestamp: "2026-11-10T04:07:51.913Z",
    signal: "snmptrap",
    device: "vedge-51-0a0b4db5", hostname: "vedge-51-0a0b4db5", host: "192.168.222.101", device_id: "vedge-51-0a0b4db5",
    vendor: "cisco", vendor_source: "inventory", platform: "SD-WAN", model: "vEdge", site: "", role: "SD-WAN Edge",
    tenant_id: "global", tenant_attribution: "platform_owned",
    native_severity: "critical", severity: "critical", normalized_severity: "critical",
    title: "CPU utilization reached 100% on vEdge-51 — system CPU 95.85%",
    summary: "CPU utilization reached 100% on vEdge-51 — system CPU 95.85%.",
    message: "System cpu usage is above 90% (critically high)",
    event_type: "viptela_system_cpu_usage", family: "cpu", category: "platform_health",
    event_state: "raise", lifecycle_state: "raise", recovery_verified: false,
    trap_oid: "1.3.6.1.4.1.41916.100.2.114", trap_name: "viptelaSystemCpuUsage", mib_module: "VIPTELA-TRAPS",
    snmp_version: "v2c", snmp_community_present: true, auth_model: "community", authenticated: false,
    snmp_community: FIXTURE_SECRET,
    device_event_time: "2026-11-10T04:07:27.500Z", received_time: "2026-11-10T04:07:51.913Z",
    observed_delay_s: 24.413, delay_basis: "device_clock_vs_receive",
    device_uptime_s: 1432774.15, device_uptime_human: "16d 13h 59m",
    correlation_key: "cpu:vedge-51-0a0b4db5:device",
    event_id: "snmptrap:cisco:vedge-51-0a0b4db5:1.3.6.1.4.1.41916.100.2.114",
    metrics: {
      cpu_user_percent: { value: 4.15, basis: "observed" },
      cpu_system_percent: { value: 95.85, basis: "observed" },
      cpu_idle_percent: { value: 0, basis: "observed" },
      cpu_total_percent: { value: 100, basis: "derived", formula: "100 - cpu_idle_percent" },
    },
    threshold_reported_percent: 90, threshold_basis: "reported_by_device",
    varbinds: CPU_VARBINDS,
    guidance: {
      impact: [
        "High risk of control-plane or management performance degradation",
        "May affect routing, tunnel stability, and device responsiveness",
        "No idle CPU reported (0.00%)",
      ],
      next_checks: [
        "Verify running processes and system load on the device",
        "Check for abnormal control-plane or data-plane spikes",
        "Review recent configuration changes or traffic spikes",
        "Monitor for a recovery (CPU below threshold)",
      ],
      basis: "pack_guidance",
    },
    enrichment: {
      fields_observed: ["cpu_user_percent", "cpu_system_percent", "cpu_idle_percent", "device_event_time", "received_time"],
      fields_derived: ["cpu_total_percent", "observed_delay_s", "title"],
      fields_guidance: ["guidance"],
      unknown: [],
    },
    parser_status: "parsed", enrichment_status: "enriched", ts_source: "event",
    ...PIPELINE,
  },
};

function cpuAt(id: string, over: Record<string, unknown>, metrics: [number, number, number]): LogHit {
  const [user, system, idle] = metrics;
  return {
    ...CPU_GOLDEN,
    _id: id,
    _source: {
      ...CPU_GOLDEN._source,
      metrics: {
        cpu_user_percent: { value: user, basis: "observed" },
        cpu_system_percent: { value: system, basis: "observed" },
        cpu_idle_percent: { value: idle, basis: "observed" },
        cpu_total_percent: { value: Number((100 - idle).toFixed(2)), basis: "derived", formula: "100 - cpu_idle_percent" },
      },
      ...over,
    },
  };
}

/** The same device a few minutes earlier, at warning: "above 75%". */
export const CPU_WARNING = cpuAt("cpu-warning", {
  native_severity: "major", severity: "warning", normalized_severity: "warning",
  title: "CPU utilization reached 80.1% on vEdge-51 — system CPU 62.3%",
  message: "System cpu usage is above 75%", lifecycle_state: "escalate", event_state: "escalate",
  threshold_reported_percent: 75, device_event_time: "2026-11-10T01:00:39.119Z", received_time: "2026-11-10T01:00:39.900Z",
  observed_delay_s: 0.781, timestamp: "2026-11-10T01:00:39.900Z", guidance: undefined,
}, [17.8, 62.3, 19.9]);

/** An informational repeat below any threshold. */
export const CPU_INFO = cpuAt("cpu-info", {
  native_severity: "info", severity: "info", normalized_severity: "info",
  title: "CPU utilization at 34.5% on vEdge-51", message: "System cpu usage report",
  lifecycle_state: "repeat", event_state: "repeat", threshold_reported_percent: undefined, threshold_basis: undefined,
  observed_delay_s: 0.4, guidance: undefined,
}, [20.1, 14.4, 65.5]);

/** The verified recovery: "back to normal level". */
export const CPU_RECOVERED = cpuAt("cpu-recovered", {
  native_severity: "cleared", severity: "ok", normalized_severity: "ok",
  title: "CPU recovered on vEdge-51 — utilization 34.54%",
  message: "System cpu usage back to normal level", lifecycle_state: "clear", event_state: "clear",
  recovery_verified: true, threshold_reported_percent: undefined, threshold_basis: undefined, guidance: undefined,
  device_event_time: "2026-11-10T01:00:38.664Z", received_time: "2026-11-10T01:00:39.100Z", observed_delay_s: 0.436,
}, [20.1, 14.44, 65.46]);

/** BGP peer2 notification: a session that never reached Established. */
export const BGP_TRANSITION: LogHit = {
  _index: "netops-snmptrap-global-2026.11.10",
  _id: "bgp-1",
  _source: {
    timestamp: "2026-11-10T03:12:09.412Z", signal: "snmptrap",
    device: "cedge-11-0a0b4da1", hostname: "cedge-11-0a0b4da1", host: "192.168.223.11", device_id: "cedge-11-0a0b4da1",
    vendor: "cisco", model: "C8000V", role: "SD-WAN Edge", site: "dallas-dc1", tenant_id: "t_acme", tenant_attribution: "enriched",
    native_severity: "warning", severity: "warning", normalized_severity: "warning",
    title: "BGP peer 10.10.20.2 (IPv4 unicast) never established on cedge-11",
    message: "cbgpPeer2BackwardTransition", event_type: "bgp_backward_transition", family: "bgp", category: "routing",
    lifecycle_state: "raise", trap_oid: "1.3.6.1.4.1.9.9.187.0.8", trap_name: "cbgpPeer2BackwardTransition",
    mib_module: "CISCO-BGP4-MIB", snmp_version: "v2c", snmp_community_present: true, auth_model: "community", authenticated: false,
    device_event_time: "2026-11-10T03:12:09.120Z", received_time: "2026-11-10T03:12:09.412Z", observed_delay_s: 0.292,
    device_uptime_human: "4d 2h 11m",
    bgp: { peer_address: "10.10.20.2", peer_afi: "ipv4-unicast", peer_as: "65020", local_address: "10.10.20.1", vrf: "", prev_state: "OpenSent", state: "Idle", transition_class: "never_established" },
    transition_id: "bgp:cedge-11-0a0b4da1:10.10.20.2:ipv4", occurrence_count: 6,
    correlation_key: "bgp:cedge-11-0a0b4da1:10.10.20.2",
    event_id: "snmptrap:cisco:cedge-11-0a0b4da1:1.3.6.1.4.1.9.9.187.0.8",
    varbinds: [
      { name: "cbgpPeer2State", oid: "1.3.6.1.4.1.9.9.187.1.2.5.1.3.1.4.10.10.20.2", type: "INTEGER", value: "1", decoded: "idle (1)" },
      { name: "cbgpPeer2LastError", oid: "1.3.6.1.4.1.9.9.187.1.2.5.1.17.1.4.10.10.20.2", type: "OCTET", value: "0x0000", decoded: "0x0000" },
    ],
    guidance: { impact: ["Routes from this peer are not being learned"], next_checks: ["Check reachability to 10.10.20.2 and the configured remote AS"], basis: "pack_guidance" },
    parser_status: "parsed", enrichment_status: "enriched",
  },
};

/** A parsed Cisco SD-WAN syslog fault (VTRACKER DNS). */
export const SYSLOG_FAULT: LogHit = {
  _index: "netops-syslog-global-2026.11.10",
  _id: "sys-fault-1",
  _source: {
    timestamp: "2026-11-10T03:58:02.000Z", ingested_at: "2026-11-10T03:58:02.311Z", ts_source: "timestamp",
    hostname: "vedge-52-0a0b4db6", source_ip: "192.168.222.102", device_id: "vedge-52-0a0b4db6",
    vendor: "cisco", platform: "SD-WAN", model: "vEdge", role: "SD-WAN Edge", tenant_id: "global", tenant_attribution: "platform_owned",
    appname: "ftmd", procid: "1931", syslog_facility: "local7", facility: "VTRACKER", frame_format: "rfc3164",
    severity: "err", severity_native_text: "err", normalized_severity: "error",
    message: "%Viptela-vedge-52-ftmd-3-ERR-1: VTRACKER: DNS probe to 8.8.8.8 failed for tracker dns-tracker on VPN 0",
    message_original: "<187>Nov 10 03:58:02 vedge-52 ftmd[1931]: %Viptela-vedge-52-ftmd-3-ERR-1: VTRACKER: DNS probe to 8.8.8.8 failed for tracker dns-tracker on VPN 0",
    summary: "The DNS tracker dns-tracker on VPN 0 could not reach 8.8.8.8.",
    event_type: "sdwan_vtracker_dns_failure", event_category: "tracker", family: "tracker",
    parser_status: "parsed", parser_id: "cisco-sdwan.vtracker",
    "topic": "netops.syslog", partition: 2,
  },
};

/** A management audit line: an SNMP poll session, from where. ConfD names a v1/v2c SNMP
 *  session by the community the request carried, so the parse reads no user from it
 *  (audit_user unset); the message holds a placeholder account. */
export const SYSLOG_AUDIT: LogHit = {
  _index: "netops-syslog-global-2026.11.10",
  _id: "sys-audit-1",
  _source: {
    timestamp: "2026-11-10T03:41:17.000Z", ingested_at: "2026-11-10T03:41:17.204Z", ts_source: "timestamp",
    hostname: "vedge-52-0a0b4db6", source_ip: "192.168.222.102", device_id: "vedge-52-0a0b4db6",
    vendor: "cisco", platform: "SD-WAN", model: "vEdge", tenant_id: "global", tenant_attribution: "platform_owned",
    appname: "confd", syslog_facility: "user", severity: "notice", normalized_severity: "notice",
    message: "audit user: svc-poller/980840 created new session via snmp from 127.0.0.1:54511 with udp",
    event_type: "sdwan_session_created", event_category: "management_audit",
    audit_action: "created new session", audit_source: "127.0.0.1:54511", audit_via: "snmp (udp)", session_id: "980840",
    parser_status: "parsed", parser_id: "cisco-sdwan.audit",
  },
};

/** A line no parser understands yet. */
export const SYSLOG_UNPARSED: LogHit = {
  _index: "netops-syslog-global-2026.11.10",
  _id: "sys-unparsed-1",
  _source: {
    timestamp: "2026-11-10T03:30:00.000Z", ingested_at: "2026-11-10T03:30:00.150Z", ts_source: "timestamp",
    hostname: "vedge-53-0a0b4db7", source_ip: "192.168.222.103", tenant_attribution: "unmatched",
    appname: "fpmd", procid: "2201", syslog_facility: "daemon", severity: "warning",
    message: "fp-um-2: %UNK-4-FP_QFULL: queue 7 nearing limit hwm=4096",
    message_original: "<28>Nov 10 03:30:00 vedge-53 fpmd[2201]: fp-um-2: %UNK-4-FP_QFULL: queue 7 nearing limit hwm=4096",
    parser_status: "unparsed", frame_format: "rfc3164",
  },
};

/** A flow with interface names the API resolved and a traffic class. */
export const FLOW_RECORD: LogHit = {
  _index: "netops-flows-global-2026.11.10",
  _id: "flow-1",
  _source: {
    timestamp: "2026-11-10T03:50:00.000Z", signal: "netflow", src_addr: "192.168.222.105", dst_addr: "192.168.172.1",
    src_port: 161, dst_port: 38204, proto: 17, sampler_address: "192.168.222.104", exporter_name: "vedge-54-0a0b4db8",
    in_if: 1, out_if: 4, bytes: 1003, packets: 13, sample_rate: 50, sampling_rate: 0, flow_type: "netflow_v9",
    tenant_attribution: "platform_owned", partition: 1,
  },
  _resolved: { in_if_name: "ge0/0", in_if_name_basis: "resolved", out_if_name: "ge0/3", out_if_name_basis: "resolved", service_name: "snmp", service_port: 161, traffic_class: "platform_monitoring" },
};

/** The platform's own container log. */
export const APP_LOG: LogHit = {
  _index: "netops-applogs-2026.11.10",
  _id: "app-1",
  _source: { timestamp: "2026-11-10T03:55:00.000Z", level: "error", compose_service: "api", container_name: "cx-api-1", component: "ticketing", message: "ticket sync failed: upstream returned 502", trace_id: "4bf92f3577b34da6" },
};

/** A cloud log line. */
export const CLOUD_LOG: LogHit = {
  _index: "netops-cloudlogs-t_acme-2026.11.10",
  _id: "cloud-1",
  _source: { timestamp: "2026-11-10T03:52:00.000Z", level: "warning", cloud_provider: "aws", account: "123456789012", region: "us-east-1", resource_id: "i-0abc123", cloud_family: "vpc_flow", message: "REJECT 10.0.1.5 → 10.0.2.9 tcp/443" },
};

/** A security finding. */
export const SECURITY_FINDING: LogHit = {
  _index: "netops-secfindings-t_acme-2026.11.10",
  _id: "sec-1",
  _source: { timestamp: "2026-11-10T02:00:00.000Z", severity: "high", title: "SSH open to the internet", control_title: "Restrict management access", resource: "edge-9 ge0/0", status: "open", remediation: "Limit SSH to the management subnet" },
};

/** A record the router quarantined. */
export const QUARANTINE_RECORD: LogHit = {
  _index: "netops-quarantine-global-2026.11.10",
  _id: "q-1",
  _source: { timestamp: "2026-11-10T01:00:00.000Z", received_at: "2026-11-10T01:00:00.000Z", reason: "tenant claim refused", lane: "syslog", source_ip: "203.0.113.9" },
};

/** A trap with almost nothing in it: nothing may be invented around it. */
export const MINIMAL_TRAP: LogHit = {
  _index: "netops-snmptrap-global-2026.11.10",
  _id: "min-1",
  _source: { timestamp: "2026-11-10T00:00:00.000Z", host: "192.0.2.8", trap_oid: "1.3.6.1.4.1.99.1", message: "1.3.6.1.4.1.99.1" },
};

export const ALL_FIXTURES: Record<string, LogHit> = {
  CPU_GOLDEN, CPU_WARNING, CPU_INFO, CPU_RECOVERED, BGP_TRANSITION, SYSLOG_FAULT, SYSLOG_AUDIT, SYSLOG_UNPARSED,
  FLOW_RECORD, APP_LOG, CLOUD_LOG, SECURITY_FINDING, QUARANTINE_RECORD, MINIMAL_TRAP,
};

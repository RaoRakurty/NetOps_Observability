// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// eventModel.test.ts — the one presenter behind the Event Intelligence panel. One case
// per lane, the golden CPU trap pinned value by value, and the honesty rules: nothing
// invented when a field is missing, no incident state, guidance labelled, secrets gone.

import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  DASH, EventView, TIMELINE_KEYS, TIMELINE_SEARCHABLE, clauseQuery, fmtLocal, fmtUtc, toEventView,
} from "./eventModel";
import {
  ALL_FIXTURES, APP_LOG, BGP_TRANSITION, CLOUD_LOG, CPU_GOLDEN, CPU_INFO, CPU_RECOVERED, CPU_WARNING, FIXTURE_SECRET,
  FLOW_RECORD, MINIMAL_TRAP, QUARANTINE_RECORD, SECURITY_FINDING, SYSLOG_AUDIT, SYSLOG_FAULT, SYSLOG_UNPARSED,
} from "./eventFixtures";
import { SEVERITY_TONES, SeverityKey, severityKey, severityTone } from "../theme/severity";

const row = (rows: { key: string; value: string }[], key: string) => rows.find((r) => r.key === key)?.value;
const text = (v: EventView) => JSON.stringify(v);

describe("the golden CPU trap (vedge-51, 2026-11-10)", () => {
  const v = toEventView(CPU_GOLDEN);

  it("leads with the record's title, the vendor message under it, and critical severity", () => {
    expect(v.lane).toBe("trap");
    expect(v.title).toBe("CPU utilization reached 100% on vEdge-51 — system CPU 95.85%");
    expect(v.subtitle).toBe("System cpu usage is above 90% (critically high)");
    expect(v.severity).toEqual({ native: "critical", normalized: "critical", label: "Critical", tone: "critical" });
  });

  it("chips: vendor/platform, family, category, signal, lifecycle", () => {
    expect(v.chips.map((c) => c.label)).toEqual(["Cisco SD-WAN", "CPU Saturation", "Platform Health", "SNMP Trap", "Raise"]);
    expect(v.chips.find((c) => c.key === "lifecycle")?.tone).toBe("critical");
  });

  it("the CPU breakdown: a 100% ring, system/user/idle, and the reported 90% threshold", () => {
    expect(v.primaryVisual.kind).toBe("cpu");
    if (v.primaryVisual.kind !== "cpu") throw new Error("not cpu");
    const u = v.primaryVisual.data;
    expect(u.total).toBe(100);
    expect(u.totalProv).toBe("derived");
    expect(u.segments.map((s) => [s.key, s.value, s.prov])).toEqual([
      ["system", 95.85, "observed"], ["user", 4.15, "observed"], ["idle", 0, "observed"],
    ]);
    expect(u.threshold).toEqual({ value: 90, label: "Threshold (reported)" });
    expect(v.sideStats.map((r) => [r.label, r.value])).toEqual([
      ["Total CPU (derived)", "100.00%"], ["Reported Threshold", "90%"], ["System CPU", "95.85%"],
      ["User CPU", "4.15%"], ["Idle CPU", "0.00%"],
    ]);
  });

  it("the device card: name, IP, type, ownership, tenant, a dash for the blank site, inventory matched", () => {
    expect(v.device.rows.map((r) => [r.label, r.value])).toEqual([
      ["Device", "vedge-51-0a0b4db5"], ["IP", "192.168.222.101"], ["Device Type", "Cisco vEdge (SD-WAN)"],
      ["Ownership", "Platform device"], ["Tenant", "Platform (platform_owned)"], ["Site", DASH], ["Role", "SD-WAN Edge"],
      ["Inventory Status", "Inventory Matched"],
    ]);
    expect(v.device.inventory).toEqual({ label: "Inventory Matched", tone: "ok" });
  });

  it("timing: device time, received, a 24.413 s observed delay that says it is not latency, uptime", () => {
    expect(row(v.timing, "device_time")).toBe("2026-11-10 04:07:27.500 UTC");
    expect(row(v.timing, "received")).toBe("2026-11-10 04:07:51.913 UTC");
    const delay = v.timing.find((r) => r.key === "delay")!;
    expect(delay.value).toBe("24.413 seconds");
    expect(delay.tip).toMatch(/not network latency/);
    expect(delay.pill).toBe("warning");
    expect(row(v.timing, "uptime")).toBe("16d 13h 59m (1,432,774.15 s)");
  });

  it("classification: type, category, family, MIB, OID, version, community as a boolean, auth not a failure", () => {
    expect(v.classification.map((r) => [r.label, r.value])).toEqual([
      ["Event Type", "viptela_system_cpu_usage"], ["Category", "Platform Health"], ["Family", "CPU"],
      ["MIB Module", "VIPTELA-TRAPS"], ["Trap OID", "1.3.6.1.4.1.41916.100.2.114"], ["SNMP Version", "v2c"],
      ["Community Present", "Yes (hidden)"], ["Authenticated", "No (v2c – not applicable)"],
    ]);
  });

  it("identity: event id and correlation key with copy, raise, not recovered; no incident status", () => {
    expect(v.identity.rows.map((r) => [r.label, r.value, !!r.copy])).toEqual([
      ["Event ID", "snmptrap:cisco:vedge-51-0a0b4db5:1.3.6.1.4.1.41916.100.2.114", true],
      ["Correlation Key", "cpu:vedge-51-0a0b4db5:device", true],
      ["Event State", "Raise", false],
      ["Recovery Status", "Not recovered", false],
    ]);
    expect(text(v)).not.toMatch(/incident status/i);
  });

  it("overview from observed values, guidance labelled with its basis", () => {
    expect(v.overview.what).toBe(
      "The device reported CPU utilization at 100% (derived as 100 - cpu_idle_percent), with system processes consuming 95.85% of CPU. This exceeds the threshold of 90% that the device reported in its own message.",
    );
    expect(v.overview.impact).toHaveLength(3);
    expect(v.overview.nextChecks).toHaveLength(4);
    expect(v.overview.basis).toMatch(/vendor pack's guidance/);
  });

  it("decoded varbinds with name, OID, type and value; the severity value marked as a pill", () => {
    expect(v.details.kind).toBe("varbinds");
    expect(v.details.varbinds.map((b) => [b.name, b.oid, b.type, b.decoded])).toEqual([
      ["sysUpTime", "1.3.6.1.2.1.1.3.0", "TimeTicks", "143277415"],
      ["eventTime", "1.3.6.1.4.1.41916.100.1.1.0", "DateAndTime", "2026-11-10T04:07:27.500Z"],
      ["netconfNotificationSeverity", "1.3.6.1.4.1.41916.100.1.2.0", "INTEGER", "critical (1)"],
      ["viptelaSystemWarning", "1.3.6.1.4.1.41916.100.1.54.0", "OCTET", "System cpu usage is above 90% (critically high)"],
      ["viptelaSystemCpuUserPercentage", "1.3.6.1.4.1.41916.100.1.190.0", "OCTET", "4.15"],
      ["viptelaSystemCpuSystemPercentage", "1.3.6.1.4.1.41916.100.1.191.0", "OCTET", "95.85"],
      ["viptelaSystemCpuIdlePercentage", "1.3.6.1.4.1.41916.100.1.192.0", "OCTET", "0.00"],
    ]);
    expect(v.details.varbinds[2].tone).toBe("critical");
    expect(v.details.varbinds[1].isTime).toBe(true);
  });

  it("its own timeline: the raise at device time, then the receipt 24.413 s later", () => {
    expect(v.timeline.map((e) => [e.pill, e.timeBasis, e.text])).toEqual([
      ["Raise (Critical)", "device time", "CPU utilization reached 100% (system 95.85%, user 4.15%, idle 0.00%)"],
      ["Event Received", "received", "SNMP trap received and decoded"],
    ]);
    expect(v.timeline[1].afterSeconds).toBeCloseTo(24.413, 3);
  });

  it("metrics: each value with its basis, the derived one with its formula, the threshold as reported", () => {
    expect(v.metrics.map((m) => [m.label, m.value, m.prov])).toEqual([
      ["User CPU", "4.15%", "observed"], ["System CPU", "95.85%", "observed"], ["Idle CPU", "0.00%", "observed"],
      ["Total CPU", "100.00%", "derived"], ["Threshold", "90%", "reported"],
    ]);
    expect(v.metrics.find((m) => m.key === "cpu_total_percent")?.formula).toBe("100 - cpu_idle_percent");
    expect(v.metricSeries).toEqual({ metric: "device_cpu_percent", deviceId: "vedge-51-0a0b4db5", label: "CPU %" });
  });

  it("no timeline series is fabricated from one trap: the only trend source is a stored metric", () => {
    expect(text(v)).not.toMatch(/"points"/);
  });

  it("links related records by fields the index can answer, quoted", () => {
    expect(v.timelineQuery?.basis).toMatch(/Same device and event type/);
    expect(clauseQuery(v.timelineQuery!.clauses)).toBe('device_id:"vedge-51-0a0b4db5" AND event_type:"viptela_system_cpu_usage"');
    expect(v.timelineQuery?.signal).toBe("snmptrap");
  });

  it("an incident draft holds only stated, redacted values", () => {
    expect(v.incidentDraft.severity).toBe("critical");
    expect(v.incidentDraft.title).toBe(v.title);
    expect(v.incidentDraft.description).toContain("cpu:vedge-51-0a0b4db5:device");
    expect(v.incidentDraft.description).not.toContain(FIXTURE_SECRET);
  });

  it("never carries the community string anywhere", () => {
    expect(text(v)).not.toContain(FIXTURE_SECRET);
    expect(v.raw.snmp_community).toBe("hidden");
  });
});

describe("CPU at other severities re-tints, and recovery is only claimed when verified", () => {
  it("warning, info and recovered take their own tone", () => {
    expect(toEventView(CPU_WARNING).severity.tone).toBe("warning");
    expect(toEventView(CPU_INFO).severity.tone).toBe("info");
    const r = toEventView(CPU_RECOVERED);
    expect(r.severity.tone).toBe("ok");
    expect(r.identity.lifecycle).toBe("clear");
    expect(row(r.identity.rows, "recovery")).toBe("Recovered (verified)");
    expect(r.chips.find((c) => c.key === "lifecycle")).toMatchObject({ label: "Clear", tone: "ok" });
  });

  it("with no threshold reported, none is shown and the family is not called saturated", () => {
    const v = toEventView(CPU_INFO);
    if (v.primaryVisual.kind !== "cpu") throw new Error("not cpu");
    expect(v.primaryVisual.data.threshold).toBeNull();
    expect(v.chips.find((c) => c.key === "family")?.label).toBe("CPU");
    expect(v.overview.impact).toEqual([]);
  });

  it("a threshold that is not stated as reported by the device is not shown", () => {
    const v = toEventView({ ...CPU_GOLDEN, _source: { ...CPU_GOLDEN._source, threshold_basis: "configured" } });
    if (v.primaryVisual.kind !== "cpu") throw new Error("not cpu");
    expect(v.primaryVisual.data.threshold).toBeNull();
  });

  it("out-of-range and non-numeric metrics are dropped, not drawn", () => {
    const v = toEventView({ ...CPU_GOLDEN, _source: { ...CPU_GOLDEN._source, metrics: { cpu_system_percent: { value: 140, basis: "observed" }, cpu_user_percent: { value: "abc", basis: "observed" }, cpu_idle_percent: { value: 20, basis: "observed" } } } });
    if (v.primaryVisual.kind !== "cpu") throw new Error("not cpu");
    expect(v.primaryVisual.data.segments.map((s) => s.key)).toEqual(["idle"]);
    expect(v.primaryVisual.data.total).toBe(80);
  });
});

describe("BGP transition", () => {
  const v = toEventView(BGP_TRANSITION);
  it("puts the peer first, previous → current, and says it never established rather than lost", () => {
    expect(v.primaryVisual.kind).toBe("bgp");
    if (v.primaryVisual.kind !== "bgp") throw new Error("not bgp");
    const b = v.primaryVisual.data;
    expect([b.peerAddress, b.afi, b.peerAs, b.prev, b.state]).toEqual(["10.10.20.2", "IPv4 unicast", "65020", "OpenSent", "Idle"]);
    expect(b.sentence).toMatch(/never came up, not the loss of a working one/);
    expect(b.occurrences).toBe(6);
    expect(row(v.identity.rows, "transition_id")).toBe("bgp:cedge-11-0a0b4da1:10.10.20.2:ipv4");
  });
  it("does not invent a previous state the record does not state", () => {
    const src = { ...BGP_TRANSITION._source!, bgp: { ...BGP_TRANSITION._source!.bgp, prev_state: undefined } };
    const x = toEventView({ ...BGP_TRANSITION, _source: src });
    if (x.primaryVisual.kind !== "bgp") throw new Error("not bgp");
    expect(x.primaryVisual.data.prev).toBeNull();
    expect(x.overview.what).toMatch(/previous state was not reported/);
  });
});

describe("syslog", () => {
  it("a fault: the parser's explanation, process, facility, device severity and the original frame", () => {
    const v = toEventView(SYSLOG_FAULT);
    expect(v.lane).toBe("syslog");
    expect(v.primaryVisual.kind).toBe("syslog_fault");
    if (v.primaryVisual.kind !== "syslog_fault") throw new Error();
    expect(v.primaryVisual.data).toMatchObject({
      explanation: "The DNS tracker dns-tracker on VPN 0 could not reach 8.8.8.8.", unparsed: false, process: "ftmd",
      procid: "1931", facility: "local7", deviceSeverity: "err",
    });
    expect(v.primaryVisual.data.frame).toContain("<187>Nov 10 03:58:02 vedge-52 ftmd[1931]");
    expect(v.severity.tone).toBe("error");
    expect(v.details.title).toBe("Parsed Fields");
  });

  it("syslog timing: device time vs ingested_at with ts_source as the basis", () => {
    const v = toEventView(SYSLOG_FAULT);
    expect(row(v.timing, "device_time")).toBe("2026-11-10 03:58:02.000 UTC");
    expect(row(v.timing, "received")).toBe("2026-11-10 03:58:02.311 UTC");
    expect(row(v.timing, "delay")).toBe("0.311 seconds");
    expect(row(v.timing, "basis")).toBe("Device clock");
  });

  it("a clock the edge did not believe says so, with the offset", () => {
    const v = toEventView({ ...SYSLOG_FAULT, _source: { ...SYSLOG_FAULT._source, ts_source: "edge_receive", device_timestamp: "2026-11-09T21:58:02.000Z", clock_skew_s: -21600 } });
    expect(v.timing.map((r) => r.label)).toEqual(["Event Time", "Device Clock Said", "Device Clock Offset", "Time Basis"]);
    expect(row(v.timing, "basis")).toMatch(/not believed/);
  });

  it("an unparsed line says so plainly and offers no explanation", () => {
    const v = toEventView(SYSLOG_UNPARSED);
    if (v.primaryVisual.kind !== "syslog_fault") throw new Error();
    expect(v.primaryVisual.title).toBe("Not parsed yet");
    expect(v.primaryVisual.data.unparsed).toBe(true);
    expect(v.primaryVisual.data.explanation).toBe("");
    expect(v.primaryVisual.data.process).toBe("fpmd");
    expect(v.primaryVisual.data.deviceSeverity).toBe("warning");
    expect(v.overview.what).toMatch(/not been parsed yet/);
    expect(v.device.inventory).toEqual({ label: "Not in inventory", tone: "warning" });
  });

  it("a management audit line reads as an audit record: who, what, from where, session", () => {
    const v = toEventView(SYSLOG_AUDIT);
    expect(v.primaryVisual.kind).toBe("audit");
    if (v.primaryVisual.kind !== "audit") throw new Error();
    expect(v.primaryVisual.data.rows.map((r) => [r.label, r.value])).toEqual([
      ["Who", "ciscosdwan"], ["Action", "created new session"], ["From", "127.0.0.1:54511"], ["Via", "snmp (udp)"], ["Session", "980840"],
    ]);
  });

  it("an audit line without split-out fields shows the words and says so", () => {
    const src = { ...SYSLOG_AUDIT._source };
    for (const k of ["audit_user", "audit_action", "audit_source", "audit_via", "session_id"]) delete src[k];
    const v = toEventView({ ...SYSLOG_AUDIT, _source: src });
    if (v.primaryVisual.kind !== "audit") throw new Error();
    expect(v.primaryVisual.data.unparsed).toBe(true);
    expect(v.primaryVisual.data.message).toContain("audit user: ciscosdwan/980840");
  });
});

describe("flow", () => {
  const v = toEventView(FLOW_RECORD);
  it("source → destination with protocol, service, named interfaces, bytes, packets and the traffic class", () => {
    expect(v.primaryVisual.kind).toBe("flow");
    if (v.primaryVisual.kind !== "flow") throw new Error();
    const f = v.primaryVisual.data;
    expect([f.source.address, f.source.port, f.destination.address, f.destination.port, f.protocol]).toEqual(["192.168.222.105", "161", "192.168.172.1", "38204", "UDP"]);
    expect(f.inInterfaceLabel).toBe("ge0/0 (1)");
    expect(f.outInterfaceLabel).toBe("ge0/3 (4)");
    expect(f.service).toBe("snmp (port 161, likely)");
    expect(f.trafficClass).toBe("Correlix's own polling");
    expect(v.sideStats.map((r) => [r.label, r.value])).toEqual([
      ["Bytes", "1,003"], ["Packets", "13"], ["Search index keeps", "1 in 50"], ["Exporter sampling", "None reported"],
    ]);
  });
});

describe("app, cloud, security and quarantine records use the same skeleton", () => {
  it("an app log: level, service, container, message, structured fields", () => {
    const v = toEventView(APP_LOG);
    expect(v.lane).toBe("app");
    expect(v.primaryVisual.kind).toBe("generic");
    if (v.primaryVisual.kind !== "generic") throw new Error();
    expect(v.primaryVisual.data.rows.map((r) => [r.label, r.value])).toEqual([
      ["Level", "Error"], ["Service", "api"], ["Container", "cx-api-1"], ["Component", "ticketing"], ["Trace ID", "4bf92f3577b34da6"],
    ]);
    expect(v.device.rows.map((r) => r.label)).toEqual(["Service", "Container"]);
    expect(v.title).toBe("ticket sync failed: upstream returned 502");
  });

  it("a cloud log: provider, account, region and resource", () => {
    const v = toEventView(CLOUD_LOG);
    expect(v.lane).toBe("cloud");
    expect(v.device.rows.map((r) => [r.label, r.value])).toEqual([
      ["Resource", "i-0abc123"], ["Provider", "aws"], ["Account", "123456789012"], ["Region", "us-east-1"],
    ]);
    expect(v.severity.tone).toBe("warning");
  });

  it("a security finding and a quarantined record have their own lane and key rows", () => {
    const s = toEventView(SECURITY_FINDING);
    expect(s.lane).toBe("security");
    expect(s.laneLabel).toBe("Security finding");
    if (s.primaryVisual.kind !== "generic") throw new Error();
    expect(s.primaryVisual.data.rows.map((r) => r.label)).toEqual(["Finding", "Resource", "Status", "Remediation"]);
    const q = toEventView(QUARANTINE_RECORD);
    expect(q.lane).toBe("quarantine");
    expect(row(q.classification, "reason")).toBe("tenant claim refused");
  });

  it("every fixture renders with a title, a severity or none, and the same sections", () => {
    for (const [name, hit] of Object.entries(ALL_FIXTURES)) {
      const v = toEventView(hit);
      expect(v.title, name).toBeTruthy();
      expect(v.primaryVisual.kind, name).toBeTruthy();
      expect(v.chips.some((c) => c.key === "signal"), name).toBe(true);
      expect(text(v), name).not.toContain(FIXTURE_SECRET);
    }
  });
});

describe("missing fields: nothing invented", () => {
  const v = toEventView(MINIMAL_TRAP);
  it("no severity, no metrics, no guidance, no identity, no recovery, no incident", () => {
    expect(v.severity).toEqual({ native: null, normalized: null, label: "", tone: null });
    expect(v.metrics).toEqual([]);
    expect(v.metricSeries).toBeNull();
    expect(v.overview).toMatchObject({ impact: [], nextChecks: [], basis: "" });
    expect(v.identity.rows).toEqual([]);
    expect(v.identity.recovery).toBeNull();
    expect(v.identity.lifecycle).toBeNull();
    expect(v.timelineQuery).toBeNull();
    expect(v.sideStats).toEqual([]);
    expect(v.primaryVisual.kind).toBe("generic");
    expect(v.device.inventory).toBeNull();
    expect(text(v)).not.toMatch(/incident status|recovered|Inventory Matched/i);
  });
  it("device fields the inventory left blank read as a dash, not a guess", () => {
    expect(row(v.device.rows, "type")).toBe(DASH);
    expect(row(v.device.rows, "site")).toBe(DASH);
    expect(row(v.device.rows, "role")).toBe(DASH);
  });
  it("a hostile device id never reaches a metric query", () => {
    const x = toEventView({ ...CPU_GOLDEN, _source: { ...CPU_GOLDEN._source, device_id: 'x"} or vector(1)' } });
    expect(x.metricSeries).toBeNull();
  });
});

describe("formatting", () => {
  it("UTC in the screenshots' shape, and local time when a zone is given", () => {
    expect(fmtUtc("2026-11-10T04:07:27.500Z")).toBe("2026-11-10 04:07:27.500 UTC");
    expect(fmtLocal("2026-11-10T04:07:27.500Z", "America/Chicago")).toBe("Nov 09, 2026 22:07:27.500 CST");
  });
});

describe("one severity → tone map", () => {
  it.each<[string, SeverityKey]>([
    ["emergency", "critical"], ["alert", "critical"], ["critical", "critical"], ["crit", "critical"], ["critical (1)", "critical"],
    ["error", "error"], ["err", "error"], ["major", "error"],
    ["warning", "warning"], ["warn", "warning"], ["minor", "warning"],
    ["notice", "notice"],
    ["info", "info"], ["informational", "info"],
    ["debug", "debug"],
    ["ok", "ok"], ["recovered", "ok"], ["clear", "ok"], ["cleared", "ok"],
  ])("%s → %s", (raw, key) => {
    expect(severityKey(raw)).toBe(key);
    expect(severityTone(raw).key).toBe(key);
  });

  it("uses the owner's palette on dark, a distinct hue per tone, and an icon for each", () => {
    expect(SEVERITY_TONES.critical.dark).toBe("#EF4444");
    expect(SEVERITY_TONES.warning.dark).toBe("#F59E0B");
    expect(SEVERITY_TONES.notice.dark).toBe("#38BDF8");
    expect(SEVERITY_TONES.ok.dark).toBe("#22C55E");
    expect(SEVERITY_TONES.debug.dark).toBe("#94A3B8");
    const hues = Object.values(SEVERITY_TONES).map((t) => t.dark);
    expect(new Set(hues).size).toBe(hues.length);
    for (const t of Object.values(SEVERITY_TONES)) expect(t.icon).toBeTruthy();
  });

  // WCAG 2.x relative luminance contrast.
  const lum = (hex: string) => {
    const c = [1, 3, 5].map((i) => parseInt(hex.slice(i, i + 2), 16) / 255).map((s) => (s <= 0.03928 ? s / 12.92 : ((s + 0.055) / 1.055) ** 2.4));
    return 0.2126 * c[0] + 0.7152 * c[1] + 0.0722 * c[2];
  };
  const ratio = (a: string, b: string) => { const [x, y] = [lum(a), lum(b)].sort((p, q) => q - p); return (x + 0.05) / (y + 0.05); };

  it.each(Object.values(SEVERITY_TONES).map((t) => [t.key, t] as const))("%s holds AA: solid pill text, light accent on white, dark accent on the dark canvas", (_k, t) => {
    expect(ratio(t.solid, t.on)).toBeGreaterThanOrEqual(4.5);
    expect(ratio(t.light, "#FFFFFF")).toBeGreaterThanOrEqual(4.5);
    expect(ratio(t.dark, "#121829")).toBeGreaterThanOrEqual(4.5);
  });

  it("the stylesheet carries the same hues as the map, for both themes", () => {
    const css = readFileSync(join(dirname(fileURLToPath(import.meta.url)), "../styles.css"), "utf-8");
    for (const t of Object.values(SEVERITY_TONES)) {
      expect(css, `${t.key} light`).toMatch(new RegExp(`--sev-${t.key}:\\s+${t.light};`));
      expect(css, `${t.key} dark`).toMatch(new RegExp(`--sev-${t.key}:\\s+${t.dark};`));
      expect(css, `${t.key} solid`).toMatch(new RegExp(`--sev-${t.key}-solid:\\s+${t.solid};\\s+--sev-${t.key}-on:\\s+${t.on};`));
    }
  });
});

describe("the timeline only filters on fields the index can answer", () => {
  const templates = JSON.parse(readFileSync(join(dirname(fileURLToPath(import.meta.url)), "../../../../deployment/docker/opensearch/index-templates.json"), "utf-8"));
  const mapped = (pattern: string): string[] => {
    for (const t of Object.values<any>(templates.templates)) {
      if ((t.index_patterns ?? []).includes(pattern)) return Object.keys(t.template?.mappings?.properties ?? t.mappings?.properties ?? {});
    }
    return [];
  };
  it.each([["trap", "netops-snmptrap-*"], ["syslog", "netops-syslog-*"]] as const)("%s", (lane, pattern) => {
    const fields = mapped(pattern);
    expect(fields.length).toBeGreaterThan(5);
    for (const f of TIMELINE_SEARCHABLE[lane] ?? []) expect(fields, f).toContain(f);
  });
  it("adopts the correlation key the moment it is mapped (today it is not)", () => {
    const trapFields = mapped("netops-snmptrap-*");
    for (const k of TIMELINE_KEYS) {
      expect(trapFields.includes(k), `${k} is now mapped: add it to TIMELINE_SEARCHABLE.trap`).toBe((TIMELINE_SEARCHABLE.trap ?? []).includes(k));
    }
  });
});

describe("identity fields that look like secrets", () => {
  it("correlation_key and dedup_key are ids and stay readable", () => {
    const v = toEventView(CPU_GOLDEN);
    expect(v.raw.correlation_key).toBe("cpu:vedge-51-0a0b4db5:device");
  });
  it("snmp_community_present is shown only as a boolean; a string there is hidden", () => {
    const v = toEventView({ ...CPU_GOLDEN, _source: { ...CPU_GOLDEN._source, snmp_community_present: FIXTURE_SECRET } });
    expect(v.raw.snmp_community_present).toBe("hidden");
    expect(v.classification.find((r) => r.key === "community")).toBeUndefined();
    expect(JSON.stringify(v)).not.toContain(FIXTURE_SECRET);
  });
});

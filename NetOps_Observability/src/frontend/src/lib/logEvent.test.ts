// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  HIDDEN,
  LogSignal,
  SEARCHABLE_FILTER_FIELDS,
  SIGNAL_INDEX_PATTERN,
  addClause,
  buildFacets,
  clauseText,
  isSecretName,
  luceneQuote,
  queryHasClause,
  redactSecrets,
  redactText,
  removeClause,
  toLogEvent,
} from "./logEvent";
import { severityKey, severityLabel, severityVar } from "../theme/severity";

// The three record shapes measured on the lab. They are deliberately the awkward
// ones: a trap nobody can name yet, a syslog line the parser gave up on, and a flow
// carrying two different sampling values.
const VIPTELA_TRAP = {
  _index: "netops-snmptrap-global-2026.11.09",
  _id: "t1",
  _source: {
    timestamp: "2026-11-09T01:35:01.120Z",
    signal: "snmptrap",
    _signal: "snmptrap",
    host: "192.168.222.102",
    hostname: "192.168.222.102",
    device: "",
    snmp_version: "v2c",
    snmp_community: "s3cr3t-community",
    authenticated: false,
    trap_oid: "1.3.6.1.4.1.41916.100.2.27",
    trap_name: "enterpriseSpecific",
    event_type: "enterprise_specific",
    severity: "notice",
    sys_uptime_human: "3d 4h",
    parser_status: "partially_decoded",
    message: "enterpriseSpecific 1.3.6.1.4.1.41916.100.2.27 sysUpTime=27300000",
    varbinds: [
      { name: "sysUpTime", oid: "1.3.6.1.2.1.1.3.0", value: "27300000" },
      { oid: "1.3.6.1.4.1.41916.100.1.54.0", value: "System cpu usage back to normal level" },
      { oid: "1.3.6.1.4.1.41916.100.1.190.0", value: "12.23" },
    ],
    tenant_attribution: "unmatched",
    tenant_seg: "global",
    tenant_registry: "miss",
    topic: "netops.snmptrap",
    partition: 3,
    offset: 991823,
    source_type: "kafka",
    message_key: "abc123",
    ts_source: "event",
    log_index_base: "netops-snmptrap",
    headers: { traceparent: "00-aa" },
    path: "/ingest",
    version: "1",
    cx_admission: { v: "1", by: "router" },
  },
};

const CONFD_SYSLOG = {
  _index: "netops-syslog-global-2026.11.09",
  _id: "s1",
  _source: {
    timestamp: "2026-11-09T01:54:30Z",
    signal: "syslog",
    hostname: "vEdge-52",
    source_ip: "192.168.222.102",
    appname: "confd",
    facility: "user",
    severity: "notice",
    vendor: "unknown",
    parser_status: "unparsed",
    message: "4220 - - audit user: ciscosdwan/980840 created new session via snmp from 127.0.0.1:54511 with udp",
    tenant_attribution: "unmatched",
    topic: "netops.syslog",
  },
};

const IPFIX_FLOW = {
  _index: "netops-flows-global-2026.11.09",
  _id: "f1",
  _source: {
    timestamp: "2026-11-09T01:53:15Z",
    signal: "netflow",
    src_addr: "192.168.222.105",
    dst_addr: "192.168.172.1",
    src_port: 161,
    dst_port: 38204,
    proto: 17,
    sampler_address: "192.168.222.104",
    in_if: 1,
    out_if: 4,
    bytes: 1003,
    packets: 13,
    sample_rate: 50,
    sampling_rate: 0,
    tenant_attribution: "unmatched",
    partition: 1,
  },
};

const everyVisibleString = (ev: ReturnType<typeof toLogEvent>): string =>
  JSON.stringify({ ...ev, pipeline: undefined, raw: undefined });

describe("toLogEvent — today's records", () => {
  it("a trap nobody can name yet says so, with its OID and numeric varbinds", () => {
    const ev = toLogEvent(VIPTELA_TRAP);
    expect(ev.signal).toBe("trap");
    expect(ev.signalLabel).toBe("Trap");
    expect(ev.severity).toBe("notice");
    expect(ev.title).toBe("enterpriseSpecific");
    expect(ev.chips.filter((c) => c.stream).map((c) => c.label)).toEqual(["Not decoded yet"]);
    expect(ev.detailLine).toContain("1.3.6.1.4.1.41916.100.2.27");
    expect(ev.deviceLabel).toBe("192.168.222.102");
    expect(ev.deviceAddress).toBe("");
    expect(ev.varbinds?.[0]).toMatchObject({ label: "sysUpTime", numeric: false });
    expect(ev.varbinds?.[1]).toMatchObject({ label: "1.3.6.1.4.1.41916.100.1.54.0", numeric: true });
    // No client-side Viptela decoding, no guessed lifecycle from "back to normal".
    expect(ev.lifecycle).toBeUndefined();
    expect(everyVisibleString(ev)).not.toMatch(/viptelaSystem|recovered/i);
  });

  it("a named trap leads with its name and shows its named values", () => {
    const ev = toLogEvent({
      _index: "netops-snmptrap-t-2026.11.09",
      _source: {
        trap_name: "bgpBackwardTransition", trap_oid: "1.3.6.1.2.1.15.7.2", severity: "warning", device: "edge-1", host: "10.0.0.1",
        varbinds: [
          { name: "sysUpTime", oid: "1.3.6.1.2.1.1.3.0", value: "7" },
          { name: "bgpPeerState", oid: "1.3.6.1.2.1.15.3.1.2", value: "idle(1)" },
        ],
      },
    });
    expect(ev.title).toBe("bgpBackwardTransition");
    expect(ev.detailLine).toBe("bgpPeerState=idle(1)");
    expect(ev.chips).toEqual([]);
    expect(ev.deviceLabel).toBe("edge-1");
    expect(ev.deviceAddress).toBe("10.0.0.1");
  });

  it("an unparsed syslog line shows the message as it came and no 'unknown' vendor", () => {
    const ev = toLogEvent(CONFD_SYSLOG);
    expect(ev.signal).toBe("syslog");
    expect(ev.deviceLabel).toBe("vEdge-52");
    expect(ev.deviceAddress).toBe("192.168.222.102");
    expect(ev.vendor).toBe("");
    expect(ev.detailLine).toBe("confd");
    expect(everyVisibleString(ev)).not.toContain('"vendor":"unknown"');
    // The envelope is the backend parser's to fix: no client-side RFC decoding.
    expect(ev.title.startsWith("4220 - - audit")).toBe(true);
    expect(ev.syslog?.pills).toEqual([
      { name: "Facility", value: "user" },
      { name: "Severity", value: "notice" },
      { name: "App", value: "confd" },
    ]);
    expect(ev.chips).toEqual([{ label: "Not parsed yet", stream: false }]);
  });

  it("an unknown hostname falls back to the address rather than reading 'unknown'", () => {
    const ev = toLogEvent({ _index: "netops-syslog-x", _source: { hostname: "unknown", source_ip: "10.1.1.1", message: "m" } });
    expect(ev.deviceLabel).toBe("10.1.1.1");
    expect(ev.deviceAddress).toBe("");
    expect(ev.deviceClause).toBeUndefined();
  });

  it("a flow reads as source → destination with the values it reported and nothing more", () => {
    const ev = toLogEvent(IPFIX_FLOW);
    expect(ev.signal).toBe("flow");
    expect(ev.title).toBe("192.168.222.105 → 192.168.172.1");
    expect(ev.detailLine).toBe("UDP 161 → 38204 · 1,003 bytes · 13 packets");
    expect(ev.severity).toBeNull();
    expect(ev.deviceLabel).toBe("192.168.222.104");
    expect(ev.flow).toMatchObject({
      exporter: "192.168.222.104", protocol: "UDP", inInterface: "1", outInterface: "4",
      bytes: "1,003", packets: "13",
      sampling: [{ name: "Search index keeps", value: "1 in 50" }, { name: "Exporter sampling", value: "None reported" }],
    });
    // Sampling is reported, not interpreted, and traffic is never estimated.
    expect(everyVisibleString(ev)).not.toMatch(/ambiguous|estimated|bps|1:50/);
  });

  it("an interface the API named reads `name (index)`, otherwise the index (tracker 387 PR 13b)", () => {
    const named = toLogEvent({
      ...IPFIX_FLOW,
      _resolved: {
        in_if_name: "ge0/3", in_if_name_basis: "resolved",
        out_if_name: "", out_if_name_basis: "absent",
        service_name: "snmp", service_port: 161,
      },
    });
    expect(named.flow?.inInterfaceLabel).toBe("ge0/3 (1)");
    expect(named.flow?.outInterfaceLabel).toBe("4");
    expect(named.flow?.service).toBe("snmp (port 161, likely)");
    // Without the API's names the index stands alone, and nothing is invented.
    const bare = toLogEvent(IPFIX_FLOW);
    expect(bare.flow?.inInterfaceLabel).toBe("1");
    expect(bare.flow?.service).toBe("");
    const sentinel = toLogEvent({
      _index: "netops-flows-x",
      _source: { src_addr: "1.1.1.1", in_if: 4294967295 },
      _resolved: { in_if_name: "", in_if_name_basis: "sentinel" },
    });
    expect(sentinel.flow?.inInterfaceLabel).toBe("none reported (4294967295)");
    // A name without the resolved basis is not shown.
    const unproven = toLogEvent({ ...IPFIX_FLOW, _resolved: { in_if_name: "ge0/3", in_if_name_basis: "absent" } });
    expect(unproven.flow?.inInterfaceLabel).toBe("1");
  });

  it("names a protocol from the shared table and marks one it cannot name", () => {
    const proto = (p: unknown) => toLogEvent({ _index: "netops-flows-x", _source: { src_addr: "1.1.1.1", proto: p } }).flow?.protocol;
    expect(proto(6)).toBe("TCP");
    expect(proto(47)).toBe("GRE");
    expect(proto(200)).toBe("IP/200");
    expect(proto("tcp")).toBe("TCP");
  });

  it("the tenant value 'unmatched' never reaches a stream or summary field", () => {
    for (const hit of [VIPTELA_TRAP, CONFD_SYSLOG, IPFIX_FLOW]) {
      const ev = toLogEvent(hit);
      expect(everyVisibleString(ev), hit._id).not.toContain("unmatched");
      expect(ev.pipeline.tenant_attribution).toBe("unmatched");
    }
  });

  it("a record with no message says so instead of dumping itself as JSON", () => {
    const ev = toLogEvent({ _index: "netops-applogs-x", _source: { container_name: "api" } });
    expect(ev.title).toBe("No message");
    expect(ev.signal).toBe("app");
    expect(ev.deviceLabel).toBe("api");
  });

  it("a missing timestamp stays missing rather than reading as now", () => {
    expect(toLogEvent({ _index: "netops-syslog-x", _source: { message: "m" } }).time).toBe("");
  });

  it("classifies by index, then by the record itself", () => {
    expect(toLogEvent({ _index: "netops-platformlogs-x", _source: {} }).signal).toBe("app");
    expect(toLogEvent({ _index: "netops-cloudlogs-x", _source: {} }).signal).toBe("cloud");
    expect(toLogEvent({ _index: "elsewhere", _source: { trap_oid: "1.3" } }).signal).toBe("trap");
    expect(toLogEvent({ _index: "elsewhere", _source: { src_addr: "1.1.1.1" } }).signal).toBe("flow");
    expect(toLogEvent({ _index: "elsewhere", _source: {} }).signal).toBe("other");
    expect(toLogEvent({ _source: null }).signal).toBe("other");
  });
});

describe("toLogEvent — richer fields win when they arrive", () => {
  it("prefers the summary over the raw message", () => {
    const ev = toLogEvent({ _index: "netops-syslog-x", _source: { summary: "Session created", message: "4220 - - audit" } });
    expect(ev.title).toBe("Session created");
  });

  it("prefers the canonical event name, which also retires the not-decoded chip", () => {
    const ev = toLogEvent({
      _index: "netops-snmptrap-x",
      _source: { trap_name: "enterpriseSpecific", trap_oid: "1.3.6", event: { name: "viptelaSystemCpuUsage" } },
    });
    expect(ev.title).toBe("viptelaSystemCpuUsage");
    expect(ev.chips).toEqual([]);
  });

  it("prefers the canonical parser status", () => {
    const ev = toLogEvent({ _index: "netops-syslog-x", _source: { parser: { status: "decoded" }, parser_status: "unparsed", message: "m" } });
    expect(ev.chips).toEqual([]);
  });

  it("prefers native severity and shows a stated lifecycle next to it, independently", () => {
    const ev = toLogEvent({ _index: "netops-snmptrap-x", _source: { native_severity: "minor", severity: "notice", event: { action: "recovered" } } });
    expect(ev.severity).toBe("minor");
    expect(ev.lifecycle).toBe("recovered");
    // Filtering needs a field the index can answer, and this one is not it.
    expect(ev.severityClause).toBeUndefined();
  });

  it("shows the PRI facility, falling back to the grammar's facility", () => {
    const pill = (source: Record<string, unknown>) =>
      toLogEvent({ _index: "netops-syslog-x", _source: { message: "m", ...source } })
        .syslog?.pills.find((p) => p.name === "Facility")?.value;
    expect(pill({ syslog_facility: "local7", facility: "LINK" })).toBe("local7");
    expect(pill({ facility: "LINK" })).toBe("LINK");
    expect(pill({})).toBeUndefined();
  });

  it("hides secrets in the raw frame and the sender's structured data", () => {
    const ev = toLogEvent({
      _index: "netops-syslog-x",
      _source: {
        message: "m",
        message_original: "<189>Nov  9 09:00:01 r1 app: login password=hunter2 ok",
        structured_data: '[a@1 snmp_community="public"]',
      },
    });
    expect(ev.raw.message_original).toBe("<189>Nov  9 09:00:01 r1 app: login password=hidden ok");
    expect(ev.raw.structured_data).not.toContain("public");
  });

  it("reads the canonical syslog, device and flow blocks", () => {
    const sys = toLogEvent({
      _index: "netops-syslog-x",
      _source: {
        event: { message: "audit user created", name: "cisco.sdwan.session.created" },
        device: { hostname: "vEdge-52", observed_address: "10.0.0.2", vendor: "cisco" },
        syslog: { app_name: "confd", procid: "4220", facility: "user", severity: "notice" },
      },
    });
    expect(sys.title).toBe("audit user created");
    expect(sys.deviceLabel).toBe("vEdge-52");
    expect(sys.deviceAddress).toBe("10.0.0.2");
    expect(sys.vendor).toBe("cisco");
    expect(sys.detailLine).toBe("confd · cisco · cisco.sdwan.session.created");
    expect(sys.syslog?.pills.map((p) => p.name)).toEqual(["Facility", "Severity", "App", "Process"]);

    const fl = toLogEvent({
      _index: "netops-flows-x",
      _source: {
        exporter: { address: "10.9.9.9", name: "edge-9" },
        network: {
          source: { address: "10.0.0.1", port: 1 }, destination: { address: "10.0.0.2", port: 2 },
          transport: { number: 17, name: "udp" }, ingress: { interface: { index: 7 } },
        },
        flow: { bytes: { observed: 5 }, packets: { observed: 1 } },
        sampling_rate: 100,
      },
    });
    expect(fl.title).toBe("10.0.0.1 → 10.0.0.2");
    expect(fl.deviceLabel).toBe("edge-9");
    expect(fl.deviceAddress).toBe("10.9.9.9");
    expect(fl.flow?.protocol).toBe("UDP");
    expect(fl.flow?.inInterface).toBe("7");
    expect(fl.flow?.sampling).toEqual([{ name: "Exporter sampling", value: "1 in 100" }]);
  });
});

describe("secrets never leave the presenter", () => {
  it("replaces the community everywhere, including the copy a raw view reads", () => {
    const ev = toLogEvent(VIPTELA_TRAP);
    expect(JSON.stringify(ev)).not.toContain("s3cr3t-community");
    expect(ev.raw.snmp_community).toBe(HIDDEN);
    expect(ev.fields.find((f) => f.name === "snmp_community")?.value).toBe(HIDDEN);
    // The input is left alone: this is a copy, not a mutation of the search result.
    expect(VIPTELA_TRAP._source.snmp_community).toBe("s3cr3t-community");
  });

  it.each([
    "snmp_community", "community", "snmpCommunity", "communities", "password", "user_password",
    "secret", "clientSecret", "token", "access_token", "accessToken", "api_key", "apiKey",
    "authKey", "private-key", "privKey", "key", "Authorization", "credentials", "community_string",
  ])("%s is treated as a secret", (name) => {
    expect(isSecretName(name)).toBe(true);
  });

  it.each(["keyword", "monkey", "hostname", "severity", "trap_oid", "authenticated", "message", "tcp_flags", "snmp_user", "message_key", "bgp_communities", "bgpCommunities"])(
    "%s is not",
    (name) => {
      expect(isSecretName(name)).toBe(false);
    },
  );

  it("reaches nested objects, arrays and a whole secret subtree", () => {
    const out = redactSecrets({
      a: { b: [{ password: "x1" }] },
      credentials: { user: "u", other: "x2" },
      fine: { keep: "y" },
    });
    expect(JSON.stringify(out)).not.toMatch(/x1|x2/);
    expect(out.fine.keep).toBe("y");
    expect(out.credentials).toBe(HIDDEN);
  });

  it("hides a varbind that names itself as a secret, by name or by OID", () => {
    const out = redactSecrets({
      varbinds: [
        { name: "snmpTrapCommunity", oid: "1.3.6.1.6.3.18.1.4.0", value: "pub1" },
        { oid: "1.3.6.1.6.3.18.1.4.0", value: "pub2" },
        { oid: "1.3.6.1.2.1.1.3.0", value: "keep" },
      ],
    });
    expect(JSON.stringify(out)).not.toMatch(/pub1|pub2/);
    expect(out.varbinds[2].value).toBe("keep");
  });

  it("hides secrets quoted inside free text", () => {
    expect(redactText("login snmp_community=public from a")).toBe("login snmp_community=hidden from a");
    expect(redactText('{"snmp_community":"public","x":1}')).toBe('{"snmp_community":"hidden","x":1}');
    expect(redactText("password: 'hunter 2' ok")).toBe("password: 'hidden' ok");
    expect(redactText("1.3.6.1.6.3.18.1.4.0=public next")).toBe("1.3.6.1.6.3.18.1.4.0=hidden next");
    expect(redactText("interface up")).toBe("interface up");
    const ev = toLogEvent({ _index: "netops-syslog-x", _source: { message: "auth token=abc123 failed" } });
    expect(JSON.stringify(ev)).not.toContain("abc123");
  });

  it("does not stall on a hostile message", () => {
    const hostile = `${"a".repeat(200_000)} ${"token".repeat(20_000)}`;
    const started = performance.now();
    redactText(hostile);
    expect(performance.now() - started).toBeLessThan(2000);
  });
});

describe("pipeline fields stay out of the way", () => {
  const PIPELINE = ["partition", "offset", "topic", "source_type", "message_key", "log_index_base", "headers",
    "tenant_seg", "tenant_registry", "ts_source", "path", "version", "cx_admission"];

  it("moves them out of Fields and into pipeline{}", () => {
    const ev = toLogEvent(VIPTELA_TRAP);
    const names = ev.fields.map((f) => f.name.split(".")[0]);
    for (const p of PIPELINE) {
      expect(names, p).not.toContain(p);
      expect(ev.pipeline, p).toHaveProperty(p);
    }
    expect(ev.pipeline._index).toBe(VIPTELA_TRAP._index);
  });

  it("sorts what is left by name", () => {
    const names = toLogEvent(VIPTELA_TRAP).fields.map((f) => f.name);
    expect(names).toEqual([...names].sort((a, b) => a.localeCompare(b)));
    expect(names).toContain("trap_oid");
  });
});

describe("hostile values stay data", () => {
  it("returns markup untouched for React to escape, and never alters it into something else", () => {
    const xss = '<img src=x onerror="alert(1)">';
    const ev = toLogEvent({ _index: "netops-syslog-x", _source: { message: xss, hostname: xss, appname: xss } });
    expect(ev.title).toBe(xss);
    expect(ev.deviceLabel).toBe(xss);
  });

  it("survives non-scalar values where a scalar is expected", () => {
    const ev = toLogEvent({
      _index: "netops-snmptrap-x",
      _source: { message: { a: 1 }, severity: ["x"], varbinds: "nope", trap_name: 7, hostname: { evil: true } },
    });
    expect(ev.title).toBe("7");
    expect(ev.severity).toBeNull();
    expect(ev.varbinds).toBeUndefined();
    expect(ev.deviceLabel).toBe("");
  });
});

describe("quick filters", () => {
  it("quotes values and escapes what would break out of the quotes", () => {
    expect(luceneQuote("edge-1")).toBe('"edge-1"');
    expect(luceneQuote('a"b')).toBe('"a\\"b"');
    expect(luceneQuote("a\\b")).toBe('"a\\\\b"');
    expect(luceneQuote('x" OR tenant_id:"other')).toBe('"x\\" OR tenant_id:\\"other"');
    expect(luceneQuote("a\nb\u0000c")).toBe('"a b c"');
    expect(clauseText({ field: "hostname", value: "core 1" })).toBe('hostname:"core 1"');
  });

  const dev = { field: "hostname", value: "edge-1" };
  const sev = { field: "severity", value: "err" };

  it("replaces the match-all query", () => {
    expect(addClause("*", dev)).toBe('hostname:"edge-1"');
    expect(addClause("  ", dev)).toBe('hostname:"edge-1"');
  });

  it("keeps a chain flat and keeps an OR or bare words together", () => {
    const chained = addClause(addClause("*", dev), sev);
    expect(chained).toBe('hostname:"edge-1" AND severity:"err"');
    expect(addClause("a OR b", dev)).toBe('(a OR b) AND hostname:"edge-1"');
    expect(addClause("link down", dev)).toBe('(link down) AND hostname:"edge-1"');
    expect(addClause("linkdown", dev)).toBe('linkdown AND hostname:"edge-1"');
    expect(addClause('msg:"x y" AND z', dev)).toBe('msg:"x y" AND z AND hostname:"edge-1"');
  });

  it("does not add the same clause twice, and takes it back out", () => {
    const q = addClause(addClause("*", dev), sev);
    expect(addClause(q, dev)).toBe(q);
    expect(queryHasClause(q, dev)).toBe(true);
    expect(queryHasClause(q, sev)).toBe(true);
    expect(queryHasClause(q, { field: "severity", value: "e" })).toBe(false);
    expect(removeClause(q, sev)).toBe('hostname:"edge-1"');
    expect(removeClause(q, dev)).toBe('severity:"err"');
    expect(removeClause('hostname:"edge-1"', dev)).toBe("*");
    expect(removeClause(`(a OR b) AND ${clauseText(dev)}`, dev)).toBe("(a OR b)");
  });

  it("counts only what it is given, grouped by the exact value to search for", () => {
    const f = buildFacets([VIPTELA_TRAP, CONFD_SYSLOG, CONFD_SYSLOG, IPFIX_FLOW].map(toLogEvent));
    expect(f.severity).toEqual([
      expect.objectContaining({ label: "notice", count: 3, clause: { field: "severity", value: "notice" } }),
    ]);
    expect(f.signal.map((s) => [s.signal, s.count])).toEqual([["syslog", 2], ["flow", 1], ["trap", 1]]);
    expect(f.device.find((d) => d.label === "vEdge-52")?.clause).toEqual({ field: "hostname", value: "vEdge-52" });
    expect(f.device.find((d) => d.label === "192.168.222.104")?.clause).toEqual({ field: "sampler_address", value: "192.168.222.104" });
  });

  it("offers no filter for a value that is not there or not valid for the field", () => {
    expect(toLogEvent(IPFIX_FLOW).severityClause).toBeUndefined();
    expect(toLogEvent({ _index: "netops-flows-x", _source: { sampler_address: "not-an-ip" } }).deviceClause).toBeUndefined();
    expect(toLogEvent({ _index: "elsewhere", _source: { hostname: "h", severity: "err" } }).deviceClause).toBeUndefined();
  });

  it("an app log filters on level, the field its index maps", () => {
    const ev = toLogEvent({ _index: "netops-applogs-x", _source: { level: "error", compose_service: "api", container_name: "cx-api-1" } });
    expect(ev.severityClause).toEqual({ field: "level", value: "error" });
    expect(ev.deviceLabel).toBe("api");
    expect(ev.deviceClause).toEqual({ field: "container_name", value: "cx-api-1" });
  });

  // The indices are dynamic=false: an unmapped field is stored and not searchable,
  // so a filter on it would silently find nothing. This reads the real templates.
  it("every field a filter can use is mapped in the index it searches", () => {
    const here = dirname(fileURLToPath(import.meta.url));
    const file = join(here, "../../../../deployment/docker/opensearch/index-templates.json");
    const templates = Object.values(JSON.parse(readFileSync(file, "utf-8")).templates as Record<string, any>);
    const mapped = (pattern: string): string[] => {
      const t = templates.find((x) => x.index_patterns?.includes(pattern));
      expect(t, `no template for ${pattern}`).toBeTruthy();
      return Object.keys((t.template ?? t).mappings.properties);
    };
    for (const [signal, fields] of Object.entries(SEARCHABLE_FILTER_FIELDS) as [LogSignal, readonly string[]][]) {
      const pattern = SIGNAL_INDEX_PATTERN[signal];
      if (!pattern) {
        expect(fields, signal).toEqual([]);
        continue;
      }
      const props = mapped(pattern);
      for (const f of fields) expect(props, `${f} on ${pattern}`).toContain(f);
    }
  });
});

describe("one severity authority", () => {
  it.each([
    ["emerg", "critical", "Emergency"],
    ["alert", "critical", "Alert"],
    ["crit", "critical", "Critical"],
    ["err", "error", "Error"],
    ["warn", "warning", "Warning"],
    ["notice", "notice", "Notice"],
    ["informational", "info", "Info"],
    ["debug", "debug", "Debug"],
    ["3", "error", "Error"],
  ])("%s colours as %s and reads as %s", (raw, key, label) => {
    expect(severityKey(raw)).toBe(key);
    expect(severityVar(raw)).toBe(`var(--sev-${key})`);
    expect(severityLabel(raw)).toBe(label);
  });

  it("shows a spelling it does not know as the record gave it", () => {
    expect(severityLabel("minor")).toBe("minor");
    expect(severityLabel(null)).toBe("");
  });

  it("the stylesheet has a chip for every level and no second severity palette", () => {
    const css = readFileSync(join(dirname(fileURLToPath(import.meta.url)), "../styles.css"), "utf-8");
    for (const key of ["critical", "error", "warning", "notice", "info", "debug", "ok"]) {
      expect(css).toContain(`.lf-sev-${key} { --lf-sev: var(--sev-${key}); --lf-sev-bg: var(--sev-${key}-bg); }`);
    }
    expect(css).not.toMatch(/\.lf-(crit|err|warn|notice|info|debug)\b/);
  });
});

describe("ownership wording (tracker 387 D6)", () => {
  it.each([
    ["platform_owned", "Platform device"],
    ["enriched", "Tenant device"],
    ["unmatched", "Unknown device"],
  ])("%s reads as %s, and the raw value stays out of the details fields", (outcome, words) => {
    const ev = toLogEvent({ _index: "netops-syslog-untagged-2026.11.09", _source: { message: "x", tenant_attribution: outcome } });
    expect(ev.owner).toBe(words);
    expect(ev.fields.some((f) => f.name === "tenant_attribution")).toBe(false);
  });

  it("a record with no attribution claims no owner", () => {
    expect(toLogEvent({ _index: "netops-syslog-untagged-2026.11.09", _source: { message: "x" } }).owner).toBe("");
  });
});

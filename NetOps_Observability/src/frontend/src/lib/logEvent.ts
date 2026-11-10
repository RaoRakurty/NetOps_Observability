// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// logEvent — the pure presenter behind the Logs page. It turns one search hit
// into what an operator reads, and it is the only place that knows the record
// shapes. Two rules shape every line below:
//
//   1. It reads what the record SAYS. Canonical fields win when a record carries
//      them, today's flat fields are the fallback, and anything the record does
//      not state stays absent. No vendor decoding, no guessed lifecycle, no
//      estimated bandwidth and no reading of what a sampling value means: that
//      work belongs to the ingest parsers, and their output shows up here by
//      itself.
//   2. Every value is untrusted. It is returned as data for React to escape, and
//      secrets are replaced before anything else looks at the record, so no view,
//      tooltip or client-built export can reach the original value.

import { attributionLabel } from "./tenantOwner";
import { IANA_PROTO_NAMES } from "../proto";

export type LogSignal = "syslog" | "trap" | "flow" | "app" | "cloud" | "other";

export const SIGNAL_LABEL: Record<LogSignal, string> = {
  syslog: "Syslog",
  trap: "Trap",
  flow: "Flow",
  app: "App",
  cloud: "Cloud",
  other: "Log",
};

export const HIDDEN = "hidden";

export interface LogChip {
  label: string;
  /** Also shown on the stream row. Most chips are for the details view only. */
  stream: boolean;
}

export interface LogField {
  name: string;
  value: string;
}

export interface LogVarbind {
  /** The symbolic name when the record has one, otherwise the numeric OID. */
  label: string;
  /** True when `label` is a numeric OID. */
  numeric: boolean;
  oid: string;
  value: string;
}

export interface FlowEndpoint {
  address: string;
  port: string;
}

export interface FlowView {
  exporter: string;
  exporterName: string;
  source: FlowEndpoint;
  destination: FlowEndpoint;
  protocol: string;
  inInterface: string;
  outInterface: string;
  /**
   * The interface as an operator reads it: `ge0/3 (4)` when the API named the
   * index (tracker 387 PR 13b), `4` when it could not, and `none reported (0)` for
   * the IPFIX "no interface" sentinels. Never a name the API did not give.
   */
  inInterfaceLabel: string;
  outInterfaceLabel: string;
  /** The likely service on the lower port, from the IANA registry: a heuristic. */
  service: string;
  /** A flow to or from Correlix's own pollers (traffic_class=platform_monitoring). */
  platformMonitoring: boolean;
  packets: string;
  bytes: string;
  /** The search-index sample and the exporter's own sampling, labelled apart. */
  sampling: LogField[];
}

export interface SyslogView {
  pills: LogField[];
  message: string;
}

/** A `field:value` search clause the mapped index can actually answer. */
export interface LogClause {
  field: string;
  value: string;
}

export interface LogEvent {
  signal: LogSignal;
  signalLabel: string;
  time: string;
  severity: string | null;
  deviceLabel: string;
  deviceAddress: string;
  /** How the record got its owner, in operator words. Never who may read it. */
  owner: string;
  vendor: string;
  title: string;
  detailLine: string;
  lifecycle?: string;
  chips: LogChip[];
  fields: LogField[];
  varbinds?: LogVarbind[];
  flow?: FlowView;
  syslog?: SyslogView;
  /** Trap identity, kept apart so the details view can set it in mono. */
  /**
   * `interface` is the receiver's port, as an operator reads it (tracker 387 PR 13c):
   * `ge0/3 (4)` when named, `4` when only the index is known; `interfaceHow` says
   * how it was named. Empty when the trap is about no interface.
   */
  trap?: { oid: string; uptime: string; interface: string; interfaceHow: string };
  message: string;
  pipeline: Record<string, unknown>;
  raw: Record<string, any>;
  severityClause?: LogClause;
  deviceClause?: LogClause;
}

// ── secrets ──────────────────────────────────────────────────────────────────
//
// Defence in depth: the server is being fixed as well, but a record that still
// carries a community string must not reach the screen, the clipboard or a
// client-built export. "key" and "token" match as whole words or with a known
// prefix so `keyword` and `monkey` survive; the others match anywhere in the name.
const SECRET_ANYWHERE = /communit|passw|passphrase|secret|credential|authorization|cookie/i;
const SECRET_WORD = /(^|_)(key|keys|token|tokens|pwd|psk|bearer)(_|$)/;
const SECRET_JOINED = /(api|auth|priv|private|access|ssh|enc|sign|session)(key|token)/;
// snmpTrapCommunity.0 (RFC 3584): the community travels as a varbind on proxied traps.
const COMMUNITY_OID = "1.3.6.1.6.3.18.1.4";

function isCommunityOid(oid: string): boolean {
  return oid === COMMUNITY_OID || oid.startsWith(`${COMMUNITY_OID}.`);
}

// Names the patterns would catch but which hold no secret: a dedup key, and BGP
// communities, which are routing data an operator needs to read. Exact names only,
// so anything unrecognised stays hidden.
const NOT_SECRET = new Set([
  "message_key", "__key", "partition_key", "routing_key", "sort_key", "primary_key",
  // Event identity (tracker 387): the alarm's correlation key and the syslog dedup key
  // are ids an operator copies, not credentials.
  "correlation_key", "dedup_key",
  "bgp_community", "bgp_communities", "large_communities", "extended_communities",
]);

// Names that would read as secrets but are booleans by contract ("a community was
// present"). Shown only while they ARE booleans: any other value is hidden.
const BOOLEAN_ONLY = new Set(["snmp_community_present"]);

export function isSecretName(name: string): boolean {
  const snake = name.replace(/([a-z0-9])([A-Z])/g, "$1_$2").replace(/[.\-\s]+/g, "_").toLowerCase();
  if (NOT_SECRET.has(snake)) return false;
  if (SECRET_ANYWHERE.test(name)) return true;
  return SECRET_WORD.test(snake) || SECRET_JOINED.test(snake);
}

// A device controls this text, so the scan must stay linear: the lookbehind starts
// a name only at the head of a word, which keeps one long word from being re-read
// from every position, and the name itself is judged in code, not in the pattern.
const TEXT_PAIR = /(?<![\w.-])([\w.-]+)(["']?\s*[=:]\s*)("(?:[^"\\]|\\.)*"|'[^']*'|[^\s,;&}\]]+)/g;
const TEXT_COMMUNITY_OID = /(\b1\.3\.6\.1\.6\.3\.18\.1\.4(?:\.\d+)*\s*[=:]\s*)[^\s,;&}\]]+/g;

/** Hides `name=value` secrets inside free text (a message can quote a whole record). */
export function redactText(text: string): string {
  const named = text.replace(TEXT_PAIR, (whole: string, name: string, sep: string, value: string) => {
    if (!isSecretName(name)) return whole;
    const q = value[0] === '"' || value[0] === "'" ? value[0] : "";
    return `${name}${sep}${q}${HIDDEN}${q}`;
  });
  return named.includes(COMMUNITY_OID) ? named.replace(TEXT_COMMUNITY_OID, `$1${HIDDEN}`) : named;
}

const MAX_DEPTH = 32;

/** A copy of `value` with every secret replaced. The input is never mutated. */
export function redactSecrets<T>(value: T, depth = 0): T {
  if (depth > MAX_DEPTH) return HIDDEN as unknown as T;
  if (typeof value === "string") return redactText(value) as unknown as T;
  if (Array.isArray(value)) return value.map((v) => redactSecrets(v, depth + 1)) as unknown as T;
  if (value && typeof value === "object") {
    const rec = value as Record<string, unknown>;
    // A varbind names itself through its siblings, not through its key.
    const labelled = "value" in rec && (
      (typeof rec.name === "string" && isSecretName(rec.name)) ||
      (typeof rec.oid === "string" && isCommunityOid(rec.oid))
    );
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(rec)) {
      if (BOOLEAN_ONLY.has(k)) out[k] = typeof v === "boolean" ? v : HIDDEN;
      else out[k] = isSecretName(k) || (labelled && k === "value") ? HIDDEN : redactSecrets(v, depth + 1);
    }
    return out as T;
  }
  return value;
}

// ── field access ─────────────────────────────────────────────────────────────

/** Values a pipeline writes when it knows nothing. They read as noise, so they read as nothing. */
const PLACEHOLDER = /^(?:|-|unknown|n\/?a|none|null|undefined)$/i;

export function scalar(v: unknown): string {
  if (typeof v === "string") return v.trim();
  if (typeof v === "number" && Number.isFinite(v)) return String(v);
  if (typeof v === "boolean") return String(v);
  return "";
}

export function lookup(src: Record<string, any>, path: string): unknown {
  if (path in src) return src[path];
  let cur: any = src;
  for (const part of path.split(".")) {
    if (cur === null || typeof cur !== "object") return undefined;
    cur = cur[part];
  }
  return cur;
}

/** First scalar value among `paths`; a nested path and a literal dotted key both resolve. */
export function pick(src: Record<string, any>, ...paths: string[]): string {
  for (const p of paths) {
    const s = scalar(lookup(src, p));
    if (s !== "") return s;
  }
  return "";
}

/** Same, but `unknown`-style placeholders do not count as a value. */
export function known(src: Record<string, any>, ...paths: string[]): string {
  for (const p of paths) {
    const s = scalar(lookup(src, p));
    if (!PLACEHOLDER.test(s)) return s;
  }
  return "";
}

function pickKnownField(src: Record<string, any>, paths: readonly string[]): { field: string; value: string } | null {
  for (const field of paths) {
    const value = known(src, field);
    if (value) return { field, value };
  }
  return null;
}

const IP_LIKE = /^(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F:]*:[0-9a-fA-F:.]+)$/;
export function isIpLike(s: string): boolean {
  return IP_LIKE.test(s);
}

function count(raw: string): string {
  if (raw === "") return "";
  const n = Number(raw);
  return Number.isFinite(n) ? n.toLocaleString() : raw;
}

// ── what the mapped indices can answer ───────────────────────────────────────
//
// The indices are dynamic=false, so a field outside the template is stored but
// not searchable and a filter on it silently returns nothing. These are the fields
// a clickable filter may use; logEvent.test.ts pins them to
// deployment/docker/opensearch/index-templates.json.
export const SEARCHABLE_FILTER_FIELDS: Record<LogSignal, readonly string[]> = {
  syslog: ["severity", "hostname"],
  trap: ["severity", "hostname", "device", "host"],
  flow: ["sampler_address"],
  app: ["level", "container_name", "service", "host"],
  cloud: ["severity", "level", "host"],
  other: [],
};

/** The template that backs each signal, for the guard above. */
export const SIGNAL_INDEX_PATTERN: Partial<Record<LogSignal, string>> = {
  syslog: "netops-syslog-*",
  trap: "netops-snmptrap-*",
  flow: "netops-flows-*",
  app: "netops-applogs-*",
  cloud: "netops-cloudlogs-*",
};

const DEVICE_CLAUSE_FIELDS: Record<LogSignal, readonly string[]> = {
  syslog: ["hostname"],
  trap: ["hostname", "device", "host"],
  flow: ["sampler_address"],
  app: ["container_name", "service", "host"],
  cloud: ["host"],
  other: [],
};

// ── pipeline bookkeeping ─────────────────────────────────────────────────────

const PIPELINE_FIELDS = new Set([
  "_signal", "__key", "partition", "offset", "topic", "source_type", "message_key",
  "log_index_base", "headers", "tenant_seg", "tenant_registry", "ts_source", "ts_invalid",
  "timestamp_raw", "path", "version", "cx_admission", "tenant_attribution",
]);

function flatten(prefix: string, value: unknown, out: LogField[]): void {
  if (value === null || value === undefined) {
    out.push({ name: prefix, value: "" });
  } else if (Array.isArray(value)) {
    out.push({ name: prefix, value: JSON.stringify(value) });
  } else if (typeof value === "object") {
    const entries = Object.entries(value as Record<string, unknown>);
    if (entries.length === 0) out.push({ name: prefix, value: "" });
    for (const [k, v] of entries) flatten(`${prefix}.${k}`, v, out);
  } else {
    out.push({ name: prefix, value: String(value) });
  }
}

export function fieldsOf(rec: Record<string, unknown>): LogField[] {
  const out: LogField[] = [];
  for (const [k, v] of Object.entries(rec)) flatten(k, v, out);
  return out.sort((a, b) => a.name.localeCompare(b.name));
}

/** What the Fields view lists: what the record states. A placeholder stays in Raw only. */
function statedFields(rec: Record<string, unknown>): LogField[] {
  return fieldsOf(rec).filter((f) => !PLACEHOLDER.test(f.value.trim()));
}

// ── signal ───────────────────────────────────────────────────────────────────

const INDEX_SIGNAL: [RegExp, LogSignal][] = [
  [/^netops-syslog-/, "syslog"],
  [/^netops-snmptrap-/, "trap"],
  [/^netops-flows-/, "flow"],
  [/^netops-(applogs|platformlogs)-/, "app"],
  [/^netops-cloudlogs-/, "cloud"],
];

const SIGNAL_WORDS: Record<string, LogSignal> = {
  syslog: "syslog", snmptrap: "trap", trap: "trap", flow: "flow", flows: "flow", netflow: "flow",
  ipfix: "flow", sflow: "flow", applog: "app", applogs: "app", cloud: "cloud",
};

function signalOf(index: string, src: Record<string, any>): LogSignal {
  const canonical = SIGNAL_WORDS[pick(src, "telemetry.signal").toLowerCase()];
  if (canonical) return canonical;
  for (const [re, sig] of INDEX_SIGNAL) if (re.test(index)) return sig;
  const named = SIGNAL_WORDS[pick(src, "signal", "_signal").toLowerCase()];
  if (named) return named;
  if (pick(src, "trap_oid")) return "trap";
  if (pick(src, "src_addr", "dst_addr")) return "flow";
  return "other";
}

// ── per-signal views ─────────────────────────────────────────────────────────

const NOT_DECODED = "Not decoded yet";

function parserChip(status: string): LogChip | null {
  switch (status.toLowerCase()) {
    case "unparsed": return { label: "Not parsed yet", stream: false };
    case "raw_only": return { label: NOT_DECODED, stream: false };
    case "partially_decoded": return { label: "Partly decoded", stream: false };
    default: return null;
  }
}

function varbindsOf(src: Record<string, any>): LogVarbind[] | undefined {
  if (!Array.isArray(src.varbinds) || src.varbinds.length === 0) return undefined;
  return src.varbinds
    .filter((v: unknown) => v && typeof v === "object")
    .map((v: Record<string, unknown>) => {
      const name = scalar(v.name);
      const oid = scalar(v.oid);
      return { label: name || oid, numeric: !name, oid, value: scalar(v.value) };
    });
}

function endpoint(src: Record<string, any>, canonical: string, addr: string, port: string): FlowEndpoint {
  return {
    address: pick(src, `network.${canonical}.address`, addr),
    port: pick(src, `network.${canonical}.port`, port),
  };
}

function protocolName(src: Record<string, any>): string {
  const named = pick(src, "network.transport.name");
  if (named) return named.toUpperCase();
  const raw = pick(src, "network.transport.number", "proto");
  if (raw === "") return "";
  if (!/^\d+$/.test(raw)) return raw.toUpperCase();
  return IANA_PROTO_NAMES[raw] ?? `IP/${raw}`;
}

/**
 * Two different facts that look alike: `sample_rate` is the router keeping 1 record in
 * N for the search index, and `sampling_rate` is what the exporter reported about its
 * own sampling (0 means it reported none). No volume is estimated from either.
 */
function flowSamplingOf(src: Record<string, any>): LogField[] {
  const out: LogField[] = [];
  const kept = pick(src, "sample_rate");
  if (kept !== "" && kept !== "0") out.push({ name: "Search index keeps", value: `1 in ${kept}` });
  const reported = pick(src, "sampling_rate");
  if (reported !== "") {
    const none = reported === "0";
    out.push({ name: "Exporter sampling", value: none ? "None reported" : `1 in ${reported}` });
  }
  return out;
}

/** How the receiver named a trap's interface, in plain words. */
const TRAP_INTERFACE_HOW: Record<string, string> = {
  varbind_name: "named in the trap",
  ifindex_map: "named from the device's interface table",
  ifindex_only: "index only, not named",
};

/** A trap's interface: the receiver's name beside the index, or the index alone. */
function trapInterfaceOf(src: Record<string, any>): { label: string; how: string } {
  const basis = pick(src, "interface_basis");
  const name = pick(src, "interface");
  const index = pick(src, "ifindex");
  if (!name || basis === "none" || !(basis in TRAP_INTERFACE_HOW)) return { label: "", how: "" };
  const label = basis === "ifindex_only" || !index || index === name ? name : `${name} (${index})`;
  return { label, how: TRAP_INTERFACE_HOW[basis] };
}

/** One interface as shown: the API's name beside the index, or the index alone. */
function interfaceLabel(index: string, name: unknown, basis: unknown): string {
  if (index === "") return "";
  if (basis === "sentinel") return `none reported (${index})`;
  const n = typeof name === "string" ? name.trim() : "";
  return basis === "resolved" && n ? `${n} (${index})` : index;
}

function flowViewOf(src: Record<string, any>, resolved: Record<string, any>): FlowView {
  const sampling = flowSamplingOf(src);
  const inIdx = pick(src, "network.ingress.interface.index", "in_if");
  const outIdx = pick(src, "network.egress.interface.index", "out_if");
  const svcName = typeof resolved.service_name === "string" ? resolved.service_name : "";
  const svcPort = resolved.service_port !== undefined ? String(resolved.service_port) : "";
  return {
    exporter: pick(src, "exporter.address", "sampler_address"),
    exporterName: known(src, "exporter.name", "exporter_name", "device_name"),
    source: endpoint(src, "source", "src_addr", "src_port"),
    destination: endpoint(src, "destination", "dst_addr", "dst_port"),
    protocol: protocolName(src),
    inInterface: inIdx,
    outInterface: outIdx,
    inInterfaceLabel: interfaceLabel(inIdx, resolved.in_if_name, resolved.in_if_name_basis),
    outInterfaceLabel: interfaceLabel(outIdx, resolved.out_if_name, resolved.out_if_name_basis),
    service: svcName && svcPort ? `${svcName} (port ${svcPort}, likely)` : "",
    platformMonitoring: resolved.traffic_class === "platform_monitoring",
    packets: count(pick(src, "flow.packets.observed", "packets")),
    bytes: count(pick(src, "flow.bytes.observed", "bytes")),
    sampling,
  };
}

function flowDetail(f: FlowView): string {
  const ports = f.source.port || f.destination.port
    ? `${f.source.port || "—"} → ${f.destination.port || "—"}`
    : "";
  return [
    [f.protocol, ports].filter(Boolean).join(" "),
    f.bytes && `${f.bytes} bytes`,
    f.packets && `${f.packets} packets`,
  ].filter(Boolean).join(" · ");
}

function join(...parts: string[]): string {
  return parts.filter(Boolean).join(" · ");
}

// ── the presenter ────────────────────────────────────────────────────────────

export interface LogHit {
  _index?: string;
  _id?: string;
  _source?: Record<string, any> | null;
  /** Names the API resolved beside the stored document (tracker 387 PR 13b). Never stored. */
  _resolved?: Record<string, any> | null;
}

export function toLogEvent(hit: LogHit): LogEvent {
  const index = hit._index ?? "";
  // Everything below reads the redacted copy: there is no path back to a secret.
  const src = redactSecrets(hit._source ?? {}) as Record<string, any>;
  const signal = signalOf(index, src);

  const fields: Record<string, unknown> = {};
  const pipeline: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(src)) {
    (PIPELINE_FIELDS.has(k) ? pipeline : fields)[k] = v;
  }
  if (index) pipeline._index = index;

  const summary = pick(src, "summary", "event.summary");
  const eventMessage = pick(src, "event.message");
  const message = eventMessage || pick(src, "message", "msg");
  const parserStatus = pick(src, "parser.status", "parser_status");
  const eventName = pick(src, "event.name", "event_name");
  const vendor = known(src, "device.vendor", "vendor");

  const severityRaw = pick(src, "native_severity", "severity_native", "event.severity", "syslog.severity", "level", "severity");
  const severity = PLACEHOLDER.test(severityRaw) ? null : severityRaw;
  const lifecycle = pick(src, "event.lifecycle", "alarm.state", "event.action") || undefined;

  const chips: LogChip[] = [];
  const addChip = (c: LogChip | null) => {
    if (c && !chips.some((x) => x.label === c.label)) chips.push(c);
  };

  // Device identity differs per signal. A name is preferred; the address sits beside it.
  let deviceLabel = "";
  let deviceAddress = "";
  let title = "";
  let detailLine = "";
  let varbinds: LogVarbind[] | undefined;
  let flow: FlowView | undefined;
  let syslog: SyslogView | undefined;
  let trap: LogEvent["trap"];

  switch (signal) {
    case "trap": {
      deviceLabel = known(src, "device.hostname", "device", "hostname", "host");
      deviceAddress = known(src, "device.observed_address", "host", "source_address", "source_ip");
      const name = eventName || pick(src, "trap_name");
      const oid = pick(src, "trap_oid");
      const uptime = pick(src, "sys_uptime_human");
      varbinds = varbindsOf(src);
      const iface = trapInterfaceOf(src);
      trap = { oid, uptime, interface: iface.label, interfaceHow: iface.how };
      if (iface.label) addChip({ label: `Interface ${iface.label}`, stream: true });
      const undecoded = name.toLowerCase() === "enterprisespecific";
      if (undecoded) addChip({ label: NOT_DECODED, stream: true });
      else addChip(parserChip(parserStatus));
      title = summary || eventMessage || name || oid || message;
      const named = (varbinds ?? [])
        .filter((v) => !v.numeric && v.label !== "sysUpTime")
        .slice(0, 4)
        .map((v) => `${v.label}=${v.value}`)
        .join(" ");
      detailLine = undecoded || !named ? join(oid, uptime && `uptime ${uptime}`) : join(named, uptime && `uptime ${uptime}`);
      break;
    }
    case "flow": {
      flow = flowViewOf(src, (redactSecrets(hit._resolved ?? {}) as Record<string, any>) ?? {});
      deviceLabel = flow.exporterName || flow.exporter;
      deviceAddress = flow.exporter;
      title = summary || (flow.source.address || flow.destination.address
        ? `${flow.source.address || "—"} → ${flow.destination.address || "—"}`
        : message);
      detailLine = flowDetail(flow);
      break;
    }
    case "syslog": {
      deviceLabel = known(src, "device.hostname", "hostname", "host");
      deviceAddress = known(src, "device.observed_address", "source_ip", "host");
      const app = known(src, "syslog.app_name", "appname");
      const pills: LogField[] = [];
      for (const [name, value] of [
        // The PRI facility, which the aggregator keeps apart. `facility` is a body grammar's
        // answer (`LINK`, `FTMD`), and is all a record stored before that split has.
        ["Facility", known(src, "syslog.facility", "syslog_facility", "facility")],
        ["Severity", severity ?? ""],
        ["App", app],
        ["Process", known(src, "syslog.procid", "procid")],
      ] as const) {
        if (value) pills.push({ name, value });
      }
      syslog = { pills, message };
      addChip(parserChip(parserStatus));
      title = summary || message;
      detailLine = join(app, vendor, eventName);
      break;
    }
    default: {
      deviceLabel = known(src, "device.hostname", "compose_service", "container_name", "service", "hostname", "host", "appname");
      deviceAddress = known(src, "device.observed_address", "source_ip");
      title = summary || message;
      detailLine = join(known(src, "component", "subsystem"), eventName);
    }
  }

  if (!deviceLabel) deviceLabel = deviceAddress;
  if (deviceAddress === deviceLabel) deviceAddress = "";
  if (!title) title = "No message";

  const searchable = SEARCHABLE_FILTER_FIELDS[signal];
  const severityField = (["level", "severity"] as const).find((f) => searchable.includes(f) && scalar(src[f]) === severityRaw);
  const deviceClause = pickKnownField(src, DEVICE_CLAUSE_FIELDS[signal]);

  const owner = attributionLabel(pick(src, "tenant_attribution"));
  return {
    owner,
    signal,
    signalLabel: SIGNAL_LABEL[signal],
    time: pick(src, "event.timestamp", "@timestamp", "timestamp", "ts", "time_received_ns"),
    severity,
    deviceLabel,
    deviceAddress,
    vendor,
    title,
    detailLine,
    lifecycle,
    chips,
    fields: statedFields(fields),
    varbinds,
    flow,
    syslog,
    trap,
    message,
    pipeline,
    raw: src,
    severityClause: severity && severityField ? { field: severityField, value: severityRaw } : undefined,
    deviceClause: deviceClause && (deviceClause.field !== "sampler_address" || isIpLike(deviceClause.value))
      ? deviceClause
      : undefined,
  };
}

// ── quick filters ────────────────────────────────────────────────────────────

export function luceneQuote(value: string): string {
  // eslint-disable-next-line no-control-regex
  const clean = value.replace(/[\u0000-\u001f\u007f]/g, " ");
  return `"${clean.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;
}

export function clauseText(c: LogClause): string {
  return `${c.field}:${luceneQuote(c.value)}`;
}

const TERM = String.raw`(?:[^\s()":]+:"(?:[^"\\]|\\.)*"|[^\s()"]+)`;
const AND_CHAIN = new RegExp(String.raw`^${TERM}(?:\s+AND\s+${TERM})*$`);

export function queryHasClause(query: string, c: LogClause): boolean {
  const text = clauseText(c);
  const q = query.trim();
  return q === text || q.endsWith(` AND ${text}`) || q.includes(` AND ${text} AND `) || q.startsWith(`${text} AND `);
}

/**
 * Adds a clause without changing what the existing query means. Anything that is
 * not already a plain AND chain is parenthesised first: `a OR b` must stay one
 * thing, and two bare words are an OR in this search syntax.
 */
export function addClause(query: string, c: LogClause): string {
  const q = query.trim();
  const text = clauseText(c);
  if (q === "" || q === "*") return text;
  if (queryHasClause(q, c)) return q;
  return AND_CHAIN.test(q) ? `${q} AND ${text}` : `(${q}) AND ${text}`;
}

export function removeClause(query: string, c: LogClause): string {
  const text = clauseText(c);
  const q = query.trim();
  if (q === text) return "*";
  const out = q.split(` AND ${text} AND `).join(" AND ");
  if (out.endsWith(` AND ${text}`)) return out.slice(0, -(` AND ${text}`.length));
  if (out.startsWith(`${text} AND `)) return out.slice(text.length + 5);
  return out;
}

export interface FacetValue {
  key: string;
  label: string;
  count: number;
}
export interface ClauseFacet extends FacetValue {
  clause: LogClause;
}
export interface SignalFacet extends FacetValue {
  signal: LogSignal;
}
export interface LogFacets {
  severity: ClauseFacet[];
  signal: SignalFacet[];
  device: ClauseFacet[];
}

const MAX_DEVICE_FACETS = 6;

/** Counts over the rows passed in, which are only the LOADED rows, never a total. */
export function buildFacets(events: readonly LogEvent[]): LogFacets {
  const severity = new Map<string, ClauseFacet>();
  const device = new Map<string, ClauseFacet>();
  const signal = new Map<LogSignal, SignalFacet>();
  const bump = (map: Map<string, ClauseFacet>, clause: LogClause, label: string) => {
    const key = clauseText(clause);
    const cur = map.get(key);
    if (cur) cur.count += 1;
    else map.set(key, { key, label, count: 1, clause });
  };
  for (const e of events) {
    if (e.severityClause && e.severity) bump(severity, e.severityClause, e.severity);
    if (e.deviceClause) bump(device, e.deviceClause, e.deviceClause.value);
    const s = signal.get(e.signal);
    if (s) s.count += 1;
    else signal.set(e.signal, { key: e.signal, label: e.signalLabel, count: 1, signal: e.signal });
  }
  const byCount = <T extends FacetValue>(a: T, b: T) => b.count - a.count || a.label.localeCompare(b.label);
  return {
    severity: [...severity.values()].sort(byCount),
    signal: [...signal.values()].sort(byCount),
    device: [...device.values()].sort(byCount).slice(0, MAX_DEVICE_FACETS),
  };
}

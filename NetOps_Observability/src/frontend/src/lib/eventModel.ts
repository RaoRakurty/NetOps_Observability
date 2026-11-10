// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// eventModel — ONE view model (EventView) for every record the Logs page can show:
// syslog, SNMP traps, flows, app/container logs, cloud logs, security findings and
// quarantine/dead-letter records. Every section of the Event Intelligence panel and the
// full event page renders from an EventView and never from the raw record.
//
// It builds on toLogEvent, which already owns the record shapes and the redaction, and
// adds the per-lane mapping. The rules are toLogEvent's, restated because they decide
// every line below:
//
//   1. Read what the record SAYS. A lane extractor maps fields into the common model;
//      it never decodes a vendor message, guesses a previous state, estimates a value,
//      or explains a fault the record does not explain. A derived value (CPU total =
//      100 − idle, a delay between two stated times) is computed only from stated
//      values, and is marked "derived" with its formula.
//   2. Every value is untrusted. Secrets are replaced before this code sees the record
//      (toLogEvent reads a redacted copy and so does everything here), and every value
//      is returned as plain text for React to escape.
//   3. No section is invented. A section with no data is absent; a device field the
//      inventory left blank shows "—", as the owner's screenshots do for Site.

import { ownerOf, PROVIDER_TENANT } from "./tenantOwner";
import {
  FlowView, LogClause, LogEvent, LogField, LogHit, LogSignal, clauseText, known, pick, scalar, toLogEvent,
} from "./logEvent";
import { SeverityKey, severityKey, severityLabel } from "../theme/severity";

// ── the model ────────────────────────────────────────────────────────────────

/** Where a value came from. "reported" is the device's own statement of a threshold. */
export type Provenance = "observed" | "derived" | "reported" | "guidance" | "unknown";

export type EvIconName =
  | "triangle" | "octagon" | "info" | "check" | "bug" | "cpu" | "memory" | "pulse" | "layers" | "arrow-up"
  | "arrow-down" | "refresh" | "list" | "chart" | "clock" | "code" | "braces" | "server" | "calendar" | "grid"
  | "wrench" | "fingerprint" | "copy" | "circle" | "share" | "external" | "close" | "doc" | "chevron"
  | "arrow-right" | "network" | "flow" | "terminal" | "user" | "cloud" | "shield" | "inbox" | "tag" | "link"
  | "plus-doc" | "vendor";

export type Tone = SeverityKey | "accent" | "neutral";

export interface ViewRow {
  key: string;
  label: string;
  value: string;
  /** IPs, OIDs, ids and numbers are set in mono. */
  mono?: boolean;
  prov?: Provenance;
  /** Short help on an (i) beside the label. */
  tip?: string;
  /** A copy button beside the value. */
  copy?: boolean;
  /** Shown as a pill in this tone instead of plain text. */
  pill?: Tone;
  /** A leading glyph inside the value (always beside text, never instead of it). */
  icon?: EvIconName;
  /** A quieter second line under the value (e.g. the same time in local time). */
  secondary?: string;
  /** The formula of a derived value. */
  formula?: string;
}

export interface EventChip {
  key: "vendor" | "family" | "category" | "signal" | "lifecycle" | "status";
  label: string;
  icon: EvIconName;
  tone?: Tone;
}

export type Lane = LogSignal | "security" | "quarantine";

export type VisualKind = "cpu" | "memory" | "bgp" | "interface" | "tunnel" | "flow" | "syslog_fault" | "audit" | "generic";

export interface UtilSegment {
  key: "system" | "user" | "idle" | "used" | "free";
  label: string;
  value: number;
  prov: Provenance;
}

export interface UtilizationData {
  resource: "cpu" | "memory";
  /** The total in percent, or null when the record states neither it nor what derives it. */
  total: number | null;
  totalProv: Provenance;
  totalFormula?: string;
  segments: UtilSegment[];
  /** A threshold the DEVICE reported in its own message. Never a configured one. */
  threshold: { value: number; label: string } | null;
}

export interface BgpData {
  peerAddress: string;
  afi: string;
  peerAs: string;
  localAddress: string;
  vrf: string;
  /** Null when the record does not state it: the UI says "not reported", never a guess. */
  prev: string | null;
  state: string;
  transitionClass: string;
  sentence: string;
  occurrences: number | null;
}

export interface InterfaceData {
  name: string;
  how: string;
  oper: string;
  admin: string;
}

export interface TunnelData {
  name: string;
  state: string;
  peer: string;
}

export interface SyslogFaultData {
  /** What the record's own summary says. Empty when it says nothing: no guessed cause. */
  explanation: string;
  unparsed: boolean;
  process: string;
  procid: string;
  facility: string;
  deviceSeverity: string;
  frame: string;
  frameFormat: string;
}

export interface AuditData {
  rows: ViewRow[];
  message: string;
  /** True when the parser has not split out who/what/where yet. */
  unparsed: boolean;
}

export interface FlowData extends FlowView {
  trafficClass: string;
}

export interface GenericData {
  headline: string;
  rows: ViewRow[];
  message: string;
}

export type PrimaryVisual =
  | { kind: "cpu" | "memory"; title: string; data: UtilizationData }
  | { kind: "bgp"; title: string; data: BgpData }
  | { kind: "interface"; title: string; data: InterfaceData }
  | { kind: "tunnel"; title: string; data: TunnelData }
  | { kind: "flow"; title: string; data: FlowData }
  | { kind: "syslog_fault"; title: string; data: SyslogFaultData }
  | { kind: "audit"; title: string; data: AuditData }
  | { kind: "generic"; title: string; data: GenericData };

export interface VarbindRow {
  name: string;
  oid: string;
  type: string;
  value: string;
  decoded: string;
  /** A severity word in the decoded value (e.g. "critical (1)") renders as a pill. */
  tone?: SeverityKey;
  /** The decoded value is a time. */
  isTime: boolean;
}

export interface TimelineEntry {
  key: string;
  time: string;
  /** What the time is: "device time", "received", … */
  timeBasis: string;
  pill: string;
  tone: Tone;
  text: string;
  /** Seconds after the device time, for the receive step. */
  afterSeconds?: number;
}

export interface TimelineQuery {
  /** AND-ed clauses over fields the index can actually answer. */
  clauses: LogClause[];
  /** What links the records, in operator words. */
  basis: string;
  signal: "syslog" | "snmptrap" | "flows" | "applogs" | "cloud" | "";
}

export interface EventLink {
  signal: TimelineQuery["signal"];
  id: string;
  /** The record's `timestamp` (the field the search range filters on). */
  t: string;
}

export interface EventView {
  lane: Lane;
  laneLabel: string;
  severity: { native: string | null; normalized: string | null; label: string; tone: SeverityKey | null };
  title: string;
  subtitle: string;
  chips: EventChip[];
  primaryVisual: PrimaryVisual;
  /** The bordered stat table beside the primary visual. */
  sideStats: ViewRow[];
  device: { name: string; address: string; inventory: { label: string; tone: Tone } | null; rows: ViewRow[] };
  timing: ViewRow[];
  classification: ViewRow[];
  identity: {
    rows: ViewRow[];
    lifecycle: string | null;
    /** Null when the record carries no recovery fact at all. */
    recovery: { verified: boolean } | null;
  };
  overview: { what: string; impact: string[]; nextChecks: string[]; basis: string };
  /** This record's own steps (its device time and its receipt), before related records join. */
  timeline: TimelineEntry[];
  timelineQuery: TimelineQuery | null;
  details: { kind: "varbinds" | "fields"; title: string; varbinds: VarbindRow[]; rows: ViewRow[] };
  metrics: ViewRow[];
  metricSeries: { metric: string; deviceId: string; label: string } | null;
  provenance: Record<string, Provenance>;
  fields: LogField[];
  pipeline: Record<string, unknown>;
  raw: Record<string, any>;
  incidentDraft: { title: string; description: string; severity: "info" | "low" | "medium" | "high" | "critical" };
  link: EventLink | null;
  /** The record id the search returned, for de-duplication and deep links. */
  id: string;
  /** The underlying presenter output (owner, flow sampling, chips, …). */
  ev: LogEvent;
}

// ── small helpers ────────────────────────────────────────────────────────────

export const DASH = "—";

function num(v: unknown): number | null {
  if (typeof v === "number") return Number.isFinite(v) ? v : null;
  if (typeof v === "string" && v.trim() !== "" && /^-?\d+(\.\d+)?$/.test(v.trim())) return Number(v);
  return null;
}

function pct(v: number | null): number | null {
  return v !== null && v >= 0 && v <= 100 ? v : null;
}

function bool(v: unknown): boolean | null {
  if (typeof v === "boolean") return v;
  if (v === "true") return true;
  if (v === "false") return false;
  return null;
}

function obj(v: unknown): Record<string, any> | null {
  return v && typeof v === "object" && !Array.isArray(v) ? (v as Record<string, any>) : null;
}

function strList(v: unknown): string[] {
  return Array.isArray(v) ? v.map(scalar).filter(Boolean) : [];
}

/** platform_health → Platform Health. */
export function humanize(s: string): string {
  return s
    .replace(/[_\-.]+/g, " ")
    .trim()
    .replace(/\s+/g, " ")
    .replace(/\b([a-z])/g, (m) => m.toUpperCase())
    .replace(/\bBgp\b/g, "BGP").replace(/\bCpu\b/g, "CPU").replace(/\bSnmp\b/g, "SNMP")
    .replace(/\bOspf\b/g, "OSPF").replace(/\bBfd\b/g, "BFD").replace(/\bVpn\b/g, "VPN").replace(/\bDns\b/g, "DNS");
}

export function fmtPercent(v: number, digits = 2): string {
  return `${v.toFixed(digits)}%`;
}

/** 100 → "100%", 95.85 → "95.85%": the ring reads like the device wrote it. */
export function fmtPercentShort(v: number): string {
  return Number.isInteger(v) ? `${v}%` : `${Number(v.toFixed(2))}%`;
}

const p2 = (n: number, w = 2) => String(n).padStart(w, "0");

/** 2026-11-10 04:07:27.500 UTC — the screenshots' format, always UTC. */
export function fmtUtc(iso: string): string {
  const d = parseIso(iso);
  if (!d) return iso;
  return `${d.getUTCFullYear()}-${p2(d.getUTCMonth() + 1)}-${p2(d.getUTCDate())} ${p2(d.getUTCHours())}:${p2(d.getUTCMinutes())}:${p2(d.getUTCSeconds())}.${p2(d.getUTCMilliseconds(), 3)} UTC`;
}

const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

/** (Nov 09, 2026 22:07:27.500 CST) — the same instant on the viewer's clock. */
export function fmtLocal(iso: string, timeZone?: string): string {
  const d = parseIso(iso);
  if (!d) return "";
  let parts: Intl.DateTimeFormatPart[];
  try {
    parts = new Intl.DateTimeFormat("en-US", {
      timeZone, year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit",
      second: "2-digit", hour12: false, timeZoneName: "short",
    }).formatToParts(d);
  } catch {
    return "";
  }
  const get = (t: string) => parts.find((p) => p.type === t)?.value ?? "";
  const hour = get("hour") === "24" ? "00" : get("hour");
  return `${MONTHS[Number(get("month")) - 1]} ${get("day")}, ${get("year")} ${hour}:${get("minute")}:${get("second")}.${p2(d.getMilliseconds(), 3)} ${get("timeZoneName")}`;
}

export function parseIso(v: string): Date | null {
  if (!v) return null;
  if (/^\d{16,19}$/.test(v)) {
    // Nanoseconds since the epoch (flows' time_received_ns).
    const d = new Date(Number(v.slice(0, v.length - 6)));
    return Number.isNaN(d.getTime()) ? null : d;
  }
  const d = new Date(v);
  return Number.isNaN(d.getTime()) ? null : d;
}

function secondsBetween(a: string, b: string): number | null {
  const da = parseIso(a);
  const db = parseIso(b);
  if (!da || !db) return null;
  return (db.getTime() - da.getTime()) / 1000;
}

/** 1432774.15 → "1,432,774.15 s" */
function fmtSeconds(s: number): string {
  return `${s.toLocaleString("en-US", { maximumFractionDigits: 3 })} s`;
}

// ── vendor and device wording ───────────────────────────────────────────────

const VENDOR_LABEL: Record<string, string> = {
  cisco: "Cisco", viptela: "Cisco", juniper: "Juniper", arista: "Arista", nokia: "Nokia", sonic: "SONiC",
  fortinet: "Fortinet", fortigate: "Fortinet", paloalto: "Palo Alto Networks", "palo alto": "Palo Alto Networks",
  versa: "Versa", huawei: "Huawei", hpe: "HPE", aruba: "Aruba", extreme: "Extreme", dell: "Dell",
  microsoft: "Microsoft", aws: "AWS", azure: "Azure", gcp: "Google Cloud",
};

export function vendorLabel(v: string): string {
  if (!v) return "";
  return VENDOR_LABEL[v.toLowerCase()] ?? v;
}

// ── lanes ────────────────────────────────────────────────────────────────────

const LANE_LABEL: Record<Lane, string> = {
  syslog: "Syslog", trap: "SNMP Trap", flow: "Flow", app: "App log", cloud: "Cloud log", other: "Log",
  security: "Security finding", quarantine: "Quarantined record",
};

const LANE_ICON: Record<Lane, EvIconName> = {
  syslog: "terminal", trap: "layers", flow: "flow", app: "server", cloud: "cloud", other: "doc",
  security: "shield", quarantine: "inbox",
};

function laneOf(index: string, signal: LogSignal): Lane {
  if (/^netops-secfindings-/.test(index)) return "security";
  if (/^netops-(quarantine|deadletter)-/.test(index)) return "quarantine";
  return signal;
}

const SEARCH_SIGNAL: Record<Lane, TimelineQuery["signal"]> = {
  syslog: "syslog", trap: "snmptrap", flow: "flows", app: "applogs", cloud: "cloud", other: "",
  security: "", quarantine: "",
};

/**
 * Fields a timeline search may filter on, per lane. The indices are dynamic=false, so a
 * field outside the template is stored but silently unsearchable: correlation_key and
 * transition_id are not mapped yet, so a timeline over them would always come back empty.
 * eventModel.test.ts pins every entry here to deployment/docker/opensearch/index-templates.json.
 */
export const TIMELINE_SEARCHABLE: Partial<Record<Lane, readonly string[]>> = {
  trap: ["device_id", "event_type", "trap_oid"],
  syslog: ["device_id", "event_type"],
};

/** The search text for a set of clauses: each value quoted, so none can break out. */
export function clauseQuery(clauses: readonly LogClause[]): string {
  return clauses.map(clauseText).join(" AND ");
}

/** The fields that SHOULD link a timeline, and will as soon as they are mapped. */
export const TIMELINE_KEYS = ["transition_id", "correlation_key"] as const;

// ── metrics ──────────────────────────────────────────────────────────────────

interface MetricVal {
  value: number;
  prov: Provenance;
  formula?: string;
}

function metricsOf(src: Record<string, any>): Record<string, MetricVal> {
  const out: Record<string, MetricVal> = {};
  const m = obj(src.metrics);
  if (!m) return out;
  for (const [name, raw] of Object.entries(m)) {
    const rec = obj(raw);
    const value = num(rec ? rec.value : raw);
    if (value === null) continue;
    const basis = rec ? scalar(rec.basis) : "";
    out[name] = {
      value,
      prov: basis === "derived" ? "derived" : basis === "observed" ? "observed" : "unknown",
      formula: rec && scalar(rec.formula) ? scalar(rec.formula) : undefined,
    };
  }
  return out;
}

const METRIC_LABEL: Record<string, string> = {
  cpu_total_percent: "Total CPU", cpu_system_percent: "System CPU", cpu_user_percent: "User CPU",
  cpu_idle_percent: "Idle CPU", mem_used_percent: "Memory used", mem_free_percent: "Memory free",
  memory_used_percent: "Memory used", memory_free_percent: "Memory free", memory_total_percent: "Total memory",
};

function metricLabel(name: string): string {
  return METRIC_LABEL[name] ?? humanize(name.replace(/_percent$/, " (%)"));
}

function utilizationOf(resource: "cpu" | "memory", m: Record<string, MetricVal>, src: Record<string, any>): UtilizationData | null {
  const keys = resource === "cpu" ? ["cpu"] : ["mem", "memory"];
  const get = (part: string): MetricVal | null => {
    for (const k of keys) {
      const v = m[`${k}_${part}_percent`];
      if (v && pct(v.value) !== null) return v;
    }
    return null;
  };
  const segs: UtilSegment[] = [];
  const add = (key: UtilSegment["key"], label: string, v: MetricVal | null) => {
    if (v) segs.push({ key, label, value: v.value, prov: v.prov });
  };
  if (resource === "cpu") {
    add("system", "System CPU", get("system"));
    add("user", "User CPU", get("user"));
    add("idle", "Idle", get("idle"));
  } else {
    add("used", "Used", get("used"));
    add("free", "Free", get("free"));
  }
  if (segs.length === 0) return null;
  // The total: stated, else derived from idle/free, which the record stated.
  const stated = get("total");
  let total: number | null = stated ? stated.value : null;
  let totalProv: Provenance = stated ? stated.prov : "unknown";
  let totalFormula = stated?.formula;
  if (total === null) {
    const spare = resource === "cpu" ? get("idle") : get("free");
    if (spare) {
      total = Number((100 - spare.value).toFixed(2));
      totalProv = "derived";
      totalFormula = resource === "cpu" ? "100 − idle" : "100 − free";
    } else if (resource === "memory" && get("used")) {
      total = get("used")!.value;
      totalProv = get("used")!.prov;
    }
  }
  const thr = num(src.threshold_reported_percent);
  const reported = scalar(src.threshold_basis) === "reported_by_device" && pct(thr) !== null;
  return {
    resource,
    total: pct(total),
    totalProv,
    totalFormula,
    segments: segs,
    threshold: reported ? { value: thr as number, label: "Threshold (reported)" } : null,
  };
}

// ── BGP ──────────────────────────────────────────────────────────────────────

const AFI_LABEL: Record<string, string> = {
  ipv4: "IPv4", ipv6: "IPv6", "ipv4-unicast": "IPv4 unicast", "ipv6-unicast": "IPv6 unicast",
  ipv4_unicast: "IPv4 unicast", ipv6_unicast: "IPv6 unicast", vpnv4: "VPNv4", vpnv6: "VPNv6", l2vpn: "L2VPN EVPN",
};

const TRANSITION_SENTENCE: Record<string, string> = {
  never_established: "The session has not reached Established in what was observed: a session that never came up, not the loss of a working one.",
  session_lost: "An established session went down: the peer was lost.",
  established: "The session reached Established.",
  flap: "The session went down and came back up.",
  regression: "The session fell back from a later state without being established.",
};

function bgpOf(src: Record<string, any>): BgpData | null {
  const b = obj(src.bgp);
  if (!b) return null;
  const peer = scalar(b.peer_address);
  const state = scalar(b.state);
  if (!peer && !state) return null;
  const cls = scalar(b.transition_class);
  const afiRaw = scalar(b.peer_afi);
  const occ = num(src.occurrence_count);
  return {
    peerAddress: peer,
    afi: AFI_LABEL[afiRaw.toLowerCase()] ?? afiRaw,
    peerAs: scalar(b.peer_as),
    localAddress: scalar(b.local_address),
    vrf: scalar(b.vrf),
    prev: scalar(b.prev_state) || null,
    state,
    transitionClass: cls,
    sentence: TRANSITION_SENTENCE[cls] ?? (cls ? humanize(cls) : ""),
    occurrences: occ !== null && occ >= 1 ? occ : null,
  };
}

// ── varbinds ─────────────────────────────────────────────────────────────────

const SEV_IN_VALUE = /^(critical|major|minor|warning|cleared|clear|indeterminate|error|info|notice)\s*\(\d+\)$/i;

function varbindRowsOf(src: Record<string, any>): VarbindRow[] {
  if (!Array.isArray(src.varbinds)) return [];
  return src.varbinds
    .filter((v: unknown) => v && typeof v === "object")
    .map((v: Record<string, unknown>) => {
      const value = scalar(v.value);
      const decoded = scalar(v.decoded);
      const type = scalar(v.type);
      const shown = decoded || value;
      const sev = SEV_IN_VALUE.test(shown) ? severityKey(shown.replace(/\s*\(\d+\)$/, "")) : undefined;
      return {
        name: scalar(v.name),
        oid: scalar(v.oid),
        type,
        value,
        decoded,
        tone: sev,
        isTime: /dateandtime/i.test(type) || (decoded !== "" && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}/.test(decoded)),
      };
    });
}

// ── provenance ───────────────────────────────────────────────────────────────

function provenanceOf(src: Record<string, any>): Record<string, Provenance> {
  const out: Record<string, Provenance> = {};
  const e = obj(src.enrichment);
  if (!e) return out;
  for (const f of strList(e.fields_observed)) out[f] = "observed";
  for (const f of strList(e.fields_derived)) out[f] = "derived";
  for (const f of strList(e.fields_guidance)) out[f] = "guidance";
  for (const f of strList(e.unknown)) out[f] = "unknown";
  return out;
}

// ── lifecycle ────────────────────────────────────────────────────────────────

const LIFECYCLE: Record<string, { label: string; icon: EvIconName }> = {
  raise: { label: "Raise", icon: "arrow-up" },
  escalate: { label: "Escalate", icon: "arrow-up" },
  downgrade: { label: "Downgrade", icon: "arrow-down" },
  clear: { label: "Clear", icon: "check" },
  repeat: { label: "Repeat", icon: "refresh" },
};

function lifecycleOf(src: Record<string, any>, ev: LogEvent): string | null {
  const s = (pick(src, "lifecycle_state", "event_state") || ev.lifecycle || "").toLowerCase();
  return s in LIFECYCLE ? s : null;
}

// ── the presenter ────────────────────────────────────────────────────────────

const FAMILY_ICON: Record<string, EvIconName> = {
  cpu: "cpu", memory: "memory", mem: "memory", bgp: "network", interface: "network", tunnel: "link",
  audit: "user", management_audit: "user", security: "shield",
};

function familyKind(family: string, category: string, eventType: string): VisualKind | null {
  const f = family.toLowerCase();
  if (f === "cpu") return "cpu";
  if (f === "memory" || f === "mem") return "memory";
  if (f === "bgp") return "bgp";
  if (f === "interface" || f === "link") return "interface";
  if (f === "tunnel") return "tunnel";
  if (f === "audit" || /audit/.test(category.toLowerCase()) || /audit/.test(eventType.toLowerCase())) return "audit";
  return null;
}

const TRAFFIC_CLASS: Record<string, string> = {
  platform_monitoring: "Correlix's own polling",
  customer: "Customer traffic",
  control_plane: "Control plane",
};

const SEVERITY_TO_INCIDENT: Record<SeverityKey, EventView["incidentDraft"]["severity"]> = {
  critical: "critical", error: "high", warning: "medium", notice: "low", info: "info", debug: "info", ok: "info",
};

const DELAY_TIP = "The time between the device's clock and our receiver. It can include clock difference and queueing on the device, so it is not network latency.";

export function toEventView(hit: LogHit): EventView {
  const ev = toLogEvent(hit);
  const src = ev.raw; // the redacted copy: there is no path back to a secret
  const index = hit._index ?? "";
  const lane = laneOf(index, ev.signal);
  const laneLabel = LANE_LABEL[lane];
  const prov = provenanceOf(src);
  const metrics = metricsOf(src);
  const family = known(src, "family");
  const category = known(src, "category", "event_category");
  const eventType = known(src, "event_type");
  const parserStatus = pick(src, "parser.status", "parser_status").toLowerCase();

  // Severity: the device's word and the normalized one, kept apart.
  const native = known(src, "native_severity", "severity_native_text", "severity_native", "syslog.severity") || null;
  const normalized = known(src, "normalized_severity", "severity", "level") || null;
  const toneSource = normalized ?? native ?? ev.severity;
  const tone = toneSource ? severityKey(toneSource) : null;
  const sevLabel = toneSource ? severityLabel(normalized ?? toneSource) : "";

  // Title and subtitle: the record's own headline, then the vendor's words under it.
  const stated = known(src, "title");
  const title = stated || ev.title;
  const message = ev.message;
  const summary = known(src, "summary");
  const subtitle = [message, summary].find((s) => s && s !== title && !(lane === "flow" && s === "flow record")) ?? "";

  // ── primary visual ──
  let kind: VisualKind = familyKind(family, category, eventType) ?? "generic";
  let visual: PrimaryVisual | null = null;
  let utilization: UtilizationData | null = null;
  if (kind === "cpu" || kind === "memory") {
    utilization = utilizationOf(kind, metrics, src);
    if (utilization) visual = { kind, title: kind === "cpu" ? "CPU Breakdown" : "Memory Breakdown", data: utilization };
  } else if (kind === "bgp") {
    const b = bgpOf(src);
    if (b) visual = { kind, title: "BGP Session", data: b };
  } else if (kind === "interface" && (ev.trap?.interface || known(src, "interface"))) {
    visual = {
      kind, title: "Interface",
      data: {
        name: ev.trap?.interface || known(src, "interface"),
        how: ev.trap?.interfaceHow ?? "",
        oper: known(src, "oper_status", "if_oper_status", "interface_oper_status"),
        admin: known(src, "admin_status", "if_admin_status", "interface_admin_status"),
      },
    };
  } else if (kind === "tunnel" && known(src, "tunnel", "tunnel_name")) {
    visual = {
      kind, title: "Tunnel",
      data: { name: known(src, "tunnel", "tunnel_name"), state: known(src, "tunnel_state", "state"), peer: known(src, "tunnel_peer", "remote_address") },
    };
  } else if (kind === "audit") {
    const rows = auditRows(src);
    visual = { kind, title: "Management Audit", data: { rows, message, unparsed: rows.length === 0 } };
  }
  if (!visual && ev.flow) {
    kind = "flow";
    visual = { kind, title: "Flow", data: { ...ev.flow, trafficClass: TRAFFIC_CLASS[scalar(obj(hit._resolved)?.traffic_class) || scalar(src.traffic_class)] ?? humanize(scalar(src.traffic_class)) } };
  }
  if (!visual && lane === "syslog") {
    kind = "syslog_fault";
    visual = {
      kind, title: parserStatus === "unparsed" ? "Not parsed yet" : "Device Message",
      data: {
        explanation: summary && summary !== message ? summary : "",
        unparsed: parserStatus === "unparsed",
        process: known(src, "syslog.app_name", "appname"),
        procid: known(src, "syslog.procid", "procid"),
        facility: known(src, "syslog.facility", "syslog_facility", "facility"),
        deviceSeverity: native ?? ev.severity ?? "",
        frame: known(src, "message_original") || message,
        frameFormat: known(src, "frame_format"),
      },
    };
  }
  if (!visual) {
    kind = "generic";
    visual = { kind, title: lane === "app" || lane === "cloud" ? "Log Record" : laneLabel, data: { headline: summary || title, rows: genericRows(lane, src, ev), message } };
  }

  // ── side stats ──
  const sideStats: ViewRow[] = [];
  if (utilization) {
    const word = utilization.resource === "cpu" ? "CPU" : "Memory";
    if (utilization.total !== null) {
      sideStats.push({
        key: "total", label: `Total ${word}${utilization.totalProv === "derived" ? " (derived)" : ""}`,
        value: fmtPercent(utilization.total), prov: utilization.totalProv, formula: utilization.totalFormula,
      });
    }
    if (utilization.threshold) {
      sideStats.push({ key: "threshold", label: "Reported Threshold", value: fmtPercentShort(utilization.threshold.value), prov: "reported" });
    }
    for (const s of utilization.segments) {
      sideStats.push({ key: s.key, label: s.key === "idle" ? `Idle ${word}` : s.label, value: fmtPercent(s.value), prov: s.prov });
    }
  } else if (visual.kind === "bgp") {
    const b = visual.data;
    if (b.peerAs) sideStats.push({ key: "as", label: "Peer AS", value: b.peerAs });
    if (b.afi) sideStats.push({ key: "afi", label: "Address family", value: b.afi });
    if (b.localAddress) sideStats.push({ key: "local", label: "Local address", value: b.localAddress, mono: true });
    if (b.vrf) sideStats.push({ key: "vrf", label: "VRF", value: b.vrf, mono: true });
  } else if (visual.kind === "flow") {
    const f = visual.data;
    if (f.bytes) sideStats.push({ key: "bytes", label: "Bytes", value: f.bytes, prov: "observed" });
    if (f.packets) sideStats.push({ key: "packets", label: "Packets", value: f.packets, prov: "observed" });
    for (const s of f.sampling) sideStats.push({ key: s.name, label: s.name, value: s.value });
  }

  // ── chips ──
  const chips: EventChip[] = [];
  const vendor = vendorLabel(known(src, "device.vendor", "vendor"));
  const platform = known(src, "platform");
  if (vendor) chips.push({ key: "vendor", label: platform ? `${vendor} ${platform}` : vendor, icon: "vendor" });
  if (family) {
    const saturated = utilization && utilization.total !== null && utilization.threshold && utilization.total >= utilization.threshold.value;
    const label = saturated ? `${utilization!.resource === "cpu" ? "CPU" : "Memory"} Saturation` : humanize(family);
    chips.push({ key: "family", label, icon: FAMILY_ICON[family.toLowerCase()] ?? "tag" });
  }
  if (category && !chips.some((c) => c.label === humanize(category))) chips.push({ key: "category", label: humanize(category), icon: "pulse" });
  chips.push({ key: "signal", label: laneLabel, icon: LANE_ICON[lane] });
  const lifecycle = lifecycleOf(src, ev);
  if (lifecycle) chips.push({ key: "lifecycle", label: LIFECYCLE[lifecycle].label, icon: LIFECYCLE[lifecycle].icon, tone: lifecycle === "clear" ? "ok" : tone ?? "neutral" });
  for (const c of ev.chips) {
    if (!c.label.startsWith("Interface ")) chips.push({ key: "status", label: c.label, icon: "info", tone: "neutral" });
  }

  // ── device card ──
  const dash = (v: string) => v || DASH;
  const deviceName = ev.deviceLabel;
  const deviceAddr = ev.deviceAddress || known(src, "host", "source_ip", "source_address");
  const model = known(src, "model");
  const deviceType = known(src, "device_type") || [vendor, model].filter(Boolean).join(" ") + (platform && model ? ` (${platform})` : "");
  const attribution = pick(src, "tenant_attribution");
  const tenantId = pick(src, "tenant_id");
  const deviceId = known(src, "device_id");
  const enrichStatus = pick(src, "enrichment_status").toLowerCase();
  let inventory: EventView["device"]["inventory"] = null;
  if (deviceId && !/^(unmatched|none|miss|failed)$/.test(enrichStatus)) inventory = { label: "Inventory Matched", tone: "ok" };
  else if (attribution === "unmatched" || /^(unmatched|miss)$/.test(enrichStatus)) inventory = { label: "Not in inventory", tone: "warning" };
  const deviceRows: ViewRow[] = [];
  if (lane !== "app" && lane !== "cloud") {
    deviceRows.push({ key: "device", label: "Device", value: dash(deviceName) });
    deviceRows.push({ key: "ip", label: "IP", value: dash(deviceAddr), mono: true });
    deviceRows.push({ key: "type", label: "Device Type", value: dash(deviceType) });
    deviceRows.push({ key: "owner", label: "Ownership", value: dash(ev.owner) });
    // The tenant only when the record names one; how it was attributed is already the
    // Ownership row, so the raw attribution only rides along beside a named tenant.
    if (tenantId) {
      const t = ownerOf(tenantId) === PROVIDER_TENANT ? "Platform" : tenantId;
      deviceRows.push({ key: "tenant", label: "Tenant", value: attribution ? `${t} (${attribution})` : t });
    }
    deviceRows.push({ key: "site", label: "Site", value: dash(known(src, "site")) });
    deviceRows.push({ key: "role", label: "Role", value: dash(known(src, "role")) });
    if (inventory) deviceRows.push({ key: "inventory", label: "Inventory Status", value: inventory.label, pill: inventory.tone, icon: inventory.tone === "ok" ? "check" : "triangle" });
  } else {
    if (lane === "cloud") {
      deviceRows.push({ key: "resource", label: "Resource", value: dash(known(src, "resource_id", "app") || ev.deviceLabel), mono: true });
    } else {
      deviceRows.push({ key: "service", label: "Service", value: dash(known(src, "compose_service", "service", "component") || ev.deviceLabel) });
      const container = known(src, "container_name", "container_id");
      if (container) deviceRows.push({ key: "container", label: "Container", value: container, mono: true });
    }
    const host = known(src, "host");
    if (host) deviceRows.push({ key: "host", label: "Host", value: host, mono: true });
    if (lane === "cloud") {
      for (const [k, label] of [["cloud_provider", "Provider"], ["account", "Account"], ["region", "Region"]] as const) {
        const v = known(src, k);
        if (v) deviceRows.push({ key: k, label, value: v, mono: k !== "cloud_provider" });
      }
    }
    if (ev.owner) deviceRows.push({ key: "owner", label: "Ownership", value: ev.owner });
  }

  // ── timing ──
  const timing = timingRows(lane, src, ev);

  // ── classification ──
  const classification: ViewRow[] = [];
  const addC = (key: string, label: string, value: string, extra: Partial<ViewRow> = {}) => {
    if (value) classification.push({ key, label, value, ...extra });
  };
  addC("event_type", "Event Type", eventType, { mono: false });
  addC("category", "Category", category ? humanize(category) : "", { pill: "accent" });
  addC("family", "Family", family ? humanize(family) : "", { icon: FAMILY_ICON[family.toLowerCase()] ?? "tag" });
  if (native && normalized && native.toLowerCase() !== normalized.toLowerCase()) addC("native_severity", "Native Severity", native, { mono: true });
  if (lane === "trap") {
    addC("mib", "MIB Module", known(src, "mib_module"));
    addC("trap_oid", "Trap OID", ev.trap?.oid ?? "", { mono: true });
    addC("snmp_version", "SNMP Version", known(src, "snmp_version"));
    const present = bool(src.snmp_community_present);
    if (present !== null) addC("community", "Community Present", present ? "Yes (hidden)" : "No", { icon: present ? "check" : "circle", pill: undefined });
    const authModel = known(src, "auth_model").toLowerCase();
    const authed = bool(src.authenticated);
    const version = known(src, "snmp_version").toLowerCase();
    if (authModel === "community" || (authModel === "" && /^v(1|2c?)$/.test(version) && authed !== null)) {
      // Community SNMP carries no authentication at all: "false" is not a failure.
      addC("auth", "Authenticated", `No (${version || "community"} – not applicable)`, { icon: "info" });
    } else if (authModel === "usm" && authed !== null) {
      addC("auth", "Authenticated", authed ? "Yes (SNMPv3 USM)" : "No (SNMPv3 USM)", { icon: authed ? "check" : "triangle" });
    }
  } else if (lane === "syslog") {
    const parser = ({ parsed: "Parsed", unparsed: "Not parsed yet", raw_only: "Not decoded yet", partially_decoded: "Partly decoded" } as Record<string, string>)[parserStatus] ?? (parserStatus ? humanize(parserStatus) : "");
    addC("parser", "Parser", parser, { pill: parserStatus === "unparsed" ? "warning" : undefined });
    addC("parser_id", "Parser ID", known(src, "parser_id"), { mono: true });
    addC("facility", "Facility", known(src, "syslog_facility", "facility"));
    addC("frame", "Frame Format", known(src, "frame_format"), { mono: true });
    addC("msgid", "Message ID", known(src, "msgid"), { mono: true });
  } else if (lane === "flow") {
    addC("flow_type", "Flow Type", known(src, "flow_type", "type").toUpperCase());
    addC("sampling_status", "Sampling", known(src, "sampling_status"));
  } else if (lane === "app" || lane === "cloud") {
    addC("level", "Level", ev.severity ? severityLabel(ev.severity) : "");
    addC("log_class", "Log Class", known(src, "log_class", "cloud_family"));
    addC("component", "Component", known(src, "component", "subsystem"));
  } else if (lane === "security") {
    addC("control", "Control", known(src, "control_title", "control"));
    addC("status", "Status", known(src, "status"));
  } else if (lane === "quarantine") {
    addC("reason", "Reason", known(src, "reason"));
    addC("lane", "Lane", known(src, "lane"), { mono: true });
  }

  // ── identity ──
  const identityRows: ViewRow[] = [];
  const eventId = known(src, "event_id", "cx_event_id");
  if (eventId) identityRows.push({ key: "event_id", label: "Event ID", value: eventId, mono: true, copy: true });
  const corr = known(src, "correlation_key");
  if (corr) identityRows.push({ key: "correlation_key", label: "Correlation Key", value: corr, mono: true, copy: true });
  const transition = known(src, "transition_id");
  if (transition) identityRows.push({ key: "transition_id", label: "Transition ID", value: transition, mono: true, copy: true });
  if (lifecycle) identityRows.push({ key: "state", label: "Event State", value: LIFECYCLE[lifecycle].label, icon: LIFECYCLE[lifecycle].icon, pill: undefined });
  const recoveredFact = bool(src.recovery_verified);
  const recovery = recoveredFact === null ? null : { verified: recoveredFact };
  if (recovery) identityRows.push({ key: "recovery", label: "Recovery Status", value: recovery.verified ? "Recovered (verified)" : "Not recovered", icon: recovery.verified ? "check" : "circle" });
  const occ = num(src.occurrence_count);
  if (occ !== null && occ > 1 && visual.kind !== "bgp") identityRows.push({ key: "occ", label: "Occurrences", value: String(occ) });

  // ── overview ──
  const guidance = obj(src.guidance);
  const impact = guidance ? strList(guidance.impact) : [];
  const nextChecks = guidance ? strList(guidance.next_checks) : [];
  const gBasis = guidance ? scalar(guidance.basis) : "";
  const overview = {
    what: whatHappened(visual, summary, message, title),
    impact,
    nextChecks,
    basis: gBasis === "pack_guidance" ? "vendor pack" : gBasis ? humanize(gBasis).toLowerCase() : "",
  };

  // ── own timeline steps ──
  const timeline: TimelineEntry[] = [];
  const deviceTime = known(src, "device_event_time") || (lane === "syslog" && pick(src, "ts_source") !== "edge_receive" ? pick(src, "timestamp") : "");
  const received = known(src, "received_time") || (lane === "syslog" ? known(src, "ingested_at") : "") || (lane === "trap" ? pick(src, "timestamp") : "");
  const pillWord = lifecycle ? `${LIFECYCLE[lifecycle].label}${sevLabel ? ` (${sevLabel})` : ""}` : sevLabel || laneLabel;
  if (deviceTime) {
    timeline.push({ key: "device", time: deviceTime, timeBasis: "device time", pill: pillWord, tone: lifecycle === "clear" ? "ok" : tone ?? "neutral", text: utilization ? utilizationSentence(utilization) : summary || title });
  }
  if (received && received !== deviceTime) {
    const after = deviceTime ? secondsBetween(deviceTime, received) : null;
    timeline.push({
      key: "received", time: received, timeBasis: "received", pill: "Event Received", tone: "accent",
      text: lane === "trap" ? `SNMP trap received${varbindRowsOf(src).some((v) => v.decoded || v.name) ? " and decoded" : ""}` : `${laneLabel} received`,
      afterSeconds: after ?? undefined,
    });
  }
  if (!deviceTime && !received && ev.time) {
    timeline.push({ key: "event", time: ev.time, timeBasis: "event time", pill: pillWord, tone: tone ?? "neutral", text: title });
  }

  // ── timeline query (fields the index can answer) ──
  const timelineQuery = timelineQueryOf(lane, src);

  // ── details ──
  const varbinds = varbindRowsOf(src);
  const fieldRows = detailRows(lane, src, prov, ev);
  const details: EventView["details"] = varbinds.length > 0
    ? { kind: "varbinds", title: "SNMP Varbinds (Decoded)", varbinds, rows: [] }
    : { kind: "fields", title: lane === "syslog" ? "Parsed Fields" : lane === "flow" ? "Flow Fields" : "Record Fields", varbinds: [], rows: fieldRows };

  // ── metrics ──
  const metricRows: ViewRow[] = Object.entries(metrics).map(([name, m]) => ({
    key: name, label: metricLabel(name), value: fmtPercentOrNum(name, m.value), prov: m.prov, formula: m.formula,
  }));
  if (utilization?.threshold) {
    metricRows.push({ key: "threshold", label: "Threshold", value: fmtPercentShort(utilization.threshold.value), prov: "reported", tip: "Stated in the device's own message. It is not a threshold configured in Correlix." });
  }
  const metricSeries = deviceId && (kind === "cpu" || kind === "memory") && SAFE_LABEL.test(deviceId)
    ? { metric: kind === "cpu" ? "device_cpu_percent" : "device_mem_percent", deviceId, label: kind === "cpu" ? "CPU %" : "Memory %" }
    : null;

  // ── incident draft (only what the record states, already redacted) ──
  const descLines = [
    `From ${laneLabel.toLowerCase()} record${eventId ? ` ${eventId}` : ""}.`,
    deviceName && `Device: ${deviceName}${deviceAddr && deviceAddr !== deviceName ? ` (${deviceAddr})` : ""}`,
    (deviceTime || ev.time) && `Time: ${deviceTime || ev.time}`,
    corr && `Correlation key: ${corr}`,
    message && message !== title && `Device message: ${message}`,
  ].filter(Boolean) as string[];
  const incidentDraft = {
    title: title.slice(0, 200),
    description: descLines.join("\n").slice(0, 3900),
    severity: tone ? SEVERITY_TO_INCIDENT[tone] : "medium" as const,
  };

  const id = hit._id ?? "";
  const t = pick(src, "timestamp") || ev.time;
  const link = id && t ? { signal: SEARCH_SIGNAL[lane], id, t } : null;

  return {
    lane,
    laneLabel,
    severity: { native, normalized, label: sevLabel, tone },
    title,
    subtitle,
    chips,
    primaryVisual: visual,
    sideStats,
    device: { name: deviceName, address: deviceAddr, inventory, rows: deviceRows },
    timing,
    classification,
    identity: { rows: identityRows, lifecycle, recovery },
    overview,
    timeline,
    timelineQuery,
    details,
    metrics: metricRows,
    metricSeries,
    provenance: prov,
    fields: ev.fields,
    pipeline: ev.pipeline,
    raw: src,
    incidentDraft,
    link,
    id,
    ev,
  };
}

/** A PromQL label value we are willing to put between quotes. Anything else gets no trend. */
const SAFE_LABEL = /^[A-Za-z0-9_.:\-]{1,128}$/;

function fmtPercentOrNum(name: string, v: number): string {
  return /percent$/.test(name) ? fmtPercent(v) : v.toLocaleString("en-US");
}

function utilizationSentence(u: UtilizationData): string {
  const word = u.resource === "cpu" ? "CPU utilization" : "Memory utilization";
  const parts = u.segments.map((s) => `${s.key} ${fmtPercent(s.value)}`).join(", ");
  return u.total !== null ? `${word} reached ${fmtPercentShort(u.total)}${parts ? ` (${parts})` : ""}` : `${word}: ${parts}`;
}

/** 2–3 sentences from observed values only. Nothing here explains a cause. */
function whatHappened(v: PrimaryVisual, summary: string, message: string, title: string): string {
  switch (v.kind) {
    case "cpu":
    case "memory": {
      const u = v.data;
      const word = u.resource === "cpu" ? "CPU" : "memory";
      const out: string[] = [];
      const sys = u.segments.find((s) => s.key === "system");
      const used = u.segments.find((s) => s.key === "used");
      if (u.total !== null) {
        const how = u.totalProv === "derived" && u.totalFormula ? ` (derived as ${u.totalFormula})` : "";
        out.push(`The device reported ${word} utilization at ${fmtPercentShort(u.total)}${how}${sys ? `, with system processes consuming ${fmtPercentShort(sys.value)} of ${word}` : used ? `, ${fmtPercentShort(used.value)} used` : ""}.`);
      } else {
        out.push(`The device reported ${u.segments.map((s) => `${s.label.toLowerCase()} ${fmtPercentShort(s.value)}`).join(", ")}.`);
      }
      if (u.threshold && u.total !== null) {
        out.push(u.total >= u.threshold.value
          ? `This exceeds the threshold of ${fmtPercentShort(u.threshold.value)} that the device reported in its own message.`
          : `This is below the threshold of ${fmtPercentShort(u.threshold.value)} that the device reported in its own message.`);
      }
      return out.join(" ");
    }
    case "bgp": {
      const b = v.data;
      const who = [b.peerAddress && `Peer ${b.peerAddress}`, b.afi && `(${b.afi}${b.peerAs ? `, AS ${b.peerAs}` : ""})`].filter(Boolean).join(" ");
      const move = b.prev ? `moved from ${b.prev} to ${b.state}` : `reported state ${b.state}; the previous state was not reported`;
      return [`${who || "The BGP peer"} ${move}.`, b.sentence].filter(Boolean).join(" ");
    }
    case "syslog_fault":
      if (v.data.unparsed) return "This line has not been parsed yet, so Correlix offers no explanation for it. The original frame is shown as the device sent it.";
      return v.data.explanation || summary || message;
    case "audit":
      return summary || message;
    default:
      return summary && summary !== title ? summary : message !== title ? message : "";
  }
}

function auditRows(src: Record<string, any>): ViewRow[] {
  const rows: ViewRow[] = [];
  const add = (key: string, label: string, value: string, mono = false) => {
    if (value) rows.push({ key, label, value, mono });
  };
  add("who", "Who", known(src, "audit.user", "audit_user", "user", "username", "user_name"));
  add("action", "Action", known(src, "audit.action", "audit_action", "action"));
  add("from", "From", known(src, "audit.source", "audit_source", "remote_address", "remote_addr", "src_ip", "client_ip"), true);
  add("via", "Via", known(src, "audit.via", "audit_via", "via", "method"));
  add("session", "Session", known(src, "audit.session", "session_id", "session"), true);
  return rows;
}

function genericRows(lane: Lane, src: Record<string, any>, ev: LogEvent): ViewRow[] {
  const rows: ViewRow[] = [];
  const add = (key: string, label: string, value: string, mono = false) => {
    if (value) rows.push({ key, label, value, mono, prov: "observed" });
  };
  if (lane === "app" || lane === "cloud") {
    add("level", "Level", ev.severity ? severityLabel(ev.severity) : "");
    add("service", lane === "cloud" ? "Provider" : "Service", known(src, lane === "cloud" ? "cloud_provider" : "compose_service", "service"));
    add("container", lane === "cloud" ? "Resource" : "Container", known(src, "container_name", "resource_id"), true);
    add("component", "Component", known(src, "component"));
    add("trace", "Trace ID", known(src, "trace_id"), true);
    add("error", "Error", known(src, "error"));
  } else if (lane === "security") {
    add("title", "Finding", known(src, "title", "control_title"));
    add("resource", "Resource", known(src, "resource", "entity_id"), true);
    add("status", "Status", known(src, "status"));
    add("remediation", "Remediation", known(src, "remediation"));
  } else if (lane === "quarantine") {
    add("reason", "Reason", known(src, "reason"));
    add("lane", "Lane", known(src, "lane"), true);
    add("source", "Source", known(src, "source_ip"), true);
    add("detail", "Detail", known(src, "detail"));
  } else if (lane === "trap") {
    add("trap", "Trap", known(src, "trap_name"));
    add("oid", "Trap OID", ev.trap?.oid ?? "", true);
    if (ev.trap?.interface) add("iface", "Interface", ev.trap.interface, true);
    add("uptime", "Device up for", ev.trap?.uptime ?? "", true);
  }
  return rows;
}

function timingRows(lane: Lane, src: Record<string, any>, ev: LogEvent): ViewRow[] {
  const rows: ViewRow[] = [];
  const timeRow = (key: string, label: string, iso: string, extra: Partial<ViewRow> = {}) => {
    if (!iso) return;
    // The local line only when the viewer's clock is not UTC already (it would repeat).
    const local = fmtLocal(iso);
    rows.push({ key, label, value: fmtUtc(iso), secondary: local && !/ (UTC|GMT)$/.test(local) ? `(${local})` : undefined, ...extra });
  };
  const delayRow = (seconds: number | null, prov: Provenance, tip = DELAY_TIP) => {
    if (seconds === null) return;
    rows.push({ key: "delay", label: "Observed Delay", value: `${Number(seconds.toFixed(3)).toLocaleString("en-US", { maximumFractionDigits: 3 })} seconds`, pill: Math.abs(seconds) >= 5 ? "warning" : "neutral", tip, prov });
  };
  if (lane === "trap") {
    const dev = known(src, "device_event_time");
    const rec = known(src, "received_time") || pick(src, "timestamp");
    timeRow("device_time", "Device Event Time", dev, { tip: "The time the device stamped on the event, from its own clock." });
    timeRow("received", "Received / Indexed", rec);
    const stated = num(src.observed_delay_s);
    delayRow(stated ?? (dev && rec ? secondsBetween(dev, rec) : null), stated !== null ? "derived" : "derived");
    const upS = num(src.device_uptime_s) ?? num(src.sys_uptime_seconds);
    const upH = known(src, "device_uptime_human", "sys_uptime_human");
    if (upH || upS !== null) {
      rows.push({ key: "uptime", label: "Device Uptime", value: [upH, upS !== null && `(${fmtSeconds(upS)})`].filter(Boolean).join(" "), icon: "clock" });
    }
  } else if (lane === "syslog") {
    const ts = pick(src, "timestamp");
    const ingested = known(src, "ingested_at");
    const basis = pick(src, "ts_source");
    if (basis === "edge_receive") {
      timeRow("event_time", "Event Time", ts, { tip: "The device's clock was off by more than five minutes, so the event time is when our edge read the frame." });
      timeRow("device_claim", "Device Clock Said", known(src, "device_timestamp"));
      const skew = num(src.clock_skew_s);
      if (skew !== null) rows.push({ key: "skew", label: "Device Clock Offset", value: `${skew.toLocaleString("en-US")} seconds`, pill: "warning" });
      rows.push({ key: "basis", label: "Time Basis", value: "Receiver clock (device clock not believed)" });
    } else {
      timeRow("device_time", "Device Time", ts, { tip: "The time in the syslog frame, from the device's clock." });
      timeRow("received", "Received / Indexed", ingested);
      if (ts && ingested) delayRow(secondsBetween(ts, ingested), "derived");
      if (basis) rows.push({ key: "basis", label: "Time Basis", value: basis === "timestamp" || basis === "event" ? "Device clock" : humanize(basis) });
    }
  } else if (lane === "flow") {
    timeRow("flow_time", "Flow Time", pick(src, "timestamp") || ev.time);
    const ns = pick(src, "time_received_ns");
    if (ns) timeRow("received", "Received", parseIso(ns)?.toISOString() ?? "");
  } else {
    timeRow("event_time", "Event Time", pick(src, "timestamp", "time", "dropped_at", "received_at") || ev.time);
    timeRow("received", "Received / Indexed", known(src, "ingested_at", "cx_restored_at"));
  }
  return rows;
}

function timelineQueryOf(lane: Lane, src: Record<string, any>): TimelineQuery | null {
  const fields = TIMELINE_SEARCHABLE[lane];
  if (!fields) return null;
  // Preferred: the correlation key or transition id, once the index can answer it.
  for (const k of TIMELINE_KEYS) {
    const v = known(src, k);
    if (v && fields.includes(k)) {
      return { clauses: [{ field: k, value: v }], basis: k === "transition_id" ? "Same transition" : "Same correlation key", signal: SEARCH_SIGNAL[lane] };
    }
  }
  const deviceId = known(src, "device_id");
  const eventType = known(src, "event_type");
  if (deviceId && eventType && fields.includes("device_id") && fields.includes("event_type")) {
    return {
      clauses: [{ field: "device_id", value: deviceId }, { field: "event_type", value: eventType }],
      basis: "Same device and event type (the correlation key is not searchable yet)",
      signal: SEARCH_SIGNAL[lane],
    };
  }
  return null;
}

/** The parsed/structured fields as typed rows, each marked with where it came from. */
function detailRows(lane: Lane, src: Record<string, any>, prov: Record<string, Provenance>, ev: LogEvent): ViewRow[] {
  if (lane === "flow" && ev.flow) {
    const f = ev.flow;
    const rows: ViewRow[] = [];
    const add = (key: string, label: string, value: string, p: Provenance = "observed") => {
      if (value) rows.push({ key, label, value, mono: true, prov: p });
    };
    add("src", "Source", f.source.address + (f.source.port ? `:${f.source.port}` : ""));
    add("dst", "Destination", f.destination.address + (f.destination.port ? `:${f.destination.port}` : ""));
    add("proto", "Protocol", f.protocol);
    add("service", "Service", f.service, "derived");
    add("in", "In interface", f.inInterfaceLabel);
    add("out", "Out interface", f.outInterfaceLabel);
    add("bytes", "Bytes", f.bytes);
    add("packets", "Packets", f.packets);
    add("exporter", "Exporter", f.exporter);
    for (const s of f.sampling) add(s.name, s.name, s.value);
    return rows;
  }
  // ev.fields is already the stated, non-pipeline fields, flattened and sorted.
  const SKIP = new Set(["message", "message_original", "varbinds", "metrics", "guidance", "enrichment", "bgp", "title", "summary"]);
  return ev.fields
    .filter((f) => f.value !== "" && !SKIP.has(f.name.split(".")[0]) && !(lane === "syslog" && f.name === "timestamp" && !src.timestamp))
    .map((f) => ({ key: f.name, label: f.name, value: f.value, mono: true, prov: prov[f.name] ?? prov[f.name.split(".")[0]] }))
    .slice(0, 200);
}

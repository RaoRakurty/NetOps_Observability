// Human-readable labels for the operator-facing RCA story. The engine speaks in
// signature ids and signal kinds; operators need plain language. These maps turn
// `sig.ent.middle-mile.dia-egress-latency` → "ISP / DIA egress latency" and
// `probe_latency_departure` → "Probe latency departure — active probe", while the
// raw id stays available (rendered small/gray) for debugging.
import type { Tone } from "./rcaCase";
import type { RcaFeedback, RcaVerdict, RcaWrongPart } from "../../services/api";
import { fmtDateTime } from "../../lib/time";

// NOC color system — tuned for engineers on wall + desk monitors, 24/7 day/night.
// Principle: the surface stays CALM (desaturated slate, off-white text, never pure
// black/white) so a quiet room reads as quiet; severity colors are the ONLY loud
// hues and are always paired with a glyph/label (colorblind-safe, color-not-only).
// All values clear WCAG 4.5:1 on the dark slate surfaces below.
// IMPORTANT: the app ships BOTH a light (default) and a dark theme. Text colors
// MUST defer to the theme tokens (var(--fg)/var(--muted)/var(--fg-subtle)) or
// they go invisible on the light canvas. Severity hues are mid-tone (≈600-level)
// so they read on a WHITE card and on dark slate alike — no neon (which only
// works on dark) and no pale (which only works on dark).
export const C = {
  // severity — mid-tone, theme-neutral (legible on white AND dark).
  // 2026-07: crit + discriminates lifted one step lighter (600→500) so the
  // CONFIRMED red and the evidence violet read vivid, not heavy, on the light
  // canvas; still ≥3:1 on white for the short bold chip text they colour.
  crit: "#F43F5E",        // critical / contradicts / malformed (matches --crit)
  warn: "#D97706",        // warning / caution / needed-to-confirm / control-plane / seam
  caution: "#B45309",     // softer burnt-amber for inline warnings (calm caution, not alarm; AA on white)
  ok: "#16A34A",          // healthy / linked / supports
  info: "#2563EB",        // info / device-telemetry / present-not-linked
  flow: "#0D9488",        // flows (teal)
  discriminates: "#8B5CF6", // discriminating evidence (violet)
  // text/surfaces — defer to theme tokens so they adapt light↔dark
  fg: "var(--fg)",        // primary text (theme-aware)
  muted: "#6B7280",       // secondary text — mid gray, readable on white + dark
  faint: "#8A93A6",       // tertiary / absent — lighter mid gray
  line: "var(--border)",  // borders/dividers (theme-aware)
  bg: "#0E1320",          // deepest surface, never #000
  panel: "#151B2B",       // card surface
} as const;

// Evidence planes — distinct, calm hues; always positioned + labeled so they read
// without relying on color alone. `label` is the NOC/operator name; `help` is the
// plain-English "what this is" line. Debug View shows the raw key instead (see
// modalityLabel(key, "debug")).
export const MODALITY_META: Record<string, { label: string; color: string; help: string }> = {
  device_telemetry: { label: "Device health", color: C.info, help: "interface errors, link counters, CPU, memory" },
  control_plane: { label: "Routing & link events", color: C.warn, help: "BGP, link up/down, syslog, traps" },
  passive_flow: { label: "Traffic flow evidence", color: C.flow, help: "traffic loss, volume drop, traffic shift" },
  active_probe: { label: "Active checks", color: C.ok, help: "ping, HTTP, STAMP, path checks" },
  // The FOURTH evidence class (T2b). A rule/benchmark/advisory VERDICT evaluated
  // against captured state — its own independent source class, never folded into
  // the network planes and never called "signals" on screen.
  security: { label: "Security", color: C.discriminates, help: "posture drift, internet exposure, security detections" },
};

export const MODALITY_ORDER = ["device_telemetry", "control_plane", "passive_flow", "active_probe"];

// Operator View → NOC label ("Device health"); Debug View → raw engine key
// ("device_telemetry"). Most callers are operator paths and omit `view`.
export function modalityLabel(key: string, view: "operator" | "debug" = "operator"): string {
  if (view === "debug") return key;
  return MODALITY_META[key]?.label ?? key.replace(/_/g, " ");
}
export function modalityHelp(key: string): string {
  return MODALITY_META[key]?.help ?? "";
}

// Signature id → friendly "Domain / fault" title.
const SIG_NAME: Record<string, string> = {
  "sig.ent.middle-mile.dia-egress-latency": "ISP / DIA egress latency",
  "sig.ent.wan-edge.bgp-peer-flap": "BGP peer flap",
  "sig.ent.access.local-link-fault": "Local link fault",
  "sig.ent.wan-edge.congestion": "WAN edge congestion",
  "sig.ent.wan-edge.routing-instability": "Routing instability",
  "sig.ent.middle-mile.physical-degradation": "Circuit / optics degradation",
  "sig.ent.internet.dns-impairment": "Internet / DNS impairment",
  "sig.ent.cloud.region-degradation": "Cloud / region degradation",
  "sig.ent.wan-edge.tunnel-mtu-blackhole": "Tunnel MTU blackhole",
};

export function signatureName(id: string): string {
  if (SIG_NAME[id]) return SIG_NAME[id];
  // fallback: last two dotted segments, humanized — "sig.sp.foo.bar-baz" → "Foo / bar baz"
  const parts = id.replace(/^sig\./, "").split(".");
  const tail = parts.slice(-2);
  return tail.map((p, i) => {
    const t = p.replace(/-/g, " ");
    return i === 0 ? t.charAt(0).toUpperCase() + t.slice(1) : t;
  }).join(" / ");
}

// Operator View headline — NOC "Possible …" phrasing from a small, fixed
// vocabulary (NOT the technical signature name, and never the raw id). Debug View
// uses signatureName()/the raw id instead.
// Scenario-signature → factual NOC title (the #14 decision: titles state WHAT was
// observed, never the verdict — confirmed/suspected is carried by the RCA-state
// pill + the engine wording). Covers every signature the correlation engine emits
// today, plus the enterprise/SP/DC scenarios the Phase-2/3 catalog will add (SD-WAN,
// cloud, LAN access, app, MPLS, DC fabric, security) so wording is ready the moment
// a signature lands. Titles stay neutral and non-overclaiming per rca-copy-precision.
const SIG_NOC_TITLE: Record<string, string> = {
  // ── WAN edge / middle-mile / internet / cloud (emitted today) ──
  "sig.ent.middle-mile.dia-egress-latency": "Middle-mile latency increase",
  "sig.ent.middle-mile.physical-degradation": "Middle-mile path degradation",
  "sig.ent.wan-edge.bgp-peer-flap": "Routing adjacency change",
  "sig.ent.wan-edge.routing-instability": "Routing instability",
  "sig.ent.wan-edge.congestion": "WAN edge congestion",
  "sig.ent.wan-edge.tunnel-mtu-blackhole": "Path MTU blackhole",
  "sig.ent.access.local-link-fault": "Link state change",
  "sig.ent.internet.dns-impairment": "DNS resolution impairment",
  "sig.ent.cloud.region-degradation": "Cloud region degradation",
  "sig.ent.cloud.region-impairment": "Cloud region impairment",
  // ── SD-WAN overlay (Phase 2) ──
  "sig.ent.sdwan.tunnel-sla-breach": "SD-WAN tunnel SLA breach",
  "sig.ent.sdwan.tunnel-flap": "SD-WAN tunnel flap",
  "sig.ent.wan-edge.ipsec-down": "IPsec tunnel down",
  // ── Cloud reachability (Phase 3) ──
  "sig.ent.cloud.path-blocked": "Cloud path unreachable",
  "sig.ent.cloud.gateway-degradation": "Cloud gateway degradation",
  // ── LAN / access (Phase 2) ──
  "sig.ent.access.uplink-down": "Access uplink down",
  "sig.ent.access.qos-drops": "QoS drops on access",
  // ── Application (network attribution) ──
  "sig.ent.app.degradation-network-clear": "Application degradation (network clear)",
  // ── Application / SaaS experience lane — each cause names ITS suspect; none
  // of these may ever read as a generic "network change" (owner 2026-07-12) ──
  "sig.ent.app.saas-experience-degraded": "SaaS / application experience degraded",
  "sig.ent.app.lb-target-health-failure": "Load-balancer target health failure",
  "sig.ent.app.tls-cert-expired": "TLS certificate expired",
  "sig.ent.app.dns-failover-wrong-target": "DNS failover to a wrong target",
  // ── Cloud private-path lane ──
  "sig.ent.cloud.ipsec-tunnel-down": "IPsec tunnel down — cloud private path",
  "sig.ent.middle-mile.ipsec-underlay-down": "Underlay path to VPN peer down",
  "sig.ent.cloud.app-dependency-down": "Cloud application dependency down",
  "sig.ent.cloud.private-connectivity-down": "Cloud private connectivity down",
  "sig.ent.cloud.route-table-blackhole": "Cloud route-table blackhole",
  "sig.ent.cloud.sg-nacl-block": "Cloud security-group / NACL block",
  // ── Service-provider core · DC fabric · security ──
  "sig.sp.core.mpls-lsp-down": "MPLS LSP down",
  "sig.dc.fabric.uplink-fault": "Fabric uplink fault",
  "sig.ent.security.fw-policy-drop": "Firewall policy drop",
};
// Dominant evidence plane → NOC headline when no signature has matched.
// Titles describe the OBSERVED condition factually — the NOT CONFIRMED / Confidence
// badges carry the verdict, not the title (no speculative "Possible …" hedging).
export const PLANE_NOC_TITLE: Record<string, string> = {
  active_probe: "Path performance change",
  device_telemetry: "Device health change",
  control_plane: "Routing adjacency change",
  passive_flow: "Traffic flow change",
  security: "Security finding",
};
// Domain-correct fallback for an unmapped signature — order matters: cloud and
// SD-WAN/tunnel are tested BEFORE the generic WAN/provider catch, so a cloud or
// overlay fault is never mislabelled "WAN / provider path change" (the bug the
// old single `cloud`-in-WAN branch caused).
// friendlyProblemId turns a correlation UUID into a stable, NOC-readable handle
// (P-5564D1). The scheme is byte-identical to the Go backend's problemDisplayID
// ("P-" + first 6 hex of the UUID, uppercased) so an operator sees ONE consistent
// id across the Action Queue, the RCA inspector and Iris AI. Display-only:
// callers keep the full UUID for routes/API/citation ids. A non-UUID input
// (already-friendly id, empty) is returned unchanged so it's safe to call twice.
export function friendlyProblemId(corrId: string): string {
  if (!corrId || corrId.startsWith("P-")) return corrId;
  const hex = corrId.replace(/-/g, "");
  if (hex.length < 6) return corrId;
  return "P-" + hex.slice(0, 6).toUpperCase();
}

// friendlyIncidentId is the Incident-system sibling of friendlyProblemId
// (INC-8591A3 from a 16-hex internal id) — byte-identical to the Go backend's
// incidentDisplayID, so Slack cards, the Incidents list and the Inspector show
// ONE handle (#103 UX-2). Display-only; the internal id stays canonical.
export function friendlyIncidentId(id: string): string {
  if (!id || id.startsWith("INC-")) return id;
  if (id.length < 6) return id;
  return "INC-" + id.slice(0, 6).toUpperCase();
}

export function signatureNocTitle(id: string): string {
  if (SIG_NOC_TITLE[id]) return SIG_NOC_TITLE[id];
  // app/SaaS BEFORE every network rung: an application-domain signature must
  // never be mislabelled as a network change (owner directive 2026-07-12).
  // Mirrors ai_labels.go signatureNocTitle — keep both sides in sync.
  if (/\.app\.|saas|experience/.test(id)) return "Application / service experience change";
  if (/k8s|kubernetes|mesh/.test(id)) return "Cloud workload networking change";
  if (/cert|tls/.test(id)) return "TLS / certificate issue";
  if (/cloud/.test(id)) return "Cloud service-path change";
  if (/sdwan|overlay|tunnel|ipsec/.test(id)) return "SD-WAN / tunnel change";
  if (/dns/.test(id)) return "DNS resolution impairment";
  if (/mpls|lsp|l3vpn|vrf/.test(id)) return "MPLS / VPN path change";
  if (/dia|middle-mile|internet|provider|congestion|wan/.test(id)) return "WAN / provider path change";
  if (/bgp|ospf|isis|routing/.test(id)) return "Routing adjacency change";
  if (/link|access|uplink/.test(id)) return "Link state change";
  if (/nat|fw|firewall|policy|security|waf|proxy/.test(id)) return "Security / policy change";
  if (/device|resource|cpu|mem|hardware|fabric/.test(id)) return "Device health change";
  // honest last resort: an unmapped signature is an anomaly with an
  // undetermined cause — never assert "network change" without evidence.
  return "Anomaly observed — cause undetermined";
}

// signal kind → (humanized label, modality, expected source).
const KIND_META: Record<string, { modality: string; source: string }> = {
  probe_rtt_anomaly: { modality: "active_probe", source: "STAMP / synthetic probes" },
  probe_latency_departure: { modality: "active_probe", source: "STAMP / synthetic probes" },
  probe_loss: { modality: "active_probe", source: "STAMP / synthetic probes" },
  dns_latency_high: { modality: "active_probe", source: "DNS probes" },
  dns_failure_rate: { modality: "active_probe", source: "DNS probes" },
  bgp_state_anomaly: { modality: "device_telemetry", source: "gNMI / SNMP BGP-MIB" },
  bgp_adjacency_change: { modality: "control_plane", source: "syslog (%BGP ADJCHANGE)" },
  bgp_path_change: { modality: "control_plane", source: "BGP / routing telemetry" },
  ospf_adjacency_change: { modality: "control_plane", source: "syslog (%OSPF ADJCHANGE)" },
  link_state_change: { modality: "control_plane", source: "syslog (%LINK/%LINEPROTO)" },
  lldp_neighbor_change: { modality: "control_plane", source: "syslog / LLDP" },
  device_resource_anomaly: { modality: "device_telemetry", source: "SNMP / gNMI host metrics" },
  if_metric_anomaly: { modality: "device_telemetry", source: "SNMP / gNMI interface counters" },
  if_util_high: { modality: "device_telemetry", source: "SNMP / gNMI interface counters" },
  if_errors: { modality: "device_telemetry", source: "SNMP / gNMI interface counters" },
  metric_anomaly: { modality: "device_telemetry", source: "SNMP / gNMI metrics" },
  qos_drops: { modality: "device_telemetry", source: "SNMP / gNMI QoS counters" },
  lb_5xx: { modality: "passive_flow", source: "LB / app telemetry" },
  cloud_gw_anomaly: { modality: "passive_flow", source: "cloud gateway telemetry" },
  cloud_health_event: { modality: "passive_flow", source: "cloud health feed" },
  flow_volume_anomaly: { modality: "passive_flow", source: "NetFlow / IPFIX / sFlow" },
  tunnel_degraded: { modality: "active_probe", source: "tunnel probes" },
  tunnel_flap: { modality: "control_plane", source: "SD-WAN controller" },
};

// Routing-protocol signals that a NOC reads as "routing", regardless of HOW they
// were observed. The engine keeps these on their true modality_class for the
// independence math (a polled BGP metric and a BGP syslog event are independent
// observers); this is a DISPLAY-only test, used to place them on the operator
// timeline's "Routing & link events" lane where operators expect to find them.
export function isRoutingKind(kind: string): boolean {
  return /bgp|ospf|isis|^ldp|rsvp|adjacency|route_|_route|^bfd|peer/.test(kind);
}

export function kindMeta(kind: string): { modality: string; source: string } {
  if (KIND_META[kind]) return KIND_META[kind];
  if (/^probe_|_rtt|loss|latency/.test(kind)) return { modality: "active_probe", source: "synthetic probes" };
  if (/dns_/.test(kind)) return { modality: "active_probe", source: "DNS probes" };
  if (/bgp|ospf|isis|link|lldp|adjacency|_state_/.test(kind)) return { modality: "control_plane", source: "syslog / routing telemetry" };
  if (/flow|^cloud|lb_/.test(kind)) return { modality: "passive_flow", source: "flow / cloud telemetry" };
  return { modality: "device_telemetry", source: "device metrics" };
}

// Friendly NOC names for the engine's signal kinds. Used everywhere a kind is
// shown to an operator (timeline labels, marker panel, tooltips). Debug surfaces
// that need the exact engine kind use the raw `kind` string directly instead.
const KIND_NOC: Record<string, string> = {
  probe_rtt_anomaly: "Slower response", probe_latency_departure: "Response-time change",
  probe_loss: "Packet loss", dns_latency_high: "Slow DNS", dns_failure_rate: "DNS failures",
  if_metric_anomaly: "Interface counter change", if_util_high: "High link utilization",
  if_errors: "Interface errors", metric_anomaly: "Metric change",
  device_resource_anomaly: "Device CPU/memory change", qos_drops: "QoS drops",
  link_state_change: "Link up/down", lldp_neighbor_change: "Neighbor change",
  bgp_adjacency_change: "BGP neighbor change", bgp_state_anomaly: "BGP state change",
  bgp_path_change: "Route change", ospf_adjacency_change: "OSPF neighbor change",
  flow_volume_anomaly: "Traffic volume change", lb_5xx: "Gateway errors",
  cloud_gw_anomaly: "Cloud gateway change", cloud_health_event: "Cloud health event",
  tunnel_degraded: "Tunnel degraded", tunnel_flap: "Tunnel flap",
  // Cloud App Observability kinds (#81 P3G) — operator language for the cloud plane.
  cloud_health: "Cloud app health event", cloud_resource_health: "Cloud resource health change",
  cloud_metric: "Cloud metric change", database_metric: "Database metric change",
  cloud_flow_log: "Cloud flow-log change", cloud_lb_log: "Load-balancer error rate",
  cloud_change: "Cloud configuration change", cloud_audit: "Cloud audit event",
  security_policy_change: "Security policy change",
  ipsec_tunnel_status: "IPsec/IKE tunnel state",
  ipsec_underlay_status: "Underlay path check (gateway to peer)",
  // Security evidence-class kinds (T2b). The lane discriminator IS the kind; the
  // producing rule/control identity rides in attrs.
  security_posture: "Security posture finding", security_exposure: "Exposure finding",
  security_signal: "Security detection",
};
// "probe_latency_departure" → "Response-time change"; trims a trailing _clear.
export function kindLabel(kind: string): string {
  const base = kind.replace(/_clear$/, "");
  if (KIND_NOC[base]) return KIND_NOC[base];
  const words = base.replace(/_/g, " ");
  return words.charAt(0).toUpperCase() + words.slice(1);
}

// ── Security evidence class (T2b / A7) ───────────────────────────────────────
// The engine's fourth evidence class is a VERDICT plane (a rule/benchmark/
// advisory evaluated against captured state), so it is an INDEPENDENT source in
// its own right — never folded into the network planes, and never displayed with
// the engine word. The three lane kinds each get their own operator noun so a
// reader can tell a posture drift from an internet exposure from a detection.
export const SECURITY_MODALITY = "security";

// The class name as it appears in the "N independent sources" accounting and in
// the verdict reason ("Only security evidence saw this — …"). MODALITY_META's
// label is the bare noun because the prose paths append " evidence" themselves.
export const SECURITY_SOURCE_LABEL = "Security evidence";

const SECURITY_KIND_TITLE: Record<string, string> = {
  security_posture: "Security posture",
  security_exposure: "Exposure",
  security_signal: "Security detection",
};

/** True for the engine's security modality_class (case-insensitive: the wire
 *  value is lowercase, the enum name is SECURITY — accept either). */
export function isSecurityModality(modality: string): boolean {
  return (modality || "").trim().toLowerCase() === SECURITY_MODALITY;
}

/** Security lane kind → its operator source class ("Exposure"). An unregistered
 *  security kind degrades to the class label rather than showing a raw token. */
export function securityClassTitle(kind: string): string {
  return SECURITY_KIND_TITLE[kind.replace(/_clear$/, "")] ?? SECURITY_SOURCE_LABEL;
}

/** The independent SOURCE CLASS one observation is read as. Security evidence
 *  reports its subclass ("Exposure"); every other modality keeps the existing
 *  plane label, so this is a pure widening of modalityLabel(). */
export function evidenceSourceLabel(s: { kind: string; modality_class: string }): string {
  return isSecurityModality(s.modality_class) ? securityClassTitle(s.kind) : modalityLabel(s.modality_class);
}

/** The provider behind a security observation. The engine stamps the observer as
 *  `security:<provider>`; the prefix is engine plumbing, the provider is the
 *  witness an operator needs to see. "" when unknown — never a guess. */
export function securityProvider(observerId?: string): string {
  const raw = (observerId ?? "").trim();
  if (!raw) return "";
  const i = raw.indexOf(":");
  const tail = i >= 0 ? raw.slice(i + 1).trim() : raw;
  return tail && tail !== "lane" ? tail : "";
}

// Operator-facing evidence CLASS for a signal — the lane a NOC reads it as.
// Routing-protocol kinds (BGP/OSPF/ISIS/…) read as "routing/link" regardless of
// HOW they were observed: a *polled* BGP state metric (modality device_telemetry)
// is still routing evidence to an operator, NOT device health. So this classifies
// by isRoutingKind() over the raw modality_class. The engine's independence /
// verdict math always uses modality_class; this is DISPLAY-only. Pure + testable.
export function signalClassKey(s: { kind: string; modality_class: string }): string {
  return isRoutingKind(s.kind.replace(/_clear$/, "")) ? "control_plane" : s.modality_class;
}
// class key → the "<Class> evidence:" prefix used on the selected-evidence panel.
// ("signal" is engine vocabulary — a NOC reads it as an independent clue, so the
// word never reaches operator text; see rca-evidence-summary.md §3.)
const CLASS_SIGNAL_LABEL: Record<string, string> = {
  control_plane: "Routing/link evidence",
  device_telemetry: "Device-health evidence",
  passive_flow: "Traffic-flow evidence",
  active_probe: "Active-check evidence",
  security: "Security evidence",
};
// class key → short noun for inline prose ("supporting routing/link evidence").
export const CLASS_NOUN: Record<string, string> = {
  control_plane: "routing/link", device_telemetry: "device-health",
  passive_flow: "traffic-flow", active_probe: "active-check",
  security: "security",
};
// "Routing/link evidence: BGP state change" — the operator title for one signal.
export function signalClassTitle(s: { kind: string; modality_class: string }): string {
  const key = signalClassKey(s);
  return `${CLASS_SIGNAL_LABEL[key] ?? "Evidence"}: ${kindLabel(s.kind)}`;
}

// ── Verdict-reason wording (owner directive 2026-07-18) ──────────────────────
// The engine's verdict reasons are precise but speak engine ("single modality
// class (active_probe); need ≥2 — every modality has a blind spot"). A NOC admin
// needs the OPERATIONAL consequence, not the taxonomy lecture. This rewrites the
// known reason shapes into operator language; unrecognized reasons pass through
// with raw tokens humanized. Honesty is preserved — only the register changes;
// the verbatim engine reasons stay available behind "How was this verified?".
const REASON_TOKEN_LABEL: Record<string, string> = {
  active_probe: "probes", control_plane: "routing/link events",
  device_telemetry: "device health", passive_flow: "traffic flow",
  internal_self_probe: "an internal self-check", customer_path: "a customer-path probe",
  synthetic_lab_probe: "a lab probe",
};
export function nocVerdictReason(r: string): string {
  let m = r.match(/single modality class \((\w+)\)/i);
  if (m) {
    const who = REASON_TOKEN_LABEL[m[1]] ?? m[1].replace(/_/g, " ");
    return `Only ${who} saw this — a second independent source is needed to confirm.`;
  }
  m = r.match(/no independent cross-modality pair(?: \(fate-shared: ([^)]+)\))?/i);
  if (m) {
    return m[1]
      ? `The sources that saw this share a failure point (${m[1].replace(/_/g, " ")}), so they cannot confirm each other independently.`
      : "The sources that saw this share a failure point, so they cannot confirm each other independently.";
  }
  m = r.match(/required modality (\w+) present but only low-authority/i);
  if (m) {
    const who = REASON_TOKEN_LABEL[m[1]] ?? m[1].replace(/_/g, " ");
    return `Only low-trust ${who} saw this — not enough on their own to confirm.`;
  }
  m = r.match(/required modality missing[^:]*:\s*(\w+)/i);
  if (m) {
    const who = REASON_TOKEN_LABEL[m[1]] ?? m[1].replace(/_/g, " ");
    return `No trusted ${who} evidence in this window.`;
  }
  if (/cannot confirm without an independent trusted modality/i.test(r))
    return "A second independent source is needed to confirm.";
  // fallback: humanize raw tokens, drop ≥ notation
  let out = r;
  for (const [tok, label] of Object.entries(REASON_TOKEN_LABEL)) out = out.split(tok).join(label);
  return out.replace(/≥\s*(\d+)/g, "$1 or more").replace(/\bmodality\b/gi, "source");
}

// Probe authority model (Step 3) — operator labels + colors.
export const PROBE_AUTHORITY_META: Record<string, { label: string; color: string }> = {
  high: { label: "High authority", color: C.ok },
  medium: { label: "Medium authority", color: C.info },
  low: { label: "Low authority — support only", color: C.warn },
  debug_only: { label: "Debug / lab — excluded", color: C.faint },
};
export const PROBE_SCOPE_LABEL: Record<string, string> = {
  customer_path: "Customer path",
  service_dependency: "Service dependency",
  internal_self_probe: "Internal self-probe",
  synthetic_lab_probe: "Synthetic / lab probe",
  unknown: "Unclassified probe",
};
export function probeAuthorityLabel(a?: string): string {
  return a ? (PROBE_AUTHORITY_META[a]?.label ?? a) : "";
}
export function probeScopeLabel(s?: string): string {
  return s ? (PROBE_SCOPE_LABEL[s] ?? s) : "";
}
export function canConfirm(a?: string): boolean {
  return a === "high" || a === "medium";
}

// Display-name / entity-label layer (Operator View). Internal platform-service /
// container / storage names are replaced with NOC-safe role labels so the product
// never leaks its own infrastructure (backend component names, raw service /
// storage / database names). Real network device + path names (leaf1, wan-r2, …)
// pass through — they ARE NOC-meaningful. Bare IPs with no metadata genericize to
// "Monitored target". Raw entity ids stay available in Debug View only.
const INFRA_DISPLAY: Record<string, string> = {
  // our own telemetry/data stores → generic, never product-internal names
  clickhouse: "Monitoring data store", opensearch: "Monitoring data store",
  "opensearch-dashboards": "Monitoring data store", prometheus: "Monitoring data store",
  victoriametrics: "Monitoring data store", victoria: "Monitoring data store",
  // kafka is current; redpanda/redis stay mapped for historical rows only.
  loki: "Monitoring data store", kafka: "Internal service", valkey: "Internal service",
  redpanda: "Internal service", redis: "Internal service",
  postgres: "Internal service", "netbox-postgres": "Internal service",
  // app / gateway / platform services
  nginx: "Web gateway", api: "Platform service", backend: "Platform service",
  frontend: "Web app", correlation: "Monitoring service", netbox: "Inventory service",
  grafana: "Monitoring service",
  // pipeline / collectors
  vector: "Ingest pipeline", "vector-aggregator": "Ingest pipeline", "vector-router": "Ingest pipeline",
  promtail: "Internal service", "syslog-ng": "Internal service", goflow2: "Internal service",
  "node-exporter": "Internal service", cadvisor: "Internal service",
  // monitoring agents / probes
  prober: "Monitoring agent", reflector: "Monitoring agent", stamp: "Monitoring agent",
  // identity / platform sidecars / generators — never surface product internals
  keycloak: "Identity service", alertmanager: "Internal service", gotenberg: "Internal service",
  swtpm: "Internal service", "swtpm-sidecar": "Internal service", gnmic: "Ingest pipeline",
  telegraf: "Ingest pipeline", tgen: "Traffic generator",
};
const IPV4 = /^\d{1,3}(?:\.\d{1,3}){3}$/;
// Entity-type prefixes the engine stamps onto ids (path:a->b, device:leaf1). They
// are engine vocabulary — strip them for the operator display so a name never
// reads as "path:prober". (An interface id like "leaf1:Ethernet1" carries no such
// keyword prefix, so it survives intact.)
const ENTITY_PREFIX = /^(?:path|device|host|node|segment|site|service|prefix):/i;
// Internal / test markers — never customer-meaningful. Genericized even when the
// exact name isn't in the infra map, so a lab/demo/sidecar target can't leak into
// Operator View (item 6). Matched only as a delimited word to spare real devices.
const INTERNAL_HINT = /(?:^|[-_.])(?:demo|scratch|sidecar|dummy|sandbox|fixture|selftest|test)(?:[-_.]|$)/i;
function mapToken(t: string): string {
  const s = t.trim().replace(ENTITY_PREFIX, "");         // drop entity-type prefix for display
  const base = s.split(":")[0].trim().toLowerCase();
  if (INFRA_DISPLAY[base]) return INFRA_DISPLAY[base];
  if (INTERNAL_HINT.test(base)) return "Internal / test target";
  if (IPV4.test(base)) return "Monitored endpoint";      // bare IP, no metadata → generic
  return s;                                              // real device / interface / path name
}
// Friendly entity label. "prober->clickhouse" → "Monitoring agent → Monitoring data store".
export function entityLabel(raw: string): string {
  if (!raw) return raw;
  if (raw.includes("->")) return raw.split("->").map((s) => mapToken(s)).join(" → ");
  return mapToken(raw);
}

// isInternalEntity — true when EVERY part of the entity resolves to the platform's
// own infrastructure / a test target (clickhouse, nginx, api, prober, …). Used to
// keep internal self-monitoring objects out of the customer-facing RCA view (RCA is
// for customer networks, not our own stack). A mixed entity (one real device) is
// NOT internal, so a genuine incident touching a customer device is never hidden.
export function isInternalEntity(raw: string): boolean {
  if (!raw) return false;
  const parts = raw.includes("->") ? raw.split("->") : [raw];
  return parts.every((p) => {
    const s = p.trim().replace(ENTITY_PREFIX, "");
    const base = s.split(":")[0].trim().toLowerCase();
    return !!INFRA_DISPLAY[base] || INTERNAL_HINT.test(base);
  });
}

// mentionsInternal — true when ANY part of the entity is platform infra / a
// monitoring agent. Used for ENTITY-LEVEL display filtering: a path episode like
// "api->192.0.2.120" must NOT show to the operator (its source is a platform
// service), even though isInternalEntity() (all-parts) returns false for it.
// (Object-level HIDING still uses the conservative all-parts isInternalEntity so a
// real customer incident touching some infra is never hidden wholesale.)
export function mentionsInternal(raw: string): boolean {
  if (!raw) return false;
  const parts = raw.includes("->") ? raw.split("->") : [raw];
  return parts.some((p) => {
    const s = p.trim().replace(ENTITY_PREFIX, "");
    const base = s.split(":")[0].trim().toLowerCase();
    return !!INFRA_DISPLAY[base] || INTERNAL_HINT.test(base);
  });
}

// isInternalStackAffected — true when a correlation object's `affected` JSON
// touches ONLY internal infrastructure (every entity internal). Shared by the
// Correlations tab + the front-page Top Issues so internal self-monitoring never
// shows as a customer incident (decision #76).
export function isInternalStackAffected(affectedJSON: string): boolean {
  try {
    const a = JSON.parse(affectedJSON || "{}");
    const ents: string[] = [];
    for (const k of ["devices", "interfaces", "paths", "services", "segments", "prefixes", "sites"]) {
      (a[k] || []).forEach((e: string) => ents.push(e));
    }
    if (ents.length === 0) return false;
    return ents.every(isInternalEntity);
  } catch {
    return false;
  }
}

// Verdict owner → who acts.
export const OWNER_LABEL: Record<string, string> = {
  netops: "NetOps", isp: "ISP / carrier", carrier: "Carrier", cloud_provider: "Cloud provider",
  app_team: "App team", colo_provider: "Colo provider", sdwan_vendor: "SD-WAN vendor",
};
export function ownerLabel(o?: string): string {
  return o ? (OWNER_LABEL[o] ?? o) : "";
}

// External-ticket state → operator wording (#78). Keeps engine enum tokens
// (not_created/open/…) out of the UI; plain NOC phrasing instead.
export const TICKET_STATE_LABEL: Record<string, string> = {
  not_created: "No ticket",
  pending: "Creation queued",
  open: "Open",
  updated: "Updated",
  resolved: "Resolved",
  failed: "Failed",
};
export function ticketStateLabel(s?: string): string {
  return s ? (TICKET_STATE_LABEL[s] ?? s) : "No ticket";
}
// Ticket state → pill tone (matches the rw-pill tones: green/orange/red/blue/gray).
export function ticketStateTone(s?: string): "green" | "orange" | "red" | "blue" | "gray" {
  switch ((s ?? "").toLowerCase()) {
    case "open":
    case "updated": return "blue";
    case "resolved": return "green";
    case "pending": return "orange";
    case "failed": return "red";
    default: return "gray";
  }
}
// Ticket audit action → operator wording.
export const TICKET_ACTION_LABEL: Record<string, string> = {
  create: "Created", update: "Updated", add_work_note: "Work note", resolve: "Resolved", reopen: "Reopened",
};
export function ticketActionLabel(a?: string): string {
  return a ? (TICKET_ACTION_LABEL[a] ?? a) : "—";
}

// --- Operator wording for the causal-graph / boundary view (item 10) ----------
// Engine vocabulary ("seam", "topo", "grounding", "visibility partial/blind") is
// backend language; Operator View uses plain NOC phrasing. Debug View keeps raw.

// Seam control_plane_owner → who owns the boundary (NOC phrasing).
export const SEAM_OWNER_LABEL: Record<string, string> = {
  enterprise: "Internal", isp: "ISP", carrier: "Carrier", cloud: "Cloud",
  sdwan_controller: "SD-WAN", colo: "Colo", unknown: "Provider",
};
export function seamOwnerLabel(o?: string): string {
  return o ? (SEAM_OWNER_LABEL[o] ?? o) : "Provider";
}
// Seam control_plane_owner → color, so a boundary reads "whose domain / whose
// fault" at a glance (the ThousandEyes responsibility-split idea, validated in
// docs/design/research/cisco-cloud-control-aicanvas-study.md). Always paired with
// the owner LABEL on the node, so color is reinforcing — never the sole carrier
// (colorblind-safe). One source of truth across SeamGraph, the summary mini-graph,
// and the relationship preview.
export const SEAM_OWNER_COLOR: Record<string, string> = {
  enterprise: C.info,           // internal — blue
  isp: C.warn,                  // ISP — amber
  carrier: "#C2410C",           // carrier — deep orange (distinct from ISP)
  cloud: C.discriminates,       // cloud — violet
  sdwan_controller: C.flow,     // SD-WAN — teal
  colo: "#0EA5E9",              // colo — sky
  unknown: C.faint,             // unknown owner — grey
};
export function seamOwnerColor(o?: string): string {
  return SEAM_OWNER_COLOR[o ?? "unknown"] ?? SEAM_OWNER_COLOR.unknown;
}
// Seam visibility → how much we can see across the handoff.
export function visibilityLabel(v?: string): string {
  switch (v) {
    case "partial": return "limited visibility";
    case "blind": return "no provider visibility";
    case "full": return "full visibility";
    default: return v ? `${v} visibility` : "";
  }
}
// grounding_kind → how the evidence relates (operator phrasing). "Handoff", not
// "boundary": boundary is the path-spine ZONE word (LAN/WAN/CARRIER/CLOUD) and
// reusing it for seams caused a real owner-level confusion (2026-07-26) — the
// two vocabularies must never collide again.
export function relationLabel(kind?: string): string {
  return kind === "seam" ? "related through a provider handoff" : "related on the same path / device area";
}

// Seam type → short operator display (owner 2026-07-26: KEEP the short seam
// names — no long "demarc" phrases — but "DIA" is telco-sales jargon; operators
// know that seam as their ISP handoff). One source of truth; raw values pass
// through so an unknown type is never hidden.
export const SEAM_TYPE_LABEL: Record<string, string> = {
  DX: "DX", VPN: "VPN", SDWAN: "SD-WAN", "SD-WAN": "SD-WAN",
  DIA: "ISP", CLOUD_BACKBONE: "Cloud backbone",
};
export function seamTypeLabel(t?: string): string {
  return t ? (SEAM_TYPE_LABEL[t.toUpperCase()] ?? t) : "";
}
// Seam type → domain umbrella (owner 2026-07-26): WAN is the umbrella holding
// every enterprise external handoff (DX · ISP · SD-WAN · VPN); the cloud
// backbone is the provider's own. LAN and DC are DOMAINS the enterprise owns
// end-to-end — they have no handoff, so no seam ever carries them.
export const SEAM_UMBRELLA: Record<string, string> = {
  DX: "WAN", VPN: "WAN", SDWAN: "WAN", "SD-WAN": "WAN", DIA: "WAN",
  CLOUD_BACKBONE: "Cloud",
};
export function seamUmbrella(t?: string): string {
  return t ? (SEAM_UMBRELLA[t.toUpperCase()] ?? "") : "";
}

// --- Affected scope (item 1) -------------------------------------------------
// engine `affected` bucket key → operator label. The engine emits only buckets
// it populated (devices/interfaces/sites/paths/segments/services/prefixes).
export const AFFECTED_LABEL: Record<string, string> = {
  devices: "Devices", interfaces: "Interfaces", sites: "Sites", paths: "Paths",
  segments: "Boundary segments", services: "Apps / services", prefixes: "Networks",
};

// --- Escalation decision (item 5) --------------------------------------------
// Owners that sit OUTSIDE our walls — a confirmed issue owned by one of these is
// escalated to that provider, not worked internally.
export const OWNER_EXTERNAL = new Set([
  "isp", "carrier", "cloud_provider", "colo_provider", "sdwan_vendor",
]);

// --- "Not tied to this issue" reason (item 4) --------------------------------
// Operator-safe explanation for why a signal was NOT counted toward the issue.
// Maps the engine's raw link_reason (which uses seam/topology/grounding words) to
// plain NOC phrasing; the raw link_reason stays in Debug View only.
export function nocUnlinkedReason(s: {
  link_status: string; link_reason?: string; probe_authority?: string;
}): string {
  if (s.probe_authority === "debug_only")
    return "Internal/test check — kept for context, but it can't confirm a customer-impacting issue on its own.";
  switch (s.link_status) {
    case "attached": return "";
    case "recovery": return "This marks a recovery / all-clear, not the problem itself.";
    case "malformed": return "The source didn't identify what it measured, so it couldn't be tied to this issue.";
    default: {
      const r = s.link_reason || "";
      if (/threshold|weight|reinforc|single-modality|too far|fell short/i.test(r))
        return "Happened in the same window, but the change wasn't strong or corroborated enough to tie it to this issue.";
      return "Happened in the same window, but on a different path or device area — not part of this issue.";
    }
  }
}

// ── Application identity (#81 P5) — confidence bands + identification techniques
// in plain operator language (customer-facing rule: no raw enum tokens in the UI).
export function bandLabel(b?: string): string {
  switch ((b || "").toLowerCase()) {
    case "authoritative": return "Authoritative";
    case "high": return "High confidence";
    case "medium": return "Medium confidence";
    case "low": return "Low confidence";
    default: return "Unresolved";
  }
}

export function bandTone(b?: string): Tone {
  switch ((b || "").toLowerCase()) {
    case "authoritative": case "high": return "green";
    case "medium": return "blue";
    case "low": return "orange";
    default: return "gray";
  }
}

export const APP_ID_SOURCE_LABEL: Record<string, string> = {
  ngfw_app_id: "Firewall App-ID",
  ipfix_app_id: "NBAR2 / IPFIX App-ID",
  operator: "Operator catalog",
  sot: "Source of Truth",
  cloud_tag: "Cloud tag",
  cloud_graph: "Cloud resource graph",
  workload: "Workload identity",
  dns: "DNS",
  sni: "TLS SNI",
  ip_catalog: "IP / CIDR catalog",
  asn: "ASN",
  port: "Port heuristic",
};

export function appIdSourceLabel(s?: string): string {
  const k = (s || "").toLowerCase();
  return APP_ID_SOURCE_LABEL[k] || (s || "").replace(/_/g, " ");
}

// ── Path-causality RCA (P3 render) — customer-facing labels for the discovered
// typed SRC→DST path (design §5). The engine speaks in segment_type / role tokens
// (cloud/lan/dc/wan/wan_seam/internet/unknown; load_balancer/waf/dns/…); operators
// read plain NOC nouns ("Cloud", "Load Balancer", "Web Application Firewall"). No
// schema kinds, no backend vendor names — the customer-facing-language rule.

// segment_type → (label, short badge, tone class, accent color). Each type gets a
// DISTINCT visual treatment so the path reads as a typed sequence at a glance.
// Tone maps to the rw-pill palette (green/orange/blue/red/gray/purple). Accent is a
// concrete color (fallbacks legible on both the light report surface and dark app).
export const SEGMENT_META: Record<string, { label: string; short: string; tone: Tone; color: string }> = {
  // ── canonical segment taxonomy (owner directive 2026-07-19): the enterprise
  // connectivity chain a NOC operator recognizes. Every rendered path segment
  // canonicalizes onto one of these (pathModel.ts canonicalSegment).
  site_lan:      { label: "Site LAN",             short: "LAN",  tone: "blue",   color: C.info },
  edge_security: { label: "Edge security",        short: "SEC",  tone: "orange", color: C.caution },
  wan_edge:      { label: "WAN edge",             short: "WAN",  tone: "orange", color: C.warn },
  carrier:       { label: "Carrier / middle mile", short: "CARR", tone: "gray",  color: C.faint },
  dc_wan_edge:   { label: "DC WAN edge",          short: "DCWAN", tone: "orange", color: "#C2410C" },
  dc_fabric:     { label: "DC fabric",            short: "DC",   tone: "green",  color: C.flow },
  cloud_edge:    { label: "Cloud edge",           short: "CEDGE", tone: "purple", color: "#7C3AED" },
  cloud:         { label: "Cloud",                short: "CLOUD", tone: "purple", color: C.discriminates },
  // ── legacy engine vocabulary (typed-path blobs / spine boundaries still emit
  // these; pathModel canonicalizes them, but any direct render keeps a label).
  lan:      { label: "Site LAN",     short: "LAN",   tone: "blue",   color: C.info },
  dc:       { label: "DC fabric",    short: "DC",    tone: "green",  color: C.flow },
  wan:      { label: "WAN edge",     short: "WAN",   tone: "orange", color: C.warn },
  wan_seam: { label: "WAN Seam",     short: "SEAM",  tone: "orange", color: "#C2410C" },
  internet: { label: "Carrier / middle mile", short: "CARR", tone: "gray", color: C.faint },
  unknown:  { label: "Unknown segment", short: "?",  tone: "gray",   color: C.faint },
};
export function segmentLabel(t?: string): string {
  return SEGMENT_META[(t || "").toLowerCase()]?.label ?? "Unknown segment";
}
export function segmentMeta(t?: string) {
  return SEGMENT_META[(t || "").toLowerCase()] ?? SEGMENT_META.unknown;
}
// A segment we couldn't classify — rendered greyed WITH its reason, never guessed.
export function isOpaqueSegment(t?: string): boolean {
  return !t || (t || "").toLowerCase() === "unknown";
}

// device role → customer-facing device name. Cloud service devices (DNS/WAF/LB/FW/
// app) + LAN/DC roles (client/leaf/spine/edge) + WAN roles (NVA/tunnel).
export const ROLE_LABEL: Record<string, string> = {
  dns: "DNS", waf: "Web Application Firewall",
  load_balancer: "Load Balancer", lb: "Load Balancer",
  firewall: "Firewall", fw: "Firewall",
  app: "Application", application: "Application", host: "Host", server: "Server",
  client: "Client", leaf: "Leaf switch", spine: "Spine switch",
  edge: "Edge router", router: "Router", switch: "Switch",
  nva: "Network appliance", tunnel: "Tunnel", gateway: "Gateway", proxy: "Proxy",
  unknown: "Device",
  // canonical discovery-driven device roles (backend topology/roles.go)
  access_switch: "Access switch", distribution_switch: "Distribution switch",
  core_router: "Core router", wan_edge: "WAN edge router", carrier_hop: "Carrier hop",
  dc_wan_edge: "DC WAN edge", dc_leaf: "Leaf switch", dc_spine: "Spine switch",
  cloud_edge: "Cloud edge gateway",
};
export function roleLabel(r?: string): string {
  const k = (r || "").toLowerCase();
  return ROLE_LABEL[k] ?? (r ? r.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase()) : "Device");
}
// Short glyph for the path node badge (kept ≤4 chars, colorblind-safe when paired
// with the role label it always accompanies).
export const ROLE_ABBR: Record<string, string> = {
  dns: "DNS", waf: "WAF", load_balancer: "LB", lb: "LB", firewall: "FW", fw: "FW",
  app: "APP", application: "APP", host: "HOST", server: "SRV", client: "USER",
  leaf: "LEAF", spine: "SPN", edge: "EDGE", router: "RTR", switch: "SW",
  nva: "NVA", tunnel: "TUN", gateway: "GW", proxy: "PXY", unknown: "•",
  // canonical discovery-driven device roles
  access_switch: "SW", distribution_switch: "DIST", core_router: "CORE",
  wan_edge: "WAN", carrier_hop: "CARR", dc_wan_edge: "DCW",
  dc_leaf: "LEAF", dc_spine: "SPN", cloud_edge: "CGW",
};
export function roleAbbr(r?: string): string {
  const k = (r || "").toLowerCase();
  return ROLE_ABBR[k] ?? (r ? r.slice(0, 4).toUpperCase() : "•");
}
// role → the Cloud Logs family lane a device's logs live in (design §5: the
// device-in-path drill opens the family-tagged Cloud Logs). Only cloud service
// devices have a cloud-logs lane; a LAN/WAN device returns "" (no cloud drill).
const ROLE_CLOUD_FAMILY: Record<string, string> = {
  load_balancer: "lb", lb: "lb", waf: "waf", dns: "dns",
  host: "host", app: "host", application: "host", server: "host",
};
export function roleCloudFamily(r?: string): string {
  return ROLE_CLOUD_FAMILY[(r || "").toLowerCase()] ?? "";
}

// verdict tier → operator label + pill tone. The path headline shows the LIFT
// (baseline tier → verdict tier) so the on-path evidence's contribution is visible.
export const TIER_LABEL: Record<string, string> = {
  confirmed: "Confirmed", suspected: "Suspected", inconclusive: "Inconclusive",
  observed: "Observed", undetermined: "Undetermined",
};
export function tierLabel(t?: string): string {
  const k = (t || "").toLowerCase();
  return TIER_LABEL[k] ?? (t ? t.replace(/\b\w/g, (c) => c.toUpperCase()) : "Undetermined");
}
export function tierTone(t?: string): Tone {
  switch ((t || "").toLowerCase()) {
    case "confirmed": return "red";      // a confirmed customer-impacting break — loud
    case "suspected": return "orange";
    case "inconclusive": case "observed": return "blue";
    default: return "gray";
  }
}
// confidence token (strong/medium/weak) → operator label, for a segment/device.
export function confidenceLabel(c?: string): string {
  switch ((c || "").toLowerCase()) {
    case "strong": return "strong match";
    case "medium": return "likely";
    case "weak": return "weak signal";
    default: return c || "";
  }
}

// ---- Operator verdict feedback (Project 2 P7) -------------------------------
// One vocabulary for the control, the recorded line, and the exported report, so
// the PDF can never disagree with the screen.

/** Max reason CHARACTERS the backend accepts (rcafeedback.MaxReasonChars).
 *  Lives with the vocabulary, not the transport, so the counter and the server
 *  cap can never drift apart behind a mocked api module. */
export const RCA_MAX_REASON_CHARS = 500;

/** Button copy — the three choices an operator is offered. */
export const VERDICT_LABEL: Record<RcaVerdict, string> = {
  correct: "Correct", partial: "Partially", wrong: "Wrong",
};
/** Prose copy — the same verdict inside a sentence ("Partially" alone is not one). */
export const VERDICT_PROSE: Record<RcaVerdict, string> = {
  correct: "Correct", partial: "Partially correct", wrong: "Wrong",
};
/** The five RCA claims an operator can point at, in the order the case asserts
 *  them: what broke, who owns it, who it hit, what proved it, how it came back. */
export const WRONG_PART_ORDER: readonly RcaWrongPart[] = ["cause", "owner", "affected", "evidence", "recovery"];
export const WRONG_PART_LABEL: Record<RcaWrongPart, string> = {
  cause: "Cause", owner: "Owner", affected: "Affected", evidence: "Evidence", recovery: "Recovery",
};

/**
 * rcaVerdictLine — the single rendering of a recorded operator verdict:
 *   "Operator verdict: Wrong - owner - 'ISP was not at fault' - alice, Sep 02, 10:14:00 UTC"
 * Absent parts are omitted rather than filled with a placeholder. `utc` pins the
 * zone for exported documents (a printed report must not depend on a UI toggle).
 */
export function rcaVerdictLine(fb: RcaFeedback, opts: { utc?: boolean } = {}): string {
  const bits: string[] = [VERDICT_PROSE[fb.verdict] ?? String(fb.verdict)];
  if (fb.wrong_part) bits.push(fb.wrong_part);
  const reason = (fb.reason ?? "").trim();
  if (reason) bits.push(`'${reason}'`);
  const who = (fb.created_by || "").trim();
  const when = fb.created_at ? fmtDateTime(fb.created_at, opts.utc ? { mode: "utc" } : {}) : "";
  const stamp = [who, when].filter(Boolean).join(", ");
  if (stamp) bits.push(stamp);
  return `Operator verdict: ${bits.join(" \u2014 ")}`;
}

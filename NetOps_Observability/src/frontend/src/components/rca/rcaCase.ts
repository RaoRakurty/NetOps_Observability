import { CorrTimeline, CorrObject, Seam } from "../../services/api";
import { isRoutingKind, kindLabel, entityLabel, modalityLabel, MODALITY_ORDER, mentionsInternal, signatureNocTitle, PLANE_NOC_TITLE } from "./labels";

// rcaCase.ts — the data contract for the RCA workspace + the adapter that maps a
// real correlation object/timeline into it. The workspace component is pure
// presentation; ALL logic to decide verdict/evidence/ladder/etc. lives here (and
// ultimately in the engine). A confirmed multi-evidence object renders rich; a
// suspected single-signal object renders honestly (sparse, "not observed").
//
// EXAMPLE_CASE is a labelled synthetic scenario used only as a fallback / golden
// reference — never presented as live data.

export type Tone = "green" | "orange" | "blue" | "red" | "gray" | "purple";
export type NodeKind = "good" | "warn" | "bad" | "info";

export interface RcaPill { tone: Tone; text: string; }
export interface KV { k: string; v: string; mono?: boolean; tone?: Tone; }
export interface WhyLine { tone: "orange" | "green" | "blue"; label: string; text: string; }
export interface TopoNode { kind: NodeKind; abbr: string; name: string; meta: string; tag?: RcaPill; }
export interface TopoEdge { state: "good" | "warn" | "bad"; label?: string; side?: -1 | 1; }
export interface EvidenceCard { variant: "main" | "confirm" | "missing" | "conflict"; dot: Tone; title: string; pill: RcaPill; desc: string; finding: string; foot: string; }
export interface LadderStep { state: "done" | "active" | "next"; label: string; caption: string; }
export interface TimelineMarker { left: number; tone: Tone; label: string; detail: string; }
export interface TimelineLane { dot: Tone; label: string; markers: TimelineMarker[]; }
export interface HypothesisRow { rank: string; hypo: string; sub: string; conf: RcaPill; reason: string; }
export interface NextAction { badge: string; tone?: "red" | "green" | ""; text: string; }
export interface DebugRow { signal: string; used: RcaPill; weight: string; reason: string; }

export interface RcaCase {
  synthetic: boolean;             // true → show the "synthetic / example" watermark
  title: string;
  subtitle: string;
  pills: RcaPill[];
  decision: { tone: "confirmed" | "" | "red"; text: string };
  observedAt: string;
  rcaId: string;
  aside: KV[];
  summary: string;
  why: WhyLine[];
  impact: KV[];
  topology?: { nodes: TopoNode[]; edges: TopoEdge[] };
  evidence: EvidenceCard[];
  ladder: LadderStep[];
  timelineTicks: string[];
  timeline: TimelineLane[];
  hypotheses: HypothesisRow[];
  ticket: { callout: { tone: "confirmed" | "" | "red"; strong: string; text: string }; rows: KV[] };
  nextActions: NextAction[];
  assistant: { questions: string[]; sampleAnswer: string };
  debug: { accounting: DebugRow[]; promotion: KV[]; reasoning: string; model: unknown };
}

// ── EXAMPLE_CASE — synthetic golden scenario (confirmed multi-evidence) ───────
export const EXAMPLE_CASE: RcaCase = {
  synthetic: true,
  title: "Confirmed customer-impacting routing incident",
  subtitle: "Example case · LAN + SD-WAN + BGP + Cloud application evidence",
  pills: [
    { tone: "green", text: "✓ CONFIRMED" }, { tone: "blue", text: "Confidence: High" },
    { tone: "orange", text: "State: Recovering" }, { tone: "red", text: "Impact: Checkout API degraded" },
  ],
  decision: { tone: "confirmed", text: "Open incident and assign to NetOps / ISP escalation. Independent evidence confirms the BGP adjacency change caused SD-WAN path degradation and application impact." },
  observedAt: "2026-06-16 19:25:55 UTC",
  rcaId: "RCA-20260616-0427",
  aside: [
    { k: "Root cause object", v: "wan-r2 ↔ 192.168.100.5" }, { k: "Likely owner", v: "NetOps / Carrier" },
    { k: "MTTD", v: "28s" }, { k: "Suggested ticket", v: "Open P2" },
  ],
  summary: "A BGP state change was observed on wan-r2 with peer 192.168.100.5. Within the same evidence window, SD-WAN tunnel loss increased, active probes failed from the Dallas branch, traffic retransmits spiked, and Checkout API errors increased for the same branch users.",
  why: [
    { tone: "orange", label: "Why suspected", text: "Routing adjacency changed on the affected WAN device and peer." },
    { tone: "green", label: "Why confirmed", text: "Independent SD-WAN, flow, active-check, LAN, and app-log evidence all align to the same time window and affected scope." },
    { tone: "blue", label: "What changed", text: "BGP neighbor transitioned Established → Idle → Established; traffic shifted to the backup underlay after SLA failure." },
  ],
  impact: [
    { k: "Impact", v: "Confirmed customer impact", tone: "red" }, { k: "Affected site", v: "Dallas Branch" },
    { k: "Affected device", v: "wan-r2", mono: true }, { k: "Affected peer", v: "192.168.100.5", mono: true },
    { k: "SD-WAN path", v: "DIA-primary → AWS TGW" }, { k: "Application", v: "Checkout API" },
    { k: "Users affected", v: "~184 active sessions" }, { k: "Scope status", v: "Limited to Dallas egress path" },
  ],
  topology: {
    nodes: [
      { kind: "good", abbr: "LAN", name: "Dallas LAN", meta: "access healthy" },
      { kind: "good", abbr: "FW", name: "edge-fw-1", meta: "no drops" },
      { kind: "warn", abbr: "WAN", name: "wan-r2", meta: "BGP flap", tag: { tone: "orange", text: "ROOT CAUSE" } },
      { kind: "bad", abbr: "ISP", name: "192.168.100.5", meta: "primary underlay", tag: { tone: "red", text: "packet loss" } },
      { kind: "info", abbr: "TGW", name: "AWS TGW", meta: "path recovered" },
      { kind: "bad", abbr: "APP", name: "Checkout API", meta: "5xx spike", tag: { tone: "red", text: "IMPACT" } },
    ],
    edges: [
      { state: "good" }, { state: "warn", label: "BGP neighbor changed", side: -1 },
      { state: "bad", label: "loss 18.4% · jitter 74 ms", side: 1 }, { state: "good" },
      { state: "bad", label: "p95 920 ms · 5xx +12.8%", side: -1 },
    ],
  },
  evidence: [
    { variant: "main", dot: "orange", title: "Routing / BGP", pill: { tone: "orange", text: "Main evidence" }, desc: "BGP state, route updates, peer adjacency", finding: "Neighbor 192.168.100.5 changed state on wan-r2.", foot: "1 event used · no conflicting peer record yet" },
    { variant: "confirm", dot: "green", title: "SD-WAN telemetry", pill: { tone: "green", text: "Confirms" }, desc: "Tunnel SLA, loss, jitter, failover", finding: "Primary DIA tunnel loss reached 18.4%; SLA fail triggered.", foot: "3 signals used · aligned within +7s" },
    { variant: "confirm", dot: "green", title: "Traffic flow", pill: { tone: "green", text: "Confirms" }, desc: "NetFlow/IPFIX, retransmits, traffic shift", finding: "Checkout flows dropped 42%; TCP retransmits increased 6.2×.", foot: "5-min baseline · Dallas scope only" },
    { variant: "confirm", dot: "green", title: "Active checks", pill: { tone: "green", text: "Confirms" }, desc: "ICMP, HTTP, STAMP from independent vantage", finding: "Dallas probe to Checkout API hit 920 ms p95 and 3 HTTP failures.", foot: "Independent vantage confirmed" },
    { variant: "confirm", dot: "green", title: "Application logs", pill: { tone: "green", text: "Confirms impact" }, desc: "5xx, timeout, regional user errors", finding: "Checkout API 5xx increased 12.8% for Dallas source NAT range.", foot: "Tied to affected branch users" },
    { variant: "confirm", dot: "green", title: "Device health", pill: { tone: "green", text: "Supports" }, desc: "Interface counters, CPU, memory, link state", finding: "WAN interface showed input errors and carrier transitions; CPU/memory normal.", foot: "Supports network path, not host overload" },
    { variant: "missing", dot: "gray", title: "Cloud metrics", pill: { tone: "gray", text: "No issue" }, desc: "ALB, TGW, app node, region health", finding: "AWS service-side health normal; no region-wide degradation.", foot: "Helps exclude cloud outage" },
    { variant: "missing", dot: "gray", title: "Similar incidents", pill: { tone: "gray", text: "1 match" }, desc: "History, change window, known signatures", finding: "Similar ISP loss signature seen 21 days ago on same underlay.", foot: "Not used as confirmation alone" },
  ],
  ladder: [
    { state: "done", label: "✓ Observed", caption: "BGP event happened" },
    { state: "done", label: "✓ Suspected", caption: "Localized to wan-r2 adjacency" },
    { state: "done", label: "✓ Probable", caption: "Independent network evidence aligned" },
    { state: "active", label: "✓ Confirmed", caption: "Application impact confirmed" },
  ],
  timelineTicks: ["+0s", "+10s", "+20s", "+30s", "+40s", "+50s"],
  timeline: [
    { dot: "orange", label: "Routing / BGP", markers: [
      { left: 6, tone: "orange", label: "BGP state change", detail: "BGP neighbor 192.168.100.5 changed Established → Idle on wan-r2. This is the first observed routing event and localizes the suspected adjacency." },
      { left: 72, tone: "green", label: "BGP recovered", detail: "BGP neighbor recovered to Established after traffic shifted away from the degraded underlay." }] },
    { dot: "green", label: "SD-WAN", markers: [
      { left: 16, tone: "red", label: "SLA fail", detail: "SD-WAN primary DIA tunnel showed 18.4% loss and 74 ms jitter. SLA fail was observed after the BGP adjacency change." },
      { left: 48, tone: "blue", label: "traffic shifted", detail: "Traffic shifted to backup underlay. Loss started falling after path failover." }] },
    { dot: "green", label: "Traffic flows", markers: [{ left: 22, tone: "red", label: "flow drop + retransmits", detail: "NetFlow/IPFIX showed 42% drop in checkout traffic from Dallas and a 6.2× TCP retransmit spike." }] },
    { dot: "blue", label: "Active checks", markers: [
      { left: 30, tone: "red", label: "probe failed", detail: "Independent Dallas branch vantage probe observed Checkout API p95 latency at 920 ms and three HTTP failures." },
      { left: 84, tone: "green", label: "probe recovered", detail: "Probe recovered after failover. This confirms the impact was path-related and transient." }] },
    { dot: "red", label: "Application logs", markers: [{ left: 37, tone: "red", label: "5xx spike", detail: "Checkout API logs showed 5xx and timeout spike for Dallas branch source NAT range. This confirms customer impact." }] },
    { dot: "gray", label: "Cloud health", markers: [{ left: 42, tone: "gray", label: "normal", detail: "AWS ALB, app nodes, and TGW health checks were normal. This evidence helps exclude a cloud-side outage." }] },
  ],
  hypotheses: [
    { rank: "#1", hypo: "Customer-impacting routing incident", sub: "wan-r2 → ISP peer", conf: { tone: "green", text: "High" }, reason: "BGP, SD-WAN, active checks, flows, and app logs align in same window and scope." },
    { rank: "#2", hypo: "ISP/underlay packet-loss event", sub: "primary DIA path", conf: { tone: "green", text: "High" }, reason: "Loss/jitter spike and similar prior signature support carrier escalation." },
    { rank: "#3", hypo: "Application-side outage", sub: "Checkout API", conf: { tone: "gray", text: "Low" }, reason: "Cloud and service health normal; errors limited to Dallas source path." },
    { rank: "#4", hypo: "LAN access issue", sub: "Dallas branch LAN", conf: { tone: "gray", text: "Low" }, reason: "LAN switch and firewall health normal; impact begins at WAN edge." },
  ],
  ticket: {
    callout: { tone: "red", strong: "Open P2 incident:", text: "Customer impact is confirmed. Recommended owner is NetOps with carrier escalation." },
    rows: [
      { k: "Ticket state", v: "Open" }, { k: "Priority", v: "P2 · branch application degradation" },
      { k: "Assignment", v: "NetOps → ISP/Carrier" },
      { k: "Customer note", v: "Path instability affected Checkout API for Dallas users; traffic has shifted and service is recovering." },
      { k: "Auto-close", v: "After 20 min clean probes + no new BGP flap" },
    ],
  },
  nextActions: [
    { badge: "ESCALATE", tone: "red", text: "Open carrier ticket with peer 192.168.100.5, loss/jitter evidence, and BGP flap timestamps." },
    { badge: "INVESTIGATE", text: "Verify BGP flap reason: hold timer expiry, interface bounce, policy push, or prefix withdrawal." },
    { badge: "CHECK", text: "Review wan-r2 WAN interface counters, optics, and underlay circuit alarms for ±10 min." },
    { badge: "MONITOR", tone: "green", text: "Keep Dallas branch on backup underlay until 20 minutes of clean probes are observed." },
    { badge: "UPDATE", text: "Add RCA summary and blast radius to ServiceNow incident INC-104882." },
  ],
  assistant: {
    questions: ["Why is this confirmed instead of suspected?", "What evidence excludes a cloud outage?", "Which team owns the next action?", "What should I tell the customer?", "Show only evidence tied to Dallas branch."],
    sampleAnswer: "App errors are limited to Dallas source NAT users and start after WAN/BGP/SD-WAN loss. Cloud health and app node metrics are normal, so the app is impacted but is not the root cause.",
  },
  debug: {
    accounting: [
      { signal: "BGP state change", used: { tone: "green", text: "Used" }, weight: "0.25", reason: "First/strongest routing event. Localizes to wan-r2 peer adjacency." },
      { signal: "SD-WAN loss/jitter", used: { tone: "green", text: "Used" }, weight: "0.25", reason: "Independent path degradation within +7s." },
      { signal: "Traffic retransmits", used: { tone: "green", text: "Used" }, weight: "0.15", reason: "Confirms traffic impact and scope." },
      { signal: "Active probe failures", used: { tone: "green", text: "Used" }, weight: "0.15", reason: "Independent vantage from branch confirms user path impact." },
      { signal: "Application 5xx spike", used: { tone: "green", text: "Used" }, weight: "0.15", reason: "Confirms downstream customer impact." },
      { signal: "AWS regional health", used: { tone: "gray", text: "Excluding" }, weight: "0.05", reason: "Normal cloud health lowers app/cloud-root-cause hypothesis." },
    ],
    promotion: [
      { k: "Observed threshold", v: "1 trusted event" }, { k: "Suspected threshold", v: "localized routing object" },
      { k: "Probable threshold", v: "2 independent network signals" }, { k: "Confirmed threshold", v: "customer-impact evidence tied to same scope" },
      { k: "Current score", v: "0.92 / 1.00" }, { k: "Conflict penalty", v: "0.00" },
    ],
    reasoning: "The RCA promoted to confirmed because the application impact was independently observed and temporally/spatially tied to the network path event.",
    model: {
      rca_id: "RCA-20260616-0427", verdict: { status: "confirmed", confidence: "high", state: "recovering", priority: "P2" },
      root_cause: { type: "routing_adjacency", device: "wan-r2", peer: "192.168.100.5", event: "BGP Established → Idle → Established" },
      blast_radius: { site: "Dallas Branch", application: "Checkout API", users_affected: 184 },
    },
  },
};

// ── adapter: real correlation object/timeline → RcaCase ──────────────────────
const PLANE_DESC: Record<string, string> = {
  device_telemetry: "interface errors, link counters, CPU, memory",
  control_plane: "BGP, link up/down, syslog, traps",
  passive_flow: "traffic loss, volume drop, traffic shift",
  active_probe: "ping, HTTP, STAMP, path checks",
};
const PLANE_TITLE: Record<string, string> = {
  device_telemetry: "Device health", control_plane: "Routing / link", passive_flow: "Traffic flow", active_probe: "Active checks",
};

export function buildRcaCase(timeline: CorrTimeline, obj: CorrObject, _seams: Record<string, Seam>, owner: string, steps: string[]): RcaCase {
  const confirmed = timeline.verdict_tier === "confirmed";
  const suspected = timeline.verdict_tier === "suspected";

  // display-plane counts (routing kinds read as routing/link in operator view)
  const att: Record<string, number> = {};
  for (const s of timeline.signals) {
    if (s.kind.endsWith("_clear") || !s.attached) continue;
    const p = isRoutingKind(s.kind) ? "control_plane" : s.modality_class;
    att[p] = (att[p] ?? 0) + 1;
  }
  const dominant = Object.entries(att).sort((a, b) => b[1] - a[1])[0]?.[0] ?? "control_plane";
  const hasDevice = (att.device_telemetry ?? 0) > 0;
  const hasRouting = (att.control_plane ?? 0) > 0;
  const attachedCount = timeline.signals.filter((s) => s.attached && !s.kind.endsWith("_clear")).length;

  // routing context (device + peer)
  let device = "", peer = "", routeKind = "";
  for (const s of timeline.signals) {
    if (!s.attached || s.kind.endsWith("_clear") || !isRoutingKind(s.kind)) continue;
    device = s.entity_id; routeKind = s.kind;
    try { const a = JSON.parse((s as { attrs?: string }).attrs || "{}"); peer = a.peer || a.neighbor || ""; } catch { /* */ }
    const ci = s.entity_id.indexOf(":");
    if (ci > 0) { device = s.entity_id.slice(0, ci); if (!peer) peer = s.entity_id.slice(ci + 1); }
    if (mentionsInternal(device)) { device = ""; peer = ""; }
    break;
  }
  device = device ? entityLabel(device) : "";

  let title = timeline.top_hypothesis !== "undetermined" ? signatureNocTitle(timeline.top_hypothesis) : (PLANE_NOC_TITLE[dominant] ?? "Possible network issue");
  if (!confirmed && hasDevice && hasRouting && /routing|network/i.test(title) && !/wan|provider|boundary/i.test(title)) title = "Possible device/routing issue";

  const confidence = confirmed ? "High" : attachedCount >= 2 ? "Medium" : "Low";
  const stateText = (obj.state === "open") ? "Open" : "No longer active";
  const verdictTone: Tone = confirmed ? "green" : suspected ? "orange" : "gray";

  const summary = confirmed
    ? `${title.replace(/^Possible /, "")} — independent evidence confirms a real network issue.`
    : (hasRouting && device)
      ? `A ${kindLabel(routeKind)} was observed on ${device}${peer ? ` with peer ${peer}` : ""}. Customer impact is not confirmed yet.`
      : "Evidence changed but does not yet confirm a real network issue.";

  const why: WhyLine[] = [{
    tone: "orange", label: "Why suspected",
    text: (hasDevice && hasRouting) ? "Device health and routing/link evidence were observed on the same device area."
      : hasRouting ? "A routing/link change was observed on the affected routing adjacency." : "The available evidence matches this issue type.",
  }];
  if (confirmed) why.push({ tone: "green", label: "Why confirmed", text: "Independent evidence aligns to the same time window and affected scope." });
  else why.push({ tone: "green", label: "Why not confirmed", text: attachedCount <= 1 ? "This issue currently rests on a single observed signal. Independent evidence is needed before confirming customer impact." : "The supporting signals are related, but independent evidence is needed before confirming customer impact." });
  why.push({ tone: "blue", label: "To confirm", text: hasDevice ? "Add peer-side BGP/routing state, traffic-flow loss, downstream service impact, or an active check from an independent vantage." : "Add peer-side BGP/routing state, interface errors or drops, traffic-flow loss, downstream service impact, or an active check from an independent vantage." });

  // impact
  const notTied: string[] = [];
  if (!hasDevice) notTied.push("device-health");
  if ((att.passive_flow ?? 0) === 0) notTied.push("traffic-flow");
  if ((att.active_probe ?? 0) === 0) notTied.push("active-check");
  if (!hasRouting || attachedCount <= 1) notTied.push("peer-side");
  const impact: KV[] = [
    { k: "Impact", v: confirmed ? "Confirmed customer impact" : "No confirmed customer impact", tone: confirmed ? "red" : "orange" },
    ...(device ? [{ k: "Affected device", v: device, mono: true }] : []),
    ...(peer ? [{ k: "Affected peer", v: peer, mono: true }] : []),
    { k: "Scope type", v: device && peer ? "Routing adjacency" : "Device area" },
    { k: "Service / application", v: confirmed ? "Under assessment" : "Not confirmed" },
    { k: "Path impact", v: confirmed ? "Under assessment" : "Not confirmed" },
  ];

  // evidence cards per plane
  const evidence: EvidenceCard[] = MODALITY_ORDER.map((p) => {
    const n = att[p] ?? 0;
    const main = p === dominant && n > 0;
    return {
      variant: main ? "main" : n > 0 ? "confirm" : "missing", dot: main ? "orange" : n > 0 ? "green" : "gray",
      title: PLANE_TITLE[p] ?? modalityLabel(p), pill: main ? { tone: "orange", text: "Main evidence" } : n > 0 ? { tone: "green", text: "Used" } : { tone: "gray", text: "Not observed" },
      desc: PLANE_DESC[p] ?? "", finding: n > 0 ? `${n} ${n === 1 ? "signal" : "signals"} used.` : "No signals seen in this window.",
      foot: n > 0 ? (main ? "Primary evidence for this issue" : "Supports the case") : "Would help confirm if present",
    };
  });

  // confidence ladder
  const reached = confirmed ? 4 : suspected ? 2 : 1;
  const ladder: LadderStep[] = [
    { state: "done", label: "✓ Observed", caption: "Signal observed" },
    { state: reached >= 2 ? (confirmed ? "done" : "active") : "next", label: (reached >= 2 ? "✓ " : "") + "Suspected", caption: device ? `Localized to ${device}` : "Localized to a device area" },
    { state: confirmed ? "done" : "next", label: (confirmed ? "✓ " : "🔒 ") + "Probable", caption: "Independent network evidence aligned" },
    { state: confirmed ? "active" : "next", label: (confirmed ? "✓ " : "🔒 ") + "Confirmed", caption: confirmed ? "Customer impact confirmed" : "Independent evidence missing" },
  ];

  // timeline lanes per plane
  const ticks = ["+0s", "+15s", "+30s", "+45s", "+60s", "+75s"];
  const t0 = Date.parse((timeline.window_start || "").replace(" ", "T") + "Z");
  const span = Math.max(1, Date.parse((timeline.window_end || "").replace(" ", "T") + "Z") - t0);
  const lanes = new Map<string, TimelineLane>();
  for (const p of MODALITY_ORDER) lanes.set(p, { dot: p === "control_plane" ? "orange" : p === "device_telemetry" ? "blue" : p === "passive_flow" ? "green" : "purple", label: PLANE_TITLE[p] ?? modalityLabel(p), markers: [] });
  for (const s of timeline.signals) {
    if (s.kind.endsWith("_clear") || mentionsInternal(s.entity_id)) continue;
    const p = isRoutingKind(s.kind) ? "control_plane" : s.modality_class;
    const lane = lanes.get(p);
    if (!lane) continue;
    const left = Math.max(3, Math.min(97, ((Date.parse(s.ts.replace(" ", "T") + "Z") - t0) / span) * 94 + 3));
    lane.markers.push({ left, tone: s.attached ? (p === "control_plane" ? "orange" : "blue") : "gray", label: kindLabel(s.kind.replace(/_clear$/, "")), detail: `${kindLabel(s.kind)} on ${entityLabel(s.entity_id.split(":")[0])}. ${s.attached ? "Counted as evidence for this issue." : "Seen in the window but not linked."}` });
  }
  // Show ALL standard evidence lanes (in MODALITY_ORDER), even empty ones — an
  // empty lane is informative: it shows the operator exactly which evidence plane
  // has nothing in this window (what's missing to confirm), not just what fired.
  const timelineLanes = MODALITY_ORDER.map((p) => lanes.get(p)).filter((l): l is TimelineLane => !!l);

  // hypotheses
  const conf: RcaPill = { tone: confirmed ? "green" : "gray", text: confidence };
  const hypotheses: HypothesisRow[] = [{ rank: "#1", hypo: title, sub: device ? `${device}${peer ? ` → ${peer}` : ""}` : "primary", conf, reason: confirmed ? "Independent evidence aligns in the same window and scope." : "Primary signal observed; independent confirmation still missing." }];
  if (!confirmed) {
    if (hasDevice) hypotheses.push({ rank: `#${hypotheses.length + 1}`, hypo: "Isolated device-health change", sub: device || "device", conf: { tone: "gray", text: "Low" }, reason: "Device metric changed, but no traffic-flow or path impact is confirmed." });
    if (hasRouting) hypotheses.push({ rank: `#${hypotheses.length + 1}`, hypo: "Customer-impacting routing issue", sub: device || "routing", conf: { tone: "gray", text: "Low" }, reason: "Possible, but peer-side or downstream evidence is missing." });
  }

  const nextActions: NextAction[] = (steps.length ? steps.slice(0, 5).map((s, i) => ({ badge: i === 0 ? "INVESTIGATE" : "CHECK", text: s })) : [
    { badge: "INVESTIGATE", text: "Check the affected device/interface state and recent changes around the event window." },
  ]);
  if (!confirmed) nextActions.push({ badge: "HOLD", tone: "green", text: "Hold ticketing/escalation until independent impact evidence appears." });

  // causal topology — a compact, honest chain. Only placed when a real device is
  // known; the peer node appears when the routing adjacency resolved one. Suspected
  // objects render the device as SUSPECTED (amber), confirmed as ROOT CAUSE (red).
  const mkAbbr = (n: string): string => (/^[\d[]/.test(n) ? "NET" : (n.replace(/[^a-zA-Z]/g, "").slice(0, 3).toUpperCase() || "DEV"));
  let topology: RcaCase["topology"];
  if (device) {
    const nodes: TopoNode[] = [{
      kind: confirmed ? "bad" : "warn", abbr: mkAbbr(device), name: device,
      meta: hasRouting ? "routing/link change" : hasDevice ? "device-health change" : "signal observed",
      tag: { tone: confirmed ? "red" : "orange", text: confirmed ? "ROOT CAUSE" : "SUSPECTED" },
    }];
    const edges: TopoEdge[] = [];
    if (peer) {
      nodes.push({ kind: "info", abbr: mkAbbr(peer), name: peer, meta: "adjacency peer" });
      edges.push({ state: confirmed ? "bad" : "warn", label: hasRouting ? kindLabel(routeKind) : "evidence", side: -1 });
    }
    topology = { nodes, edges };
  }

  const subtitle = confirmed ? "Independent evidence across multiple planes"
    : (hasDevice && hasRouting) ? "Device-health and routing/link evidence"
      : hasRouting ? "Routing/link evidence" : "Limited evidence — single source";

  return {
    synthetic: false,
    title, subtitle,
    pills: [
      { tone: verdictTone, text: confirmed ? "✓ CONFIRMED" : "NOT CONFIRMED" },
      { tone: "blue", text: `Confidence: ${confidence}` },
      { tone: "orange", text: `State: ${stateText}` },
    ],
    decision: confirmed
      ? { tone: "confirmed", text: `Escalate — confirmed; route to ${owner || "the network team"}.` }
      : { tone: "", text: `HOLD — suspected only. Confirm with ${(hasDevice ? ["peer-side routing", "traffic-flow loss", "downstream impact", "or an independent active check"] : ["peer-side routing", "device health", "traffic-flow loss", "downstream impact", "or an independent active check"]).join(", ")}.` },
    observedAt: (timeline.window_start || "").replace("T", " ").slice(0, 19) + " UTC",
    rcaId: obj.correlation_id.slice(0, 13),
    aside: [
      { k: "Root cause object", v: device ? `${device}${peer ? ` ↔ ${peer}` : ""}` : "—" },
      { k: "Likely owner", v: owner || "NetOps" },
      { k: "Signals", v: String(obj.signal_count ?? attachedCount) },
      { k: "Suggested ticket", v: confirmed ? "Open P2" : "Hold" },
    ],
    summary, why, impact, topology,
    evidence, ladder, timelineTicks: ticks, timeline: timelineLanes, hypotheses,
    ticket: {
      callout: confirmed ? { tone: "red", strong: "Open incident:", text: "Customer impact is confirmed." } : { tone: "", strong: "Not opened —", text: "impact not confirmed. Auto-ticketing holds until independent evidence confirms customer impact." },
      rows: confirmed ? [{ k: "Ticket state", v: "Recommend open" }, { k: "Priority", v: "P2" }, { k: "Assignment", v: owner || "NetOps" }] : [{ k: "Ticket state", v: "Not opened" }, { k: "Reason", v: "RCA not confirmed" }],
    },
    nextActions,
    assistant: {
      questions: ["Why is this not confirmed?", "What would confirm it?", `What should ${owner || "the team"} check first?`, "Why were active checks ignored?", "Should a ticket be opened?"],
      sampleAnswer: confirmed ? "Independent evidence aligns in the same window and scope, so customer impact is confirmed." : "This rests on a single observation; independent evidence (peer-side routing, traffic-flow loss, downstream impact, or an active check) is needed before confirming customer impact.",
    },
    debug: {
      accounting: timeline.signals.filter((s) => s.attached && !s.kind.endsWith("_clear")).slice(0, 8).map((s) => ({ signal: kindLabel(s.kind), used: { tone: "green", text: "Used" }, weight: "—", reason: `Attached ${isRoutingKind(s.kind) ? "routing/link" : modalityLabel(s.modality_class).toLowerCase()} evidence.` })),
      promotion: [
        { k: "Observed threshold", v: "1 trusted event" }, { k: "Suspected threshold", v: "localized object" },
        { k: "Probable threshold", v: "2 independent signals" }, { k: "Confirmed threshold", v: "customer-impact tied to scope" },
        { k: "Verdict tier", v: timeline.verdict_tier }, { k: "Attached observers", v: String(timeline.signals.filter((s) => s.attached).length) },
      ],
      reasoning: confirmed ? "Promoted to confirmed: independent customer-impact evidence tied to the network path event." : "Held at suspected: a single device-area signal cannot confirm customer impact without an independent observer.",
      model: { correlation_id: obj.correlation_id, verdict_tier: timeline.verdict_tier, top_hypothesis: timeline.top_hypothesis, signal_count: obj.signal_count },
    },
  };
}

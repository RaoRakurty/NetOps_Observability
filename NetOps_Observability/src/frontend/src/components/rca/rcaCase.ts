import { CorrTimeline, CorrObject, CorrSignal, Seam, VerificationRun } from "../../services/api";
import { isRoutingKind, kindLabel, entityLabel, modalityLabel, MODALITY_ORDER, mentionsInternal, signatureNocTitle, PLANE_NOC_TITLE, ownerLabel, nocVerdictReason } from "./labels";
import { kindForRole, type ShapeKind } from "../graph/shapes";
import { parseTs } from "../../lib/time";
import type { TopoGraph } from "./topoGraph";
import { readServicePath } from "./servicePath";

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
// kind = health state (→ colour); shape = device type (→ icon), matching the
// on-screen RcaTopology convention so the PDF reads in the same visual language.
export interface TopoNode { kind: NodeKind; abbr: string; name: string; meta: string; tag?: RcaPill; shape?: ShapeKind; chips?: string[]; }
// from/to are node indices for an ARBITRARY graph (e.g. two probe sources
// converging on one target). When omitted, the edge is positional (edge i joins
// node i↔i+1) — the legacy linear-chain form, still supported.
export interface TopoEdge { state: "good" | "warn" | "bad"; label?: string; side?: -1 | 1; from?: number; to?: number; }
export interface EvidenceCard { variant: "main" | "confirm" | "missing" | "conflict"; dot: Tone; title: string; pill: RcaPill; desc: string; finding: string; foot: string; }
export interface LadderStep { state: "done" | "active" | "next"; label: string; caption: string; }
export interface TimelineMarker { left: number; tone: Tone; label: string; detail: string; }
export interface TimelineLane { dot: Tone; label: string; markers: TimelineMarker[]; }
export interface HypothesisRow { rank: string; hypo: string; sub: string; conf: RcaPill; reason: string; }
// One rung of the failure-propagation ladder (owner directive 2026-07-13): the
// matched signature's declared cascade — how one failure caused the next — with
// each rung either witnessed (evidence labels cited) or honestly unobserved.
export interface CascadeStage { stage: string; root: boolean; witnessed: boolean; kinds: string[]; note: string; }
export interface NextAction { badge: string; tone?: "red" | "green" | ""; text: string; }
export interface DebugRow { signal: string; used: RcaPill; weight: string; reason: string; }

// Cloud App Observability projection (#81 P3G 1c). Additive: present ONLY when the
// object carries cloud-plane evidence (source=cloud signals). `crossPlane` is true
// when an INDEPENDENT non-cloud observer also attached — the basis for confirming
// a cloud picture (a single cloud vantage is suspected-at-best by design).
export interface CloudResourceRow { name: string; kind: string; tone: Tone; finding: string; }
export interface CloudChangeRow { name: string; detail: string; }
export interface RcaCloud {
  app: string;            // the affected application (operator name), if the object names one
  account: string;
  region: string;
  signalCount: number;
  crossPlane: boolean;    // an independent (non-cloud) observer corroborates → can confirm
  resources: CloudResourceRow[];
  changes: CloudChangeRow[];
  note: string;           // honest single-plane vs corroborated explanation
}

// Application Impact (#81 P5) — which applications this incident affects, named from
// fused identity with explainable provenance. Built from attached source=app_identity
// signals (the engine's enrichment lane), exactly parallel to the cloud section.
export interface RcaImpactedApp {
  app: string;            // resolved application name (operator identifier, verbatim)
  band: string;           // confidence band: unresolved|low|medium|high|authoritative
  state: string;          // resolution state: observed|fused|inferred|conflicted|unknown
  sources: string[];      // identification techniques that backed it (ngfw_app_id, …)
  evidenceScore: number;  // 0..100 evidence score (NOT a probability)
  provider?: string;
}
export interface RcaAppImpact {
  apps: RcaImpactedApp[];
  note: string;           // honest "names, does not confirm" explanation
}

// Canonical verdict state (the full ladder the engine can reach). `confirmed`/
// `suspected`/`undetermined` are the engine tiers; `contradicted` = the leading cause
// was ruled OUT by discriminating evidence; `recovered` = the incident has cleared.
export type VerdictState = "confirmed" | "suspected" | "undetermined" | "contradicted" | "recovered";

// ── Evidence summary (owner directive 2026-07-18, rca-evidence-summary.md) ────
// The NOC evidence read: distinct SYMPTOMS · INDEPENDENT SOURCES · duration are
// the headline; each symptom carries a time-density series (repetition rendered
// as ink, never counted as evidence); the raw observation total is a muted
// trailing fact. The word "signals" never reaches the UI.
export interface EvidenceSymptom {
  label: string;        // NOC name of the manifestation
  source: string;       // which evidence class saw it (operator label)
  since: string;        // onset, HH:MM
  buckets: number[];    // observation density over the case window
  observations: number;
}
export interface EvidenceSummary {
  symptoms: number;
  sources: number;         // independent evidence streams (the confirm rule's count)
  durationLabel: string;   // "22m, ongoing" / "22m"
  verdictReason: string;   // names the reason — never a percentage
  rows: EvidenceSymptom[];
  observations: number;    // raw rows collected — muted, collapsed
}

// bucketTimes — pure render-side density bucketing (design §9: the only new
// computation; everything else the engine already derived).
export function bucketTimes(times: number[], start: number, end: number, n: number): number[] {
  const out = new Array<number>(n).fill(0);
  const span = Math.max(end - start, 1);
  for (const t of times) {
    const idx = Math.min(n - 1, Math.max(0, Math.floor(((t - start) / span) * n)));
    out[idx]++;
  }
  return out;
}

export const EVIDENCE_BUCKETS = 24;

// buildEvidenceSummary — pure: derives the summary from the timeline the
// workspace already holds. `sources` is the SAME independent-stream count the
// confirm rule uses (streamCount), so the headline can never out-claim the verdict.
export function buildEvidenceSummary(
  signals: CorrTimeline["signals"], windowStart: string, windowEnd: string,
  open: boolean, streams: string[], verdict: VerdictState, rawTotal: number,
): EvidenceSummary {
  const anomalous = signals.filter((s) => s.attached && !s.kind.endsWith("_clear"));
  const byKind = new Map<string, { source: string; times: number[] }>();
  for (const s of anomalous) {
    const g = byKind.get(s.kind) ?? { source: modalityLabel(s.modality_class), times: [] };
    const t = parseTs(s.ts)?.getTime();
    if (t) g.times.push(t);
    byKind.set(s.kind, g);
  }
  const start = parseTs(windowStart)?.getTime() ?? 0;
  const end = parseTs(windowEnd)?.getTime() ?? start;
  const rows: EvidenceSymptom[] = [...byKind.entries()]
    .map(([kind, g]) => ({
      label: kindLabel(kind),
      source: g.source,
      since: g.times.length ? new Date(Math.min(...g.times)).toISOString().slice(11, 16) : "",
      buckets: bucketTimes(g.times, start, end, EVIDENCE_BUCKETS),
      observations: g.times.length,
      _first: g.times.length ? Math.min(...g.times) : Number.MAX_SAFE_INTEGER,
    }))
    .sort((a, b) => (a as any)._first - (b as any)._first)
    .map(({ _first, ...r }: any) => r);

  const durMin = Math.max(0, Math.round((end - start) / 60000));
  const durationLabel = `${durMin >= 60 ? `${Math.floor(durMin / 60)}h ${durMin % 60}m` : `${durMin}m`}${open ? ", ongoing" : ""}`;

  const pair = streams.length >= 2 ? ` (${streams.slice(0, 3).join(" + ")})` : "";
  let verdictReason: string;
  if (verdict === "confirmed") {
    verdictReason = `Confirmed — cross-checked by ${streams.length} independent sources${pair}.`;
  } else if (verdict === "contradicted") {
    verdictReason = "The leading cause was ruled out by the evidence — see the reasoning below.";
  } else if (streams.length === 1) {
    verdictReason = `Only ${streams[0].toLowerCase()} saw this — a second independent source is needed to confirm.`;
  } else if (verdict === "suspected" || verdict === "recovered") {
    verdictReason = "Sources agree, but no independent pair confirms customer impact yet.";
  } else {
    verdictReason = "Not confirmed — no cause has enough supporting evidence yet.";
  }
  return {
    symptoms: byKind.size, sources: streams.length, durationLabel,
    verdictReason, rows, observations: rawTotal,
  };
}

// ── Event timeline (owner P1 2026-07-19: "RCA basics") ────────────────────────
// One chronological list of REAL, timestamped case events in NOC language: first
// sighting of each symptom, detection trigger, case milestones, verification
// runs, symptom clears and recorded recovery. Every entry carries a timestamp
// that exists in the payload — nothing is fabricated or interpolated.
export interface CaseEvent {
  ts: string;        // raw timestamp as received (formatted at render time)
  label: string;     // plain-language NOC event
  detail?: string;   // secondary context (evidence source, trigger, …)
  tone: Tone;
}

// Optional slices of the canonical RCA report JSON + the latest verification run
// — used ONLY to add honestly-recorded milestones to the event timeline.
export interface CaseEventExtras {
  times?: { recovered_at?: string; component_recovered_at?: string };
  promotion?: { manual?: { promoted_by: string; promoted_at: string } };
  verification?: VerificationRun | null;
}

// buildCaseEvents — pure derivation of the chronological event list from data
// the workspace already holds. Only timestamps present in the payload are used.
export function buildCaseEvents(timeline: CorrTimeline, obj: CorrObject, extras?: CaseEventExtras): CaseEvent[] {
  const out: CaseEvent[] = [];
  const t = (v: string | undefined): number | null => {
    const d = v ? parseTs(v) : null;
    return d ? d.getTime() : null;
  };
  const push = (ts: string | undefined, label: string, tone: Tone, detail?: string) => {
    if (ts && t(ts) !== null) out.push({ ts, label, tone, detail });
  };

  // First sighting of each distinct symptom (attached anomalous evidence only;
  // internal/platform entities never appear) + first clear per symptom.
  const firstByKind = new Map<string, CorrSignal>();
  const clearByKind = new Map<string, CorrSignal>();
  for (const s of timeline.signals) {
    if (mentionsInternal(s.entity_id)) continue;
    if (s.kind.endsWith("_clear")) {
      const k = s.kind.replace(/_clear$/, "");
      const prev = clearByKind.get(k);
      if (!prev || (t(s.ts) ?? 0) < (t(prev.ts) ?? 0)) clearByKind.set(k, s);
      continue;
    }
    if (!s.attached) continue;
    const prev = firstByKind.get(s.kind);
    if (!prev || (t(s.ts) ?? 0) < (t(prev.ts) ?? 0)) firstByKind.set(s.kind, s);
  }
  const firsts = [...firstByKind.values()]
    .sort((a, b) => (t(a.ts) ?? 0) - (t(b.ts) ?? 0))
    .slice(0, 10);
  const seenSources = new Set<string>();
  firsts.forEach((s, i) => {
    const entity = entityLabel(s.entity_id.split(":")[0]);
    const source = modalityLabel(isRoutingKind(s.kind) ? "control_plane" : s.modality_class);
    const newSource = !seenSources.has(source);
    seenSources.add(source);
    const detail = [
      source,
      i > 0 && newSource ? "independent source joined" : "",
      s.is_trigger ? "detection trigger" : "",
    ].filter(Boolean).join(" · ");
    push(s.ts, `${i === 0 ? "First symptom — " : ""}${kindLabel(s.kind)} on ${entity}`, i === 0 ? "red" : "orange", detail);
  });

  // Case milestones recorded by the platform.
  push(obj.created_at, "Case opened — related evidence grouped into one case", "blue");
  const promo = extras?.promotion?.manual;
  if (promo?.promoted_at) push(promo.promoted_at, `Promoted to RCA case${promo.promoted_by ? ` by ${promo.promoted_by}` : ""}`, "blue");

  // Verification battery (read-only device interrogation), when one was run.
  const run = extras?.verification;
  if (run?.started_at) {
    const results = run.results ?? [];
    const fails = results.filter((r) => r.status === "fail").length;
    const corroborating = results.some((r) => (r.corroborates_kinds ?? []).length > 0 && r.status === "fail");
    const refuting = fails === 0 && results.some((r) => (r.refutes_kinds ?? []).length > 0 && r.status === "pass");
    const outcome = run.status === "running" ? "in progress"
      : results.length === 0 ? "completed"
        : fails > 0 ? `${fails} fault${fails === 1 ? "" : "s"} found${corroborating ? " — corroborating" : ""}`
          : `devices healthy${refuting ? " — refuting" : ""}`;
    push(run.started_at, `Verification battery run — ${outcome}`, fails > 0 ? "orange" : "blue", "read-only device checks");
  }

  // Recovery: per-symptom clears (only for symptoms actually seen), then the
  // recorded recovery times off the report.
  for (const [k, s] of clearByKind) {
    if (!firstByKind.has(k)) continue;
    push(s.ts, `${kindLabel(k)} cleared on ${entityLabel(s.entity_id.split(":")[0])}`, "green");
  }
  const times = extras?.times ?? {};
  if (times.component_recovered_at && times.component_recovered_at !== times.recovered_at) {
    push(times.component_recovered_at, "Component recovery seen", "green");
  }
  if (times.recovered_at) push(times.recovered_at, "Service recovery confirmed", "green");

  return out.sort((a, b) => (t(a.ts) ?? 0) - (t(b.ts) ?? 0));
}

export interface RcaCase {
  synthetic: boolean;             // true → show the "synthetic / example" watermark
  title: string;
  subtitle: string;
  pills: RcaPill[];
  decision: { tone: "confirmed" | "" | "red"; text: string };
  // Canonical 5-state verdict (one contract shared by the workspace AND the topology
  // Investigate banner — no divergent verdict vocabularies).
  verdictState: VerdictState;
  // Discriminating/contradicting evidence the engine used to RULE OUT competing causes.
  ruledOut: string[];
  // Why the verdict is not stronger (engine gate reasons), operator language.
  whyNot: string[];
  // The verbatim engine verdict reasons — shown only behind the "How was this
  // verified?" disclosure (owner 2026-07-18: honesty stays, jargon moves).
  verifyDetail?: string[];
  observedAt: string;
  rcaId: string;
  aside: KV[];
  // Evidence summary (owner 2026-07-18): symptom density bars + verdict reason
  // for the workspace aside — quality-first, raw volume demoted.
  evidenceSummary?: EvidenceSummary;
  summary: string;
  why: WhyLine[];
  impact: KV[];
  // legacy compact chain (EXAMPLE_CASE + buildRcaCase fallback). When `topoGraph`
  // is set, the PDF renders the rich shared graph instead and this is a fallback.
  topology?: { nodes: TopoNode[]; edges: TopoEdge[] };
  // the SAME positioned graph the on-screen RcaTopology draws (built by
  // buildTopoGraph) — wired in by CorrelationDetail so the PDF matches the page.
  topoGraph?: TopoGraph;
  evidence: EvidenceCard[];
  ladder: LadderStep[];
  // Chronological event timeline (real timestamps only) — the NOC "what
  // happened when" read; rendered as a collapsible list near the summary.
  events?: CaseEvent[];
  // Seam-ownership display ("Lumen (DIA #12345) · ISP / carrier") + the honest
  // "possibly because of X" phrase — surfaced by the merged network-path view.
  ownershipLabel?: string;
  possiblyCause?: string;
  timelineTicks: string[];
  timeline: TimelineLane[];
  hypotheses: HypothesisRow[];
  // Failure-propagation ladder from the matched signature — omitted when the
  // signature declares no cascade (most do not; render nothing, never invent).
  cascade?: CascadeStage[];
  ticket: { callout: { tone: "confirmed" | "" | "red"; strong: string; text: string }; rows: KV[] };
  nextActions: NextAction[];
  assistant: { questions: string[]; sampleAnswer: string };
  // Cloud App Observability section — omitted entirely when the object carries no
  // cloud evidence (network RCA renders exactly as before).
  cloud?: RcaCloud;
  // Application Impact (#81 P5) — omitted when no fused identity is attached.
  appImpact?: RcaAppImpact;
  debug: { accounting: DebugRow[]; promotion: KV[]; reasoning: string; model: unknown };
}

// ── EXAMPLE_CASE — synthetic golden scenario (confirmed multi-evidence) ───────
export const EXAMPLE_CASE: RcaCase = {
  synthetic: true,
  title: "Confirmed customer-impacting routing incident",
  subtitle: "Example case · LAN + SD-WAN + BGP + Cloud application evidence",
  pills: [
    { tone: "green", text: "✓ CONFIRMED" }, { tone: "blue", text: "Confidence: High" },
    { tone: "orange", text: "RCA state: Recovering" }, { tone: "red", text: "Impact: Checkout API degraded" },
  ],
  decision: { tone: "confirmed", text: "Open incident and assign to NetOps / ISP escalation. Independent evidence confirms the BGP adjacency change caused SD-WAN path degradation and application impact." },
  verdictState: "confirmed",
  ruledOut: ["Isolated device-health change (no traffic-flow impact)"],
  whyNot: [],
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
    { variant: "confirm", dot: "green", title: "SD-WAN telemetry", pill: { tone: "green", text: "Confirms" }, desc: "Tunnel SLA, loss, jitter, failover", finding: "Primary DIA tunnel loss reached 18.4%; SLA fail triggered.", foot: "3 observations used · aligned within +7s" },
    { variant: "confirm", dot: "green", title: "Traffic flow", pill: { tone: "green", text: "Confirms" }, desc: "NetFlow/IPFIX, retransmits, traffic shift", finding: "Checkout flows dropped 42%; TCP retransmits increased 6.2×.", foot: "5-min baseline · Dallas scope only" },
    { variant: "confirm", dot: "green", title: "Active checks", pill: { tone: "green", text: "Confirms" }, desc: "ICMP, HTTP, STAMP from independent vantage", finding: "Dallas probe to Checkout API hit 920 ms p95 and 3 HTTP failures.", foot: "Independent vantage confirmed" },
    { variant: "confirm", dot: "green", title: "Application logs", pill: { tone: "green", text: "Confirms impact" }, desc: "5xx, timeout, regional user errors", finding: "Checkout API 5xx increased 12.8% for Dallas source NAT range.", foot: "Tied to affected branch users" },
    { variant: "confirm", dot: "green", title: "Device health", pill: { tone: "green", text: "Supports" }, desc: "Interface counters, CPU, memory, link state", finding: "WAN interface showed input errors and carrier transitions; CPU/memory normal.", foot: "Supports network path, not host overload" },
    { variant: "missing", dot: "gray", title: "Cloud metrics", pill: { tone: "gray", text: "No issue" }, desc: "ALB, TGW, app node, region health", finding: "AWS service-side health normal; no region-wide degradation.", foot: "Helps exclude cloud outage" },
    { variant: "missing", dot: "gray", title: "Similar incidents", pill: { tone: "gray", text: "1 match" }, desc: "History, change window, known signatures", finding: "Similar ISP loss signature seen 21 days ago on same underlay.", foot: "Not used as confirmation alone" },
  ],
  ladder: [
    { state: "done", label: "✓ Detected", caption: "BGP event detected" },
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
  cloud: {
    app: "Checkout API", account: "478221", region: "us-east-1",
    signalCount: 3, crossPlane: true,
    resources: [
      { name: "checkout-alb", kind: "Load-balancer error rate", tone: "red", finding: "alb_5xx_pct = 6.4" },
      { name: "checkout-ecs", kind: "Cloud resource health change", tone: "orange", finding: "task_restarts = 3" },
      { name: "billing-db", kind: "Database metric change", tone: "gray", finding: "connections_pct = 41 (normal)" },
    ],
    changes: [{ name: "Cloud configuration change", detail: "checkout-svc · task-definition v37 deployed +2m before onset" }],
    note: "Cloud evidence is corroborated by an independent network observer — confirmation does not rest on the cloud plane alone.",
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
      { k: "Probable threshold", v: "2 independent sources" }, { k: "Confirmed threshold", v: "customer-impact evidence tied to same scope" },
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

export function buildRcaCase(timeline: CorrTimeline, obj: CorrObject, _seams: Record<string, Seam>, owner: string, steps: string[], seamOwners?: Record<string, { name: string; contact?: string }>, extras?: CaseEventExtras): RcaCase {
  // #113 slice 2: the tenant's seam-ownership registry turns an owner CLASS
  // into the actual responsible party — "Lumen (DIA #12345) · ISP / carrier"
  // instead of the bare class label. Absent registry → class label only.
  const ownerDisplay = (cls: string): string => {
    const entry = seamOwners?.[cls];
    return entry?.name ? `${entry.name} · ${ownerLabel(cls)}` : ownerLabel(cls);
  };
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

  // INDEPENDENT evidence streams (NOC hard rule): a routing-or-device event,
  // a traffic/flow change, and an active probe are three independent ways to see
  // the same fault. "Confirmed root cause" is NEVER shown on fewer than two — a
  // single stream, however strong, reads as suspected, not confirmed. This guard
  // sits in the UI on top of the engine verdict so the page can never overclaim.
  const streamCount = [hasRouting || hasDevice, (att.passive_flow ?? 0) > 0, (att.active_probe ?? 0) > 0].filter(Boolean).length;
  const confirmed = timeline.verdict_tier === "confirmed" && streamCount >= 2;
  const suspected = !confirmed && (timeline.verdict_tier === "suspected" || timeline.verdict_tier === "confirmed");

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

  // Cloud-dominant objects must NOT be titled by the network plane they happen to
  // ride (cloud_health / database_metric map onto device_telemetry). Detect the
  // cloud app early so the title/summary/hypotheses read app-centric, not "device".
  const cloudAppEarly = (() => {
    for (const s of timeline.signals) {
      if (s.source !== "cloud" || !s.attached || s.kind.endsWith("_clear") || s.entity_type !== "app") continue;
      try { const a = JSON.parse((s as { attrs?: string }).attrs || "{}"); return a.app ? String(a.app) : s.entity_id; } catch { return s.entity_id; }
    }
    return "";
  })();
  const hasCloudEarly = cloudAppEarly !== "" || timeline.signals.some((s) => s.source === "cloud" && s.attached && !s.kind.endsWith("_clear"));

  let title = timeline.top_hypothesis !== "undetermined" ? signatureNocTitle(timeline.top_hypothesis)
    : hasCloudEarly ? (cloudAppEarly ? `Cloud application issue — ${cloudAppEarly}` : "Cloud service issue")
      : (PLANE_NOC_TITLE[dominant] ?? "Telemetry anomaly — cause undetermined");
  if (!confirmed && hasDevice && hasRouting && /routing|network/i.test(title) && !/wan|provider|boundary/i.test(title)) title = "Device & routing change";

  const confidence = confirmed ? "High" : attachedCount >= 2 ? "Medium" : "Low";
  // lifecycle (user state model): active → recovering (clears seen, still open) →
  // recovered (object closed). Drives the RCA-state badge + the MONITOR decision.
  const hasClears = timeline.signals.some((s) => s.kind.endsWith("_clear"));
  const lifecycle: "active" | "recovering" | "recovered" = obj.state !== "open" ? "recovered" : hasClears ? "recovering" : "active";
  // (The old single "RCA state" badge conflated lifecycle with analysis maturity;
  // the pills below now carry Incident and Analysis as independent dimensions.)

  // Canonical 5-state verdict + discriminating ("ruled out") evidence + why-not, parsed
  // from the engine hypotheses. additive — never changes the existing confirmed/suspected
  // pills/decision the workspace + tests rely on.
  let ruledOut: string[] = [];
  let whyNot: string[] = [];
  let rawReasons: string[] = [];
  let contradicted = false;
  let cascade: CascadeStage[] | undefined;
  try {
    const ranked = JSON.parse(obj.hypotheses || "{}")?.ranking?.hypotheses ?? [];
    const top = ranked.find((h: any) => h.id === timeline.top_hypothesis) ?? ranked[0];
    if (top) {
      contradicted = !!top.contradicted;
      if (Array.isArray(top.contradictions)) ruledOut = top.contradictions.map((c: string) => kindLabel(c));
      const reasons: string[] = top?.verdict?.reasons ?? [];
      // Operator register (owner 2026-07-18): the consequence, not the taxonomy —
      // the verbatim engine reasons stay behind "How was this verified?".
      if (!confirmed && reasons.length) {
        whyNot = reasons.map(nocVerdictReason);
        rawReasons = reasons;
      }
      // Propagation ladder: carried verbatim from the signature (engine already
      // marked witnessed/unobserved); only the raw kinds are humanized here —
      // Operator View never shows schema tokens.
      if (Array.isArray(top.causal_chain) && top.causal_chain.length) {
        cascade = top.causal_chain.map((s: any) => ({
          stage: String(s.stage ?? ""),
          root: !!s.root,
          witnessed: !!s.witnessed,
          kinds: (Array.isArray(s.kinds) ? s.kinds : []).map((k: string) => kindLabel(k)),
          // catalog notes speak engine ("No routing-protocol signals seen") —
          // operator text never says "signals" (2026-07-18 terminology rule)
          note: String(s.note ?? "").replace(/\bsignals?\b/g, "evidence").replace(/\bSignals?\b/g, "Evidence"),
        }));
      }
    }
  } catch { /* hypotheses absent/malformed → no ruled-out/why-not */ }
  const verdictState: VerdictState =
    lifecycle === "recovered" ? "recovered"
      : confirmed ? "confirmed"
        : contradicted ? "contradicted"
          : suspected ? "suspected"
            : "undetermined";
  // Evidence summary (owner 2026-07-18): the headline numbers reuse the SAME
  // independent-stream components the confirm rule counts, so the summary can
  // never out-claim the verdict; streams are named in operator labels.
  const streamLabels = [
    ...(hasRouting || hasDevice ? [modalityLabel(hasRouting ? "control_plane" : "device_telemetry")] : []),
    ...((att.passive_flow ?? 0) > 0 ? [modalityLabel("passive_flow")] : []),
    ...((att.active_probe ?? 0) > 0 ? [modalityLabel("active_probe")] : []),
  ];
  const evidenceSummary = buildEvidenceSummary(
    timeline.signals, timeline.window_start, timeline.window_end,
    obj.state === "open", streamLabels, verdictState,
    obj.signal_count ?? attachedCount,
  );

  // #113 point 4 — cause honesty, owner register (2026-07-19): the possible
  // cause names the UPSTREAM explanation — the observed fault on the seam the
  // engine attributed ("packet loss on the ISP / middle-mile path") — never the
  // symptom restated back at itself. Built only from what was actually seen
  // (fault kinds in this window + the attributed owner class); nothing there →
  // the absence is stated, never guessed.
  const SEAM_PHRASE: Record<string, string> = {
    isp: "the ISP / middle-mile path", carrier: "the carrier segment",
    cloud_provider: "the cloud provider's edge", colo_provider: "the colo provider's network",
    sdwan_vendor: "the SD-WAN overlay", app_team: "the application/SaaS provider's side",
    netops: "the internal network",
  };
  const kindsSeen = new Set(timeline.signals.filter((s) => s.attached && !s.kind.endsWith("_clear")).map((s) => s.kind));
  const faultPhrases: string[] = [];
  if ([...kindsSeen].some((k) => k.includes("loss"))) faultPhrases.push("packet loss");
  if ([...kindsSeen].some((k) => k.includes("latency") || k.includes("rtt") || k.includes("timeout"))) faultPhrases.push("latency");
  if (hasRouting) faultPhrases.push("routing instability");
  if ([...kindsSeen].some((k) => k.includes("dns"))) faultPhrases.push("DNS trouble");
  const seamWhere = SEAM_PHRASE[owner] ?? (owner ? `the ${ownerLabel(owner).toLowerCase()} side` : "");
  const possiblyCause = !confirmed && !contradicted && timeline.top_hypothesis !== "undetermined"
    ? (faultPhrases.length
      ? `${faultPhrases.slice(0, 2).join(" or ")} on ${seamWhere || "the network path"}`
      : seamWhere ? `an issue on ${seamWhere}` : "")
    : "";
  // Evidence state, one plain sentence (owner: no signature ids, no rule text —
  // the verbatim engine reasons stay behind "How was this verified?"): what saw
  // it, and what would confirm it. evidence_missing rows arrive prefixed with
  // the engine signature id — strip that and translate like the verdict reasons.
  const evidenceGaps: string[] = (() => {
    try {
      const a = JSON.parse(obj.evidence_missing || "[]");
      return Array.isArray(a) ? a.map(String) : [];
    } catch { return []; }
  })();
  const evidenceState = (() => {
    const translated = [...whyNot, ...evidenceGaps.map((g) => nocVerdictReason(g.replace(/^sig[\w.-]*:\s*/i, "")))]
      .map((s) => s.trim()).filter(Boolean);
    const seen = new Set<string>(); const out: string[] = [];
    for (const t of translated) {
      const k = t.toLowerCase();
      if (!seen.has(k)) { seen.add(k); out.push(t); }
    }
    return out.slice(0, 2).join(" ");
  })();
  const verdictTone: Tone = confirmed ? "green" : verdictState === "recovered" ? "blue" : verdictState === "contradicted" ? "gray" : suspected ? "orange" : "gray";

  // ticket decision → exact global NOC phrase (consistent wording across the app).
  // confirmed → OPEN; cleared/recovered with no impact → MONITOR; >=2 aligned but
  // unconfirmed streams → INVESTIGATE; otherwise → HOLD.
  const decisionKind: "open" | "monitor" | "investigate" | "hold" =
    confirmed ? "open" : lifecycle === "recovered" ? "monitor" : streamCount >= 2 ? "investigate" : "hold";
  const DECISION_TEXT: Record<typeof decisionKind, string> = {
    open: "OPEN INCIDENT — customer impact is confirmed by independent evidence. Assign ownership and begin restoration workflow.",
    investigate: "INVESTIGATE — evidence is aligned but not sufficient to confirm customer impact. Validate the missing evidence before opening a customer incident.",
    monitor: "MONITOR — the triggering anomaly has cleared and no customer-impacting evidence was observed within available telemetry coverage. Auto-closes after the monitoring window if there is no recurrence and no customer-impact evidence.",
    hold: "HOLD — suspected only. Customer impact is not confirmed. Auto-ticketing remains on hold until independent evidence confirms impact.",
  };

  const summary = confirmed
    ? `${title.replace(/^Possible /, "")} — independent evidence confirms a real issue.`
    : (hasRouting && device)
      ? `A ${kindLabel(routeKind)} was observed on ${device}${peer ? ` with peer ${peer}` : ""}. Customer impact is not confirmed yet.`
      : hasCloudEarly
        ? `A cloud issue was observed${cloudAppEarly ? ` for ${cloudAppEarly}` : ""}. Customer impact is not confirmed yet.`
        : dominant === "active_probe"
          ? "Automated checks detected loss or latency in this window. No independent routing, device, traffic-flow, or application evidence confirmed the same failure, so customer impact is not confirmed."
          : `Anomalous ${modalityLabel(dominant).toLowerCase()} evidence was observed in this window. No independent evidence class confirmed the same failure, so customer impact is not confirmed.`;

  const why: WhyLine[] = [{
    tone: "orange", label: "Why suspected",
    text: (hasDevice && hasRouting) ? "Device health and routing/link evidence were observed on the same device area."
      : hasRouting ? "A routing/link change was observed on the affected routing adjacency."
        : dominant === "active_probe" ? "Active-check sources reported degradation to the same target during an overlapping time window."
          : `Anomalous ${modalityLabel(dominant).toLowerCase()} evidence was observed in the same time window and scope.`,
  }];
  if (confirmed) why.push({ tone: "green", label: "Why confirmed", text: "Independent evidence aligns to the same time window and affected scope." });
  else why.push({
    tone: "green", label: "Why not confirmed",
    text: attachedCount <= 1
      ? "This issue currently rests on a single observation. Independent evidence is needed before confirming customer impact."
      : `The supporting observations come from the ${modalityLabel(dominant).toLowerCase()} evidence class. No independent routing, device, traffic-flow, or application evidence confirmed the same failure.`,
  });
  why.push({
    tone: "blue", label: "To confirm",
    text: dominant === "active_probe" && !hasRouting && !hasDevice
      ? "Identify whether the checks failed during DNS, TCP, TLS, or HTTP; validate vantage independence; and compare the incident window with real-user traffic, load-balancer health, application errors, and network telemetry."
      : hasDevice
        ? "Add peer-side BGP/routing state, traffic-flow loss, downstream service impact, or an active check from an independent vantage."
        : "Add peer-side BGP/routing state, interface errors or drops, traffic-flow loss, downstream service impact, or an active check from an independent vantage.",
  });

  // impact
  const notTied: string[] = [];
  if (!hasDevice) notTied.push("device-health");
  if ((att.passive_flow ?? 0) === 0) notTied.push("traffic-flow");
  if ((att.active_probe ?? 0) === 0) notTied.push("active-check");
  if (!hasRouting || attachedCount <= 1) notTied.push("peer-side");
  // telemetry-qualified impact: "no impact" may only be said relative to the
  // coverage that actually existed in the window (owner directive 2026-07-12).
  const impactLanesPresent = (att.active_probe ?? 0) > 0 || (att.passive_flow ?? 0) > 0;
  const impact: KV[] = [
    {
      k: "Impact",
      v: confirmed ? "Confirmed customer impact"
        : impactLanesPresent ? "No customer impact confirmed within available telemetry coverage"
          : "Impact not observable — no impact telemetry in this window",
      tone: confirmed ? "red" : "orange",
    },
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
      title: PLANE_TITLE[p] ?? modalityLabel(p), pill: main ? { tone: "orange", text: "Main evidence" } : n > 0 ? { tone: "green", text: "Used" } : { tone: "gray", text: "No data" },
      desc: PLANE_DESC[p] ?? "", finding: n > 0 ? `${n} ${n === 1 ? "observation" : "observations"} used.` : "No telemetry from this evidence class reached the platform in this window — unavailable or not configured.",
      foot: n > 0 ? (main ? "Primary evidence for this issue" : "Supports the case") : "Coverage gap — absence is not evidence of health",
    };
  });

  // confidence ladder
  const reached = confirmed ? 4 : suspected ? 2 : 1;
  const ladder: LadderStep[] = [
    { state: "done", label: "✓ Detected", caption: "Anomaly detected" },
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
  const hypotheses: HypothesisRow[] = [{ rank: "#1", hypo: title, sub: device ? `${device}${peer ? ` → ${peer}` : ""}` : "primary", conf, reason: confirmed ? "Independent evidence aligns in the same window and scope." : "Primary evidence observed; independent confirmation still missing." }];
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
  // probe/path destinations read as cloud (internet/SaaS) or a target bullseye —
  // mirrors RcaTopology.destKind so the PDF picks the same icon.
  const destShape = (n: string): ShapeKind => (/cloud|internet|inet|aws|azure|gcp|tgw|transit|saas/i.test(n) ? "cloud" : "target");
  // Build a COMPLETE small graph (not a single chain) so the report localizes the
  // issue the same way for EVERY verdict tier: the routing device + peer AND every
  // affected path segment, deduped, with arbitrary edges (two probe sources can
  // converge on one target). topoSvg lays it out left→right by layer.
  let topology: RcaCase["topology"];
  {
    const idx = new Map<string, number>();
    const tNodes: TopoNode[] = [];
    const tEdges: TopoEdge[] = [];
    const addNode = (name: string, o: { kind: NodeKind; shape?: ShapeKind; meta?: string; tag?: RcaPill }): number => {
      const key = name.toLowerCase();
      let i = idx.get(key);
      if (i === undefined) {
        i = tNodes.length;
        tNodes.push({ kind: o.kind, abbr: mkAbbr(name), name, shape: o.shape ?? kindForRole(name), meta: o.meta ?? "", tag: o.tag });
        idx.set(key, i);
      } else if (o.tag && !tNodes[i].tag) {
        tNodes[i].tag = o.tag; // upgrade a plain node to the tagged anchor
      }
      return i;
    };
    const addEdge = (from: number, to: number, label: string) => {
      if (from !== to && !tEdges.some((e) => e.from === from && e.to === to)) {
        tEdges.push({ state: confirmed ? "bad" : "warn", label, side: -1, from, to });
      }
    };
    // 1) routing context: device (anchor) → peer
    if (device) {
      const di = addNode(device, {
        kind: confirmed ? "bad" : "warn", shape: kindForRole(device),
        meta: hasRouting ? "routing/link change" : hasDevice ? "device-health change" : "anomaly detected",
        tag: { tone: confirmed ? "red" : "orange", text: confirmed ? "ROOT CAUSE" : "SUSPECTED" },
      });
      if (peer) addEdge(di, addNode(peer, { kind: "info", shape: kindForRole(peer), meta: "adjacency peer" }), hasRouting ? kindLabel(routeKind) : "evidence");
    }
    // 2) every affected path segment ("a -> b"), deduped — the ACTUAL connections
    try {
      const aff = JSON.parse(obj.affected || "{}") as { paths?: string[]; devices?: string[] };
      for (const p of (aff.paths ?? []).slice(0, 6)) {
        const hops = p.split(/->|→/).map((s) => s.trim()).filter(Boolean);
        for (let h = 0; h < hops.length - 1; h++) {
          const last = h === hops.length - 2;
          const ai = addNode(hops[h], { kind: "info", shape: kindForRole(hops[h]), meta: h === 0 ? "source" : "hop" });
          const bi = addNode(hops[h + 1], {
            kind: last ? (confirmed ? "bad" : "warn") : "info", shape: last ? destShape(hops[h + 1]) : kindForRole(hops[h + 1]),
            // §15: never assert a "PATH" when no path was identified — the node is
            // the probe TARGET; the check, not the route, is what degraded.
            meta: last ? "target" : "hop", tag: last ? { tone: confirmed ? "red" : "orange", text: confirmed ? "DEGRADED TARGET" : "SUSPECTED TARGET" } : undefined,
          });
          addEdge(ai, bi, last ? "active-probe loss/latency" : "");
        }
      }
      // 3) fallback: affected devices with no path/peer — at least plot the nodes
      if (tNodes.length === 0) for (const d of (aff.devices ?? []).slice(0, 6)) addNode(d, { kind: confirmed ? "bad" : "warn", meta: "affected device", tag: { tone: confirmed ? "red" : "orange", text: confirmed ? "AFFECTED" : "SUSPECTED" } });
    } catch { /* affected not JSON */ }
    // A service-path object is rendered from the BACKEND's ordered spine (the
    // shared `topoGraph`, which the PDF prefers) — never from this legacy
    // "a -> b"-string chain, which cannot express cloud objects, hop order,
    // boundaries or evidence. When a spine exists, this fallback is suppressed so
    // the report and the screen provably draw the SAME graph (contract §7).
    if (tNodes.length > 0 && !readServicePath(timeline)) topology = { nodes: tNodes.slice(0, 8), edges: tEdges };
  }

  const subtitle = confirmed ? "Independent evidence across multiple planes"
    : (hasDevice && hasRouting) ? "Device-health and routing/link evidence"
      : hasRouting ? "Routing/link evidence" : "Limited evidence — single source";

  // ── cloud projection (#81 P3G 1c) — additive. Surface the app / resources /
  // config-changes the object carries on the cloud plane, and whether an
  // INDEPENDENT non-cloud observer corroborates them. A cloud-only object is
  // suspected-at-best by the engine's single-plane rule; we state that honestly.
  // App/resource names are real identifiers (kept verbatim, not genericized).
  let cloud: RcaCloud | undefined;
  {
    const cloudSigs = timeline.signals.filter((s) => s.source === "cloud" && s.attached && !s.kind.endsWith("_clear"));
    if (cloudSigs.length) {
      const CHANGE_KINDS = new Set(["cloud_change", "cloud_audit", "security_policy_change"]);
      const sevTone = (sev: string): Tone => {
        const v = (sev || "").toLowerCase();
        return v === "crit" || v === "critical" || v === "high" || v === "error" ? "red"
          : v === "warn" || v === "warning" ? "orange"
            : v === "info" ? "blue" : "gray";
      };
      let app = "", account = "", region = "";
      const resources: CloudResourceRow[] = [];
      const changes: CloudChangeRow[] = [];
      const seenRes = new Set<string>();
      for (const s of cloudSigs) {
        let a: Record<string, unknown> = {};
        try { a = JSON.parse((s as { attrs?: string }).attrs || "{}"); } catch { /* attrs absent/malformed */ }
        if (!account && a.account) account = String(a.account);
        if (!region && a.region) region = String(a.region);
        if (s.entity_type === "app" && !app) app = a.app ? String(a.app) : s.entity_id;
        if (CHANGE_KINDS.has(s.kind)) {
          changes.push({ name: kindLabel(s.kind), detail: s.entity_id });
        } else if (s.entity_type === "cloud_resource" && !seenRes.has(s.entity_id)) {
          seenRes.add(s.entity_id);
          const m = s.metric_name;
          resources.push({
            name: s.entity_id, kind: kindLabel(s.kind), tone: sevTone(s.severity),
            finding: m ? `${m}${typeof s.value === "number" && s.value ? ` = ${s.value}` : ""}` : kindLabel(s.kind),
          });
        }
      }
      // cross-plane = an attached NON-cloud signal exists → an independent observer
      // can corroborate. cloud-only = one vantage → suspected at best, however strong.
      const crossPlane = timeline.signals.some((s) => s.attached && !s.kind.endsWith("_clear") && s.source !== "cloud");
      const note = crossPlane
        ? "Cloud evidence is corroborated by an independent network observer — confirmation does not rest on the cloud plane alone."
        : "Cloud-only evidence from a single cloud vantage. By the single-plane rule this is suspected at best; an independent observer (an active probe, the underlay path, or the firewall) is needed to confirm.";
      cloud = { app, account, region, signalCount: cloudSigs.length, crossPlane, resources, changes, note };
    }
  }

  // ── application impact (#81 P5) — additive. Read the engine's AUTHORITATIVE
  // app_impact projection off the object (corr_objects.app_impact): the apps this
  // incident affects, named from fused identity with provenance. Reading the
  // engine's own projection (not re-deriving from signals) keeps the UI in lockstep
  // with the persisted RCA + the rca-path-view API. Identity is enrichment: it names
  // WHICH apps are hit, it does not by itself confirm the fault (note states this).
  let appImpact: RcaAppImpact | undefined;
  {
    let parsed: { apps?: Array<Record<string, unknown>> } = {};
    try { parsed = JSON.parse(obj.app_impact || "{}"); } catch { /* absent/malformed → no section */ }
    const rawApps = Array.isArray(parsed.apps) ? parsed.apps : [];
    const apps: RcaImpactedApp[] = rawApps
      .map((a) => ({
        app: String(a.app || ""),
        band: a.band ? String(a.band) : "",
        state: a.state ? String(a.state) : "",
        sources: Array.isArray(a.sources) ? (a.sources as unknown[]).map(String) : [],
        evidenceScore: Number(a.evidence_score || 0),
        provider: a.provider ? String(a.provider) : undefined,
      }))
      .filter((a) => a.app);
    if (apps.length) {
      appImpact = {
        apps,
        note: "Application identity is supplied by an upstream classifier (firewall App-ID, NBAR2, IP/CIDR catalog, or operator catalog) and fused into explainable evidence. It names which applications this incident affects; it does not, by itself, confirm the fault.",
      };
    }
  }

  return {
    synthetic: false,
    title, subtitle,
    // Four independent dimensions (owner directive 2026-07-12): the verdict pill
    // carries the ANALYSIS, the incident pill carries the LIFECYCLE — "Recovered"
    // is an incident state and never an analysis state.
    pills: [
      {
        tone: verdictTone,
        text: confirmed ? "✓ CONFIRMED"
          : verdictState === "recovered" ? "● RECOVERED"
            : verdictState === "contradicted" ? "✕ RULED OUT"
              : "NOT CONFIRMED",
      },
      { tone: "blue", text: `Confidence: ${confidence}` },
      { tone: "orange", text: `Incident: ${lifecycle === "recovered" ? "Recovered" : lifecycle === "recovering" ? "Recovering" : "Active"}` },
      { tone: "purple", text: `Analysis: ${confirmed ? "Confirmed" : contradicted ? "Inconclusive" : suspected ? "Suspected" : "Detected"}` },
    ],
    decision: { tone: confirmed ? "confirmed" : "", text: DECISION_TEXT[decisionKind] },
    verdictState, ruledOut, whyNot,
    verifyDetail: rawReasons.length ? rawReasons : undefined,
    observedAt: (timeline.window_start || "").replace("T", " ").slice(0, 19) + " UTC",
    rcaId: obj.correlation_id.slice(0, 13),
    aside: [
      // "Root cause" only names an object when CONFIRMED; a suspected case pairs
      // the honest non-claim with the best hypothesis so the reader gets
      // "possibly because of X" + the evidence state, never a bare dead-end
      // "Not identified" (#113 point 4 — cause honesty).
      {
        k: "Root cause",
        v: confirmed && device ? `${device}${peer ? ` ↔ ${peer}` : ""}`
          : possiblyCause ? `Not confirmed — possibly because of ${possiblyCause}`
            : "Not identified — no cause hypothesis has supporting evidence yet",
      },
      ...(!confirmed && evidenceState ? [{ k: "Evidence state", v: evidenceState }] : []),
      ...(!confirmed && device ? [{ k: "Evidence localizes to", v: `${device}${peer ? ` ↔ ${peer}` : ""}`, mono: true }] : []),
      // Ownership names the SEAM's responsible party from the matched signature
      // (isp / carrier / cloud provider / app team) — never a generic "NOC"
      // catch-all when the engine has an attribution. NOC appears only when the
      // seam has not been narrowed at all (#113).
      ...(owner
        ? [confirmed
          ? { k: "Owner", v: ownerDisplay(owner) }
          : { k: "Possible owner", v: `${ownerDisplay(owner)} — unconfirmed` }]
        : [{ k: "Possible owner", v: "Not yet narrowed — NOC triage" }]),
      // Evidence quality, not volume (owner 2026-07-18): symptoms · independent
      // sources · duration ARE the evidence; the raw count trails, de-emphasized.
      {
        k: "Evidence",
        v: `${evidenceSummary.symptoms} symptom${evidenceSummary.symptoms === 1 ? "" : "s"} · ${evidenceSummary.sources} independent source${evidenceSummary.sources === 1 ? "" : "s"} · ${evidenceSummary.durationLabel}`,
      },
      { k: "Suggested ticket", v: confirmed ? "Open P2" : "Hold — policy threshold not met" },
      { k: "Observations", v: `${evidenceSummary.observations} collected` },
    ],
    evidenceSummary,
    summary, why, impact, topology,
    evidence, ladder,
    events: buildCaseEvents(timeline, obj, extras),
    ownershipLabel: owner ? ownerDisplay(owner) : "",
    possiblyCause,
    timelineTicks: ticks, timeline: timelineLanes, hypotheses, cascade,
    ticket: {
      callout: confirmed ? { tone: "red", strong: "Open incident:", text: "Customer impact is confirmed." } : { tone: "", strong: "Not opened —", text: "impact not confirmed. Auto-ticketing holds until independent evidence confirms customer impact." },
      rows: confirmed ? [{ k: "Ticket state", v: "Recommend open" }, { k: "Priority", v: "P2" }, { k: "Assignment", v: ownerDisplay(owner) || "NetOps" }] : [{ k: "Ticket state", v: "Not opened" }, { k: "Reason", v: "RCA not confirmed" }],
    },
    nextActions,
    assistant: {
      questions: ["Why is this not confirmed?", "What would confirm it?", `What should ${ownerLabel(owner) || "the team"} check first?`, "Why were active checks ignored?", "Should a ticket be opened?"],
      sampleAnswer: confirmed ? "Independent evidence aligns in the same window and scope, so customer impact is confirmed." : "This rests on a single observation; independent evidence (peer-side routing, traffic-flow loss, downstream impact, or an active check) is needed before confirming customer impact.",
    },
    cloud,
    appImpact,
    debug: {
      accounting: timeline.signals.filter((s) => s.attached && !s.kind.endsWith("_clear")).slice(0, 8).map((s) => ({ signal: kindLabel(s.kind), used: { tone: "green", text: "Used" }, weight: "—", reason: `Attached ${isRoutingKind(s.kind) ? "routing/link" : modalityLabel(s.modality_class).toLowerCase()} evidence.` })),
      promotion: [
        { k: "Observed threshold", v: "1 trusted event" }, { k: "Suspected threshold", v: "localized object" },
        { k: "Probable threshold", v: "2 independent sources" }, { k: "Confirmed threshold", v: "customer-impact tied to scope" },
        { k: "Verdict tier", v: timeline.verdict_tier }, { k: "Attached observers", v: String(timeline.signals.filter((s) => s.attached).length) },
      ],
      reasoning: confirmed ? "Promoted to confirmed: independent customer-impact evidence tied to the network path event." : "Held at suspected: a single device-area source cannot confirm customer impact without an independent observer.",
      model: { correlation_id: obj.correlation_id, verdict_tier: timeline.verdict_tier, top_hypothesis: timeline.top_hypothesis, signal_count: obj.signal_count },
    },
  };
}

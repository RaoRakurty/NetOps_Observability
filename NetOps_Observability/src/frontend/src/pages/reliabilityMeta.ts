// reliabilityMeta.ts — pure presentation helpers for the NOC Recovery Scorecard:
// duration formatting, NOC-friendly delay labels, owner-domain styling, and chronic-
// offender display-name enrichment + recommended actions. No fabricated site/owner
// data: raw ids are preserved as secondary text; unknown fields read honestly.

export function fmtDur(ms: number | undefined | null): string {
  if (ms == null || ms < 0) return "—";
  const s = ms / 1000;
  if (s < 1) return `${Math.round(ms)} ms`;
  if (s < 60) return `${s.toFixed(s < 10 ? 1 : 0)}s`;
  const m = s / 60;
  if (m < 60) return `${Math.floor(m)}m ${String(Math.round(s - Math.floor(m) * 60)).padStart(2, "0")}s`;
  const h = m / 60;
  if (h < 48) return `${h.toFixed(1)}h`;
  return `${(h / 24).toFixed(1)}d`;
}

// Delay-driver / current-phase → operator language (matches the per-incident card).
export const DELAY_LABEL: Record<string, string> = {
  resolved: "Resolved", detection: "Detection", correlation: "Correlation",
  root_isolation: "Root Domain Unknown", owner_assignment: "Owner Assignment Pending",
  evidence_bundle: "Evidence Missing", ticket_creation: "Ticket Creation Pending",
  acknowledgement: "Ticket Acknowledgement Pending", provider_repair: "Provider Repair Pending",
  mitigation: "Mitigation Pending", recovery: "Recovery Validation Pending",
  closure: "Ticket Closure Pending", workflow_not_connected: "Workflow Not Connected", unknown: "—",
};
export function delayLabel(d: string): string { return DELAY_LABEL[d] ?? d; }

export type DomainTone = "isp" | "lan" | "sdwan" | "cloud" | "app" | "internal" | "unknown";
export const DOMAIN_TONE: Record<string, DomainTone> = {
  ISP: "isp", LAN: "lan", "SD-WAN": "sdwan", Cloud: "cloud", App: "app",
  "Internal Platform": "internal", Unknown: "unknown",
};

// Recommended NOC action per owner domain (the "what do we do next" column).
export const RECOMMENDED_ACTION: Record<string, string> = {
  ISP: "Escalate carrier with evidence bundle",
  LAN: "Check optics / interface errors and recent changes",
  "SD-WAN": "Review tunnel health, SLA policy, and path steering",
  Cloud: "Check cloud gateway, route table, NACL/security group, and provider status",
  App: "Route to application owner with correlated dependency evidence",
  "Internal Platform": "Review Correlix platform / service health",
  Unknown: "Collect missing evidence before assigning owner",
};
// Object-AWARE recommended action: precise next steps based on the object type
// (path segment / WAN router / spine) and owner domain. Falls back to the per-domain
// default.
export function recommendedAction(domain: string, groupKey?: string): string {
  const v = (groupKey ?? "").toLowerCase();
  if (domain === "Cloud")
    return "Check cloud route tables, gateway health, tunnel status, security policy changes, and provider events.";
  if (/\d{1,3}(\.\d{1,3}){3}:\d{1,3}(\.\d{1,3}){3}/.test(v) || /app_path|->/.test(v))
    return "Check path endpoints, interface errors, optic health, link flaps, and transport-provider changes.";
  if (/wan[-_]?r/.test(v))
    return "Check WAN interface errors, BGP/BFD stability, CPU pressure, link flaps, and recent policy/config changes.";
  if (/spine/.test(v))
    return "Check uplink errors, optic health, ECMP member health, queue drops, and recent fabric changes.";
  if (domain === "LAN")
    return "Check interface errors, optic health, link flaps, and recent config changes.";
  return RECOMMENDED_ACTION[domain] ?? RECOMMENDED_ACTION.Unknown;
}

// ── Evidence coverage (drives the strip, disabled cards, chart annotation, summary) ──
export type CoverageState = "connected" | "partial" | "missing" | "not_configured";
export type EvidenceCoverage = {
  correlation: CoverageState; isolation: CoverageState;
  recovery: CoverageState; ticketing: CoverageState;
};
// Derived from which phase metrics the rollup actually has. Recovery/ticketing are
// "missing" until recovery signals / ITSM (#78) are connected — not a broken chart.
export function deriveCoverage(has: { ttc: boolean; tti: boolean; recovery: boolean; ticketing: boolean }): EvidenceCoverage {
  return {
    correlation: has.ttc ? "connected" : "missing",
    isolation: has.tti ? "connected" : "missing",
    recovery: has.recovery ? "connected" : "missing",
    ticketing: has.ticketing ? "connected" : "missing",
  };
}
export const COVERAGE_LABEL: Record<CoverageState, string> = {
  connected: "Connected", partial: "Partial", missing: "Missing", not_configured: "Not configured",
};
export const COVERAGE_TONE: Record<CoverageState, "good" | "warn" | "muted"> = {
  connected: "good", partial: "warn", missing: "warn", not_configured: "muted",
};

// ── Recovery Readiness score (deterministic v1; TODO refine weights with telemetry) ──
export type ReadinessState = "Healthy" | "Stable" | "At Risk";
export type Readiness = { score: number; state: ReadinessState; drag: string };
export function recoveryReadiness(i: {
  repeatRate: number; topDelay: string; coverage: EvidenceCoverage;
  mttiP90Ms?: number; offenderCount: number;
}): Readiness {
  let score = 100;
  const drags: { label: string; pts: number }[] = [];
  const sub = (label: string, pts: number) => { if (pts > 0) { score -= pts; drags.push({ label, pts }); } };
  // TODO(reliability): calibrate these weights once recovery/ITSM evidence exists.
  sub("recurring incidents", Math.round(Math.max(0, Math.min(1, i.repeatRate)) * 30));
  if (i.topDelay === "evidence_bundle") sub("evidence missing", 15);
  if (i.coverage.recovery !== "connected") sub("no recovery evidence", 12);
  if (i.coverage.ticketing !== "connected") sub("no ITSM workflow", 8);
  if (i.mttiP90Ms && i.mttiP90Ms > 30 * 60 * 1000) sub("long-tail isolation", 10);
  sub("chronic offenders", Math.min(i.offenderCount * 2, 15));
  score = Math.max(0, Math.min(100, score));
  const state: ReadinessState = score >= 75 ? "Healthy" : score >= 55 ? "Stable" : "At Risk";
  drags.sort((a, b) => b.pts - a.pts);
  const drag = drags.slice(0, 2).map((d) => d.label).join(" + ") || "no significant drag";
  return { score, state, drag };
}

// A percentile value that is 0/absent means "no valid sample" (e.g. a domain with no
// isolated incidents), NOT instant isolation. Never render "0 ms".
export function pctlOrSample(ms: number | null | undefined): string | null {
  return ms != null && ms > 0 ? fmtDur(ms) : null; // null → caller shows "No valid sample"
}

// Known platform services → friendly display names (Correlix's own stack).
const SERVICE_NAME: Record<string, string> = {
  api: "Correlix API", clickhouse: "Flow Store", netbox: "Inventory Service",
  prober: "Path Probe", nginx: "Edge Proxy", grafana: "Self-Observability",
  victoria: "Metrics Store", opensearch: "Log Store", postgres: "App Database",
  redis: "Cache", correlation: "Correlation Engine", vector: "Telemetry Pipeline",
};
// Device-name patterns → friendly display.
function deviceDisplay(v: string): string {
  const m = v.toLowerCase();
  let r = v;
  r = r.replace(/^spine[-_]?(\d+)/i, "DC Spine-$1").replace(/^leaf[-_]?(\d+)/i, "DC Leaf-$1");
  r = r.replace(/^wan[-_]?r(\d+)/i, "WAN Router $1").replace(/^lan[-_]?sw(\d+)/i, "LAN Switch $1");
  r = r.replace(/^dmz[-_]?fw/i, "DMZ Firewall").replace(/^border(\d+)?/i, "Border Router $1");
  if (r !== v) return r.trim();
  if (SERVICE_NAME[m]) return SERVICE_NAME[m];
  return v;
}
function nodeDisplay(v: string): string {
  const low = v.toLowerCase();
  for (const [tok, name] of Object.entries(SERVICE_NAME)) if (low === tok || low.includes(tok)) return name;
  return deviceDisplay(v);
}

export type OffenderDisplay = { display: string; secondary: string };
// Enrich a raw group_key ("app_path:api->clickhouse", "device:spine1",
// "root_entity:10.0.0.1:192.168.0.5") into a NOC-readable name + raw secondary.
export function offenderDisplay(groupKey: string): OffenderDisplay {
  const i = groupKey.indexOf(":");
  const kind = i >= 0 ? groupKey.slice(0, i) : "";
  const value = i >= 0 ? groupKey.slice(i + 1) : groupKey;
  if (kind === "app_path" && value.includes("->")) {
    const [a, b] = value.split("->");
    return { display: `${nodeDisplay(a)} → ${nodeDisplay(b)}`, secondary: value };
  }
  if (kind === "device" || kind === "root_entity" || kind === "interface") {
    // an ip:ip pair reads as a path segment (don't pretend it's a named circuit)
    if (/^\d{1,3}(\.\d{1,3}){3}:\d{1,3}(\.\d{1,3}){3}$/.test(value)) {
      return { display: "Path segment", secondary: value };
    }
    return { display: deviceDisplay(value), secondary: value };
  }
  return { display: value, secondary: groupKey };
}

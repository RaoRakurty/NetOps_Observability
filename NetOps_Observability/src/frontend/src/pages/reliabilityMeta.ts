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
export function recommendedAction(domain: string): string {
  return RECOMMENDED_ACTION[domain] ?? RECOMMENDED_ACTION.Unknown;
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

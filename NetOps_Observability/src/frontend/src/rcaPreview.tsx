// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// TEMPORARY dev-only harness (rca-preview.html) — mounts the Correlations RCA
// detail against a fetch mock for layout screenshots. Not part of the app build
// (no import from the app entry); deleted when review is done.
import { createRoot } from "react-dom/client";
import { CorrelationDetail } from "./tabs/Correlations";

const now = Date.now();
const iso = (msAgo: number) => new Date(now - msAgo).toISOString().replace("T", " ").slice(0, 19);

let sid = 0;
const mk = (kind: string, modality: string, entity_type: string, entity_id: string, sev: string, msAgo: number, attached: boolean, attrs = "") => ({
  signal_id: `s-${sid++}`, ts: iso(msAgo), source: "correlation", kind,
  observer_type: "prober", observer_id: "probe-dal", collection_path: "kafka",
  modality_class: modality, clock_quality: "ntp", entity_type, entity_id,
  severity: sev, value: 1, metric_name: kind, attrs, onset_uncertainty_s: 5,
  phase: "anomalous", clear_ts: "", attached, is_trigger: sid === 1, evidence: null,
});
const sigs: any[] = [];
for (let i = 0; i < 40; i++) sigs.push(mk("probe_loss", "active_probe", "path", "edge1->dc1", "crit", (20 - i * 0.45) * 60_000, true));
sigs.push(mk("bgp_adjacency_change", "control_plane", "device", "wan-r2:192.0.2.5", "crit", 19 * 60_000, true, JSON.stringify({ peer: "192.0.2.5" })));
for (let i = 0; i < 6; i++) sigs.push(mk("if_errors", "device_telemetry", "device", "wan-r2", "warn", (15 - i) * 60_000, true));

const OBJ = {
  correlation_id: "corr-demo-1", version: 3, state: "open",
  window_start: iso(22 * 60_000), window_end: iso(0),
  trigger_signal: "s-0", top_hypothesis: "sig.ent.wan-edge.bgp-peer-down", top_confidence: 0.55,
  verdict_tier: "suspected",
  hypotheses: JSON.stringify({ ranking: { hypotheses: [{ id: "sig.ent.wan-edge.bgp-peer-down", contradicted: false, verdict: { reasons: ["no independent customer-impact evidence yet"], first_steps: ["Check wan-r2 BGP session to 192.0.2.5"], owner: "isp" }, causal_chain: [
    { stage: "Provider edge BGP session", root: true, witnessed: true, kinds: ["bgp_adjacency_change"] },
    { stage: "Path loss to the data center", witnessed: true, kinds: ["probe_loss"] },
    { stage: "Customer application errors", witnessed: false, note: "" },
  ] }] } }),
  evidence_missing: JSON.stringify(["peer-side BGP state", "traffic-flow loss"]),
  affected: JSON.stringify({ devices: ["wan-r2"] }), signal_count: 300, node_count: 3,
  engine_version: "v1", catalog_version: "c1", created_at: iso(22 * 60_000),
  owner: "isp", grounding: "seam", plane_count: 3,
};

const TIMELINE = {
  correlation_id: "corr-demo-1", version: 3,
  window_start: OBJ.window_start, window_end: OBJ.window_end,
  trigger_signal: "s-0", verdict_tier: "suspected", top_hypothesis: OBJ.top_hypothesis,
  top_confidence: 0.55, evidence_missing: OBJ.evidence_missing,
  signals: sigs, evidence: [], edges: [],
  counts: {
    total: 300, attached: sigs.length, unattached: 0, recovery: 0, unlinked: 0, attached_observers: 3,
    by_modality: { active_probe: 240, control_plane: 1, device_telemetry: 59 },
    attached_by_modality: { active_probe: 40, control_plane: 1, device_telemetry: 6 },
    by_role: {}, by_grounding: {}, by_status: {},
  },
};

const PATH_ATTR = {
  src: "branch-dallas", dst: "app.acme.com",
  attributed: { device: { address: "203.0.113.9", role: "provider_edge", label: "wan-r2", segment_index: 2, segment_type: "wan", upstream_rank: 1, ambiguous: false }, kind: "bgp_adjacency_change" },
  explained_away: [{ device: { address: "", role: "load_balancer", label: "lb-dal-1", segment_index: 3, segment_type: "cloud", upstream_rank: 2, ambiguous: false }, kind: "lb_5xx" }],
  discounted: [{ identity: "core-sw-7", kind: "device_resource_anomaly", reason: "off the measured path" }],
  verdict_tier: "suspected", baseline_verdict_tier: "suspected", confidence_lifted: false,
  capped: true, cap_reason: "2 hops inside the provider segment did not respond",
  on_path_device_count: 5,
  path: {
    src: "branch-dallas", dst: "app.acme.com", ambiguous: false,
    head: { query_name: "app.acme.com", resolved_address: "198.51.100.7" },
    segments: [
      { index: 0, segment_type: "lan", ambiguous: false, confidence: "high", key_devices: [{ role: "client", label: "branch-dallas" }, { role: "edge_router", label: "br-edge-1" }] },
      { index: 1, segment_type: "unknown", ambiguous: false, key_devices: [], unknown_hops: [4, 5, 6] },
      { index: 2, segment_type: "wan", provider: "transitco", ambiguous: false, confidence: "medium", key_devices: [{ role: "provider_edge", label: "wan-r2", address: "203.0.113.9" }] },
      { index: 3, segment_type: "cloud", provider: "aws", ambiguous: false, confidence: "high", key_devices: [{ role: "load_balancer", label: "lb-dal-1" }, { role: "application", label: "app.acme.com" }] },
    ],
    notes: [],
  },
};

const realFetch = window.fetch.bind(window);
window.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
  const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
  const p = new URL(url, location.href).pathname;
  const json = (b: unknown) => new Response(JSON.stringify(b), { status: 200, headers: { "Content-Type": "application/json" } });
  if (!p.startsWith("/api/")) return realFetch(input as any, init);
  if (p.endsWith("/timeline")) return json(TIMELINE);
  if (p.includes("/rca-report")) return json({ path_attribution: PATH_ATTR });
  if (p.endsWith("/api/correlations/corr-demo-1")) return json({ object: OBJ, edges: [] });
  if (p.includes("/api/settings/seam-owners")) return json({ seam_owners: {} });
  if (p.includes("/api/seams")) return json([]);
  if (p.includes("/api/auth/me")) return json({ username: "alice", role: "operator", permissions: { infrastructure: 2 } });
  return new Response("not found", { status: 404 });
}) as typeof window.fetch;

createRoot(document.getElementById("root")!).render(<CorrelationDetail id="corr-demo-1" />);

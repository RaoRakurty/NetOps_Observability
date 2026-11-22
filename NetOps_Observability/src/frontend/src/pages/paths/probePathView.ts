// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// probePathView.ts — a measured traceroute path (GET /api/probe/paths) as the
// TopologyView the NetworkPathView ribbon draws (Paths redesign P5, "Hop by
// hop"). Pure, so the first-loss rule is unit-tested.
//
// HONESTY: path_source is "measured" — every hop here was observed by a probe,
// which is what lets the ribbon say "Measured". A hop that did not answer is
// drawn as an unresolved hop, never given a name or a number it does not have.
//
// FIRST LOSS: the first hop from which loss persists to the end of the path.
// Loss at one hop that later hops do not show is that router declining to answer
// probes (control-plane rate limiting), not loss on the path, so it is not
// marked. A path that never reached its target is marked where the answers stop.

import type { ProbePath } from "../../services/api";
import type { TopologyView, TopologyNode, TopologyEdge } from "../../features/topology/api/topologyTypes";

type Hop = ProbePath["hops"][number];

const answered = (h: Hop): boolean => !!h.ip;
const lossOf = (h: Hop): number => (answered(h) && h.loss_pct != null ? h.loss_pct : 0);

/**
 * Index into `hops` of the first-loss hop, or -1 when the path shows no loss.
 * See the file comment for the rule.
 */
export function firstLossIndex(p: Pick<ProbePath, "hops" | "reached">): number {
  const hops = p.hops ?? [];
  const lastAnswer = hops.reduce((acc, h, i) => (answered(h) ? i : acc), -1);
  for (let i = 0; i <= lastAnswer; i++) {
    if (lossOf(hops[i]) <= 0) continue;
    let persists = true;
    for (let j = i + 1; j <= lastAnswer; j++) {
      if (answered(hops[j]) && lossOf(hops[j]) <= 0) { persists = false; break; }
    }
    if (persists) return i;
  }
  if (!p.reached && lastAnswer < hops.length - 1) return lastAnswer + 1;
  return -1;
}

const evidence = (detail: string) => [{ source: "trace" as const, confidence: 1, detail }];

/** The ribbon's view of one measured path: vantage → hops (→ target, when unreached). */
export function probePathToView(p: ProbePath): TopologyView {
  const hops = p.hops ?? [];
  const lossAt = firstLossIndex(p);
  const src: TopologyNode = {
    id: "vantage", label: p.vantage_id ? `Prober ${p.vantage_id}` : "Prober", kind: "server",
    health: "ok", confidence: 1, evidence: evidence("where the probes start"), resolved: true,
  };
  const hopNodes: TopologyNode[] = hops.map((h, i) => {
    const metrics: Record<string, number> = {};
    if (answered(h) && h.rtt_ms != null) metrics.trace_rtt_ms = h.rtt_ms;
    if (answered(h) && h.loss_pct != null) metrics.trace_loss_pct = h.loss_pct;
    return {
      id: `hop-${h.ttl}-${i}`,
      label: answered(h) ? h.ip : "No reply",
      kind: answered(h) ? "router" : "unresolved",
      mgmt_ip: answered(h) ? h.ip : undefined,
      health: !answered(h) ? "unknown" : i === lossAt ? "warning" : "ok",
      confidence: 1,
      metrics,
      evidence: evidence(i === lossAt ? "loss starts at this hop" : `hop ${h.ttl}`),
      resolved: answered(h),
      issues: i === lossAt ? [{ severity: "warning", summary: "Loss starts here" }] : undefined,
    };
  });
  const lastIp = hops.length ? hops[hops.length - 1].ip : "";
  const nodes: TopologyNode[] = [src, ...hopNodes];
  if (!p.reached && lastIp !== p.dst) {
    nodes.push({
      id: "target", label: p.dst, kind: "server", mgmt_ip: p.dst, health: "unknown",
      confidence: 1, evidence: evidence("the target, not reached"), resolved: false,
    });
  }
  const edges: TopologyEdge[] = [];
  for (let i = 0; i < nodes.length - 1; i++) {
    // The link INTO the first-loss hop is where the path degrades.
    const intoLoss = lossAt >= 0 && nodes[i + 1].id === hopNodes[lossAt]?.id;
    edges.push({
      id: `seg-${i}`, source: nodes[i].id, target: nodes[i + 1].id, relationship: "path_hop",
      status: intoLoss ? "degraded" : "up", confidence: 1, evidence: evidence("consecutive probe hops"),
    });
  }
  return {
    view_id: `probe-${p.vantage_id ?? ""}-${p.dst}-${p.method ?? ""}`,
    mode: "path_trace",
    layout_type: "path_first",
    generated_at: p.ts || new Date(0).toISOString(),
    nodes,
    edges,
    groups: [],
    overlays: ["health"],
    path: nodes.map((n) => n.id),
    path_source: "measured",
    scope: p.site ? { site: p.site } : undefined,
  };
}

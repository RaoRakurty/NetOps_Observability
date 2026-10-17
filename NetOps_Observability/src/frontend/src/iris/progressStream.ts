// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// progressStream.ts — folds the server's progress events (tracker 337 N-E2)
// into the steps IrisProgress shows. Pure. The vocabulary is CLOSED on both
// ends: an unknown event type is ignored, an unknown tool shows no detail and
// is never echoed.

import type { ProgressStep } from "./IrisProgress";

export interface StreamEvent {
  type: string;
  tool?: string;
  outcome?: string;
}

/** Plain-language names for the tools Iris runs (closed; unknown → none). */
const TOOL_LABEL: Record<string, string> = {
  nl_query: "your data",
  get_problem: "the incident",
  get_problem_evidence: "the evidence",
  get_active_major_incidents: "active incidents",
  get_actionable_incidents: "open incidents",
  get_incident_history: "incident history",
  get_rca_verdict: "the root-cause verdict",
  get_case_timeline: "the timeline",
  get_causal_chain: "the causal chain",
  get_blast_radius: "the impact",
  get_owner: "the owner",
  get_confidence_breakdown: "the confidence",
  get_affected_entities: "affected devices",
  get_top_talkers: "top talkers",
  get_flow_summary: "traffic",
  get_service_flow_summary: "service traffic",
  get_metric_anomalies: "anomalies",
  search_logs: "logs",
  get_device_health: "device health",
  get_topology_context: "topology",
  get_security_findings: "security findings",
  get_recent_changes: "recent changes",
  get_config_diff: "a configuration change",
  get_bgp_watchlist: "BGP watchlist",
  get_bgp_rpki: "RPKI",
  get_bgp_feed_recent: "BGP updates",
  recall_investigations: "past investigations",
  run_protocol_diagnostic: "the device (diagnostics)",
  get_device_state: "the device",
  search_docs: "the documentation",
  compile_query: "the question",
};

export function toolLabel(tool: string | undefined): string | undefined {
  if (!tool || !Object.prototype.hasOwnProperty.call(TOOL_LABEL, tool)) return undefined;
  return TOOL_LABEL[tool];
}

const PHASES = new Set(["planning", "narrating", "grounding"]);

/** Apply one event; returns a new array. */
export function applyEvent(steps: readonly ProgressStep[], ev: StreamEvent): ProgressStep[] {
  const out = steps.map((s) => ({ ...s }));
  const finishActivePhases = () => {
    for (const s of out) if (s.state === "active" && s.event !== "tool") s.state = "done";
  };
  if (PHASES.has(ev.type)) {
    finishActivePhases();
    out.push({ event: ev.type, state: "active" });
    return out;
  }
  if (ev.type === "tool_started") {
    finishActivePhases();
    out.push({ event: "tool", detail: toolLabel(ev.tool), state: "active", tool: ev.tool });
    return out;
  }
  if (ev.type === "tool_finished") {
    for (let i = out.length - 1; i >= 0; i--) {
      const s = out[i];
      if (s.event === "tool" && s.state === "active" && s.tool === ev.tool) {
        s.state = ev.outcome === "ok" ? "done" : "failed";
        return out;
      }
    }
    return out; // a finish without its start: nothing to update
  }
  return out; // unknown type: ignored
}

/** Mark every active step done (the answer arrived). */
export function finishAll(steps: readonly ProgressStep[]): ProgressStep[] {
  return steps.map((s) => (s.state === "active" ? { ...s, state: "done" } : s));
}

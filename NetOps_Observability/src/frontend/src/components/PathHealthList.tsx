// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

import { useEffect, useState } from "react";
import { api, PathHealthItem } from "../services/api";

// Path Behavior Health UI (docs/design/path-behavior-health.md). NOC wording only —
// no "percentile distance" / "p99 normalization" jargon. Answers, per path: is it
// bad? compared to what? how confident? who likely owns the fix? what's the
// evidence? Reused by NetworkPath and the front-page Hot-paths panel.

// Labels only: the hue is the stylesheet's (.ph-card[data-state] → --ph, from
// the --good/--warn/--bad tokens), so both themes stay in step (Paths redesign
// P1 — this card used to carry five raw hex colours inline).
const STATE_LABEL: Record<string, string> = {
  healthy: "Healthy",
  watch: "Watch",
  degraded: "Degraded",
  severe: "Severe",
  // Nothing could be measured for this path in the window. NOT a band on the
  // same scale — grey, never green, because "we could not ask" must never read
  // as "we asked and it was fine".
  unknown: "Unknown",
};
const CONF_LABEL: Record<string, string> = {
  low: "Low", medium_low: "Medium-low", medium: "Medium", high: "High",
};
const FAULT_LABEL: Record<string, string> = {
  insufficient_evidence: "Insufficient evidence",
  customer_lan: "Customer LAN",
  branch_edge_sdwan: "Branch edge / SD-WAN",
  isp_carrier: "ISP / carrier",
  cloud_provider_edge: "Cloud provider edge",
  saas_provider: "SaaS provider",
};

function PathHealthCard({ p }: { p: PathHealthItem }) {
  // Fall back to UNKNOWN, never healthy: an unrecognised state is a state we
  // do not understand, and defaulting it to green is how a blind lane renders
  // as a clean bill of health.
  const state = STATE_LABEL[p.health_state] ? p.health_state : "unknown";
  return (
    <div className="ph-card" data-state={state}>
      <div className="ph-top">
        <span className="ph-badge">{STATE_LABEL[state]}</span>
        <span className="ph-dst">{p.dst}</span>
        <span className="ph-agent">· {p.agent}</span>
        <span className="ph-conf">Confidence: <b>{CONF_LABEL[p.confidence] ?? p.confidence}</b></span>
      </div>
      <div className="ph-reason">{p.reason}</div>
      <dl className="ph-facts">
        <dt>Current latency</dt><dd>{`${p.current.latency_p95_5m} ms (last 5 min)`}</dd>
        <dt>Typical</dt><dd>{`~${p.baseline.latency_p50} ms`}</dd>
        <dt>Bad range</dt><dd>{`≥ ${p.baseline.latency_p99} ms`}</dd>
        {p.current.jitter_p95_5m > 0 && <><dt>Current jitter</dt><dd>{`${p.current.jitter_p95_5m} ms`}</dd></>}
        {p.current.loss_pct_5m > 0 && <><dt>Packet loss</dt><dd>{`${p.current.loss_pct_5m}%`}</dd></>}
        <dt>Likely owner</dt><dd>{FAULT_LABEL[p.likely_fault_domain] ?? p.likely_fault_domain}</dd>
        <dt>Compared with</dt><dd>{p.baseline.source_label}</dd>
      </dl>
      {p.evidence && p.evidence.length > 0 && (
        <details className="ph-ev">
          <summary>Evidence ({p.evidence.length})</summary>
          <ul>
            {p.evidence.map((e, i) => <li key={i}>{e}</li>)}
          </ul>
        </details>
      )}
    </div>
  );
}

export default function PathHealthList({ limit }: { limit?: number }) {
  const [paths, setPaths] = useState<PathHealthItem[]>([]);
  const [err, setErr] = useState("");
  const [loading, setLoading] = useState(true);
  useEffect(() => {
    let alive = true;
    const tick = async () => {
      try {
        const r = await api.pathsHealth();
        if (alive) { setPaths(r.paths ?? []); setErr(""); }
      } catch (e: any) {
        if (alive) setErr(String(e?.message ?? e));
      } finally {
        if (alive) setLoading(false);
      }
    };
    tick();
    const id = setInterval(tick, 30_000);
    return () => { alive = false; clearInterval(id); };
  }, []);
  const rows = limit ? paths.slice(0, limit) : paths;
  if (err) return <div className="empty" style={{ color: "var(--bad)" }}>{err}</div>;
  if (loading && rows.length === 0) return <div className="empty">Loading…</div>;
  if (rows.length === 0) {
    return (
      <div className="empty" data-testid="path-health-none">
        No path probes are switched on yet.
      </div>
    );
  }
  return (
    <div className="ph-list">
      {rows.map((p) => <PathHealthCard key={p.path_id} p={p} />)}
    </div>
  );
}

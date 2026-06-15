import { useEffect, useMemo, useState } from "react";
import { api, CorrObject, CorrEdge, CorrReplay, CorrTimeline, CorrSignal, Seam, ProbePath } from "../services/api";
import DataTable, { Column } from "../components/DataTable";
import { useWorkspace } from "../context/workspace";
import RcaTimeline, { STATUS_COLOR } from "../components/rca/RcaTimeline";
import SeamGraph, { episodeEntity } from "../components/rca/SeamGraph";
import RcaSummary from "../components/rca/RcaSummary";
import RcaPathView from "../components/rca/RcaPathView";
import RcaTopology from "../components/rca/RcaTopology";
import { entityLabel, signatureName, ownerLabel, kindLabel, seamOwnerLabel, visibilityLabel, nocUnlinkedReason, seamOwnerColor, isInternalStackAffected } from "../components/rca/labels";

// RCA is for CUSTOMER networks; internal self-monitoring objects (every affected
// entity is our own infra) are hidden by default and revealed via a toggle for
// platform debugging. A mixed object (any real device) is NOT hidden. Decision #76.
const isInternalStackObject = (o: CorrObject): boolean => isInternalStackAffected(o.affected);

// Correlations — read-only inspector for Correlation Engine v2 objects (#67).
// Every row is a versioned, replayable correlation object: a causal graph of
// anomaly episodes admitted by the grounding gate, ranked against the failure-
// signature catalog with an honest verdict tier. The detail view shows the
// grounded edges, the per-hypothesis evidence accounting (what's missing, not
// just what matched), and a one-click deterministic replay with drift report.

const mono: React.CSSProperties = { fontFamily: "ui-monospace, monospace", fontSize: 13 };

const TIER_CLASS: Record<string, string> = {
  confirmed: "sev-critical",   // strongest claim → strongest visual weight
  suspected: "sev-warning",
  undetermined: "",
};

// Operator-facing view of a single signal (item 8). Translates the engine's
// per-signal linkage into NOC language: what kind of check, from/to, what changed,
// whether it counted toward the verdict and why, customer-impact confidence, and
// the next step. Raw fields stay in the "Show debug details" section.
function signalOperatorFields(s: CorrSignal): {
  checkType: string; from: string; to: string; whatChanged: string;
  used: string; why: string; impact: string; next: string;
} {
  const k = s.kind.replace(/_clear$/, "");
  const isProbe = s.modality_class === "active_probe";
  const debugOnly = s.probe_authority === "debug_only";
  const low = s.probe_authority === "low";
  // check type
  let checkType: string;
  if (isProbe) {
    checkType = /loss/.test(k) ? "Active check: packet loss"
      : /rtt|latency/.test(k) ? "Active check: response time changed"
      : "Active check";
  } else if (s.modality_class === "control_plane") checkType = `Routing & link event: ${kindLabel(k)}`;
  else if (s.modality_class === "passive_flow") checkType = `Traffic-flow signal: ${kindLabel(k)}`;
  else checkType = `Device-health signal: ${kindLabel(k)}`;
  // from / to
  const raw = s.entity_id || "";
  const [fromRaw, toRaw] = raw.includes("->") ? raw.split("->") : [raw, ""];
  const from = entityLabel(fromRaw);
  const to = toRaw ? entityLabel(toRaw) : "—";
  // what changed
  const dev = s.deviation ? ` · ${Math.abs(Number(s.deviation)).toFixed(1)}× above normal` : "";
  const whatChanged = /loss/.test(k) ? `Packet loss seen on this path${dev}`
    : /rtt|latency/.test(k) ? `Slower response than normal${dev}`
    : `${kindLabel(k)}${dev}`;
  // used in verdict + why + impact + next
  const used = s.attached ? "Yes" : debugOnly ? "No — test check ignored" : "No";
  let why: string, impact: string, next: string;
  if (debugOnly) {
    why = "This is an internal/test check. It helps troubleshooting, but it cannot confirm customer impact by itself.";
    impact = "Not customer-impacting (test check)";
    next = "Re-test from a trusted customer path before acting.";
  } else if (low) {
    why = "This is a low-trust check — it can support a suspicion but can't confirm customer impact on its own.";
    impact = "Low";
    next = "Confirm with device health, a routing/link event, or traffic loss.";
  } else if (s.attached) {
    why = `Counted as ${s.link_role || "supporting"} evidence for this issue.`;
    impact = isProbe ? "Supports the case" : "Contributes to the case";
    next = "Correlate with the other evidence in the timeline.";
  } else if (s.link_status === "recovery") {
    why = nocUnlinkedReason(s);
    impact = "None — recovery";
    next = "No action — informational.";
  } else {
    // unlinked / malformed — operator-safe reason (distinguishes "different area"
    // from "not strong enough to link"); raw link_reason stays in debug details.
    why = nocUnlinkedReason(s);
    impact = "None";
    next = "No action — informational.";
  }
  return { checkType, from, to, whatChanged, used, why, impact, next };
}

function parseJSON<T>(raw: string | undefined, fallback: T): T {
  if (!raw) return fallback;
  try {
    return JSON.parse(raw) as T;
  } catch {
    return fallback;
  }
}

// Triage helpers for the left table — rank suspected rows by how openable they are.
// This MUST stay a conservative lower bound on the Inspector's own quality grade
// (RcaSummary), so the list never claims a higher grade than the detail view:
//   - "strong"    ⊆ Inspector strong  — confirmed implies grounded + ≥2 modality ×
//                   ≥2 observer (the engine's confirm gate), so it always lands
//                   strong in the Inspector too.
//   - "candidate" ⊆ Inspector {candidate, strong} — ≥2 planes ⇒ ≥2 modalities and
//                   not probe-only, matching the Inspector's cross-plane bar. Without
//                   plane_count≥2 a single-plane suspected row read "candidate" here
//                   while the Inspector narrated "weak/noisy" — the contradiction
//                   this guard removes.
// Under-claiming (list "weak", Inspector "candidate") is fine; over-claiming is not.
type Qual = "strong" | "candidate" | "weak";
function qualityOf(o: CorrObject): Qual {
  const grounded = (o.grounding ?? "none") !== "none";
  const planes = Number(o.plane_count ?? 0);
  if (o.verdict_tier === "confirmed") return "strong";
  if (o.verdict_tier === "suspected" && grounded && !o.low_authority && planes >= 2) return "candidate";
  return "weak";
}
// mid-tone hues, readable on the light canvas AND dark theme
const QUAL_TONE: Record<Qual, string> = { strong: "#E11D48", candidate: "#D97706", weak: "#8A93A6" };
function pill(text: string, tone: string, filled = false): React.ReactNode {
  return <span style={{
    fontSize: 10.5, fontWeight: 700, letterSpacing: 0.3, padding: "1px 6px", borderRadius: 4,
    whiteSpace: "nowrap",
    color: filled ? "#ffffff" : tone, background: filled ? tone : tone + "1c",
    border: `1px solid ${tone}55`,
  }}>{text}</span>;
}
const QUAL_RANK: Record<Qual, number> = { strong: 2, candidate: 1, weak: 0 };
const GROUND_TONE: Record<string, string> = { seam: "#D97706", "seam+topo": "#D97706", topo: "#2563EB", none: "#8A93A6" };
// NOC labels for the triage list (no engine vocabulary).
const VERDICT_NOC: Record<string, string> = { confirmed: "Confirmed", suspected: "Suspected", undetermined: "Not confirmed" };
const GROUND_NOC: Record<string, string> = { seam: "Boundary", "seam+topo": "Boundary + path", topo: "Same path", none: "—" };

export default function Correlations() {
  const [items, setItems] = useState<CorrObject[]>([]);
  const [state, setState] = useState("");
  const [tier, setTier] = useState("");
  const [showInternal, setShowInternal] = useState(false);
  const [sel, setSel] = useState<string | null>(null);
  const ws = useWorkspace();

  // Hide internal-stack/self-monitoring objects by default — RCA is for customer
  // networks (decision #76). The toggle reveals them for platform debugging.
  const visible = useMemo(
    () => (showInternal ? items : items.filter((o) => !isInternalStackObject(o))),
    [items, showInternal],
  );
  const hiddenInternal = items.length - visible.length;

  const columns = useMemo<Column<CorrObject>[]>(() => [
    { key: "created_at", header: "Updated", width: 160, sortable: true,
      sortValue: (o) => new Date(o.created_at + "Z").getTime() || 0,
      render: (o) => <span style={mono}>{new Date(o.created_at + "Z").toLocaleString()}</span> },
    { key: "verdict_tier", header: "Status", width: 116, sortable: true, text: (o) => o.verdict_tier,
      render: (o) => <span className={`badge ${TIER_CLASS[o.verdict_tier] ?? ""}`}>{VERDICT_NOC[o.verdict_tier] ?? o.verdict_tier}</span> },
    { key: "quality", header: "Quality", width: 90, sortable: true,
      sortValue: (o) => QUAL_RANK[qualityOf(o)],
      render: (o) => { const q = qualityOf(o); return pill(q, QUAL_TONE[q], q !== "weak"); } },
    { key: "top_hypothesis", header: "Likely cause", width: 200, sortable: true,
      text: (o) => (o.top_hypothesis === "undetermined" ? "" : signatureName(o.top_hypothesis)),
      render: (o) => o.top_hypothesis === "undetermined"
        ? <span style={{ color: "var(--muted)" }}>Not yet determined</span>
        : <span>{signatureName(o.top_hypothesis)}</span> },
    { key: "owner", header: "Owner", width: 96, sortable: true, text: (o) => o.owner ?? "",
      render: (o) => o.owner ? <span style={{ fontSize: 12 }}>{ownerLabel(o.owner)}</span> : "—" },
    { key: "grounding", header: "Linked by", width: 110, sortable: true, text: (o) => o.grounding ?? "none",
      render: (o) => { const g = o.grounding ?? "none"; return pill(GROUND_NOC[g] ?? g, GROUND_TONE[g] ?? "#7E8AA0"); } },
    { key: "planes", header: "Evidence types", width: 96, align: "right", sortable: true,
      sortValue: (o) => Number(o.plane_count ?? 0),
      render: (o) => <span style={mono}>{Number(o.plane_count ?? 0)}</span> },
    { key: "authority", header: "Evidence source", width: 116, sortable: true,
      sortValue: (o) => (o.debug_excluded ? 0 : o.low_authority ? 1 : o.top_hypothesis !== "undetermined" ? 3 : 2),
      render: (o) => o.debug_excluded ? pill("test check", "#8A93A6")
        : o.low_authority ? pill("weak", "#D97706")
        : o.top_hypothesis !== "undetermined" ? pill("trusted", "#16A34A")
        : <span style={{ color: "var(--muted)" }}>—</span> },
    { key: "shape", header: "Signals", width: 88, align: "right", sortable: true,
      sortValue: (o) => Number(o.signal_count ?? 0),
      render: (o) => <span style={mono} title={`${o.signal_count} signals`}>{o.signal_count}</span> },
  ], []);

  useEffect(() => {
    let alive = true;
    const tick = async () => {
      try {
        const r = await api.correlations(200, 86400, state || undefined, tier || undefined);
        if (alive) setItems(r?.data ?? []);
      } catch {
        if (alive) setItems([]);
      }
    };
    tick();
    const id = setInterval(tick, 15_000);
    return () => { alive = false; clearInterval(id); };
  }, [state, tier]);

  const select = (o: CorrObject) => {
    setSel(o.correlation_id);
    if (ws.enabled) {
      // Generic chrome title — the precise NOC cause title ("Possible path
      // slowdown") lives once, in the card below, where the dominant evidence
      // plane is known. Avoids a contradictory second title in the drawer header.
      ws.openInspector(<CorrelationDetail id={o.correlation_id} />, {
        title: "Root cause analysis",
        subtitle: o.verdict_tier === "confirmed" ? "Confirmed" : "Not confirmed",
      });
    }
  };

  const selected = !ws.enabled && sel ? items.find((o) => o.correlation_id === sel) : undefined;

  return (
    <div className="card">
      <h2>Root cause analysis</h2>
      <p style={{ fontSize: 13, color: "var(--muted)", marginTop: 0 }}>
        Each row is a possible issue, built from related evidence on the same path or
        boundary. An issue is only marked <b>Confirmed</b> when independent evidence agrees
        across at least two kinds of evidence — everything weaker says exactly what's missing
        to confirm it.
      </p>
      <div style={{ display: "flex", gap: 8, marginBottom: 12 }}>
        <select value={state} onChange={(e) => setState(e.target.value)}>
          <option value="">All states</option>
          <option value="open">Open</option>
          <option value="closed">Resolved</option>
        </select>
        <select value={tier} onChange={(e) => setTier(e.target.value)}>
          <option value="">All statuses</option>
          <option value="confirmed">Confirmed</option>
          <option value="suspected">Suspected</option>
          <option value="undetermined">Not confirmed</option>
        </select>
        <label style={{ display: "flex", alignItems: "center", gap: 6, fontSize: 13, color: "var(--muted)", marginLeft: "auto" }}>
          <input type="checkbox" checked={showInternal} onChange={(e) => setShowInternal(e.target.checked)} />
          Show internal/stack{hiddenInternal > 0 && !showInternal ? ` (${hiddenInternal} hidden)` : ""}
        </label>
      </div>
      {visible.length === 0 ? (
        <div className="empty">
          {items.length > 0
            ? "No customer-network issues in this range. Internal stack/self-monitoring objects are hidden — tick “Show internal/stack” to see them."
            : "No issues in this time range. One appears when related evidence — or a single high-severity sign — shows up across your network."}
        </div>
      ) : (
        <DataTable<CorrObject>
          rows={visible}
          columns={columns}
          rowKey={(o) => o.correlation_id}
          height="58vh"
          ariaLabel="Correlations"
          onRowClick={select}
          rowClassName={(o) => (sel === o.correlation_id ? "dtv-selected" : "")}
          initialSort={{ key: "created_at", dir: "desc" }}
        />
      )}
      {selected && (
        <div style={{ marginTop: 12, borderTop: "1px solid var(--border, #2a2f3a)", paddingTop: 12 }}>
          <CorrelationDetail id={selected.correlation_id} />
        </div>
      )}
    </div>
  );
}

// CorrelationDetail — the RCA Inspector. TIMELINE-PRIMARY: the cross-plane
// cascade over time is the lead view (what happened first/next, which planes
// agree, what contradicts, what the engine attached vs ignored, how certain the
// timing is). The seam-grounded causal graph is secondary but honest (seams as
// labeled boundary nodes with owner/visibility). Verdict + missing evidence are
// prominent. Read-only: everything shown is engine-recorded.
export function CorrelationDetail({ id }: { id: string }) {
  const [obj, setObj] = useState<CorrObject | null>(null);
  const [edges, setEdges] = useState<CorrEdge[]>([]);
  const [timeline, setTimeline] = useState<CorrTimeline | null>(null);
  const [seams, setSeams] = useState<Record<string, Seam>>({});
  const [probePaths, setProbePaths] = useState<ProbePath[]>([]);
  const [replay, setReplay] = useState<CorrReplay | null>(null);
  const [replaying, setReplaying] = useState(false);
  const [err, setErr] = useState("");
  const [selEdge, setSelEdge] = useState<CorrEdge | null>(null);
  const [selSignal, setSelSignal] = useState<string | null>(null);
  const [view, setView] = useState<"operator" | "debug">("operator");

  useEffect(() => {
    let alive = true;
    setObj(null); setEdges([]); setTimeline(null); setReplay(null); setErr("");
    setSelEdge(null); setSelSignal(null);
    api.correlationDetail(id)
      .then((r) => { if (alive) { setObj(r.object); setEdges(r.edges ?? []); } })
      .catch((e) => { if (alive) setErr(String(e?.message ?? e)); });
    api.correlationTimeline(id)
      .then((t) => { if (alive) setTimeline(t); })
      .catch(() => { /* timeline is best-effort; detail still renders */ });
    // Seam metadata (owner/visibility) for the graph; 501 on the file backend.
    api.seams("active")
      .then((list) => { if (alive) { const m: Record<string, Seam> = {}; (list ?? []).forEach((s) => { m[s.seam_id] = s; }); setSeams(m); } })
      .catch(() => { /* seam inventory optional — graph degrades to grounding_ref */ });
    // Live traceroute paths — fuse real hop order into the end-to-end topology
    // when a trace matches the RCA path's destination (else contextual fallback).
    api.probePaths()
      .then((p) => { if (alive) setProbePaths(p ?? []); })
      .catch(() => { /* no traces → topology stays contextual */ });
    return () => { alive = false; };
  }, [id]);

  // Selecting a graph edge highlights the signals on the timeline whose entity
  // matches either endpoint — the visual graph↔timeline link.
  const highlight = useMemo(() => {
    if (!selEdge || !timeline) return undefined;
    const ents = new Set([episodeEntity(selEdge.from_node), episodeEntity(selEdge.to_node)]);
    return new Set(timeline.signals.filter((s) => ents.has(s.entity_id)).map((s) => s.signal_id));
  }, [selEdge, timeline]);

  const runReplay = async () => {
    setReplaying(true); setReplay(null);
    try { setReplay(await api.correlationReplay(id)); }
    catch (e: any) { setErr(String(e?.message ?? e)); }
    finally { setReplaying(false); }
  };

  if (err) return <div className="empty">{err}</div>;
  if (!obj) return <div className="empty">Loading…</div>;

  const hyp = parseJSON<any>(obj.hypotheses, {});
  const ranking = hyp?.ranking ?? {};
  const ctx = hyp?.grounding_context ?? {};
  const selSig = selSignal ? timeline?.signals.find((s) => s.signal_id === selSignal) : undefined;
  // Recommended next action = the matched signature's playbook (first_steps + owner).
  const topHyp = (ranking.hypotheses ?? []).find((h: any) => h.id === obj.top_hypothesis)
    ?? (obj.top_hypothesis !== "undetermined" ? (ranking.hypotheses ?? [])[0] : undefined);
  const recommendedSteps: string[] = topHyp?.verdict?.first_steps ?? [];
  const recommendedOwner: string = topHyp?.verdict?.owner ?? "";
  const muted: React.CSSProperties = { color: "#AEB9CC" };
  const titleStyle: React.CSSProperties = { fontWeight: 600, fontSize: 13, marginBottom: 2 };
  const row = (k: string, v: React.ReactNode) => (
    <div style={{ display: "flex", gap: 8, fontSize: 13, padding: "2px 0" }}>
      <span style={{ ...muted, minWidth: 110 }}>{k}</span>
      <span style={{ wordBreak: "break-all" }}>{v}</span>
    </div>
  );

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 9, fontSize: 13 }}>
      {/* operator ↔ debug toggle */}
      <div style={{ display: "flex", justifyContent: "flex-end", gap: 0 }}>
        {(["operator", "debug"] as const).map((v) => (
          <button key={v} onClick={() => setView(v)} style={{
            fontSize: 12.5, padding: "2px 10px", cursor: "pointer", textTransform: "capitalize",
            border: "1px solid var(--border,#2a2f3a)",
            borderRadius: v === "operator" ? "4px 0 0 4px" : "0 4px 4px 0",
            background: view === v ? "var(--accent,#4c8dff)" : "transparent",
            color: view === v ? "#fff" : "var(--muted)",
          }}>{v} view</button>
        ))}
      </div>

      {/* RCA story: clean header, plain-English summary, mini seam preview,
          diagnostic coverage, human-readable missing-evidence checklist */}
      {timeline && (
        <RcaSummary timeline={timeline} seams={seams} view={view}
          state={obj.state} version={obj.version} nodeCount={obj.node_count}
          recommendedSteps={recommendedSteps} owner={recommendedOwner} affected={obj.affected} />
      )}

      {/* END-TO-END TOPOLOGY — the path observer→target with the fault marked
          (broken / suspected / possible). Data-driven overlay; live-trace fusion
          is the next phase. */}
      {timeline && (
        <div>
          <div style={titleStyle}>End-to-end path</div>
          <div style={{ ...muted, fontSize: 12.5, marginBottom: 4 }}>
            Where the issue sits on the path — and exactly what&apos;s broken there. Drag to arrange; scroll the page, drag the canvas to pan.
          </div>
          <RcaTopology timeline={timeline} seams={seams} view={view} probePaths={probePaths} />
        </div>
      )}

      {/* RCA path view (operator only) — the textual "evidence along the path"
          breakdown beneath the topology; full grounded graph stays in Debug. */}
      {view === "operator" && timeline && (
        <RcaPathView timeline={timeline} seams={seams} owner={recommendedOwner} />
      )}

      {/* PRIMARY: the evidence timeline */}
      <div>
        <div style={titleStyle}>Evidence timeline</div>
        <div style={{ ...muted, fontSize: 12.5, marginBottom: 4 }}>
          Tip: Click any marker to see what was observed and why it was or was not used.
        </div>
        {timeline
          ? <RcaTimeline timeline={timeline} selected={selSignal} onSelect={setSelSignal} highlight={highlight} view={view} />
          : <div className="empty">Loading window slice…</div>}
        {/* click-to-explain: operator-friendly first, raw fields under a collapse */}
        {selSig && (() => {
          const f = signalOperatorFields(selSig);
          const tPlus = timeline ? Math.round((Date.parse(selSig.ts.replace(" ", "T") + "Z") - Date.parse(timeline.window_start.replace(" ", "T") + "Z")) / 1000) : 0;
          const orow = (k: string, v: React.ReactNode) => (<><span style={muted}>{k}</span><span>{v}</span></>);
          return (
            <div style={{
              marginTop: 8, border: `1px solid ${STATUS_COLOR[selSig.link_status] ?? "#d29922"}55`,
              borderRadius: 6, padding: "8px 10px", background: "var(--panel,#11151c)", fontSize: 13,
            }}>
              <div style={{ fontWeight: 700, fontSize: 13.5, marginBottom: 6, color: "var(--fg)" }}>{f.checkType}</div>
              <div style={{ display: "grid", gridTemplateColumns: "auto 1fr", gap: "3px 10px" }}>
                {orow("From", f.from)}
                {f.to !== "—" && orow("To", f.to)}
                {orow("What changed", f.whatChanged)}
                {orow("Used in verdict?", <b style={{ color: selSig.attached ? "#16A34A" : "#8A93A6" }}>{f.used}</b>)}
                {orow("Why", f.why)}
                {orow("Customer-impact confidence", f.impact)}
                {orow("Next step", f.next)}
                {orow("Time", <span style={mono}>{selSig.ts.slice(11, 19)} UTC{timeline ? ` (T+${tPlus}s)` : ""}</span>)}
              </div>
              {/* raw backend fields — collapsed, Debug-grade detail */}
              <details style={{ marginTop: 8 }}>
                <summary style={{ cursor: "pointer", color: "var(--accent,#4c8dff)", fontSize: 12 }}>Show debug details</summary>
                <div style={{ display: "grid", gridTemplateColumns: "auto 1fr", gap: "2px 10px", marginTop: 6, ...mono, fontSize: 12 }}>
                  {orow("entity_id", selSig.entity_id)}
                  {orow("kind", selSig.kind)}
                  {orow("modality_class", selSig.modality_class)}
                  {orow("observer_type", selSig.observer_type)}
                  {selSig.observer_id ? orow("observer_id", selSig.observer_id) : null}
                  {orow("collection_path", selSig.collection_path)}
                  {selSig.modality_class === "active_probe" && orow("probe_scope", `${selSig.probe_scope ?? "—"} · ${selSig.probe_authority ?? "—"}${selSig.classification_source ? ` (${selSig.classification_source})` : ""}`)}
                  {orow("clock_quality", `${selSig.clock_quality} · ±${selSig.onset_uncertainty_s}s`)}
                  {orow("link_status", `${selSig.link_status}${selSig.link_role ? ` / ${selSig.link_role}` : ""}`)}
                  {orow("link_reason", selSig.link_reason)}
                  {(selSig.linked_edges ?? []).length > 0 && orow("linked_edges", (selSig.linked_edges ?? []).map((e) => `${e.peer.split(":").slice(1, -1).join(":")} [${e.grounding_kind}:${e.grounding_ref}] w=${Number(e.weight).toFixed(2)}`).join("; "))}
                  {selSig.attrs ? orow("attrs", selSig.attrs) : null}
                </div>
              </details>
            </div>
          );
        })()}
      </div>

      {/* SECONDARY: the related-evidence map (engine's grounded causal graph) */}
      <div>
        <div style={titleStyle}>{view === "debug" ? `Grounded causal graph (${edges.length} edge${edges.length === 1 ? "" : "s"})` : `How the evidence relates (${edges.length} link${edges.length === 1 ? "" : "s"})`}</div>
        <div style={{ ...muted, fontSize: 12.5, marginBottom: 4 }}>
          {view === "debug"
            ? "Seams (◆) are ownership boundaries — owner + visibility shown. Click an edge to highlight its signals on the timeline. Arrows appear only where the engine claimed direction."
            : "◆ marks a provider/ownership boundary (who owns it + how much we can see). Click a link to highlight its evidence on the timeline. An arrow shows direction only when we're confident."}
        </div>
        {/* For sparse objects (1–2 edges) the force graph reads as empty, so lead
            with a compact, clickable relationship preview; the graph follows at a
            reduced height. ≥3 edges go straight to the graph. */}
        {edges.length >= 1 && edges.length <= 2 && (
          <RelationshipPreview edges={edges} seams={seams} view={view} onSelect={setSelEdge} selected={selEdge} />
        )}
        <SeamGraph edges={edges} seams={seams} view={view} onSelectEdge={setSelEdge}
          height={edges.length <= 2 ? 220 : 360} />
      </div>

      {/* DEBUG-only: pins, competing hypotheses, deterministic replay */}
      {view === "debug" && (
        <>
          <div>
            {row("Object", <span style={mono}>{obj.correlation_id}</span>)}
            {row("Window", <span style={mono}>{obj.window_start} → {obj.window_end} UTC</span>)}
            {row("Pins", <span style={mono}>{obj.engine_version} · {obj.catalog_version} · {obj.topology_version}</span>)}
            {ctx.topology_gap_hints > 0 &&
              row("Gap hints", `${ctx.topology_gap_hints} ungrounded co-occurrences (excluded, queued for seam review)`)}
          </div>

          {(ranking.hypotheses ?? []).length > 0 && (
            <div>
              <div style={titleStyle}>Competing hypotheses</div>
              {(ranking.hypotheses as any[]).map((h) => (
                <div key={h.template_id} style={{ ...mono, padding: "1px 0" }}>
                  {h.template_id} — rank {Number(h.confidence_rank ?? 0).toFixed(2)}, coverage {Number(h.coverage ?? 0).toFixed(2)}
                </div>
              ))}
            </div>
          )}

          <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
            <button className="btn" onClick={runReplay} disabled={replaying}>
              {replaying ? "Replaying…" : "Replay (determinism check)"}
            </button>
            {replay && (
              <span className={`badge ${replay.clean ? "" : "sev-critical"}`}>
                {replay.clean
                  ? `clean — v${replay.stored_version} reproduced bit-perfect`
                  : `drift: ${replay.differences.length} difference(s)`}
              </span>
            )}
          </div>
          {replay && !replay.clean && (
            <div>
              {replay.differences.map((d) => (
                <div key={d} style={{ ...mono, ...muted }}>· {d}</div>
              ))}
              {!replay.engine_pin_match && (
                <div style={{ fontSize: 13, ...muted }}>
                  Engine pin mismatch: the object was built by an older engine — expected evolution, not corruption.
                </div>
              )}
            </div>
          )}
        </>
      )}
    </div>
  );
}

// RelationshipPreview — compact, clickable edge rows for sparse objects (1–2
// edges), where the force graph reads as empty. Mirrors the RcaSummary mini-
// preview: from → [◆ boundary owner · visibility | topology] → to. Clicking a row
// selects the edge (highlights its signals on the timeline), same as a graph edge.
// Honors Operator/Debug: friendly entity names in operator, raw keys in debug.
function RelationshipPreview({ edges, seams, view, onSelect, selected }: {
  edges: CorrEdge[];
  seams: Record<string, Seam>;
  view: "operator" | "debug";
  onSelect?: (e: CorrEdge | null) => void;
  selected?: CorrEdge | null;
}) {
  const ent = (key: string) => (view === "debug" ? episodeEntity(key) : entityLabel(episodeEntity(key)));
  const chip: React.CSSProperties = {
    fontFamily: "ui-monospace, monospace", fontSize: 12.5, background: "var(--bg,#0d1117)",
    padding: "1px 6px", borderRadius: 4, overflowWrap: "anywhere", minWidth: 0,
  };
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 6, margin: "4px 0 8px" }}>
      {edges.map((e, i) => {
        const seam = e.grounding_kind === "seam" ? seams[e.grounding_ref] : undefined;
        const directed = Number(e.direction_conf ?? 0) >= 0.5 && e.direction_basis !== "none";
        const isSel = selected === e;
        const link = directed ? "→" : "──";
        // Boundary tinted by owner (whose domain), grey for same-path/device-area.
        const seamTone = e.grounding_kind === "seam" ? seamOwnerColor(seam?.control_plane_owner) : "#8A93A6";
        return (
          <div key={i} onClick={() => onSelect?.(isSel ? null : e)} title={view === "debug" ? e.grounding_ref : undefined} style={{
            display: "flex", alignItems: "center", gap: 6, flexWrap: "wrap", cursor: "pointer",
            fontSize: 12.5, padding: "5px 8px", borderRadius: 6, minWidth: 0,
            border: `1px solid ${isSel ? "var(--accent,#4c8dff)" : "var(--border,#2a2f3a)"}`,
            background: isSel ? "var(--hover)" : "transparent",
          }}>
            <span style={chip}>{ent(e.from_node)}</span>
            <span style={{ color: "var(--muted)" }}>{link}</span>
            <span style={{
              background: seamTone + "22", border: `1px solid ${seamTone}66`, borderRadius: 4,
              padding: "1px 6px", fontWeight: 600, color: seamTone,
            }}>
              {e.grounding_kind === "seam"
                ? `◆ ${seam ? `${seamOwnerLabel(seam.control_plane_owner)} · ${visibilityLabel(seam.visibility)}` : "provider boundary"}`
                : "same path / device area"}
            </span>
            <span style={{ color: "var(--muted)" }}>{link}</span>
            <span style={chip}>{ent(e.to_node)}</span>
          </div>
        );
      })}
    </div>
  );
}

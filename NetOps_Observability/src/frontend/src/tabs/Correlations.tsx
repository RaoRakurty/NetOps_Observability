import { useEffect, useMemo, useState } from "react";
import { api, CorrObject, CorrEdge, CorrReplay, CorrTimeline, Seam } from "../services/api";
import DataTable, { Column } from "../components/DataTable";
import { useWorkspace } from "../context/workspace";
import RcaTimeline, { STATUS_COLOR } from "../components/rca/RcaTimeline";
import SeamGraph, { episodeEntity } from "../components/rca/SeamGraph";
import RcaSummary from "../components/rca/RcaSummary";
import { PROBE_AUTHORITY_META, probeScopeLabel, probeAuthorityLabel, entityLabel, signatureName, ownerLabel } from "../components/rca/labels";

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

function parseJSON<T>(raw: string | undefined, fallback: T): T {
  if (!raw) return fallback;
  try {
    return JSON.parse(raw) as T;
  } catch {
    return fallback;
  }
}

// Triage helpers for the left table — rank suspected rows by how openable they are.
type Qual = "strong" | "candidate" | "weak";
function qualityOf(o: CorrObject): Qual {
  const grounded = (o.grounding ?? "none") !== "none";
  if (o.verdict_tier === "confirmed") return "strong";
  if (o.verdict_tier === "suspected" && grounded && !o.low_authority) return "candidate";
  return "weak";
}
const QUAL_TONE: Record<Qual, string> = { strong: "#FF5366", candidate: "#F2B705", weak: "#7E8AA0" };
function pill(text: string, tone: string, filled = false): React.ReactNode {
  return <span style={{
    fontSize: 10.5, fontWeight: 700, letterSpacing: 0.3, padding: "1px 6px", borderRadius: 4,
    whiteSpace: "nowrap",
    color: filled ? "#0E1320" : tone, background: filled ? tone : tone + "22",
    border: `1px solid ${tone}66`,
  }}>{text}</span>;
}
const QUAL_RANK: Record<Qual, number> = { strong: 2, candidate: 1, weak: 0 };
const GROUND_TONE: Record<string, string> = { seam: "#F2B705", "seam+topo": "#F2B705", topo: "#5B9DFF", none: "#7E8AA0" };

export default function Correlations() {
  const [items, setItems] = useState<CorrObject[]>([]);
  const [state, setState] = useState("");
  const [tier, setTier] = useState("");
  const [sel, setSel] = useState<string | null>(null);
  const ws = useWorkspace();

  const columns = useMemo<Column<CorrObject>[]>(() => [
    { key: "created_at", header: "Updated", width: 160, sortable: true,
      sortValue: (o) => new Date(o.created_at + "Z").getTime() || 0,
      render: (o) => <span style={mono}>{new Date(o.created_at + "Z").toLocaleString()}</span> },
    { key: "verdict_tier", header: "Verdict", width: 104, sortable: true, text: (o) => o.verdict_tier,
      render: (o) => <span className={`badge ${TIER_CLASS[o.verdict_tier] ?? ""}`}>{o.verdict_tier}</span> },
    { key: "quality", header: "Quality", width: 90, sortable: true,
      sortValue: (o) => QUAL_RANK[qualityOf(o)],
      render: (o) => { const q = qualityOf(o); return pill(q, QUAL_TONE[q], q !== "weak"); } },
    { key: "top_hypothesis", header: "Likely cause", width: 200, sortable: true, text: (o) => o.top_hypothesis,
      render: (o) => o.top_hypothesis === "undetermined"
        ? <span style={{ color: "#7E8AA0" }}>undetermined</span>
        : <span title={o.top_hypothesis}>{signatureName(o.top_hypothesis)}</span> },
    { key: "owner", header: "Owner", width: 96, sortable: true, text: (o) => o.owner ?? "",
      render: (o) => o.owner ? <span style={{ fontSize: 12 }}>{ownerLabel(o.owner)}</span> : "—" },
    { key: "grounding", header: "Grounding", width: 96, sortable: true, text: (o) => o.grounding ?? "none",
      render: (o) => { const g = o.grounding ?? "none"; return pill(g, GROUND_TONE[g] ?? "#7E8AA0"); } },
    { key: "planes", header: "Planes", width: 64, align: "right", sortable: true,
      sortValue: (o) => Number(o.plane_count ?? 0),
      render: (o) => <span style={mono}>{Number(o.plane_count ?? 0)}</span> },
    { key: "authority", header: "Evidence", width: 100, sortable: true,
      sortValue: (o) => (o.debug_excluded ? 0 : o.low_authority ? 1 : 2),
      render: (o) => o.debug_excluded ? pill("debug-excl", "#7E8AA0")
        : o.low_authority ? pill("low-auth", "#F2B705") : pill("trusted", "#35D6A4") },
    { key: "shape", header: "N / E / Sig", width: 110, align: "right",
      render: (o) => <span style={mono}>{o.node_count}n · {Number(o.edge_count ?? 0)}e · {o.signal_count}s</span> },
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
      ws.openInspector(<CorrelationDetail id={o.correlation_id} />, {
        title: "RCA · " + (o.top_hypothesis === "undetermined" ? "Candidate" : o.top_hypothesis),
        subtitle: `${o.verdict_tier} · v${o.version}`,
      });
    }
  };

  const selected = !ws.enabled && sel ? items.find((o) => o.correlation_id === sel) : undefined;

  return (
    <div className="card">
      <h2>Correlations (engine v2 objects)</h2>
      <p style={{ fontSize: 13, color: "var(--muted)", marginTop: 0 }}>
        Topology-grounded, replayable correlation objects. A verdict is only
        <b> confirmed</b> with independent evidence from ≥2 modality classes and ≥2 observers —
        everything weaker says exactly what evidence is missing.
      </p>
      <div style={{ display: "flex", gap: 8, marginBottom: 12 }}>
        <select value={state} onChange={(e) => setState(e.target.value)}>
          <option value="">All states</option>
          <option value="open">Open</option>
          <option value="closed">Closed</option>
        </select>
        <select value={tier} onChange={(e) => setTier(e.target.value)}>
          <option value="">All verdicts</option>
          <option value="confirmed">Confirmed</option>
          <option value="suspected">Suspected</option>
          <option value="undetermined">Undetermined</option>
        </select>
      </div>
      {items.length === 0 ? (
        <div className="empty">
          No correlation objects in range. The engine opens one when grounded, correlated
          episodes (or a single high-severity episode) appear on the signal spine.
        </div>
      ) : (
        <DataTable<CorrObject>
          rows={items}
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
  const titleStyle: React.CSSProperties = { fontWeight: 600, fontSize: 13, marginBottom: 4 };
  const row = (k: string, v: React.ReactNode) => (
    <div style={{ display: "flex", gap: 8, fontSize: 13, padding: "2px 0" }}>
      <span style={{ ...muted, minWidth: 110 }}>{k}</span>
      <span style={{ wordBreak: "break-all" }}>{v}</span>
    </div>
  );

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 12, fontSize: 13 }}>
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
          recommendedSteps={recommendedSteps} owner={recommendedOwner} />
      )}

      {/* PRIMARY: the cross-plane cascade */}
      <div>
        <div style={titleStyle}>Timeline — cross-plane cascade</div>
        {timeline
          ? <RcaTimeline timeline={timeline} selected={selSignal} onSelect={setSelSignal} highlight={highlight} />
          : <div className="empty">Loading window slice…</div>}
        {/* click-to-explain: why this signal was / wasn't linked */}
        {selSig && (
          <div style={{
            marginTop: 8, border: `1px solid ${STATUS_COLOR[selSig.link_status] ?? "#d29922"}55`,
            borderRadius: 6, padding: "8px 10px", background: "var(--panel,#11151c)",
            display: "grid", gridTemplateColumns: "auto 1fr", gap: "2px 10px", fontSize: 13,
          }}>
            <span style={muted}>Signal</span><span>{selSig.kind} <span style={muted}>({selSig.modality_class.replace(/_/g, " ")})</span></span>
            <span style={muted}>Status</span>
            <span style={{ color: STATUS_COLOR[selSig.link_status] ?? "#d29922", fontWeight: 600 }}>
              {selSig.link_status === "attached" ? `attached / ${selSig.link_role || "supporting"}`
                : selSig.link_status === "recovery" ? "concurrent — recovery/clear"
                : selSig.link_status === "malformed" ? "malformed identity"
                : "concurrent — not linked"}
            </span>
            <span style={muted}>Reason</span><span>{selSig.link_reason}</span>
            {selSig.modality_class === "active_probe" && selSig.probe_authority && (
              <>
                <span style={muted}>Probe</span>
                <span>{probeScopeLabel(selSig.probe_scope)} · <b style={{ color: PROBE_AUTHORITY_META[selSig.probe_authority]?.color }}>{probeAuthorityLabel(selSig.probe_authority)}</b>{selSig.classification_source ? <span style={muted}> ({selSig.classification_source})</span> : null}</span>
              </>
            )}
            <span style={muted}>Entity</span><span style={view === "debug" ? mono : undefined}>{view === "debug" ? selSig.entity_id : entityLabel(selSig.entity_id)}</span>
            <span style={muted}>Time</span>
            <span style={mono}>
              {selSig.ts.slice(11, 19)} UTC{timeline && ` (T+${Math.round((Date.parse(selSig.ts.replace(" ", "T") + "Z") - Date.parse(timeline.window_start.replace(" ", "T") + "Z")) / 1000)}s)`}
            </span>
            <span style={muted}>Severity</span><span style={{ textTransform: "capitalize" }}>{selSig.severity}</span>
            {(selSig.linked_edges ?? []).length > 0 && (
              <>
                <span style={muted}>Linked to</span>
                <span style={mono}>{(selSig.linked_edges ?? []).map((e) => `${e.peer.split(":").slice(1, -1).join(":")} [${e.grounding_kind}:${e.grounding_ref}]`).join("; ")}</span>
              </>
            )}
          </div>
        )}
      </div>

      {/* SECONDARY: seam-grounded causal graph */}
      <div>
        <div style={titleStyle}>Grounded causal graph ({edges.length} edge{edges.length === 1 ? "" : "s"})</div>
        <div style={{ ...muted, fontSize: 12.5, marginBottom: 4 }}>
          Seams (◆) are ownership boundaries — owner + visibility shown. Click an edge to highlight its signals on the timeline. Arrows appear only where the engine claimed direction.
        </div>
        <SeamGraph edges={edges} seams={seams} onSelectEdge={setSelEdge} />
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

import { useEffect, useMemo, useState } from "react";
import { api, CorrObject, CorrReplay, CorrTimeline, Seam, ProbePath } from "../services/api";
import DataTable, { Column } from "../components/DataTable";
import { useWorkspace } from "../context/workspace";
import RcaWorkspace from "../components/rca/RcaWorkspace";
import RcaTopology from "../components/rca/RcaTopology";
import { buildRcaCase } from "../components/rca/rcaCase";
import { buildTopoGraph } from "../components/rca/topoGraph";
import { exportRcaPdf } from "../components/rca/rcaExport";
import { signatureName, ownerLabel, isInternalStackAffected } from "../components/rca/labels";
import { NocHeader, NocKpis, NocKpi, Chip, LiveChip } from "../components/noc";

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

const mono: React.CSSProperties = { fontFamily: "var(--font-mono)", fontSize: 13 };

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
// This MUST stay a conservative lower bound on the Inspector's own quality grade
// (the RCA workspace), so the list never claims a higher grade than the detail view:
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

// initial verdict-tier filter from a deep link (#/monitoring/correlations?tier=suspected)
// — the Front Page KPI strip drills through with this so "Suspected RCA" lands
// pre-filtered to suspected, not the full list.
function tierFromHash(): string {
  const q = (typeof location !== "undefined" ? location.hash : "").split("?")[1] || "";
  const t = new URLSearchParams(q).get("tier") || "";
  return ["confirmed", "suspected", "undetermined"].includes(t) ? t : "";
}

export default function Correlations() {
  const [items, setItems] = useState<CorrObject[]>([]);
  const [state, setState] = useState("");
  const [tier, setTier] = useState(tierFromHash);
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

  const rConfirmed = visible.filter((o) => o.verdict_tier === "confirmed").length;
  const rSuspected = visible.filter((o) => o.verdict_tier === "suspected").length;
  const rUndet = visible.filter((o) => o.verdict_tier === "undetermined").length;
  return (
    <div className="dm-board cc-board">
      <NocHeader
        title="RCA Candidates"
        subtitle="Evidence-linked correlation groups. A root cause is confirmed only when independent evidence agrees across at least two signal classes — weaker candidates say exactly what's missing."
        chips={<><Chip label={`${visible.length} candidates`} /><LiveChip detail="correlation engine" /></>}
      >
        <NocKpis cols={4}>
          <NocKpi n={visible.length} label="Candidates" interp="correlation groups" />
          <NocKpi n={rConfirmed} label="Confirmed" interp="≥2 evidence streams" tone={rConfirmed ? "var(--crit)" : "var(--ok)"} />
          <NocKpi n={rSuspected} label="Suspected" interp="impact not confirmed" tone={rSuspected ? "var(--warn)" : undefined} />
          <NocKpi n={rUndet} label="Not confirmed" interp="gathering evidence" />
        </NocKpis>
      </NocHeader>
      <div className="cc-panel">
        <div className="cc-panel-h">
          <h3 className="cc-panel-t">Candidate queue</h3>
          <span className="cc-panel-meta">{visible.length} · click a row for the RCA workspace</span>
        </div>
        <div style={{ padding: "11px 13px" }}>
          <div style={{ display: "flex", gap: 8, marginBottom: 10, flexWrap: "wrap" }}>
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
              ariaLabel="RCA candidates"
              resizable
              onRowClick={select}
              rowClassName={(o) => (sel === o.correlation_id ? "dtv-selected" : "")}
              initialSort={{ key: "created_at", dir: "desc" }}
            />
          )}
          {selected && (
            <div style={{ marginTop: 12, borderTop: "1px solid var(--border)", paddingTop: 12 }}>
              <CorrelationDetail id={selected.correlation_id} />
            </div>
          )}
        </div>
      </div>
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
  const [timeline, setTimeline] = useState<CorrTimeline | null>(null);
  const [seams, setSeams] = useState<Record<string, Seam>>({});
  const [probePaths, setProbePaths] = useState<ProbePath[]>([]);
  const [deviceByIp, setDeviceByIp] = useState<Record<string, string>>({});
  const [replay, setReplay] = useState<CorrReplay | null>(null);
  const [replaying, setReplaying] = useState(false);
  const [err, setErr] = useState("");
  const [view, setView] = useState<"operator" | "debug">("operator");

  useEffect(() => {
    let alive = true;
    setObj(null); setTimeline(null); setReplay(null); setErr("");
    api.correlationDetail(id)
      .then((r) => { if (alive) setObj(r.object); })
      .catch((e) => { if (alive) setErr(String(e?.message ?? e)); });
    api.correlationTimeline(id)
      .then((t) => { if (alive) setTimeline(t); })
      .catch(() => { /* timeline is best-effort; detail still renders */ });
    // Seam metadata (owner/visibility) — feeds the routing-context derivation.
    api.seams("active")
      .then((list) => { if (alive) { const m: Record<string, Seam> = {}; (list ?? []).forEach((s) => { m[s.seam_id] = s; }); setSeams(m); } })
      .catch(() => { /* seam inventory optional */ });
    // Live traceroute / STAMP paths — fuse real hop order into the Network-Path
    // topology when a trace matches the RCA path's destination (else contextual).
    api.probePaths()
      .then((p) => { if (alive) setProbePaths(p ?? []); })
      .catch(() => { /* no traces → topology stays contextual */ });
    // Tenant-scoped device inventory → name traced hops by their mgmt address.
    // RLS limits this to the caller's own devices (no cross-tenant naming leak).
    api.devices()
      .then((ds) => { if (alive) { const m: Record<string, string> = {}; (ds ?? []).forEach((d) => { if (d.address) m[d.address.trim()] = d.name; }); setDeviceByIp(m); } })
      .catch(() => { /* no inventory → hops stay as IPs */ });
    return () => { alive = false; };
  }, [id]);

  const runReplay = async () => {
    setReplaying(true); setReplay(null);
    try { setReplay(await api.correlationReplay(id)); }
    catch (e: any) { setErr(String(e?.message ?? e)); }
    finally { setReplaying(false); }
  };

  // Recommended next action = the matched signature's playbook (first_steps + owner).
  const { recommendedSteps, recommendedOwner } = useMemo(() => {
    const hyp = parseJSON<any>(obj?.hypotheses, {});
    const ranking = hyp?.ranking ?? {};
    const topHyp = (ranking.hypotheses ?? []).find((h: any) => h.id === obj?.top_hypothesis)
      ?? (obj && obj.top_hypothesis !== "undetermined" ? (ranking.hypotheses ?? [])[0] : undefined);
    return { recommendedSteps: (topHyp?.verdict?.first_steps ?? []) as string[], recommendedOwner: (topHyp?.verdict?.owner ?? "") as string };
  }, [obj]);

  // Map the real correlation object/timeline → the workspace data contract, and
  // attach the SAME positioned graph the on-screen topology draws (buildTopoGraph)
  // so the exported PDF renders an identical Network-Path picture. showStamp=false
  // keeps the print to the loss-only labels (the STAMP overlay is interactive-only).
  const rcaCase = useMemo(() => {
    if (!timeline || !obj) return null;
    const c = buildRcaCase(timeline, obj, seams, recommendedOwner, recommendedSteps);
    const graph = buildTopoGraph(timeline, seams, view, false, probePaths, deviceByIp);
    if (!graph.internal && (graph.nodes.length > 0 || graph.edges.length > 0)) c.topoGraph = graph;
    return c;
  }, [timeline, obj, seams, recommendedOwner, recommendedSteps, view, probePaths, deviceByIp]);

  if (err) return <div className="empty">{err}</div>;
  if (!obj || !timeline || !rcaCase) return <div className="empty">Loading…</div>;

  const exportPdf = () => {
    if (!rcaCase) return;
    const ok = exportRcaPdf(rcaCase, obj.correlation_id || "");
    if (!ok) alert("Could not generate the RCA report.");
  };

  // Deterministic-replay control — a platform/debug tool, surfaced only in Debug View.
  const replayPanel = (
    <div>
      <h3 style={{ margin: "0 0 10px", fontSize: 12, letterSpacing: ".04em", textTransform: "uppercase", color: "var(--muted)" }}>
        Determinism replay
      </h3>
      <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
        <button className="rw-btn" onClick={runReplay} disabled={replaying}>
          {replaying ? "Replaying…" : "Replay object"}
        </button>
        {replay && (
          <span className={`rw-pill ${replay.clean ? "green" : "red"}`}>
            {replay.clean
              ? `clean — v${replay.stored_version} reproduced bit-perfect`
              : `drift: ${replay.differences.length} difference(s)`}
          </span>
        )}
      </div>
      {replay && !replay.clean && (
        <div style={{ marginTop: 8, fontFamily: "var(--font-mono)", fontSize: 12, color: "var(--muted)" }}>
          {replay.differences.map((d) => <div key={d}>· {d}</div>)}
          {!replay.engine_pin_match && (
            <div style={{ marginTop: 4 }}>Engine pin mismatch: built by an older engine — expected evolution, not corruption.</div>
          )}
        </div>
      )}
    </div>
  );

  return (
    <RcaWorkspace
      data={rcaCase}
      view={view}
      onView={setView}
      onExportPdf={exportPdf}
      exportDisabled={!timeline}
      debugExtra={replayPanel}
      topologySlot={
        <RcaTopology timeline={timeline} seams={seams} view={view}
          probePaths={probePaths} deviceByIp={deviceByIp} height={300} />
      }
    />
  );
}

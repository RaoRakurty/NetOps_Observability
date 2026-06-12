import { useEffect, useMemo, useState } from "react";
import { api, CorrObject, CorrEdge, CorrReplay } from "../services/api";
import DataTable, { Column } from "../components/DataTable";
import { useWorkspace } from "../context/workspace";

// Correlations — read-only inspector for Correlation Engine v2 objects (#67).
// Every row is a versioned, replayable correlation object: a causal graph of
// anomaly episodes admitted by the grounding gate, ranked against the failure-
// signature catalog with an honest verdict tier. The detail view shows the
// grounded edges, the per-hypothesis evidence accounting (what's missing, not
// just what matched), and a one-click deterministic replay with drift report.

const mono: React.CSSProperties = { fontFamily: "ui-monospace, monospace", fontSize: 12 };

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

function affectedSummary(o: CorrObject): string {
  const a = parseJSON<Record<string, string[]>>(o.affected, {});
  return Object.entries(a)
    .map(([k, v]) => `${v.length} ${k}`)
    .join(" · ") || "—";
}

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
    { key: "verdict_tier", header: "Verdict", width: 110, sortable: true, text: (o) => o.verdict_tier,
      render: (o) => <span className={`badge ${TIER_CLASS[o.verdict_tier] ?? ""}`}>{o.verdict_tier}</span> },
    { key: "top_hypothesis", header: "Top hypothesis", width: 240, sortable: true, text: (o) => o.top_hypothesis,
      render: (o) => <span style={mono} title={o.top_hypothesis}>{o.top_hypothesis}</span> },
    { key: "top_confidence", header: "Rank", width: 64, align: "right", sortable: true,
      sortValue: (o) => o.top_confidence,
      render: (o) => (o.top_hypothesis === "undetermined" ? "—" : o.top_confidence.toFixed(2)) },
    { key: "state", header: "State", width: 76, sortable: true, text: (o) => o.state,
      render: (o) => <span className="badge">{o.state}</span> },
    { key: "version", header: "v", width: 44, align: "right", sortable: true,
      sortValue: (o) => o.version, render: (o) => `v${o.version}` },
    { key: "shape", header: "Nodes / Edges? / Signals", width: 150, align: "right",
      render: (o) => <span style={mono}>{o.node_count} n · {o.signal_count} sig</span> },
    { key: "affected", header: "Affected", text: (o) => affectedSummary(o),
      render: (o) => <span title={o.affected}>{affectedSummary(o)}</span> },
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
        title: o.top_hypothesis === "undetermined" ? "Correlation (undetermined)" : o.top_hypothesis,
        subtitle: `${o.verdict_tier} · v${o.version} · ${o.node_count} nodes`,
      });
    }
  };

  const selected = !ws.enabled && sel ? items.find((o) => o.correlation_id === sel) : undefined;

  return (
    <div className="card">
      <h2>Correlations (engine v2 objects)</h2>
      <p style={{ fontSize: 12, color: "var(--muted)", marginTop: 0 }}>
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

// CorrelationDetail — one object: verdict + hypotheses accounting + grounded
// edges + replay. Fetches the full detail (the list omits the hypotheses blob).
export function CorrelationDetail({ id }: { id: string }) {
  const [obj, setObj] = useState<CorrObject | null>(null);
  const [edges, setEdges] = useState<CorrEdge[]>([]);
  const [replay, setReplay] = useState<CorrReplay | null>(null);
  const [replaying, setReplaying] = useState(false);
  const [err, setErr] = useState("");

  useEffect(() => {
    let alive = true;
    setObj(null); setEdges([]); setReplay(null); setErr("");
    api.correlationDetail(id)
      .then((r) => { if (alive) { setObj(r.object); setEdges(r.edges ?? []); } })
      .catch((e) => { if (alive) setErr(String(e?.message ?? e)); });
    return () => { alive = false; };
  }, [id]);

  const runReplay = async () => {
    setReplaying(true); setReplay(null);
    try {
      setReplay(await api.correlationReplay(id));
    } catch (e: any) {
      setErr(String(e?.message ?? e));
    } finally {
      setReplaying(false);
    }
  };

  if (err) return <div className="empty">{err}</div>;
  if (!obj) return <div className="empty">Loading…</div>;

  const missing = parseJSON<string[]>(obj.evidence_missing, []);
  const hyp = parseJSON<any>(obj.hypotheses, {});
  const ranking = hyp?.ranking ?? {};
  const ctx = hyp?.grounding_context ?? {};
  const row = (k: string, v: React.ReactNode) => (
    <div style={{ display: "flex", gap: 8, fontSize: 12, padding: "2px 0" }}>
      <span style={{ color: "var(--muted)", minWidth: 110 }}>{k}</span>
      <span style={{ wordBreak: "break-all" }}>{v}</span>
    </div>
  );

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 10, fontSize: 13 }}>
      <div style={{ display: "flex", gap: 6, alignItems: "center", flexWrap: "wrap" }}>
        <span className={`badge ${TIER_CLASS[obj.verdict_tier] ?? ""}`}>{obj.verdict_tier}</span>
        <span className="badge">{obj.state}</span>
        <span className="badge">v{obj.version}</span>
        <span style={mono}>{obj.top_hypothesis}</span>
        {obj.top_hypothesis !== "undetermined" && (
          <span style={{ color: "var(--muted)", fontSize: 12 }}>rank {obj.top_confidence.toFixed(2)}</span>
        )}
      </div>

      <div>
        {row("Object", <span style={mono}>{obj.correlation_id}</span>)}
        {row("Window", <span style={mono}>{obj.window_start} → {obj.window_end} UTC</span>)}
        {row("Evidence", `${obj.signal_count} signals across ${obj.node_count} nodes`)}
        {row("Pins", <span style={mono}>{obj.engine_version} · {obj.catalog_version} · {obj.topology_version}</span>)}
        {row("Seams in context", String((ctx.seams ?? []).length))}
        {ctx.topology_gap_hints > 0 &&
          row("Gap hints", `${ctx.topology_gap_hints} ungrounded co-occurrences (excluded, queued for seam review)`)}
      </div>

      {missing.length > 0 && (
        <div>
          <div style={{ fontWeight: 600, fontSize: 12, marginBottom: 4 }}>What would change the verdict</div>
          {missing.map((m) => (
            <div key={m} style={{ ...mono, color: "var(--muted)", padding: "1px 0" }}>· {m}</div>
          ))}
        </div>
      )}

      {(ranking.hypotheses ?? []).length > 0 && (
        <div>
          <div style={{ fontWeight: 600, fontSize: 12, marginBottom: 4 }}>Competing hypotheses</div>
          {(ranking.hypotheses as any[]).map((h) => (
            <div key={h.template_id} style={{ ...mono, padding: "1px 0" }}>
              {h.template_id} — rank {Number(h.confidence_rank ?? 0).toFixed(2)}, coverage {Number(h.coverage ?? 0).toFixed(2)}
            </div>
          ))}
        </div>
      )}

      <div>
        <div style={{ fontWeight: 600, fontSize: 12, marginBottom: 4 }}>Grounded edges ({edges.length})</div>
        {edges.length === 0 && <div className="empty">Singleton — opened on episode severity alone.</div>}
        {edges.map((e, i) => (
          <div key={i} style={{ ...mono, padding: "2px 0" }}>
            {e.from_node} → {e.to_node}
            <span style={{ color: "var(--muted)" }}>
              {"  "}[{e.grounding_kind}:{e.grounding_ref}] w={Number(e.weight).toFixed(2)}
              {Number(e.w_reinforce) > 1 ? " ×modality" : ""}
              {e.direction_basis !== "none" ? ` dir:${e.direction_basis}` : " (direction unclaimed)"}
            </span>
          </div>
        ))}
      </div>

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
            <div key={d} style={{ ...mono, color: "var(--muted)" }}>· {d}</div>
          ))}
          {!replay.engine_pin_match && (
            <div style={{ fontSize: 12, color: "var(--muted)" }}>
              Engine pin mismatch: the object was built by an older engine — expected evolution, not corruption.
            </div>
          )}
        </div>
      )}
    </div>
  );
}

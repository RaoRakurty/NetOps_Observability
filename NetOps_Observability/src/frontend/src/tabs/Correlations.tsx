import { useEffect, useMemo, useRef, useState } from "react";
import { api, CorrObject, CorrReplay, CorrTimeline, Seam, TicketLinkRow, UndeterminedCluster } from "../services/api";
import DataTable, { Column } from "../components/DataTable";
import { useWorkspace } from "../context/workspace";
import RcaWorkspace from "../components/rca/RcaWorkspace";
import RcaTopology from "../components/rca/RcaTopology";
import RcaTimeImpact from "../components/rca/RcaTimeImpact";
import RcaAskAi from "../components/rca/RcaAskAi";
import RcaTicketCard from "../components/rca/RcaTicketCard";
import { buildRcaCase } from "../components/rca/rcaCase";
import { buildTopoGraph } from "../components/rca/topoGraph";
import { exportRcaPdf } from "../components/rca/rcaExport";
import { signatureName, ownerLabel, isInternalStackAffected, friendlyProblemId, ticketStateLabel } from "../components/rca/labels";
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

// "Notified via" chips (#103 UX-1) — compact per-destination badges. Short,
// NOC-recognized handles in the cell (full product name + ticket + state on the
// tooltip). Tone follows the ticket lifecycle: live = filled blue, resolved =
// green, failed = red, queued = amber.
const NOTIFY_SHORT: Record<string, string> = { servicenow: "SN", pagerduty: "PD", slack: "Slack", jira: "Jira" };
const NOTIFY_FULL: Record<string, string> = { servicenow: "ServiceNow", pagerduty: "PagerDuty", slack: "Slack", jira: "Jira" };
function notifyTone(state?: string): { tone: string; filled: boolean } {
  switch (state) {
    case "open": case "updated": return { tone: "#2563EB", filled: true };
    case "resolved": return { tone: "#16A34A", filled: false };
    case "failed": return { tone: "#DC2626", filled: true };
    default: return { tone: "#D97706", filled: false }; // pending / queued
  }
}
// live links sort above resolved above failed/pending; more destinations first
const NOTIFY_RANK: Record<string, number> = { open: 3, updated: 3, resolved: 2, failed: 1 };

// initial verdict-tier filter from a deep link (#/monitoring/correlations?tier=suspected)
// — the Front Page KPI strip drills through with this so "Suspected RCA" lands
// pre-filtered to suspected, not the full list.
function tierFromHash(): string {
  const q = (typeof location !== "undefined" ? location.hash : "").split("?")[1] || "";
  const t = new URLSearchParams(q).get("tier") || "";
  return ["confirmed", "suspected", "undetermined"].includes(t) ? t : "";
}

// Deep-link target id (#/monitoring/correlations?id=<correlation_id>). Command
// Center / other surfaces link here to open ONE specific RCA.
function idFromHash(): string {
  const q = (typeof location !== "undefined" ? location.hash : "").split("?")[1] || "";
  return new URLSearchParams(q).get("id") || "";
}

export default function Correlations() {
  const [items, setItems] = useState<CorrObject[]>([]);
  const [state, setState] = useState("");
  const [tier, setTier] = useState(tierFromHash);
  // When arriving via a deep link (?id=…), the target RCA can be older than the
  // default 24h list window (Command Center spans 30 days). Widen the fetch so
  // the target is always present and the auto-select below can find it.
  const deepId = useMemo(idFromHash, []);
  const [showInternal, setShowInternal] = useState(false);
  const [sel, setSel] = useState<string | null>(null);
  // corr id → external destinations it was filed to (#103 UX-1 "Notified via").
  const [notified, setNotified] = useState<Record<string, TicketLinkRow[]>>({});
  const ws = useWorkspace();

  // Hide internal-stack/self-monitoring objects by default — RCA is for customer
  // networks (decision #76). The toggle reveals them for platform debugging.
  const visible = useMemo(
    () => (showInternal ? items : items.filter((o) => !isInternalStackObject(o))),
    [items, showInternal],
  );
  const hiddenInternal = items.length - visible.length;

  const columns = useMemo<Column<CorrObject>[]>(() => [
    // UX-2: the human incident handle (same P-XXXXXX id the Inspector, Iris AI
    // and filed tickets use) — operators reference this, never the raw UUID.
    { key: "display_id", header: "ID", width: 84, sortable: true,
      text: (o) => friendlyProblemId(o.correlation_id),
      render: (o) => <span style={mono} title={o.correlation_id}>{friendlyProblemId(o.correlation_id)}</span> },
    { key: "created_at", header: "Updated", width: 160, sortable: true,
      sortValue: (o) => new Date(o.created_at + "Z").getTime() || 0,
      render: (o) => <span style={mono}>{new Date(o.created_at + "Z").toLocaleString()}</span> },
    { key: "verdict_tier", header: "Status", width: 116, sortable: true, text: (o) => o.verdict_tier,
      render: (o) => <span className={`badge ${TIER_CLASS[o.verdict_tier] ?? ""}`}>{VERDICT_NOC[o.verdict_tier] ?? o.verdict_tier}</span> },
    { key: "quality", header: "Quality", width: 90, sortable: true,
      sortValue: (o) => (o.chaos_fixture ? -1 : QUAL_RANK[qualityOf(o)]),
      // A named chaos fixture is an INTENTIONAL storm source (planned platform
      // drill, e.g. a lab target kept unreachable on purpose): badge it so the
      // NOC never triages it as a customer incident. Auto-ticketing already
      // skips it server-side.
      render: (o) => o.chaos_fixture
        ? <span title={`Planned resilience drill (${o.chaos_fixture}) — not a customer incident`}>
            {pill("planned drill", "#7C3AED")}
          </span>
        : (() => { const q = qualityOf(o); return pill(q, QUAL_TONE[q], q !== "weak"); })() },
    { key: "top_hypothesis", header: "Likely cause", width: 200, sortable: true,
      text: (o) => (o.top_hypothesis === "undetermined" ? "" : signatureName(o.top_hypothesis)),
      render: (o) => o.top_hypothesis === "undetermined"
        ? <span style={{ color: "var(--muted)" }}>Not yet determined</span>
        : <span>{signatureName(o.top_hypothesis)}</span> },
    { key: "owner", header: "Owner", width: 96, sortable: true, text: (o) => o.owner ?? "",
      render: (o) => o.owner ? <span style={{ fontSize: 12 }}>{ownerLabel(o.owner)}</span> : "—" },
    // UX-1: which external destinations this incident was filed/paged to.
    { key: "notified", header: "Notified via", width: 118, sortable: true,
      sortValue: (o) => (notified[o.correlation_id] ?? [])
        .reduce((acc, l) => acc + (NOTIFY_RANK[l.state] ?? 0), 0),
      text: (o) => (notified[o.correlation_id] ?? []).map((l) => NOTIFY_FULL[l.system ?? ""] ?? l.system ?? "").join(" "),
      render: (o) => {
        const dests = notified[o.correlation_id] ?? [];
        if (dests.length === 0) return <span style={{ color: "var(--muted)" }}>—</span>;
        return (
          <span style={{ display: "inline-flex", gap: 4, flexWrap: "wrap" }}>
            {dests.map((l) => {
              const { tone, filled } = notifyTone(l.state);
              const full = NOTIFY_FULL[l.system ?? ""] ?? l.system ?? "?";
              const tip = `${full}${l.ticket_number ? ` ${l.ticket_number}` : ""} — ${ticketStateLabel(l.state)}`;
              return <span key={l.system} title={tip}>{pill(NOTIFY_SHORT[l.system ?? ""] ?? full, tone, filled)}</span>;
            })}
          </span>
        );
      } },
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
  ], [notified]);

  useEffect(() => {
    let alive = true;
    const tick = async () => {
      try {
        const r = await api.correlations(200, 86400, state || undefined, tier || undefined);
        if (alive) setItems(r?.data ?? []);
      } catch {
        if (alive) setItems([]);
      }
      // Ticket links are a best-effort enrichment — the list renders without them.
      try {
        const l = await api.ticketLinks();
        if (alive) {
          const m: Record<string, TicketLinkRow[]> = {};
          (l?.links ?? []).forEach((row) => { (m[row.corr_object_id] ??= []).push(row); });
          setNotified(m);
        }
      } catch { /* column shows "—" */ }
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
        // UX-2: carry the human incident handle in the chrome — the precise NOC
        // cause title still lives once, in the card below.
        title: `Root cause analysis · ${friendlyProblemId(o.correlation_id)}`,
        subtitle: o.verdict_tier === "confirmed" ? "Confirmed" : "Not confirmed",
      });
    }
  };

  // Deep link by id (#81 P3G + UI-1): App Observability / Command Center link
  // here as #/monitoring/correlations?id=<correlation_id> to open ONE RCA.
  //
  // Connect DIRECTLY via the unique id — fire once on mount, independent of the
  // candidate list, its 24h window, its 200-row cap, or its load timing. The
  // previous version gated on the list CONTAINING the target, so any item the
  // windowed/capped list didn't include (e.g. an 11-day-old correlation, or a
  // slow/empty list) silently failed and dumped the user on the full candidate
  // list. Fetching the object by its id can't miss; we keep it in its own state
  // (not the polled list) so the 15s refresh can't drop it and the list's own
  // state/status filters keep working normally.
  const deepLinked = useRef(false);
  const [deepObj, setDeepObj] = useState<CorrObject | null>(null);
  const [deepErr, setDeepErr] = useState<string | null>(null);
  useEffect(() => {
    if (deepLinked.current || !deepId) return;
    deepLinked.current = true;
    let alive = true;
    api.correlationDetail(deepId)
      .then((r) => {
        const obj = r?.object;
        if (!alive) return;
        if (!obj) { setDeepErr(deepId); return; }
        setDeepObj(obj);
        select(obj);
      })
      .catch(() => { if (alive) setDeepErr(deepId); });
    return () => { alive = false; };
  }, [deepId]); // eslint-disable-line react-hooks/exhaustive-deps

  // v1 inline detail: prefer the row from the list, but fall back to the
  // directly-fetched deep-link object so a linked RCA outside the list still renders.
  const selected = !ws.enabled && sel
    ? (items.find((o) => o.correlation_id === sel) ?? (deepObj?.correlation_id === sel ? deepObj : undefined))
    : undefined;

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
      {deepErr && (
        <div className="cc-panel" style={{ borderColor: "var(--warn)", padding: "10px 13px", marginBottom: 10 }}>
          <span style={{ color: "var(--warn)", fontWeight: 600 }}>RCA not found.</span>{" "}
          <span style={{ color: "var(--muted)", fontSize: 13 }}>
            The linked correlation (<code style={mono}>{deepErr}</code>) is no longer available — it may have been
            resolved and aged out, or you don't have access to it. Showing all current candidates below.
          </span>
        </div>
      )}
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
      <SignatureGaps />
    </div>
  );
}

// SignatureGaps — the #80 undetermined-frequency feed: which recurring evidence
// gap is keeping the engine from a verdict, ranked by how often it happens. Turns
// "we couldn't tell" into a prioritized signature-coverage backlog. Read-only;
// honest empty state when there's nothing undetermined.
function SignatureGaps() {
  const [clusters, setClusters] = useState<UndeterminedCluster[]>([]);
  const [total, setTotal] = useState(0);
  const [loaded, setLoaded] = useState(false);

  useEffect(() => {
    let alive = true;
    const tick = async () => {
      try {
        const r = await api.undeterminedFrequency(604800, 12);
        if (!alive) return;
        setClusters(r?.clusters ?? []);
        setTotal(r?.total_undetermined ?? 0);
      } catch {
        if (alive) { setClusters([]); setTotal(0); }
      } finally {
        if (alive) setLoaded(true);
      }
    };
    tick();
    const id = setInterval(tick, 30_000);
    return () => { alive = false; clearInterval(id); };
  }, []);

  return (
    <div className="cc-panel" style={{ marginTop: 12 }}>
      <div className="cc-panel-h">
        <h3 className="cc-panel-t">Signature coverage gaps</h3>
        <span className="cc-panel-meta">
          {total > 0 ? `${total} not-confirmed in 7d · ranked by recurrence` : "last 7 days"}
        </span>
      </div>
      <div style={{ padding: "11px 13px" }}>
        {!loaded ? (
          <div className="empty">Loading…</div>
        ) : clusters.length === 0 ? (
          <div className="empty">
            No recurring not-confirmed patterns — the engine is reaching a verdict on what it sees.
            Clusters appear here when incidents repeatedly fall short of a confirmable signature.
          </div>
        ) : (
          <>
            <p style={{ margin: "0 0 10px", fontSize: 12.5, color: "var(--muted)" }}>
              Each row is a recurring shape the engine <em>almost</em> matched but couldn't confirm — the
              nearest signature and what it lacked. Highest-recurrence first: the best candidates to write
              or strengthen next.
            </p>
            <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
              {clusters.map((c) => (
                <div key={c.fingerprint} style={{
                  display: "grid", gridTemplateColumns: "auto 1fr auto", gap: 12, alignItems: "center",
                  padding: "9px 12px", border: "1px solid var(--border)", borderRadius: 8,
                  background: "var(--surface-2, var(--hover))",
                }}>
                  <span title="times this gap-shape recurred" style={{
                    fontVariantNumeric: "tabular-nums", fontWeight: 700, fontSize: 18,
                    minWidth: 34, textAlign: "right", color: "var(--accent)",
                  }}>{c.count}</span>
                  <div style={{ minWidth: 0 }}>
                    <div style={{ fontWeight: 600, fontSize: 13, marginBottom: 2 }}>{c.label}</div>
                    <div style={{ fontSize: 12, color: "var(--muted)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                      {c.top_gaps.length > 0
                        ? <>Missing: {c.top_gaps.map((g) => g.clause).join(" · ")}</>
                        : "no evidence-gap detail recorded"}
                    </div>
                  </div>
                  <span style={{ fontSize: 11, color: "var(--fg-subtle, var(--muted))", fontVariantNumeric: "tabular-nums", whiteSpace: "nowrap" }}
                    title={c.last_seen ? new Date(c.last_seen).toLocaleString() : ""}>
                    {Number.isFinite(c.avg_signals) ? `${c.avg_signals.toFixed(1)} sig/incident` : ""}
                  </span>
                </div>
              ))}
            </div>
          </>
        )}
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
    // NOTE: hop order comes from the BACKEND's service-path spine (contract §7).
    // The UI no longer joins traceroutes or device inventory client-side to guess
    // a path — that inference now lives server-side, with evidence per hop.
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
    const graph = buildTopoGraph(timeline, seams, view, false);
    if (!graph.internal && (graph.nodes.length > 0 || graph.edges.length > 0)) c.topoGraph = graph;
    return c;
  }, [timeline, obj, seams, recommendedOwner, recommendedSteps, view]);

  if (err) return <div className="empty">{err}</div>;
  if (!obj || !timeline || !rcaCase) return <div className="empty">Loading…</div>;

  const exportPdf = () => {
    if (!rcaCase) return;
    // Canonical server-side report first (typed states, controlled PDF headers,
    // no browser print chrome). The legacy client-side print doc remains only
    // as the last-resort fallback when the backend render fails entirely.
    api.downloadRcaReport(obj.correlation_id || "", friendlyProblemId(obj.correlation_id || ""))
      .catch(() => {
        const ok = exportRcaPdf(rcaCase, obj.correlation_id || "");
        if (!ok) alert("Could not generate the incident report.");
      });
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
        <RcaTopology timeline={timeline} seams={seams} view={view} height={300} />
      }
      aiSlot={obj.correlation_id ? <RcaAskAi correlationId={obj.correlation_id} /> : null}
      timeImpactSlot={obj.correlation_id ? <RcaTimeImpact correlationId={obj.correlation_id} /> : null}
      ticketSlot={obj.correlation_id ? <RcaTicketCard correlationId={obj.correlation_id} /> : null}
    />
  );
}

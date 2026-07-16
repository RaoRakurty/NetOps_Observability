import { useCallback, useEffect, useMemo, useState, type MouseEvent } from "react";
import { api, Incident, CorrObject } from "../services/api";
import { signatureNocTitle, entityLabel, friendlyProblemId } from "../components/rca/labels";
import DataTable, { type Column } from "../components/DataTable";
import { LogTime } from "../lib/logfmt";
import { timeRank } from "./appobs/sortRanks";
import {
  type ActionItem, type RcaState, type OwnerState, type TicketState, type Sev,
  type FaultDomain, type EvidenceState, type CcFilters,
  fmtAge, buildItem, isActionableCorr, bySeverityThenAge, filterItems, activeFilterCount,
  startedAt, sevRank, rcaRank, evidenceRank, ownerRank, ticketRank,
} from "./commandCenter.model";

// Action Queue filter bar — narrows the queue over data already in memory (no
// refetch). Facets map 1:1 to the columns an operator triages by.
const RCA_FILTERS: RcaState[] = ["Confirmed", "Suspected", "Blocked", "Correlated", "RCA running", "Resolved"];
const SEV_FILTERS: Sev[] = ["crit", "major", "warn", "ok"];
const FAULT_FILTERS: FaultDomain[] = ["LAN", "SD-WAN", "Data Center", "ISP / Carrier", "Cloud Provider", "Application", "Security", "Unknown"];
const EVID_FILTERS: EvidenceState[] = ["Complete", "Partial", "Single-stream"];
const OWNER_FILTERS: OwnerState[] = ["Missing", "Recommended", "Assigned", "Escalated"];

function FilterBar({ filters, setFilters, total, shown }: {
  filters: CcFilters; setFilters: (f: CcFilters) => void; total: number; shown: number;
}) {
  const n = activeFilterCount(filters);
  const sel = (key: keyof CcFilters, label: string, opts: string[]) => (
    <label className="cc-filter">
      <span>{label}</span>
      <select value={(filters[key] as string) ?? "all"} onChange={(e) => setFilters({ ...filters, [key]: e.target.value })}>
        <option value="all">All</option>
        {opts.map((o) => <option key={o} value={o}>{o}</option>)}
      </select>
    </label>
  );
  return (
    <div className="cc-filterbar">
      {sel("rca", "RCA", RCA_FILTERS)}
      {sel("sev", "Severity", SEV_FILTERS)}
      {sel("fault", "Fault domain", FAULT_FILTERS)}
      {sel("evidence", "Evidence", EVID_FILTERS)}
      {sel("owner", "Owner", OWNER_FILTERS)}
      <button type="button" className={`cc-filter-chip${filters.needsAction ? " on" : ""}`}
        aria-pressed={!!filters.needsAction}
        onClick={() => setFilters({ ...filters, needsAction: !filters.needsAction })}
        title="Missing owner, unticketed confirmed incident, or RCA blocked on evidence">
        Needs action
      </button>
      <span className="cc-filter-count">{n > 0 ? `${shown} of ${total}` : `${total}`}</span>
      {n > 0 && <button type="button" className="cc-filter-clear" onClick={() => setFilters({})}>Clear ({n})</button>}
    </div>
  );
}

// Command Center — the NOC operational control plane (build-order #18). NOT a raw
// alert table: the primary rows are CORRELATION GROUPS (CorrObjects), each already
// carrying an RCA verdict, owner, blast radius and evidence shortfalls. It answers
// "what's burning, who owns it, what's correlated, what's ticketed, what's blocked,
// what needs human action" — and what to do next. Incidents/ITSM fold in for the
// ticketing-gap view. Premium dark/glass via the app-wide theme tokens (frontpage
// brand consistency) — never a hardcoded palette.
//
// The triage decision logic (RCA-state/owner/ticket derivation, the single-stream
// confirm guard, internal-stack exclusion, the severity sort) lives in the pure,
// unit-tested ./commandCenter.model — this file is the view only.

// ── Badges (token-styled; small uppercase NOC chips) ────────────────────────────
const SEV_TONE: Record<Sev, string> = { crit: "var(--crit)", major: "var(--warn)", warn: "var(--warn)", ok: "var(--fg-subtle)" };
const RCA_TONE: Record<RcaState, string> = {
  Confirmed: "var(--crit)", Suspected: "var(--warn)", Blocked: "var(--warn)",
  Correlated: "var(--accent)", "RCA running": "var(--accent)", New: "var(--fg-subtle)", Resolved: "var(--ok)",
};
const ccChip = (text: string, tone: string, title?: string) => (
  <span className="cc-badge" style={{ color: tone, borderColor: tone }} title={title}>{text}</span>
);
const OWNER_TONE: Record<OwnerState, string> = { Assigned: "var(--ok)", Recommended: "var(--accent)", Missing: "var(--crit)", Escalated: "var(--warn)" };
const TICKET_TONE: Record<TicketState, string> = { Ticketed: "var(--ok)", "Ticket needed": "var(--warn)", Eligible: "var(--accent)", "Sync failed": "var(--crit)", "Not eligible": "var(--fg-subtle)" };

const impactLabel = (a: ActionItem["affected"]): string => {
  const devs = new Set([...a.devices, ...a.paths.flatMap((p) => p.split(/->|→/).map((x) => x.trim()))].filter(Boolean));
  const parts: string[] = [];
  if (devs.size) parts.push(`${devs.size} device${devs.size > 1 ? "s" : ""}`);
  parts.push(a.sites.length ? `${a.sites.length} site${a.sites.length > 1 ? "s" : ""}` : "site unknown");
  return parts.join(" · ");
};

// ── Action Queue columns (shared DataTable primitive) ───────────────────────────
// The queue renders through components/DataTable — the SAME primitive as every
// other telemetry table — so it inherits the visible column-resize grip (drag or
// ←/→), click-to-sort headers with aria-sort, and the keyboard grid model for
// free, instead of re-hand-rolling them here. The expandable detail row survives
// via DataTable's opt-in expandedKey/renderExpanded master-detail support.
//
// EVERY column sorts SEMANTICALLY, never lexically: the state ladders come from
// the model's exported ranks (sevRank/rcaRank/evidenceRank/ownerRank/ticketRank
// — ascending = work-this-first), time from timeRank (epoch), impact/occurrence
// from real counts, and free text A–Z.
const blastRadius = (a: ActionItem["affected"]): number =>
  new Set([...a.devices, ...a.paths.flatMap((p) => p.split(/->|→/).map((x) => x.trim()))].filter(Boolean)).size;

function queueColumns(openKey: string | null): Column<ActionItem>[] {
  return [
    {
      key: "sev", header: "Sev", width: 62,
      sortValue: (it) => sevRank(it.sev), text: (it) => it.sev,
      render: (it) => <span className="cc-sevdot" style={{ background: SEV_TONE[it.sev] }} title={it.sev} />,
    },
    {
      key: "pid", header: "Problem ID", width: 104,
      sortValue: (it) => shortProblemId(it.corr.correlation_id), text: (it) => it.corr.correlation_id,
      render: (it) => (
        <a className="cc-pid-link" href={rcaHref(it.corr.correlation_id)}
          title={`Problem ${it.corr.correlation_id} — open RCA`}
          onClick={(e) => e.stopPropagation()}>{shortProblemId(it.corr.correlation_id)}</a>
      ),
    },
    {
      key: "title", header: "Incident / correlation group", width: "minmax(220px,1.6fr)",
      sortValue: (it) => signatureNocTitle(it.corr.top_hypothesis),
      text: (it) => signatureNocTitle(it.corr.top_hypothesis),
      render: (it) => (
        <span className="cc-title">
          <span className="cc-caret">{openKey === it.corr.correlation_id ? "▾" : "▸"}</span>
          {signatureNocTitle(it.corr.top_hypothesis)}
          <span className="cc-occ-inline">×{it.corr.signal_count}</span>
        </span>
      ),
    },
    {
      key: "rca", header: "RCA state", width: 124,
      sortValue: (it) => rcaRank(it.rca), text: (it) => it.rca,
      render: (it) => ccChip(it.rca, RCA_TONE[it.rca], `confidence ${(it.corr.top_confidence * 100).toFixed(0)}%`),
    },
    {
      key: "impact", header: "Impact", width: 150,
      // Widest blast radius first — the operator's real ordering, not the label's spelling.
      sortValue: (it) => -blastRadius(it.affected), text: (it) => impactLabel(it.affected),
      render: (it) => <span className="cc-mono cc-dim">{impactLabel(it.affected)}</span>,
    },
    {
      key: "fault", header: "Fault domain", width: 132,
      sortValue: (it) => it.fault, text: (it) => it.fault,
      render: (it) => ccChip(it.fault, it.fault === "Unknown" ? "var(--fg-subtle)" : "var(--fg-muted)"),
    },
    {
      key: "evidence", header: "Evidence", width: 120,
      sortValue: (it) => evidenceRank(it.evidence), text: (it) => it.evidence,
      render: (it) => ccChip(it.evidence, it.evidence === "Complete" ? "var(--ok)" : "var(--warn)", it.missing.join(", ")),
    },
    {
      key: "owner", header: "Owner", width: 124,
      sortValue: (it) => ownerRank(it.owner), text: (it) => it.ownerName,
      render: (it) => ccChip(it.ownerName, OWNER_TONE[it.owner]),
    },
    {
      // Absolute start time (owner ask #3). Same instant ageMs is derived from
      // (startedAt = window_start || created_at) — never a second, invented date.
      // Rendered with the shared LogTime so a timestamp reads identically here,
      // in Logs and in Events; sorts by epoch, so it's chronological not lexical.
      key: "started", header: "Started", width: 148,
      sortValue: (it) => timeRank(startedAt(it.corr)), text: (it) => startedAt(it.corr),
      render: (it) => (startedAt(it.corr)
        ? <LogTime ts={startedAt(it.corr)} />
        : <span className="cc-dim">—</span>),
    },
    {
      // Relative age stays alongside the absolute date: "how long has this been
      // burning" and "when exactly did it start" are different operator questions.
      key: "age", header: "Age", width: 66, align: "right",
      sortValue: (it) => it.ageMs, text: (it) => fmtAge(startedAt(it.corr)),
      render: (it) => <span className="cc-mono cc-dim">{fmtAge(startedAt(it.corr))}</span>,
    },
    {
      key: "ticket", header: "Ticket", width: 122,
      sortValue: (it) => ticketRank(it.ticket), text: (it) => it.ticket,
      render: (it) => ccChip(it.ticket, TICKET_TONE[it.ticket]),
    },
    {
      key: "next", header: "Next action", width: "minmax(150px,1fr)",
      sortValue: (it) => it.nextAction, text: (it) => it.nextAction,
      render: (it) => <span className="cc-next">{it.nextAction}</span>,
    },
  ];
}

// Deep-links — the Action Queue is a launch pad, so every affordance jumps to the
// exact place that resolves it (never a bare list/section).
const rcaHref = (corrId: string) => `#/monitoring/correlations?id=${encodeURIComponent(corrId)}`;
// shortProblemId renders a correlation UUID as a friendly, stable NOC handle
// (P-5564D1) — the SAME scheme the backend AI cites (problemDisplayID in Go) so
// an operator sees one consistent id across the queue, the RCA inspector and
// Iris AI. Display-only: the full UUID stays in the hover title + the RCA
// deep link, which is what the routes/API key on.
const shortProblemId = (corrId: string): string => friendlyProblemId(corrId);
// Topology Canvas leaf is infrastructure/topology-canvas; the old infrastructure/
// topology route does not exist and silently fell back to Inventory→Devices.
const topoHref = (focus?: string) =>
  `#/infrastructure/topology-canvas${focus ? `?focus=${encodeURIComponent(focus)}` : ""}`;
// Impacted entity → its OWN status (not a generic topology view). Deep-links to
// the device inventory pre-filtered to the entity, where its live health
// (up/degraded/down) shows and one click opens its full detail. End-to-end:
// the action's impacted entity wires straight to that entity's state.
const deviceStatusHref = (entity: string) =>
  `#/infrastructure/devices?q=${encodeURIComponent(entity)}`;

// CreateTicketButton enqueues a ServiceNow incident for this correlation (#78),
// permission-gated (infrastructure:write). Without write it deep-links to the RCA
// detail where the ticket card explains status. The action is enqueued, not
// synchronous — the outbox worker opens it shortly.
function CreateTicketButton({ corrId, label = "Create ticket", cls = "cc-btn cc-btn-warn" }: { corrId: string; label?: string; cls?: string }) {
  const [canWrite, setCanWrite] = useState<boolean | null>(null);
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState("");
  useEffect(() => {
    let live = true;
    api.permissions()
      .then((p) => { if (live) setCanWrite((p.permissions?.infrastructure ?? 0) >= 2); })
      .catch(() => { if (live) setCanWrite(false); });
    return () => { live = false; };
  }, []);
  const create = async (e: MouseEvent) => {
    e.stopPropagation();
    setBusy(true); setMsg("");
    try {
      await api.correlationTicketCreate(corrId);
      setMsg("Ticket creation queued ✓ — the worker will open it shortly.");
    } catch (err) {
      setMsg(`Could not queue: ${String((err as Error)?.message ?? err)}`);
    } finally { setBusy(false); }
  };
  if (canWrite === false) {
    return <a className={cls} href={rcaHref(corrId)} onClick={(e) => e.stopPropagation()}>Open ticket…</a>;
  }
  return (
    <span className="cc-ticket-cta">
      <button className={cls} type="button" disabled={busy || canWrite === null} onClick={create}>
        {busy ? "Queuing…" : label}
      </button>
      {msg && <span className="cc-ticket-msg">{msg}</span>}
    </span>
  );
}

function ExpandPanel({ it }: { it: ActionItem }) {
  const c = it.corr;
  const devs = [...new Set([...it.affected.devices, ...it.affected.paths.flatMap((p) => p.split(/->|→/).map((x) => x.trim()))])].filter(Boolean);
  // Evidence brief (UI-4): lazily pull the same RCA path view the detail renders and
  // surface WHAT correlated — the lead human reason — not just a signal count.
  const [ev, setEv] = useState<{ reason: string; domains: string[] } | null>(null);
  useEffect(() => {
    let live = true;
    api.rcaPathView(c.correlation_id)
      .then((v) => {
        if (!live) return;
        const edges = v.path?.edges ?? [];
        const reason = (v.summary && v.summary.trim()) || (v.title && v.title.trim()) || "";
        const domains = [...new Set(edges.map((e) => e.label).filter((l): l is string => !!l && !!l.trim()))].slice(0, 4);
        setEv({ reason, domains });
      })
      .catch(() => { if (live) setEv({ reason: "", domains: [] }); });
    return () => { live = false; };
  }, [c.correlation_id]);
  const ticketCTA = it.ticket === "Ticket needed" || /ticket|escalat/i.test(it.nextAction);
  return (
    <div className="cc-expand">
      <div className="cc-expand-grid">
        <div>
          <h5 className="cc-eh">Impacted entities</h5>
          {devs.length ? <div className="cc-chips">{devs.slice(0, 12).map((d) => (
            <a key={d} className="cc-pill cc-mono cc-pill-link" href={deviceStatusHref(d)}
              title={`Open ${entityLabel(d)} status`} onClick={(e) => e.stopPropagation()}>{entityLabel(d)}</a>
          ))}</div>
            : <p className="cc-dim">Blast radius pending topology mapping.</p>}
        </div>
        <div>
          <h5 className="cc-eh">Evidence</h5>
          {/* The whole evidence brief drills into the RCA Inspector's full evidence
              ledger — count, reason and each signal domain are clickable. */}
          <a className="cc-evlink" href={rcaHref(c.correlation_id)} onClick={(e) => e.stopPropagation()}
            title="Open the full evidence ledger for this correlation">
            {c.signal_count} correlated signal{c.signal_count > 1 ? "s" : ""} across {c.node_count} node{c.node_count > 1 ? "s" : ""} →
          </a>
          {ev === null
            ? <p className="cc-dim">Reading correlated evidence…</p>
            : ev.reason
              ? <p className="cc-evtext">{ev.reason}</p>
              : null}
          {ev && ev.domains.length > 0 && (
            <div className="cc-chips">{ev.domains.map((dom) => (
              <a key={dom} className="cc-pill cc-pill-link" href={rcaHref(c.correlation_id)}
                title={`See the ${dom} evidence`} onClick={(e) => e.stopPropagation()}>{dom}</a>
            ))}</div>
          )}
          {it.missing.length > 0
            ? <div className="cc-chips">{it.missing.map((m) => <span key={m} className="cc-pill cc-miss">missing: {m}</span>)}</div>
            : <p className="cc-ok">All expected evidence streams present.</p>}
        </div>
        <div>
          <h5 className="cc-eh">Recommended next action</h5>
          <div className="cc-recd">{it.nextAction}</div>
          <p className="cc-dim" style={{ marginTop: 6 }}>
            {it.rca === "Suspected" || it.rca === "Blocked"
              ? "HOLD — suspected only. Customer impact is not confirmed; independent evidence is needed before ticketing."
              : it.rca === "Confirmed"
                ? "Customer impact confirmed by correlated evidence. Eligible for ticketing and escalation."
                : "Correlated group still gathering evidence."}
          </p>
          {ticketCTA && <div style={{ marginTop: 8 }}><CreateTicketButton corrId={c.correlation_id} label="Open ticket" cls="cc-btn cc-btn-warn" /></div>}
        </div>
      </div>
      <div className="cc-actions">
        <a className="cc-btn cc-btn-primary" href={rcaHref(c.correlation_id)}>Open RCA</a>
        <a className="cc-btn" href={topoHref(devs[0])}>View topology</a>
        {it.owner === "Missing" && <a className="cc-btn" href={rcaHref(c.correlation_id)}>Assign owner</a>}
        {it.ticket === "Ticket needed" && <CreateTicketButton corrId={c.correlation_id} />}
      </div>
    </div>
  );
}

// ── KPI card ────────────────────────────────────────────────────────────────────
function CcKpi({ n, label, interp, tone, href, onClick, active }: { n: number | string; label: string; interp: string; tone?: string; href?: string; onClick?: () => void; active?: boolean }) {
  const body = (
    <>
      <div className="cc-kpi-n" style={tone ? { color: tone } : undefined}>{n}</div>
      <div className="cc-kpi-l">{label}</div>
      <div className="cc-kpi-i">{interp}</div>
    </>
  );
  // A KPI that filters the queue is a button (consistent, accessible, counts always
  // match the data it filters). Only the ITSM tile keeps an external href.
  if (onClick) return <button type="button" className={`cc-kpi cc-kpi-btn${active ? " on" : ""}`} aria-pressed={!!active} onClick={onClick}>{body}</button>;
  return href ? <a className="cc-kpi" href={href}>{body}</a> : <div className="cc-kpi">{body}</div>;
}

// ── Main ─────────────────────────────────────────────────────────────────────────
export default function CommandCenter() {
  const [corr, setCorr] = useState<CorrObject[]>([]);
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [err, setErr] = useState<string | null>(null);
  const [open, setOpen] = useState<string | null>(null);
  const [loaded, setLoaded] = useState(false);
  const [filters, setFilters] = useState<CcFilters>({});

  const load = useCallback(async () => {
    try {
      const [cs, inc] = await Promise.all([
        api.correlations(200, 2592000, "open"),
        api.listIncidents({ limit: 500 }).catch(() => [] as Incident[]),
      ]);
      setCorr((cs?.data ?? []).filter(isActionableCorr));
      setIncidents(inc ?? []);
      setErr(null);
    } catch (e) { setErr((e as Error).message); }
    finally { setLoaded(true); }
  }, []);
  useEffect(() => { load(); const id = setInterval(load, 30_000); return () => clearInterval(id); }, [load]);

  const items = useMemo(() => corr.map((c) => buildItem(c)).sort(bySeverityThenAge), [corr]);
  // KPIs/pressure reflect the WHOLE queue; the filter bar narrows only the table.
  const visible = useMemo(() => filterItems(items, filters), [items, filters]);
  // A KPI sets its filter on the queue (and toggles off if already active), so its
  // count and the rows shown always come from the SAME data — they can't disagree.
  // Columns depend on `open` only for the row's expand caret.
  const columns = useMemo(() => queueColumns(open), [open]);
  // Size the queue viewport to its rows (capped) so a short queue has no dead
  // space and a long one windows; expanding a row makes room for its detail.
  const queueHeight = useMemo(
    () => Math.min(640, visible.length * 34 + 40 + (open ? 300 : 0)),
    [visible.length, open],
  );
  const kpiActive = (f: CcFilters) => JSON.stringify(filters) === JSON.stringify(f);
  const applyKpi = (f: CcFilters) => setFilters((cur) => JSON.stringify(cur) === JSON.stringify(f) ? {} : f);

  const critical = items.filter((i) => i.sev === "crit").length;
  const untriaged = items.filter((i) => i.rca === "Correlated" || i.rca === "RCA running" || i.rca === "New").length;
  const suspected = items.filter((i) => i.rca === "Suspected").length;
  const confirmed = items.filter((i) => i.rca === "Confirmed").length;
  const blocked = items.filter((i) => i.rca === "Blocked").length;
  const ownerMissing = items.filter((i) => i.owner === "Missing").length;
  const ticketNeeded = items.filter((i) => i.ticket === "Ticket needed").length;
  const ticketed = incidents.filter((i) => i.sync_status === "synced").length;

  const pressure = critical >= 3 ? "Severe" : critical >= 1 ? "Elevated" : suspected > 0 ? "Watch" : "Nominal";
  const pressureTone = pressure === "Severe" ? "var(--crit)" : pressure === "Elevated" ? "var(--warn)" : pressure === "Watch" ? "var(--accent)" : "var(--ok)";

  const decision = items.length === 0
    ? "No correlated incidents require action. Raw signals (if any) have not formed a correlated group."
    : `${items.length} correlated incident${items.length > 1 ? "s" : ""} in queue · ${critical} critical · ${confirmed} with confirmed RCA · ${ownerMissing} missing owner · ${ticketNeeded} awaiting a ticket. ` +
      (confirmed > 0 ? "Work confirmed-RCA criticals with missing owners first." : suspected > 0 ? "Confirm impact on suspected incidents before any ticketing." : "Triage correlated groups by blast radius.");

  return (
    <div className="dm-board cc-board">
      <div className="cc-hero">
        <div className="cc-hero-head">
          <div>
            <h1 className="cc-h1">Command Center</h1>
            <p className="cc-sub">What's burning, who owns it, and what still needs human action.</p>
          </div>
          <div className="cc-chips-row">
            {ccChip(`NOC pressure: ${pressure}`, pressureTone)}
            {ccChip(`${critical} critical`, critical ? "var(--crit)" : "var(--fg-subtle)")}
            {ccChip(`${ownerMissing} owner gap`, ownerMissing ? "var(--crit)" : "var(--ok)")}
            {ccChip(`${ticketNeeded} ticket gap`, ticketNeeded ? "var(--warn)" : "var(--ok)")}
            {ccChip(`${blocked} RCA blocked`, blocked ? "var(--warn)" : "var(--ok)")}
            <span className="cc-live"><span className="cc-live-dot" /> Live · 30s</span>
          </div>
        </div>
        <div className="cc-kpis">
          {/* KPIs filter the queue below (same data → counts always match) and toggle. */}
          <CcKpi n={items.length} label="Correlated incidents" interp="grouped, not raw alerts" onClick={() => setFilters({})} active={activeFilterCount(filters) === 0} />
          <CcKpi n={critical} label="Critical" interp="confirmed impact or high blast radius" tone={critical ? "var(--crit)" : undefined} onClick={() => applyKpi({ sev: "crit" })} active={kpiActive({ sev: "crit" })} />
          <CcKpi n={untriaged} label="Untriaged" interp="correlated, RCA not yet run" tone={untriaged ? "var(--warn)" : undefined} onClick={() => applyKpi({ untriaged: true })} active={kpiActive({ untriaged: true })} />
          <CcKpi n={suspected} label="Suspected RCA" interp="impact not confirmed" tone={suspected ? "var(--warn)" : undefined} onClick={() => applyKpi({ rca: "Suspected" })} active={kpiActive({ rca: "Suspected" })} />
          <CcKpi n={confirmed} label="Confirmed RCA" interp="≥2 evidence streams align" tone={confirmed ? "var(--crit)" : undefined} onClick={() => applyKpi({ rca: "Confirmed" })} active={kpiActive({ rca: "Confirmed" })} />
          <CcKpi n={ownerMissing} label="Owner missing" interp="needs assignment" tone={ownerMissing ? "var(--crit)" : "var(--ok)"} onClick={() => applyKpi({ owner: "Missing" })} active={kpiActive({ owner: "Missing" })} />
          <CcKpi n={blocked} label="RCA blocked" interp="missing evidence streams" tone={blocked ? "var(--warn)" : "var(--ok)"} onClick={() => applyKpi({ rca: "Blocked" })} active={kpiActive({ rca: "Blocked" })} />
          <CcKpi n={`${ticketed}/${ticketNeeded || 0}`} label="Ticketed" interp="confirmed → ITSM" href="#/incident/integrations" />
        </div>
        <div className="cc-decision">{decision}</div>
        {err && <p className="cc-err">{err}</p>}
      </div>

      <div className="cc-panel">
        <div className="cc-panel-h">
          <h3 className="cc-panel-t">Action Queue</h3>
          <span className="cc-panel-meta">correlated incidents — what to work next</span>
        </div>
        {loaded && items.length > 0 && (
          <FilterBar filters={filters} setFilters={setFilters} total={items.length} shown={visible.length} />
        )}
        {!loaded ? (
          <div className="cc-empty">Loading correlated incidents…</div>
        ) : items.length === 0 ? (
          <div className="cc-empty">No correlated incidents require action. The queue groups raw alerts into incidents — none have correlated.</div>
        ) : visible.length === 0 ? (
          <div className="cc-empty">No incidents match the current filters. <button type="button" className="cc-filter-clear" onClick={() => setFilters({})}>Clear filters</button></div>
        ) : (
          <div className="cc-table-wrap">
            <DataTable<ActionItem>
              rows={visible}
              columns={columns}
              rowKey={(it) => it.corr.correlation_id}
              rowHeight={34}
              height={queueHeight}
              ariaLabel="Action Queue — correlated incidents"
              rowAccent={(it) => (it.sev === "crit" ? "var(--crit)" : it.sev === "major" ? "var(--warn)" : undefined)}
              onRowClick={(it) => setOpen((cur) => (cur === it.corr.correlation_id ? null : it.corr.correlation_id))}
              expandedKey={open}
              renderExpanded={(it) => <ExpandPanel it={it} />}
            />
          </div>
        )}
      </div>

      <div className="cc-panel cc-ticketgap">
        <div className="cc-panel-h"><h3 className="cc-panel-t">Ticketing gap</h3>
          <span className="cc-panel-meta">tickets open at the correlated-incident level, not per raw alert</span></div>
        <div className="cc-kpis cc-kpis-4">
          <CcKpi n={ticketed} label="Ticketed" interp="synced to ITSM" tone={ticketed ? "var(--ok)" : undefined} />
          <CcKpi n={ticketNeeded} label="Ticket needed" interp="confirmed RCA, not yet opened" tone={ticketNeeded ? "var(--warn)" : undefined} />
          <CcKpi n={items.filter((i) => i.ticket === "Not eligible").length} label="Not eligible" interp="RCA not confirmed — hold" />
          <CcKpi n={incidents.filter((i) => i.sync_status === "failed").length} label="Sync failed" interp="ITSM push errored" tone={incidents.some((i) => i.sync_status === "failed") ? "var(--crit)" : undefined} href="#/incident/integrations" />
        </div>
      </div>
    </div>
  );
}

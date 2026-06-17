import { useCallback, useEffect, useMemo, useState } from "react";
import { api, Incident, CorrObject } from "../services/api";
import { ownerLabel, signatureNocTitle, entityLabel, isInternalStackAffected } from "../components/rca/labels";

// Command Center — the NOC operational control plane (build-order #18). NOT a raw
// alert table: the primary rows are CORRELATION GROUPS (CorrObjects), each already
// carrying an RCA verdict, owner, blast radius and evidence shortfalls. It answers
// "what's burning, who owns it, what's correlated, what's ticketed, what's blocked,
// what needs human action" — and what to do next. Incidents/ITSM fold in for the
// ticketing-gap view. Premium dark/glass via the app-wide theme tokens (frontpage
// brand consistency) — never a hardcoded palette.

// ── Typed derived contracts (map to backend fields when they exist) ─────────────
type RcaState = "New" | "Correlated" | "RCA running" | "Suspected" | "Confirmed" | "Blocked" | "Resolved";
type EvidenceState = "Complete" | "Partial" | "Single-stream";
type FaultDomain = "LAN" | "SD-WAN" | "Data Center" | "ISP / Carrier" | "Cloud Provider" | "Application" | "Security" | "Unknown";
type OwnerState = "Assigned" | "Recommended" | "Missing" | "Escalated";
type TicketState = "Not eligible" | "Eligible" | "Ticket needed" | "Ticketed" | "Sync failed";
type Sev = "crit" | "major" | "warn" | "ok";

interface ActionItem {
  corr: CorrObject;
  affected: { devices: string[]; paths: string[]; interfaces: string[]; sites: string[] };
  missing: string[];
  sev: Sev;
  rca: RcaState;
  evidence: EvidenceState;
  fault: FaultDomain;
  owner: OwnerState;
  ownerName: string;
  ticket: TicketState;
  nextAction: string;
  ageMs: number;
}

const fmtAge = (iso?: string): string => {
  if (!iso) return "—";
  const ms = Date.now() - Date.parse(iso);
  if (!Number.isFinite(ms) || ms < 0) return "—";
  const m = Math.floor(ms / 60_000);
  if (m < 60) return `${m}m`;
  const h = Math.floor(m / 60);
  if (h < 48) return `${h}h`;
  return `${Math.floor(h / 24)}d`;
};

const safeArr = (v: unknown): string[] => (Array.isArray(v) ? v.filter((x) => typeof x === "string") : []);
function parseAffected(json: string): ActionItem["affected"] {
  try {
    const a = JSON.parse(json || "{}");
    return { devices: safeArr(a.devices), paths: safeArr(a.paths), interfaces: safeArr(a.interfaces), sites: safeArr(a.sites) };
  } catch { return { devices: [], paths: [], interfaces: [], sites: [] }; }
}
function parseMissing(json: string): string[] {
  try { const a = JSON.parse(json || "[]"); return Array.isArray(a) ? a.map(String) : []; } catch { return []; }
}

// RCA state — verdict + lifecycle, never "Confirmed" on a single stream (the ≥2
// independent-stream rule lives upstream in verdict_tier).
function deriveRca(c: CorrObject, missing: string[]): RcaState {
  const st = (c.state || "").toLowerCase();
  if (st === "recovered" || st === "closed") return "Resolved";
  if (c.verdict_tier === "confirmed") return "Confirmed";
  if (c.verdict_tier === "suspected") return missing.length >= 3 ? "Blocked" : "Suspected";
  // undetermined: a formed group still gathering evidence
  return c.signal_count > 1 ? "Correlated" : "RCA running";
}
function deriveEvidence(c: CorrObject, missing: string[]): EvidenceState {
  if (c.signal_count <= 1) return "Single-stream";
  return missing.length === 0 ? "Complete" : "Partial";
}
function deriveFault(c: CorrObject, aff: ActionItem["affected"]): FaultDomain {
  const o = (c.owner || "").toLowerCase();
  if (o === "isp") return "ISP / Carrier";
  if (o === "cloudops") return "Cloud Provider";
  if (o === "secops") return "Security";
  if (o === "appops") return "Application";
  const hay = [...aff.devices, ...aff.paths, ...aff.interfaces].join(" ").toLowerCase();
  if (/spine|leaf|fabric|dc-|tor/.test(hay)) return "Data Center";
  if (/wan|sd-?wan|edge|tunnel|vpn|mpls/.test(hay)) return "SD-WAN";
  if (/lan|sw-|access|dmz|fw/.test(hay)) return "LAN";
  return "Unknown";
}
function deriveOwner(c: CorrObject): { state: OwnerState; name: string } {
  const o = (c.owner || "").trim().toLowerCase();
  if (!o || o === "unknown") return { state: "Missing", name: "Unassigned" };
  // verdict owner is a recommendation (no assignment workflow yet)
  return { state: "Recommended", name: ownerLabel(c.owner) };
}
function deriveTicket(rca: RcaState): TicketState {
  if (rca === "Confirmed") return "Ticket needed";
  if (rca === "Resolved") return "Not eligible";
  return "Not eligible"; // suspected/correlated: hold until RCA confirms impact
}
function deriveSev(c: CorrObject, rca: RcaState): Sev {
  if (rca === "Confirmed") return "crit";
  if (rca === "Suspected" || rca === "Blocked") return "major";
  return c.top_confidence >= 0.6 ? "warn" : "ok";
}
// Next action — enterprise NOC language; what the operator should do NOW.
function deriveNextAction(it: Omit<ActionItem, "nextAction">): string {
  if (it.rca === "Confirmed" && it.owner === "Missing") return "Assign owner · escalate";
  if (it.rca === "Confirmed") return it.ticket === "Ticketed" ? "Track resolution" : "Open ticket · escalate";
  if (it.rca === "Blocked") return "Add evidence · unblock RCA";
  if (it.owner === "Missing") return "Assign owner · open RCA";
  if (it.rca === "Suspected") return "Confirm impact · hold ticket";
  return "Review correlation";
}

function buildItem(c: CorrObject): ActionItem {
  const affected = parseAffected(c.affected);
  const missing = parseMissing(c.evidence_missing);
  const rca = deriveRca(c, missing);
  const { state: owner, name: ownerName } = deriveOwner(c);
  const base = {
    corr: c, affected, missing,
    sev: deriveSev(c, rca), rca,
    evidence: deriveEvidence(c, missing),
    fault: deriveFault(c, affected),
    owner, ownerName,
    ticket: deriveTicket(rca),
    ageMs: Date.now() - Date.parse(c.window_start || c.created_at || ""),
  };
  return { ...base, nextAction: deriveNextAction(base) };
}

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

// ── Action Queue row (expandable) ───────────────────────────────────────────────
function QueueRow({ it, expanded, onToggle }: { it: ActionItem; expanded: boolean; onToggle: () => void }) {
  const c = it.corr;
  return (
    <>
      <tr className={`cc-row sev-${it.sev}`} onClick={onToggle}>
        <td><span className="cc-sevdot" style={{ background: SEV_TONE[it.sev] }} /></td>
        <td className="cc-title">
          <span className="cc-caret">{expanded ? "▾" : "▸"}</span>
          {signatureNocTitle(c.top_hypothesis)}
          <span className="cc-occ-inline">×{c.signal_count}</span>
        </td>
        <td>{ccChip(it.rca, RCA_TONE[it.rca], `confidence ${(c.top_confidence * 100).toFixed(0)}%`)}</td>
        <td className="cc-mono cc-dim">{impactLabel(it.affected)}</td>
        <td>{ccChip(it.fault, it.fault === "Unknown" ? "var(--fg-subtle)" : "var(--fg-muted)")}</td>
        <td>{ccChip(it.evidence, it.evidence === "Complete" ? "var(--ok)" : "var(--warn)", it.missing.join(", "))}</td>
        <td>{ccChip(it.ownerName, OWNER_TONE[it.owner])}</td>
        <td className="cc-mono cc-dim" style={{ textAlign: "right" }}>{fmtAge(c.window_start || c.created_at)}</td>
        <td>{ccChip(it.ticket, TICKET_TONE[it.ticket])}</td>
        <td className="cc-next">{it.nextAction}</td>
      </tr>
      {expanded && (
        <tr className="cc-expand-row">
          <td colSpan={10}>
            <ExpandPanel it={it} />
          </td>
        </tr>
      )}
    </>
  );
}

function ExpandPanel({ it }: { it: ActionItem }) {
  const c = it.corr;
  const devs = [...new Set([...it.affected.devices, ...it.affected.paths.flatMap((p) => p.split(/->|→/).map((x) => x.trim()))])].filter(Boolean);
  return (
    <div className="cc-expand">
      <div className="cc-expand-grid">
        <div>
          <h5 className="cc-eh">Impacted entities</h5>
          {devs.length ? <div className="cc-chips">{devs.slice(0, 12).map((d) => <span key={d} className="cc-pill cc-mono">{entityLabel(d)}</span>)}</div>
            : <p className="cc-dim">Blast radius pending topology mapping.</p>}
        </div>
        <div>
          <h5 className="cc-eh">Evidence</h5>
          <p className="cc-dim">{c.signal_count} correlated signal{c.signal_count > 1 ? "s" : ""} across {c.node_count} node{c.node_count > 1 ? "s" : ""}.</p>
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
        </div>
      </div>
      <div className="cc-actions">
        <a className="cc-btn cc-btn-primary" href={`#/events/correlations`}>Open RCA</a>
        <a className="cc-btn" href="#/infrastructure/topology">View topology</a>
        {it.owner === "Missing" && <button className="cc-btn" type="button">Assign owner</button>}
        {it.ticket === "Ticket needed" && <button className="cc-btn cc-btn-warn" type="button">Create ticket</button>}
        <button className="cc-btn" type="button">Suppress duplicate</button>
      </div>
    </div>
  );
}

// ── KPI card ────────────────────────────────────────────────────────────────────
function CcKpi({ n, label, interp, tone, href }: { n: number | string; label: string; interp: string; tone?: string; href?: string }) {
  const body = (
    <>
      <div className="cc-kpi-n" style={tone ? { color: tone } : undefined}>{n}</div>
      <div className="cc-kpi-l">{label}</div>
      <div className="cc-kpi-i">{interp}</div>
    </>
  );
  return href ? <a className="cc-kpi" href={href}>{body}</a> : <div className="cc-kpi">{body}</div>;
}

// ── Main ─────────────────────────────────────────────────────────────────────────
export default function CommandCenter() {
  const [corr, setCorr] = useState<CorrObject[]>([]);
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [err, setErr] = useState<string | null>(null);
  const [open, setOpen] = useState<string | null>(null);
  const [loaded, setLoaded] = useState(false);

  const load = useCallback(async () => {
    try {
      const [cs, inc] = await Promise.all([
        api.correlations(200, 2592000, "open"),
        api.listIncidents({ limit: 500 }).catch(() => [] as Incident[]),
      ]);
      setCorr((cs?.data ?? []).filter((c) => c.verdict_tier !== "undetermined" || c.signal_count > 1).filter((c) => !isInternalStackAffected(c.affected)));
      setIncidents(inc ?? []);
      setErr(null);
    } catch (e) { setErr((e as Error).message); }
    finally { setLoaded(true); }
  }, []);
  useEffect(() => { load(); const id = setInterval(load, 30_000); return () => clearInterval(id); }, [load]);

  const items = useMemo(() => corr.map(buildItem).sort((a, b) => {
    const sr: Record<Sev, number> = { crit: 0, major: 1, warn: 2, ok: 3 };
    return sr[a.sev] - sr[b.sev] || b.ageMs - a.ageMs;
  }), [corr]);

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
          <CcKpi n={items.length} label="Correlated incidents" interp="grouped, not raw alerts" href="#/events/correlations" />
          <CcKpi n={critical} label="Critical" interp="confirmed impact or high blast radius" tone={critical ? "var(--crit)" : undefined} href="#/events/correlations?tier=confirmed" />
          <CcKpi n={untriaged} label="Untriaged" interp="correlated, RCA not yet run" tone={untriaged ? "var(--warn)" : undefined} />
          <CcKpi n={suspected} label="Suspected RCA" interp="impact not confirmed" tone={suspected ? "var(--warn)" : undefined} href="#/events/correlations?tier=suspected" />
          <CcKpi n={confirmed} label="Confirmed RCA" interp="≥2 evidence streams align" tone={confirmed ? "var(--crit)" : undefined} href="#/events/correlations?tier=confirmed" />
          <CcKpi n={ownerMissing} label="Owner missing" interp="needs assignment" tone={ownerMissing ? "var(--crit)" : "var(--ok)"} />
          <CcKpi n={blocked} label="RCA blocked" interp="missing evidence streams" tone={blocked ? "var(--warn)" : "var(--ok)"} />
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
        {!loaded ? (
          <div className="cc-empty">Loading correlated incidents…</div>
        ) : items.length === 0 ? (
          <div className="cc-empty">No correlated incidents require action. The queue groups raw alerts into incidents — none have correlated.</div>
        ) : (
          <div className="cc-table-wrap">
            <table className="cc-table">
              <thead>
                <tr>
                  <th aria-label="severity" /><th>Incident / correlation group</th><th>RCA state</th><th>Impact</th>
                  <th>Fault domain</th><th>Evidence</th><th>Owner</th><th style={{ textAlign: "right" }}>Age</th><th>Ticket</th><th>Next action</th>
                </tr>
              </thead>
              <tbody>
                {items.map((it) => (
                  <QueueRow key={it.corr.correlation_id} it={it} expanded={open === it.corr.correlation_id}
                    onToggle={() => setOpen(open === it.corr.correlation_id ? null : it.corr.correlation_id)} />
                ))}
              </tbody>
            </table>
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

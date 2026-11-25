// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

import { fmtDateTime } from "../lib/time";
import { useCallback, useEffect, useMemo, useState } from "react";
import { api, Incident, TimelineEntry } from "../services/api";
import { severityColor, severityRank } from "../theme/severity";
import { StatusChip, severityStatus } from "../components/kit";
import DataTable, { Column } from "../components/DataTable";
import Icon from "../components/Icon";
import { friendlyIncidentId } from "../components/rca/labels";
import { NocHeader, NocKpis, NocKpi, LiveChip } from "../components/noc";
import AskIris, { askIrisAbout } from "../components/AskIris";
import { useAIEntitlements } from "../lib/aiEntitlements";
import TacCaseChip from "../components/tac/TacCaseChip";
import { caseLinkFromIncident } from "../pages/troubleshoot/tacModel";
import SidePanel from "../components/event/SidePanel";
import { useIsPhone } from "../lib/useIsPhone";
import { useDevicePlaces } from "../lib/deviceNames";
import {
  INCIDENT_SOURCE_TABS, INCIDENT_STATUS_TILES, type IncidentSourceTab, type IncidentFilters,
  inSourceTab, filterIncidents, statusCounts, countsNote, pageNote, statusText, ownerText, isActiveIncident,
  activeIncidentFilterCount, incidentWhere, incidentTitle, whereText, type IncidentWhere,
} from "./incidentsModel";

// Incidents — the actionable system-of-record view. Lists incidents (minted by a
// firing alert rule, opened by a person, or promoted from Digital Experience),
// drives the lifecycle in-platform (ack → investigate → resolve), shows the full
// event timeline, and surfaces the optional external ITSM ticket. Distinct from
// Operations → Problems: an incident is an owned, tracked record, not a
// correlated case (the two lanes share no id).
//
// Laid out the way the Logs page was redone (owner, 2026-11-22): source tabs,
// status tiles that filter, one search box with quick filters over the loaded
// rows, an owner column, a true total with paging, and a side panel per row.

const SEVERITIES = ["critical", "high", "medium", "low", "info"];

type Action = "ack" | "resolve" | "investigate" | "close" | "reopen" | "note" | "assign";

const fmt = (s?: string) => (s ? fmtDateTime(s) : "—");

/** WHERE (tracker 438): the device by name over its site. The internal device id
 *  is never shown (owner, 2026-11-23). No device → an honest "—". */
function WhereCell({ w }: { w: IncidentWhere }) {
  if (!w.device) return <span className="al-detail" title="This incident names no device">—</span>;
  const second = w.site;
  return (
    <div className="lv-two" data-testid="incident-where">
      <span className="al-device">{w.device}</span>
      {second && <span className="lv-line lv-detail-line al-detail">{second}</span>}
    </div>
  );
}

// "Notified via" chips (#103 UX-1) — same visual language as the RCA Candidates
// column: the ITSM ticket (when one was filed) plus every RECORDED notification
// delivery. Nothing recorded → honest "—".
const CHANNEL_LABEL: Record<string, string> = {
  slack: "Slack", pagerduty: "PagerDuty", email: "Email", sns: "SNS",
  twilio: "SMS", teams: "Teams", ntfy: "Push", servicenow: "SN", jira: "Jira",
};
const channelLabel = (c: string) =>
  CHANNEL_LABEL[c] ?? (c ? c.charAt(0).toUpperCase() + c.slice(1) : c);
const ITSM_SHORT: Record<string, string> = { servicenow: "SN", jira: "Jira" };
function notifyPill(text: string, tone: string, filled = false): React.ReactNode {
  return <span style={{
    fontSize: 12.5, fontWeight: 600, letterSpacing: 0.3, padding: "1px 6px", borderRadius: 4,
    whiteSpace: "nowrap",
    color: filled ? "#ffffff" : tone, background: filled ? tone : tone + "1c",
    border: `1px solid ${tone}55`,
  }}>{text}</span>;
}

const PAGE = 200;

export default function Incidents() {
  const [items, setItems] = useState<Incident[]>([]);
  const [total, setTotal] = useState(0);
  const [offset, setOffset] = useState(0);
  const [tab, setTab] = useState<IncidentSourceTab>("all");
  const [filters, setFilters] = useState<IncidentFilters>({});
  const [busy, setBusy] = useState(false);
  const [loaded, setLoaded] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [unavailable, setUnavailable] = useState(false);
  const [sel, setSel] = useState<string | null>(null);
  const isPhone = useIsPhone();
  const places = useDevicePlaces();

  const load = useCallback(async () => {
    setBusy(true);
    try {
      const r = await api.listIncidentsPage({ limit: PAGE, offset });
      setItems(r.incidents ?? []);
      setTotal(r.total ?? (r.incidents ?? []).length);
      setUnavailable(false);
      setError(null);
    } catch (e) {
      const m = (e as Error).message;
      if (m.includes("409")) {
        setUnavailable(true);
        setItems([]);
      } else {
        setError(m);
      }
    } finally {
      setBusy(false);
      setLoaded(true);
    }
  }, [offset]);

  // The page refreshes on its own every 30 s, so the Live chip is a true claim.
  useEffect(() => {
    load();
    const id = setInterval(load, 30_000);
    return () => clearInterval(id);
  }, [load]);

  const set = (patch: Partial<IncidentFilters>) => setFilters((f) => ({ ...f, ...patch }));
  const shown = useMemo(() => filterIncidents(items, tab, filters, places), [items, tab, filters, places]);
  const counts = useMemo(() => statusCounts(items, tab), [items, tab]);
  const tabCount = (t: IncidentSourceTab) => items.filter((i) => inSourceTab(i, t)).length;

  // Where this incident actually went: the ITSM ticket (linked, when the
  // projection filed one) + every recorded notification delivery (#103 UX-1 —
  // "Slack is a notification, not a ticket": distinct chip, same cell).
  const notifiedCell = (i: Incident) => {
    const chips: React.ReactNode[] = [];
    // A TAC escalation's vendor case renders as the case chip: the number, the
    // vendor's own status, and — when the last read failed — "status unknown
    // since …" rather than the status it last saw.
    const tacCase = caseLinkFromIncident(i);
    if (tacCase) {
      chips.push(<TacCaseChip key="tac" link={tacCase} compact />);
    } else if (i.external_ticket_id) {
      const label = `${ITSM_SHORT[i.external_system ?? ""] ?? channelLabel(i.external_system ?? "")} ${i.external_ticket_id}`;
      const pill = notifyPill(label, "#2563EB", true);
      chips.push(i.external_url
        ? <a key="itsm" href={i.external_url} target="_blank" rel="noreferrer" onClick={(e) => e.stopPropagation()}
            title={`${i.external_system}: ${i.external_ticket_id} — open ticket`} style={{ textDecoration: "none" }}>{pill}</a>
        : <span key="itsm" title={`${i.external_system}: ${i.external_ticket_id}`}>{pill}</span>);
    } else if (i.sync_status === "pending") {
      chips.push(<span key="sync" title="ITSM ticket sync in progress">{notifyPill("syncing…", "#D97706")}</span>);
    }
    (i.notified_via ?? []).forEach((c) => {
      chips.push(<span key={c} title={`Notification delivered via ${channelLabel(c)}`}>{notifyPill(channelLabel(c), "#7C3AED")}</span>);
    });
    if (chips.length === 0) return <span style={{ color: "var(--muted)" }}>—</span>;
    return <span style={{ display: "inline-flex", gap: 4, flexWrap: "wrap" }}>{chips}</span>;
  };

  const columns = useMemo<Column<Incident>[]>(() => {
    const sevCell = (i: Incident) => <StatusChip kind={severityStatus(i.severity)} label={i.severity} />;
    const whatCell = (i: Incident) => (
      <div className="lv-two">
        <span className="al-title" title={incidentTitle(i, places)}>{incidentTitle(i, places)}</span>
        <span className="lv-line lv-detail-line al-detail">
          <span style={{ fontFamily: "var(--font-mono)" }} title={i.id}>{friendlyIncidentId(i.id)}</span>
          {" · "}{statusText(i.status)}{" · "}{Number(i.occurrences) > 1 ? `${i.occurrences} occurrences` : "1 occurrence"}
        </span>
      </div>
    );
    const ownerCell = (i: Incident) => (
      <span className={i.owner && i.owner.trim() ? "al-device" : "al-detail"}>{ownerText(i)}</span>
    );
    if (isPhone) {
      return [{
        key: "what", header: "Incident", sortable: true, sortValue: (i) => new Date(i.last_seen_at ?? 0).getTime() || 0,
        render: (i) => (
          <div className="lv-phone-cell">
            <div className="lv-phone-top">{sevCell(i)} <span className="al-when">{fmt(i.last_seen_at)}</span></div>
            {whatCell(i)}
            <WhereCell w={incidentWhere(i, places)} />
            {ownerCell(i)}
          </div>
        ),
      }];
    }
    return [
      { key: "severity", header: "Severity", width: 104, sortable: true,
        text: (i) => i.severity, sortValue: (i) => severityRank(i.severity), render: sevCell },
      // A floor on the one flexible column: the six fixed columns total 966px,
      // so at a ~1000px content width (a 1280px window with the menu open)
      // minmax(0,1fr) squeezed the incident TITLE to zero. The table scrolls
      // sideways instead (.dtv is overflow:auto).
      { key: "what", header: "Incident", width: "minmax(240px, 1fr)", sortable: true, text: (i) => `${incidentTitle(i, places)} ${friendlyIncidentId(i.id)}`, render: whatCell },
      { key: "where", header: "Where", width: 190, sortable: true,
        text: (i) => whereText(incidentWhere(i, places)),
        sortValue: (i) => whereText(incidentWhere(i, places)).toLowerCase(),
        render: (i) => <WhereCell w={incidentWhere(i, places)} /> },
      { key: "owner", header: "Owner", width: 150, sortable: true, text: ownerText, render: ownerCell },
      { key: "source", header: "Opened by", width: 150, sortable: true, text: (i) => i.source_type,
        render: (i) => <span className="al-detail">{SOURCE_LABEL[(i.source_type || "manual").toLowerCase()] ?? i.source_type}</span> },
      { key: "notified", header: "Ticket and notifications", width: 200,
        text: (i) => [i.external_ticket_id ?? "", ...(i.notified_via ?? []).map(channelLabel)].filter(Boolean).join(" "),
        render: (i) => notifiedCell(i) },
      { key: "last_seen", header: "Since", width: 172, sortable: true,
        sortValue: (i) => new Date(i.last_seen_at ?? 0).getTime() || 0,
        render: (i) => (
          <div className="lv-two al-since">
            <span title="Opened">{fmt(i.first_seen_at)}</span>
            <span className="al-last" title="Last seen">{fmt(i.last_seen_at)}</span>
          </div>
        ) },
    ];
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [isPhone, places]);

  const selected = sel ? items.find((i) => i.id === sel) : undefined;

  const iOpen = items.filter(isActiveIncident).length;
  const iCrit = items.filter((i) => i.severity === "critical" && isActiveIncident(i)).length;
  const iUnassigned = items.filter((i) => isActiveIncident(i) && !(i.owner && i.owner.trim())).length;
  const iTicketed = items.filter((i) => i.sync_status === "synced").length;
  const note = pageNote(offset, items.length, total);
  const nFilters = activeIncidentFilterCount(filters);
  return (
    <div className="dm-board cc-board">
      <NocHeader
        title="Incidents"
        topic="page.incidents"
        icon="incident"
        count={error ? undefined : total}
        chips={<>{error
          ? <StatusChip kind="critical" label="Feed unavailable" title="The incident list did not answer — the counts below are unknown, not zero." />
          : <LiveChip />}</>}
      >
        <NocKpis cols={4}>
          <NocKpi n={error ? "—" : iOpen} label="Open" topic="incidents.open" tone={error ? "var(--fg-subtle)" : iOpen ? "var(--warn)" : undefined} />
          <NocKpi n={error ? "—" : iCrit} label="Critical" topic="incidents.critical" tone={error ? "var(--fg-subtle)" : iCrit ? "var(--crit)" : undefined} />
          <NocKpi n={error ? "—" : iUnassigned} label="Unassigned" topic="incidents.unassigned" tone={error ? "var(--fg-subtle)" : iUnassigned ? "var(--crit)" : "var(--ok)"} />
          <NocKpi n={error ? "—" : iTicketed} label="Ticketed" topic="incidents.ticketed" />
        </NocKpis>
      </NocHeader>
      <div className="cc-panel">
        <div className="lv-subtabs" role="group" aria-label="Opened by">
          {INCIDENT_SOURCE_TABS.map((t) => (
            <button key={t.id} type="button" className="lv-subtab" aria-pressed={tab === t.id}
              onClick={() => { setTab(t.id); setSel(null); }}>
              {t.label}
              {tab === t.id && loaded && !error && <span className="lv-subtab-n" aria-hidden="true"> ({tabCount(t.id)})</span>}
            </button>
          ))}
        </div>
        <div style={{ padding: "11px 13px" }}>
          {!error && !unavailable && items.length > 0 && (
            <div className="lv-tiles-wrap" data-testid="incidents-status-tiles">
              <div className="lv-tiles" role="group" aria-label="Status of the loaded incidents">
                {INCIDENT_STATUS_TILES.map((t) => {
                  const on = filters.status === t.id;
                  return (
                    <button key={t.id} type="button" className="lv-tile in-tile" aria-pressed={on}
                      style={{ ["--lt-tone" as string]: t.tone, ["--lt-bg" as string]: "var(--surface)" }}
                      aria-label={`${t.label}: ${counts[t.id]}. ${on ? "Showing only these; press to show all" : "Press to show only these"}`}
                      onClick={() => set({ status: on ? undefined : t.id })}>
                      <span className="lv-tile-txt">
                        <span className="lv-tile-n">{counts[t.id].toLocaleString()}</span>
                        <span className="lv-tile-k">{t.label}</span>
                      </span>
                    </button>
                  );
                })}
              </div>
              <p className="lv-tiles-note">{countsNote(items.length, total)}</p>
            </div>
          )}
          {!error && !unavailable && items.length > 0 && (
            <div className="lv-filters" data-testid="incidents-filters">
              <input className="form-input al-search" type="search" placeholder="Search incidents, devices, sites, owners"
                aria-label="Search incidents" value={filters.q ?? ""} onChange={(e) => set({ q: e.target.value })} />
              <select aria-label="Severity" value={filters.severity ?? ""} onChange={(e) => set({ severity: e.target.value || undefined })}>
                <option value="">All severities</option>
                {SEVERITIES.map((s) => <option key={s} value={s}>{s}</option>)}
              </select>
              <label className="al-check"><input type="checkbox" checked={!!filters.unassigned} onChange={(e) => set({ unassigned: e.target.checked || undefined })} /> Unassigned</label>
              <span className="al-scope">In these {items.length.toLocaleString()} loaded incidents</span>
              {nFilters > 0 && <button type="button" className="btn-ghost" onClick={() => setFilters({})}>Clear filters</button>}
              <button className="btn" type="button" onClick={load} disabled={busy}>
                <Icon name="refresh" size={14} /> {busy ? "Loading…" : "Refresh"}
              </button>
            </div>
          )}
          {error && (
            <p role="alert" style={{ color: "var(--bad)", marginBottom: 8 }}>
              <strong>Incidents could not be loaded:</strong> {error}
              <br />
              <span style={{ color: "var(--muted)" }}>Unknown, not empty.</span>
            </p>
          )}
          {/* "quiet is good" is a claim only a successful read can support, so it
              is mutually exclusive with the error above. */}
          {unavailable ? (
            <div className="empty">Incident management is not enabled here.</div>
          ) : items.length === 0 ? (
            error || !loaded ? null : <div className="empty">No incidents.<AskIris topic="incidents.empty-queue" label="an empty incident queue" /></div>
          ) : shown.length === 0 ? (
            <div className="empty">No incident matches these filters. <button type="button" className="btn-ghost" onClick={() => { setFilters({}); setTab("all"); }}>Clear filters</button></div>
          ) : (
            <DataTable<Incident>
              rows={shown}
              columns={columns}
              rowKey={(i) => i.id}
              rowHeight={isPhone ? 120 : 48}
              height="55vh"
              ariaLabel="Incidents"
              onRowClick={(i) => setSel(i.id)}
              rowAccent={(i) => severityColor(i.severity)}
              rowClassName={(i) => (sel === i.id ? "dtv-selected" : "")}
              initialSort={{ key: "last_seen", dir: "desc" }}
            />
          )}
          {note && !error && (
            <div className="lv-pager" data-testid="incidents-pager">
              <span className="lv-pager-txt">{note}</span>
              <span className="lv-pages">
                <button type="button" className="btn-ghost" disabled={offset === 0 || busy} onClick={() => setOffset(Math.max(0, offset - PAGE))}>Newer</button>
                <button type="button" className="btn-ghost" disabled={offset + items.length >= total || busy} onClick={() => setOffset(offset + PAGE)}>Older</button>
              </span>
            </div>
          )}
        </div>
      </div>
      {selected && (
        <SidePanel
          narrow
          title={incidentTitle(selected, places)}
          subtitle={`${friendlyIncidentId(selected.id)} · ${selected.severity} · ${statusText(selected.status)}`}
          onClose={() => setSel(null)}
          testId="incident-panel"
          overlayTestId="incident-panel-overlay"
        >
          <IncidentDetailBody incident={selected} onChanged={load} onAsked={() => setSel(null)} inPanel />
        </SidePanel>
      )}
    </div>
  );
}

const SOURCE_LABEL: Record<string, string> = {
  alert: "Alert rule", log: "Log event", anomaly: "Anomaly", manual: "A person", experience: "Digital Experience",
};

// IncidentDetailBody — a self-contained detail pane: it owns the timeline fetch,
// note entry, and lifecycle actions, refetching by incident id, so it renders
// correctly inside the dockable Inspector (a captured node) OR as an inline card.
// `onChanged` lets the parent refresh its list after a lifecycle action.
/** The question "Ask Iris about this incident" sends: the incident's own title
 *  (trimmed, one line) and what the operator wants next. */
export function incidentQuestion(inc: Pick<Incident, "title" | "severity">): string {
  const title = (inc.title || "").replace(/\s+/g, " ").trim().slice(0, 160) || "this incident";
  return `Explain the ${(inc.severity || "").trim() || "open"} incident "${title}": what is happening, who is affected and what should I check next?`;
}

export function IncidentDetailBody({ incident, onChanged, onAsked, inPanel = false }: {
  incident: Incident;
  onChanged?: () => void;
  /** Called after "Ask Iris" — the side panel closes so Iris is not behind its scrim. */
  onAsked?: () => void;
  /** In the side panel the panel header already names the incident. */
  inPanel?: boolean;
}) {
  const [inc, setInc] = useState<Incident>(incident);
  const [timeline, setTimeline] = useState<TimelineEntry[]>([]);
  const [note, setNote] = useState("");
  const [owner, setOwner] = useState(incident.owner ?? "");
  const [acting, setActing] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const reload = async () => {
    try {
      const d = await api.getIncidentTimeline(incident.id);
      setInc(d.incident);
      setTimeline(d.timeline);
    } catch (e) {
      setError((e as Error).message);
    }
  };

  useEffect(() => {
    setInc(incident);
    setTimeline([]);
    setNote("");
    setOwner(incident.owner ?? "");
    reload();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [incident.id]);

  const act = async (action: Action, body?: { note?: string; owner?: string }) => {
    setActing(true);
    setError(null);
    try {
      await api.incidentAction(incident.id, action, body || {});
      setNote("");
      await reload();
      onChanged?.();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setActing(false);
    }
  };

  const open = inc.status !== "resolved" && inc.status !== "closed";
  const ent = useAIEntitlements();
  const places = useDevicePlaces();
  const where = incidentWhere(inc, places);
  const title = incidentTitle(inc, places);

  return (
    <>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "baseline", flexWrap: "wrap", gap: 8 }}>
        {!inPanel && (
          <h2 style={{ margin: 0 }}>
            <StatusChip kind={severityStatus(inc.severity)} label={inc.severity} /> {title}
          </h2>
        )}
        {/* N-E4 entry point: an incident row carries no RCA case id, so the
            question names the incident by its own title; the server reads it
            as text and answers from the caller's own data. */}
        {ent.has("ai.chat") && (
          <button type="button" className="chip-btn" data-testid="ask-iris-incident"
            onClick={() => { askIrisAbout(incidentQuestion({ ...inc, title })); onAsked?.(); }}>
            Ask Iris about this incident
          </button>
        )}
        <span style={{ color: "var(--muted)", fontSize: 14 }}>
          <span style={{ fontFamily: "var(--font-mono)" }} title={inc.id}>{friendlyIncidentId(inc.id)}</span>
          {" · "}{statusText(inc.status)} · {inc.occurrences}× · opened {fmt(inc.first_seen_at)} · owner {ownerText(inc)}
        </span>
      </div>
      <p style={{ fontSize: 14, margin: "6px 0 0" }} data-testid="incident-panel-where">
        <span style={{ color: "var(--muted)" }}>Where: </span>
        {where.device
          ? <><strong>{where.device}</strong>{where.site && <> · {where.site}</>}</>
          : <span style={{ color: "var(--muted)" }}>no device named</span>}
      </p>
      {inc.description && <p style={{ color: "var(--muted)", fontSize: 14 }}>{inc.description}</p>}
      {inc.external_ticket_id && (
        <p style={{ fontSize: 14, margin: "2px 0 0" }}>
          {inc.external_url ? (
            <a href={inc.external_url} target="_blank" rel="noreferrer">
              {inc.external_system}: {inc.external_ticket_id}
            </a>
          ) : (
            <span>{inc.external_system}: {inc.external_ticket_id}</span>
          )}
        </p>
      )}
      {error && (
        <p style={{ color: "var(--bad)", fontSize: 14 }}>
          <strong>Error:</strong> {error}
        </p>
      )}

      {/* Lifecycle actions */}
      <div style={{ display: "flex", gap: 6, flexWrap: "wrap", margin: "8px 0" }}>
        {open && (
          <>
            <button type="button" className="chip" disabled={acting} onClick={() => act("ack")}>
              Acknowledge
            </button>
            <button type="button" className="chip" disabled={acting} onClick={() => act("investigate")}>
              Investigate
            </button>
            <button type="button" className="chip chip-active" disabled={acting} onClick={() => act("resolve")}>
              Resolve
            </button>
          </>
        )}
        {inc.status === "resolved" && (
          <>
            <button type="button" className="chip" disabled={acting} onClick={() => act("close")}>
              Close
            </button>
            <button type="button" className="chip" disabled={acting} onClick={() => act("reopen")}>
              Reopen
            </button>
          </>
        )}
      </div>
      <div style={{ display: "flex", gap: 6, marginBottom: 10, flexWrap: "wrap", alignItems: "center" }}>
        <input
          className="form-input"
          style={{ width: 200 }}
          aria-label="Owner"
          placeholder="Username"
          maxLength={64}
          value={owner}
          onChange={(e) => setOwner(e.target.value)}
        />
        <button type="button" disabled={acting || !owner.trim() || owner.trim() === (inc.owner ?? "")}
          onClick={() => act("assign", { owner: owner.trim() })}>
          Assign
        </button>
      </div>
      <div style={{ display: "flex", gap: 6, marginBottom: 10 }}>
        <input
          aria-label="New note"
          value={note}
          onChange={(e) => setNote(e.target.value)}
          placeholder="Add a note to the timeline…"
          style={{ flex: 1 }}
        />
        <button type="button" disabled={acting || !note.trim()} onClick={() => act("note", { note })}>
          Add note
        </button>
      </div>

      {/* Timeline — lifecycle events and ITSM sync events, merged chronologically */}
      <h3 style={{ fontSize: 16, fontWeight: 600, letterSpacing: 0.2 }}>Timeline</h3>
      <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
        {timeline.map((ev) => (
          <div
            key={ev.id}
            style={{
              display: "flex",
              gap: 10,
              fontSize: 14,
              alignItems: "baseline",
              borderLeft: `3px solid ${ev.kind === "sync" ? "var(--accent)" : "transparent"}`,
              paddingLeft: 8,
            }}
          >
            <span style={{ fontFamily: "var(--font-mono)", color: "var(--muted)", minWidth: 150 }}>
              {fmt(ev.at)}
            </span>
            {ev.kind === "sync" ? (
              <>
                <span className="badge" title={`${ev.direction ?? ""} sync via ${ev.provider ?? ""}`}>
                  {ev.direction === "inbound" ? "↓" : ev.direction === "outbound" ? "↑" : ""} {ev.provider}
                </span>
                <span style={{ color: "var(--muted)" }}>{ev.status}</span>
                <span>{renderSync(ev)}</span>
                {ev.correlation_id && (
                  <span
                    style={{ marginLeft: "auto", fontFamily: "var(--font-mono)", color: "var(--muted)", opacity: 0.7 }}
                    title="Correlation id — grep this across logs to trace the sync end-to-end"
                  >
                    {ev.correlation_id}
                  </span>
                )}
              </>
            ) : (
              <>
                <span className="badge">{ev.event_type}</span>
                <span style={{ color: "var(--muted)" }}>{ev.actor}</span>
                <span>{renderPayload(ev)}</span>
              </>
            )}
          </div>
        ))}
        {timeline.length === 0 && <span style={{ fontSize: 14, color: "var(--muted)" }}>Loading timeline…</span>}
      </div>
    </>
  );
}

function renderPayload(ev: TimelineEntry): string {
  const p = ev.payload || {};
  switch (ev.event_type) {
    case "status_change":
      return `${p.from} → ${p.to}${p.note ? ` — ${p.note}` : ""}`;
    case "note":
      return String(p.note ?? "");
    case "assignment":
      return `owner → ${p.owner}`;
    case "sync":
      return `${p.system ?? ""} ${p.external_ticket_id ?? ""} (${p.sync_status ?? ""})`.trim();
    case "notified":
      return `notification delivered via ${channelLabel(String(p.channel ?? ""))}`;
    case "dedup":
      return "recurrence folded in";
    case "created":
      return String(p.source_type ? `from ${p.source_type}` : "created");
    default:
      return "";
  }
}

// renderSync describes an ITSM sync event: the ticket it touched and, when the
// event was dropped/failed, why (the reconciler verdict — e.g. stale, terminal).
function renderSync(ev: TimelineEntry): string {
  const ticket = ev.external_id ? `${ev.provider ?? ""} ${ev.external_id}`.trim() : "";
  const base = [ev.type, ticket].filter(Boolean).join(" · ");
  if (ev.status === "dropped" || ev.status === "failed" || ev.status === "dead") {
    return `${base}${ev.reason ? ` — ${ev.reason}` : ""}`.trim();
  }
  return base;
}

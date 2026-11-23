// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

import { useCallback, useEffect, useMemo, useState } from "react";
import { fmtDateTime } from "../lib/time";
import { api, AlertEpisode } from "../services/api";
import { severityClass, severityColor, severityRank, SEVERITY_TONES } from "../theme/severity";
import DataTable, { Column } from "../components/DataTable";
import { useWorkspace } from "../context/workspace";
import { NocHeader, NocKpis, NocKpi, Chip, LiveChip } from "../components/noc";
import AskIris from "../components/AskIris";
import EvIcon from "../components/event/EvIcon";
import SidePanel from "../components/event/SidePanel";
import Logs from "./Logs";
import { operatorError } from "../lib/errors";
import { useDeviceNames } from "../lib/deviceNames";
import { useIsPhone } from "../lib/useIsPhone";
import {
  ALERT_TABS, type AlertsTab, type AlertFilters, type AlertView,
  isSuppressed, statusLabel, statusTone, toAlertView, alertTiles, filterAlerts, facetValues, activeAlertFilterCount,
  alertSummary,
} from "./alertsModel";

// Operations → Active Alerts, grouped by EPISODE: repeated firings of the same
// (resource, signal, state) collapse into one row with first/last/count, flap
// detection and triage (acknowledge / assign / mute / snooze / notes). Muting or
// snoozing pauses NOTIFICATIONS only — the episode stays visible with its paused
// state shown honestly.
//
// Laid out the way the Logs page was redone (owner, 2026-11-22): severity tiles
// that filter, tabs that map onto the episode API's own status filter, one
// search box with quick filters over the loaded rows, two-line rows with the
// device by NAME, and a side panel for one episode.

const mono: React.CSSProperties = { fontFamily: "var(--font-mono, monospace)", fontSize: 14 };

// Labeled, mode-aware time rendering (lib/time is the single time authority —
// never a bare toLocaleString, which shows an unlabeled ambiguous clock).
const fmt = (iso?: string) => (iso ? fmtDateTime(iso) : "—");

export default function Alerts() {
  const [items, setItems] = useState<AlertEpisode[]>([]);
  const [total, setTotal] = useState(0);
  const [truncated, setTruncated] = useState(false);
  const [rawFiring, setRawFiring] = useState(0);
  const [tab, setTab] = useState<AlertsTab>("active");
  const [filters, setFilters] = useState<AlertFilters>({});
  const [sel, setSel] = useState<string | null>(null);
  // loadErr — this page's OWN failure state. It cannot be delegated to the
  // top-level health indicator: that polls /healthz, which stays 200 while a
  // route-scoped 500 takes this feed down. Without it an alerts outage rendered
  // green zeros and "all monitored conditions are within threshold".
  const [loadErr, setLoadErr] = useState<string | null>(null);
  const [loaded, setLoaded] = useState(false);
  const ws = useWorkspace();
  const names = useDeviceNames();
  const isPhone = useIsPhone();

  const load = useCallback(async () => {
    try {
      const [ep, raw] = await Promise.all([api.alertEpisodes(tab), api.alerts()]);
      setItems(ep.episodes ?? []);
      setTotal(ep.total ?? (ep.episodes ?? []).length);
      setTruncated(!!ep.truncated);
      setRawFiring((raw ?? []).length);
      setLoadErr(null);
    } catch (e) {
      setLoadErr(operatorError(e, "Alerts could not be loaded."));
    } finally {
      setLoaded(true);
    }
  }, [tab]);

  useEffect(() => {
    let alive = true;
    const tick = async () => {
      if (alive) await load();
    };
    tick();
    const id = setInterval(tick, 10000);
    return () => {
      alive = false;
      clearInterval(id);
    };
  }, [load]);

  // A triage response replaces the row in place (no full refetch needed).
  const onUpdated = useCallback((ep: AlertEpisode) => {
    setItems((prev) => prev.map((x) => (x.id === ep.id ? ep : x)));
  }, []);

  const views = useMemo(() => items.map((e) => toAlertView(e, names)), [items, names]);
  const shown = useMemo(() => filterAlerts(views, filters), [views, filters]);
  const tiles = useMemo(() => alertTiles(items, truncated, total), [items, truncated, total]);
  const deviceFacet = useMemo(() => facetValues(views, (v) => v.device), [views]);
  const monitorFacet = useMemo(() => facetValues(views, (v) => v.episode.signal), [views]);
  const set = (patch: Partial<AlertFilters>) => setFilters((f) => ({ ...f, ...patch }));

  const columns = useMemo<Column<AlertView>[]>(() => {
    const sevCell = (v: AlertView) => <span className={`badge ${severityClass(v.episode.state)}`}>{v.episode.state}</span>;
    const statusCell = (v: AlertView) => {
      const e = v.episode;
      return (
        <span style={{ display: "inline-flex", gap: 4, flexWrap: "wrap" }}>
          <Chip label={statusLabel(e.status)} tone={statusTone(e.status)} />
          {e.flapping && <Chip label="Flapping" tone="var(--warn)" title={`Rapid state changes detected (${e.flip_count ?? 0} flips)`} />}
          {isSuppressed(e) && (
            <Chip
              label={e.muted ? "Notifications paused" : `Snoozed until ${fmt(e.snoozed_until)}`}
              tone="var(--fg-subtle)"
              title="Notifications are paused for this episode. It stays visible here."
            />
          )}
          {e.acknowledged_by && <Chip label={`Ack · ${e.acknowledged_by}`} tone="var(--ok)" />}
          {e.assigned_to && <Chip label={`→ ${e.assigned_to}`} tone="var(--accent)" title={`Assigned to ${e.assigned_to}`} />}
        </span>
      );
    };
    const countCell = (v: AlertView) => (
      <span className="badge" title={`${v.episode.count} firing${v.episode.count === 1 ? "" : "s"} folded into this episode`}>
        ×{v.episode.count}
      </span>
    );
    const alertCell = (v: AlertView) => (
      <div className="lv-two">
        <span className="al-title" title={v.title}>{v.title}</span>
        <span className="lv-line lv-detail-line al-detail" title={v.detail}>{v.detail}</span>
      </div>
    );
    if (isPhone) {
      return [{
        key: "alert", header: "Alert", sortable: true, sortValue: (v) => Date.parse(v.episode.last_seen) || 0,
        render: (v) => (
          <div className="lv-phone-cell">
            <div className="lv-phone-top">{sevCell(v)} {countCell(v)} <span className="al-when">{fmt(v.episode.last_seen)}</span></div>
            {alertCell(v)}
            {statusCell(v)}
          </div>
        ),
      }];
    }
    return [
      { key: "state", header: "Severity", width: 104, sortable: true,
        text: (v) => v.episode.state, sortValue: (v) => severityRank(v.episode.state), render: sevCell },
      { key: "alert", header: "Alert", sortable: true, text: (v) => `${v.title} ${v.detail}`, render: alertCell },
      { key: "device", header: "Device", width: 170, sortable: true, text: (v) => v.device,
        render: (v) => (
          <span className="al-device">{v.device}</span>
        ) },
      { key: "count", header: "Count", width: 84, sortable: true,
        text: (v) => String(v.episode.count), sortValue: (v) => v.episode.count, render: countCell },
      { key: "status", header: "Status", width: 230, sortable: true, text: (v) => v.episode.status, render: statusCell },
      { key: "last", header: "Since", width: 172, sortable: true,
        sortValue: (v) => Date.parse(v.episode.last_seen) || 0,
        render: (v) => (
          <div className="lv-two al-since">
            <span title="First seen">{fmt(v.episode.first_seen)}</span>
            <span className="al-last" title="Last seen">{fmt(v.episode.last_seen)}</span>
          </div>
        ) },
    ];
  }, [isPhone]);

  const selected = sel ? items.find((e) => e.id === sel) : undefined;
  const selectedView = selected ? toAlertView(selected, names) : undefined;

  const active = items.filter((e) => e.status === "active");
  const eCrit = active.filter((e) => e.state === "critical" || e.state === "error").length;
  const eFlap = items.filter((e) => e.flapping && e.status !== "closed").length;
  const ePaused = items.filter((e) => isSuppressed(e) && e.status !== "closed").length;
  const tabMeta = ALERT_TABS.find((t) => t.id === tab) ?? ALERT_TABS[0];
  const nFilters = activeAlertFilterCount(filters);

  return (
    <div className="dm-board cc-board">
      <NocHeader
        title="Active Alerts"
        topic="page.active-alerts"
        chips={
          <>
            {loadErr ? (
              <Chip
                label="Feed unavailable"
                tone="var(--crit)"
                title="The alert episode API did not answer — the counts below are unknown, not zero."
              />
            ) : (
              <Chip
                label={`Firing ${rawFiring} · Episodes ${active.length}`}
                tone={active.length ? "var(--warn)" : "var(--ok)"}
                title="Currently-firing alerts, folded into episodes"
              />
            )}
            {!loadErr && <LiveChip detail="rule evaluation" />}
          </>
        }
      >
        {/* On a failed read every KPI is UNKNOWN — a green zero would be a claim
            about the network that the API never made. The em dash says so; what
            "unknown" means for each tile is one click away on its (i). */}
        <NocKpis cols={4}>
          <NocKpi n={loadErr ? "—" : active.length} label="Active episodes" topic="alerts.active-episodes" tone={loadErr ? "var(--fg-subtle)" : active.length ? "var(--warn)" : "var(--ok)"} />
          <NocKpi n={loadErr ? "—" : eCrit} label="Critical" topic="alerts.critical" tone={loadErr ? "var(--fg-subtle)" : eCrit ? "var(--crit)" : undefined} />
          <NocKpi n={loadErr ? "—" : eFlap} label="Flapping" topic="alerts.flapping" tone={loadErr ? "var(--fg-subtle)" : eFlap ? "var(--warn)" : undefined} />
          <NocKpi n={loadErr ? "—" : ePaused} label="Notifications paused" topic="alerts.notifications-paused" tone={loadErr ? "var(--fg-subtle)" : ePaused ? "var(--fg-subtle)" : undefined} />
        </NocKpis>
      </NocHeader>
      <div className="cc-panel">
        <div className="lv-subtabs" role="group" aria-label="Episode status">
          {ALERT_TABS.map((t) => (
            <button key={t.id} type="button" className="lv-subtab" aria-pressed={tab === t.id}
              onClick={() => { setTab(t.id); setSel(null); }}>
              {t.label}
              {tab === t.id && loaded && !loadErr && (
                <span className="lv-subtab-n" aria-hidden="true"> ({truncated ? `${items.length} of ${total}` : items.length})</span>
              )}
            </button>
          ))}
        </div>
        <div style={{ padding: "11px 13px" }}>
          {/* Severity tiles over the loaded episodes: a tile filters the list, and
              the note says whether the counts are every episode or only the loaded ones. */}
          {!loadErr && items.length > 0 && (
            <div className="lv-tiles-wrap" data-testid="alerts-severity-tiles">
              <div className="lv-tiles" role="group" aria-label="Severity of the loaded episodes">
                {tiles.tiles.map((t) => {
                  const on = filters.severity === t.id;
                  return (
                    <button key={t.id} type="button" className={`lv-tile lv-tile-${t.id}`} aria-pressed={on}
                      aria-label={`${t.label}: ${t.count}. ${on ? "Showing only these; press to show all" : "Press to show only these"}`}
                      onClick={() => set({ severity: on ? undefined : t.id })}>
                      <span className="lv-tile-ico" aria-hidden="true"><EvIcon name={SEVERITY_TONES[t.id].icon} size={20} /></span>
                      <span className="lv-tile-txt">
                        <span className="lv-tile-n">{t.count.toLocaleString()}</span>
                        <span className="lv-tile-k">{t.label}</span>
                      </span>
                    </button>
                  );
                })}
              </div>
              <p className="lv-tiles-note">{tiles.note}</p>
            </div>
          )}
          {!loadErr && items.length > 0 && (
            <div className="lv-filters" data-testid="alerts-filters">
              <input className="form-input al-search" type="search" placeholder="Search alerts, devices, people"
                aria-label="Search alerts" value={filters.q ?? ""} onChange={(e) => set({ q: e.target.value })} />
              <select aria-label="Device" value={filters.device ?? ""} onChange={(e) => set({ device: e.target.value || undefined })}>
                <option value="">All devices</option>
                {deviceFacet.map((o) => <option key={o.value} value={o.value}>{o.value} ({o.count})</option>)}
              </select>
              <select aria-label="Monitor" value={filters.monitor ?? ""} onChange={(e) => set({ monitor: e.target.value || undefined })}>
                <option value="">All monitors</option>
                {monitorFacet.map((o) => <option key={o.value} value={o.value}>{o.value} ({o.count})</option>)}
              </select>
              <label className="al-check"><input type="checkbox" checked={!!filters.flapping} onChange={(e) => set({ flapping: e.target.checked || undefined })} /> Flapping</label>
              <label className="al-check"><input type="checkbox" checked={!!filters.paused} onChange={(e) => set({ paused: e.target.checked || undefined })} /> Paused</label>
              <label className="al-check"><input type="checkbox" checked={!!filters.unassigned} onChange={(e) => set({ unassigned: e.target.checked || undefined })} /> Unassigned</label>
              <span className="al-scope">In these {items.length.toLocaleString()} loaded episodes</span>
              {nFilters > 0 && <button type="button" className="btn-ghost" onClick={() => setFilters({})}>Clear filters</button>}
            </div>
          )}
          {loadErr && (
            <div className="empty" role="alert" style={{ color: "var(--bad)" }}>
              <strong>Alert episodes could not be loaded.</strong>
              <div style={{ marginTop: 4 }}>{loadErr}</div>
              <div style={{ marginTop: 4, color: "var(--muted)" }}>
                Unknown, not all-clear.{items.length > 0 ? " Rows below may be stale." : ""}
                <AskIris topic="alerts.feed-unavailable" label="an unavailable alert feed" />
              </div>
            </div>
          )}
          {/* "within threshold" is a claim only a SUCCESSFUL read can support. */}
          {items.length === 0 ? (
            loadErr || !loaded ? null : (
              <div className="empty">
                {tabMeta.empty}
                <AskIris topic="alerts.nothing-firing" label="an empty alert list" />
              </div>
            )
          ) : shown.length === 0 ? (
            <div className="empty">No episode matches these filters. <button type="button" className="btn-ghost" onClick={() => setFilters({})}>Clear filters</button></div>
          ) : (
            <DataTable<AlertView>
              rows={shown}
              columns={columns}
              rowKey={(v) => v.id}
              rowHeight={isPhone ? 96 : 48}
              height="58vh"
              ariaLabel="Alert episodes"
              onRowClick={(v) => setSel(v.id)}
              rowAccent={(v) => severityColor(v.episode.state)}
              rowClassName={(v) => (sel === v.id ? "dtv-selected" : "")}
              initialSort={{ key: "last", dir: "desc" }}
            />
          )}
          {truncated && !loadErr && (
            <p className="lv-tiles-note" data-testid="alerts-truncated">Showing {items.length.toLocaleString()} of {total.toLocaleString()} episodes — the newest first.</p>
          )}
        </div>
      </div>
      {selected && selectedView && (
        <SidePanel
          narrow
          title={selectedView.title}
          subtitle={`${statusLabel(selected.status)} · ${selected.state}`}
          onClose={() => setSel(null)}
          testId="alert-panel"
          overlayTestId="alert-panel-overlay"
        >
          <EpisodeDetailBody
            episode={selected}
            deviceName={selectedView.device}
            onUpdated={onUpdated}
            onViewLogs={
              selected.resource && ws.enabled
                ? () => ws.openDrawer(<Logs initialQuery={`host:"${selected.resource}"`} initialSignal="syslog" rangeMinutes={60} />, { title: `Logs · ${selectedView.device}` })
                : undefined
            }
          />
        </SidePanel>
      )}
    </div>
  );
}

// Snooze presets, customer-facing.
const SNOOZE_OPTIONS = [
  { label: "30 minutes", minutes: 30 },
  { label: "2 hours", minutes: 120 },
  { label: "8 hours", minutes: 480 },
  { label: "24 hours", minutes: 1440 },
];

// EpisodeDetailBody — one episode's context + triage actions, rendered in the
// Inspector or inline. Keeps its own copy of the episode so triage responses
// update immediately even when detached into the Inspector; `onUpdated`
// reflects every change back into the table.
export function EpisodeDetailBody({
  episode,
  onUpdated,
  onViewLogs,
  deviceName,
}: {
  episode: AlertEpisode;
  onUpdated?: (ep: AlertEpisode) => void;
  onViewLogs?: () => void;
  /** The device's inventory name. The internal id is never shown (owner, 2026-11-23). */
  deviceName?: string;
}) {
  const [ep, setEp] = useState<AlertEpisode>(episode);
  const [assignee, setAssignee] = useState(episode.assigned_to ?? "");
  const [snoozeMin, setSnoozeMin] = useState(SNOOZE_OPTIONS[1].minutes);
  const [note, setNote] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  useEffect(() => {
    setEp(episode);
    setAssignee(episode.assigned_to ?? "");
  }, [episode]);

  const run = async (fn: () => Promise<AlertEpisode>) => {
    setBusy(true);
    setErr("");
    try {
      const next = await fn();
      setEp(next);
      onUpdated?.(next);
      return true;
    } catch (e) {
      setErr(operatorError(e, "The action could not be completed."));
      return false;
    } finally {
      setBusy(false);
    }
  };

  const row = (k: string, v: React.ReactNode) => (
    <div style={{ display: "flex", gap: 8, fontSize: 14, padding: "2px 0" }}>
      <span style={{ color: "var(--muted)", minWidth: 96 }}>{k}</span>
      <span>{v}</span>
    </div>
  );

  const acked = !!ep.acknowledged_by;
  const snoozed = !!ep.snoozed_until && Date.parse(ep.snoozed_until) > Date.now();

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
      <div style={{ display: "flex", gap: 6, alignItems: "center", flexWrap: "wrap" }}>
        <span className={`badge ${severityClass(ep.state)}`}>{ep.state}</span>
        <span style={{ fontWeight: 500 }}>{ep.signal}</span>
        <Chip label={statusLabel(ep.status)} tone={statusTone(ep.status)} />
        {ep.flapping && <Chip label="Flapping" tone="var(--warn)" title={`Rapid state changes detected (${ep.flip_count ?? 0} flips)`} />}
      </div>
      {ep.summary && <div style={{ fontSize: 14 }}>{alertSummary(ep, deviceName || ep.resource || "")}</div>}
      {isSuppressed(ep) && (
        <div style={{ fontSize: 14, color: "var(--muted)" }}>
          Notifications paused
          {ep.muted ? ` by ${ep.muted_by || "an operator"}` : ` until ${fmt(ep.snoozed_until)}`}.
          <AskIris topic="alerts.notifications-paused" label="paused notifications" />
        </div>
      )}
      <div>
        {row("Device", ep.resource ? <span>{deviceName || ep.resource}</span> : <span>Platform</span>)}
        {row("First seen", <span style={mono}>{fmt(ep.first_seen)}</span>)}
        {row("Last seen", <span style={mono}>{fmt(ep.last_seen)}</span>)}
        {row("Occurrences", <span style={mono}>{ep.count}</span>)}
        {acked && row("Acknowledged", <span style={mono}>{ep.acknowledged_by} · {fmt(ep.acknowledged_at)}</span>)}
        {ep.assigned_to && row("Assigned to", <span style={mono}>{ep.assigned_to}</span>)}
      </div>

      {/* Triage actions */}
      <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
        <button className="btn" disabled={busy} onClick={() => run(() => api.episodeAck(ep.id, !acked))}>
          {acked ? "Undo acknowledge" : "Acknowledge"}
        </button>
        <button
          className="btn"
          disabled={busy}
          title="Pauses notifications for this episode only — it stays visible in the queue"
          onClick={() => run(() => api.episodeMute(ep.id, !ep.muted))}
        >
          {ep.muted ? "Resume notifications" : "Mute notifications"}
        </button>
        {onViewLogs && ep.resource && (
          <button className="btn" onClick={onViewLogs}>View logs</button>
        )}
      </div>
      <div style={{ display: "flex", gap: 6, flexWrap: "wrap", alignItems: "center" }}>
        <input
          className="form-input"
          style={{ width: 160 }}
          placeholder="Username"
          aria-label="Assignee"
          value={assignee}
          maxLength={64}
          onChange={(e) => setAssignee(e.target.value)}
        />
        <button
          className="btn"
          disabled={busy || assignee.trim() === (ep.assigned_to ?? "")}
          onClick={() => run(() => api.episodeAssign(ep.id, assignee.trim()))}
        >
          {assignee.trim() || !ep.assigned_to ? "Assign" : "Clear assignee"}
        </button>
        <select
          className="app-select"
          aria-label="Snooze duration"
          value={snoozeMin}
          onChange={(e) => setSnoozeMin(Number(e.target.value))}
        >
          {SNOOZE_OPTIONS.map((o) => (
            <option key={o.minutes} value={o.minutes}>{o.label}</option>
          ))}
        </select>
        <button
          className="btn"
          disabled={busy}
          title="Pauses notifications until the time passes — the episode stays visible"
          onClick={() => run(() => api.episodeSnooze(ep.id, new Date(Date.now() + snoozeMin * 60_000).toISOString()))}
        >
          Snooze
        </button>
        {snoozed && (
          <button className="btn" disabled={busy} onClick={() => run(() => api.episodeSnooze(ep.id, ""))}>
            Clear snooze
          </button>
        )}
      </div>
      {err && <div style={{ fontSize: 14, color: "var(--crit)" }}>{err}</div>}

      {/* Notes */}
      <div>
        <div style={{ fontSize: 14, color: "var(--muted)", letterSpacing: 0.2, marginBottom: 4 }}>
          Notes
        </div>
        {(ep.notes ?? []).length === 0 ? (
          <div style={{ fontSize: 14, color: "var(--muted)" }}>No notes yet.</div>
        ) : (
          <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
            {(ep.notes ?? []).map((n, i) => (
              <div key={i} style={{ fontSize: 14, borderLeft: "2px solid var(--border)", paddingLeft: 8 }}>
                <div style={{ color: "var(--muted)" }}>
                  <span style={mono}>{n.by}</span> · {fmt(n.at)}
                </div>
                <div style={{ whiteSpace: "pre-wrap" }}>{n.text}</div>
              </div>
            ))}
          </div>
        )}
        <div style={{ display: "flex", gap: 6, marginTop: 6 }}>
          <input
            className="form-input"
            style={{ flex: 1 }}
            placeholder="Add a note for the next engineer…"
            aria-label="New note"
            value={note}
            maxLength={2000}
            onChange={(e) => setNote(e.target.value)}
          />
          <button
            className="btn"
            disabled={busy || !note.trim()}
            onClick={async () => {
              if (await run(() => api.episodeNote(ep.id, note.trim()))) setNote("");
            }}
          >
            Add note
          </button>
        </div>
      </div>
    </div>
  );
}

import { useCallback, useEffect, useMemo, useState } from "react";
import { fmtDateTime } from "../lib/time";
import { api, AlertEpisode } from "../services/api";
import { severityClass, severityColor, severityRank } from "../theme/severity";
import DataTable, { Column } from "../components/DataTable";
import { Segmented } from "../components/ui";
import { useWorkspace } from "../context/workspace";
import { NocHeader, NocKpis, NocKpi, Chip, LiveChip } from "../components/noc";
import Logs from "./Logs";
import { operatorError } from "../lib/errors";
// Active Alerts, grouped by EPISODE: repeated firings of the same
// (resource, signal, state) collapse into one row with first/last/count,
// flap detection and triage (acknowledge / assign / mute / snooze / notes).
// Muting or snoozing pauses NOTIFICATIONS only — the episode stays visible
// with its paused state shown honestly. Selecting a row opens the episode in
// the dockable Inspector (shell-v2) with a "View logs" pivot; v1 falls back
// to an inline detail section.

const mono: React.CSSProperties = { fontFamily: "var(--font-mono, monospace)", fontSize: 12 };

type EpisodeFilter = "open" | "closed" | "all";

const isSuppressed = (e: AlertEpisode) =>
  !!e.muted || (!!e.snoozed_until && Date.parse(e.snoozed_until) > Date.now());

const statusLabel = (s: AlertEpisode["status"]) =>
  s === "active" ? "Active" : s === "cleared" ? "Cleared" : "Closed";

const statusTone = (s: AlertEpisode["status"]) =>
  s === "active" ? "var(--warn)" : s === "cleared" ? "var(--ok)" : "var(--fg-subtle)";

// Labeled, mode-aware time rendering (lib/time is the single time authority —
// never a bare toLocaleString, which shows an unlabeled ambiguous clock).
const fmt = (iso?: string) => (iso ? fmtDateTime(iso) : "—");

export default function Alerts() {
  const [items, setItems] = useState<AlertEpisode[]>([]);
  const [total, setTotal] = useState(0);
  const [truncated, setTruncated] = useState(false);
  const [rawFiring, setRawFiring] = useState(0);
  const [filter, setFilter] = useState<EpisodeFilter>("open");
  const [sel, setSel] = useState<string | null>(null);
  // loadErr — this page's OWN failure state. It cannot be delegated to the
  // top-level health indicator: that polls /healthz, which stays 200 while a
  // route-scoped 500 takes this feed down. Without it an alerts outage rendered
  // green zeros and "all monitored conditions are within threshold".
  const [loadErr, setLoadErr] = useState<string | null>(null);
  const [loaded, setLoaded] = useState(false);
  const ws = useWorkspace();

  const load = useCallback(async () => {
    try {
      const [ep, raw] = await Promise.all([api.alertEpisodes(filter), api.alerts()]);
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
  }, [filter]);

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

  const columns = useMemo<Column<AlertEpisode>[]>(() => [
    { key: "signal", header: "Monitor", width: "16%", sortable: true, text: (e) => e.signal,
      render: (e) => <span title={e.signal}>{e.signal}</span> },
    { key: "state", header: "Severity", width: 92, sortable: true,
      text: (e) => e.state, sortValue: (e) => severityRank(e.state),
      render: (e) => <span className={`badge ${severityClass(e.state)}`}>{e.state}</span> },
    { key: "resource", header: "Resource", width: 140, sortable: true, text: (e) => e.resource ?? "",
      render: (e) => <span style={mono}>{e.resource || "Platform"}</span> },
    { key: "count", header: "Occurrences", width: 104, sortable: true,
      text: (e) => String(e.count), sortValue: (e) => e.count,
      render: (e) => (
        <span className="badge" title={`${e.count} firing${e.count === 1 ? "" : "s"} folded into this episode`}>
          ×{e.count}
        </span>
      ) },
    { key: "status", header: "Status", width: 230, sortable: true, text: (e) => e.status,
      render: (e) => (
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
      ) },
    { key: "first", header: "First seen", width: 156, sortable: true,
      sortValue: (e) => Date.parse(e.first_seen) || 0,
      render: (e) => fmt(e.first_seen) },
    { key: "last", header: "Last seen", width: 156, sortable: true,
      sortValue: (e) => Date.parse(e.last_seen) || 0,
      render: (e) => fmt(e.last_seen) },
  ], []);

  const select = (e: AlertEpisode) => {
    setSel(e.id);
    if (ws.enabled) {
      ws.openInspector(
        <EpisodeDetailBody
          episode={e}
          onUpdated={onUpdated}
          onViewLogs={
            e.resource
              ? () => ws.openDrawer(<Logs initialQuery={`host:"${e.resource}"`} initialSignal="syslog" rangeMinutes={60} />, { title: `Logs · ${e.resource}` })
              : undefined
          }
        />,
        { title: e.signal, subtitle: `${e.state}${e.resource ? ` · ${e.resource}` : ""}` },
      );
    }
  };

  const selected = !ws.enabled && sel ? items.find((e) => e.id === sel) : undefined;

  const active = items.filter((e) => e.status === "active");
  const eCrit = active.filter((e) => e.state === "critical" || e.state === "error").length;
  const eFlap = items.filter((e) => e.flapping && e.status !== "closed").length;
  const ePaused = items.filter((e) => isSuppressed(e) && e.status !== "closed").length;

  return (
    <div className="dm-board cc-board">
      <NocHeader
        title="Active Alerts"
        subtitle="Repeated firings collapse into episodes — triage each once with acknowledge, assign, mute, snooze and notes."
        chips={
          <>
            {loadErr ? (
              <Chip
                label="Alert feed unavailable"
                tone="var(--crit)"
                title="The alert episode API did not answer — the counts below are unknown, not zero."
              />
            ) : (
              <Chip
                label={`${rawFiring} firing · ${active.length} episode${active.length === 1 ? "" : "s"}`}
                tone={active.length ? "var(--warn)" : "var(--ok)"}
                title="Currently-firing alerts, folded into episodes"
              />
            )}
            {!loadErr && <LiveChip detail="rule evaluation" />}
          </>
        }
      >
        {/* On a failed read every KPI is UNKNOWN — a green zero would be a claim
            about the network that the API never made. */}
        <NocKpis cols={4}>
          <NocKpi n={loadErr ? "—" : active.length} label="Active episodes" interp={loadErr ? "unknown — feed failed" : "conditions firing now"} tone={loadErr ? "var(--fg-subtle)" : active.length ? "var(--warn)" : "var(--ok)"} />
          <NocKpi n={loadErr ? "—" : eCrit} label="Critical" interp={loadErr ? "unknown — feed failed" : "severe condition"} tone={loadErr ? "var(--fg-subtle)" : eCrit ? "var(--crit)" : undefined} />
          <NocKpi n={loadErr ? "—" : eFlap} label="Flapping" interp={loadErr ? "unknown — feed failed" : "rapid state changes"} tone={loadErr ? "var(--fg-subtle)" : eFlap ? "var(--warn)" : undefined} />
          <NocKpi n={loadErr ? "—" : ePaused} label="Notifications paused" interp={loadErr ? "unknown — feed failed" : "muted or snoozed"} tone={loadErr ? "var(--fg-subtle)" : ePaused ? "var(--fg-subtle)" : undefined} />
        </NocKpis>
      </NocHeader>
      <div className="cc-panel">
        <div className="cc-panel-h">
          <h3 className="cc-panel-t">Alert episodes</h3>
          <span className="cc-panel-meta" style={{ display: "inline-flex", alignItems: "center", gap: 10 }}>
            <Segmented<EpisodeFilter>
              value={filter}
              onChange={setFilter}
              ariaLabel="Episode filter"
              options={[
                { value: "open", label: "Open", title: "Active and recently-cleared episodes" },
                { value: "closed", label: "Closed", title: "Episodes that stayed quiet past the close window" },
                { value: "all", label: "All" },
              ]}
            />
            {loadErr
              ? "feed unavailable"
              : truncated
                ? `showing ${items.length} of ${total} episodes (most recent)`
                : `${items.length} episode${items.length === 1 ? "" : "s"}`}
          </span>
        </div>
        <div style={{ padding: "11px 13px" }}>
          {loadErr && (
            <div className="empty" role="alert" style={{ color: "var(--bad)" }}>
              <strong>Alert episodes could not be loaded.</strong>
              <div style={{ marginTop: 4 }}>{loadErr}</div>
              <div style={{ marginTop: 4, color: "var(--muted)" }}>
                Whether any condition is firing is UNKNOWN — this is not an all-clear.
                {items.length > 0 ? " The rows below are the last successful read and may be stale." : ""}
              </div>
            </div>
          )}
          {/* "within threshold" is a claim only a SUCCESSFUL read can support. */}
          {items.length === 0 ? (
            loadErr || !loaded ? null : (
              <div className="empty">
                {filter === "open"
                  ? "No open alert episodes — all monitored conditions are within threshold."
                  : "No episodes match this filter."}
              </div>
            )
          ) : (
            <DataTable<AlertEpisode>
              rows={items}
              columns={columns}
              rowKey={(e) => e.id}
              height="58vh"
              ariaLabel="Alert episodes"
              onRowClick={(e) => select(e)}
              rowAccent={(e) => severityColor(e.state)}
              rowClassName={(e) => (sel === e.id ? "dtv-selected" : "")}
              initialSort={{ key: "last", dir: "desc" }}
            />
          )}
          {selected && (
            <div style={{ marginTop: 12, borderTop: "1px solid var(--border)", paddingTop: 12 }}>
              <EpisodeDetailBody episode={selected} onUpdated={onUpdated} />
            </div>
          )}
        </div>
      </div>
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
}: {
  episode: AlertEpisode;
  onUpdated?: (ep: AlertEpisode) => void;
  onViewLogs?: () => void;
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
    <div style={{ display: "flex", gap: 8, fontSize: 12, padding: "2px 0" }}>
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
        <span style={{ fontWeight: 600 }}>{ep.signal}</span>
        <Chip label={statusLabel(ep.status)} tone={statusTone(ep.status)} />
        {ep.flapping && <Chip label="Flapping" tone="var(--warn)" title={`Rapid state changes detected (${ep.flip_count ?? 0} flips)`} />}
      </div>
      {ep.summary && <div style={{ fontSize: 13 }}>{ep.summary}</div>}
      {isSuppressed(ep) && (
        <div style={{ fontSize: 12, color: "var(--muted)" }}>
          Notifications are paused for this episode
          {ep.muted ? ` (muted by ${ep.muted_by || "an operator"})` : ` until ${fmt(ep.snoozed_until)}`}. It stays visible here and keeps updating.
        </div>
      )}
      <div>
        {row("Resource", <span style={mono}>{ep.resource || "Platform"}</span>)}
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
      {err && <div style={{ fontSize: 12, color: "var(--crit)" }}>{err}</div>}

      {/* Notes */}
      <div>
        <div style={{ fontSize: 11, color: "var(--muted)", textTransform: "uppercase", letterSpacing: 0.4, marginBottom: 4 }}>
          Notes
        </div>
        {(ep.notes ?? []).length === 0 ? (
          <div style={{ fontSize: 12, color: "var(--muted)" }}>No notes yet.</div>
        ) : (
          <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
            {(ep.notes ?? []).map((n, i) => (
              <div key={i} style={{ fontSize: 12, borderLeft: "2px solid var(--border)", paddingLeft: 8 }}>
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

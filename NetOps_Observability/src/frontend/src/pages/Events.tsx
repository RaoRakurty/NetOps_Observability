import { useEffect, useMemo, useState } from "react";
import { api } from "../services/api";
import DataTable, { Column } from "../components/DataTable";
import { EmptyHint } from "../components/board/panels";
import { NocHeader, NocKpis, NocKpi, Chip, LiveChip } from "../components/noc";
import { humanizeSyslog } from "../lib/syslog";
import { LogTime, LogSource, LogLevel, LogMessage } from "../lib/logfmt";

// Events — a unified event stream. Merges the
// signals we already collect into one time-sorted feed: syslog (OpenSearch),
// SNMP traps (OpenSearch), and active alerts (the rules engine). No new
// collection — it aggregates existing telemetry so operators have one timeline
// to correlate against metrics and flows.

type EvType = "syslog" | "trap" | "alert";
type Ev = { ts: number; type: EvType; severity: string; source: string; message: string };

const pick = (o: Record<string, any>, keys: string[], def = ""): string => {
  for (const k of keys) { const v = o?.[k]; if (v !== undefined && v !== null && v !== "") return String(v); }
  return def;
};
const parseTs = (o: Record<string, any>): number => {
  const t = pick(o, ["@timestamp", "timestamp", "ts", "time", "fired_at"]);
  const n = Date.parse(t);
  return Number.isFinite(n) ? n : 0;
};

// OpenSearch hit → feed row mappers (shared by the initial load and Load-more).
const mapSyslog = (h: { _source?: Record<string, any> }): Ev => {
  const s = h._source || {};
  return { ts: parseTs(s), type: "syslog", severity: pick(s, ["severity", "level", "syslog_severity"], "info"), source: pick(s, ["host", "hostname", "device", "source"], "—"), message: pick(s, ["message", "msg", "content", "log"], JSON.stringify(s).slice(0, 200)) };
};
const mapTrap = (h: { _source?: Record<string, any> }): Ev => {
  const s = h._source || {};
  return { ts: parseTs(s), type: "trap", severity: pick(s, ["normalized_severity", "severity", "level"], "notice"), source: pick(s, ["device", "device.ip", "device_ip", "host", "agent"], "—"), message: pick(s, ["summary", "trap_name", "snmpTrapName", "message", "content"], "SNMP trap") };
};
const evKey = (e: Ev) => `${e.ts}-${e.type}-${e.source}-${e.message.slice(0, 40)}`;

const PAGE = 200;

export default function Events({ sinceSeconds }: { sinceSeconds?: number } = {}) {
  const since = sinceSeconds ?? 3600;
  // base = the auto-refreshed newest page; extra = user-loaded older pages.
  const [base, setBase] = useState<Ev[]>([]);
  const [extra, setExtra] = useState<Ev[]>([]);
  // TRUE window totals from OpenSearch hits.total — what actually exists, not
  // what one page holds (owner directive: DON'T HIDE).
  const [sysTotal, setSysTotal] = useState<number | null>(null);
  const [trapTotal, setTrapTotal] = useState<number | null>(null);
  const [loadingMore, setLoadingMore] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [typeFilter, setTypeFilter] = useState<"" | EvType>("");
  const [q, setQ] = useState("");

  useEffect(() => {
    let alive = true;
    setExtra([]); // window change = a new result set
    const from = new Date(Date.now() - since * 1000).toISOString();
    const load = async () => {
      try {
        // The inner .catch()es used to guarantee this function never threw, which
        // made the error renderer below DEAD CODE: a total OpenSearch outage
        // rendered as "no events in this window". Settle instead, and report every
        // failed source explicitly.
        const [sysS, trapS, alertS] = await Promise.allSettled([
          api.searchLogs({ query: "*", signal: "syslog", from, size: PAGE }),
          api.searchLogs({ query: "*", signal: "snmptrap", from, size: PAGE }),
          api.alerts(),
        ]);
        if (!alive) return;
        const sys = sysS.status === "fulfilled" ? sysS.value : null;
        const traps = trapS.status === "fulfilled" ? trapS.value : null;
        const alerts = alertS.status === "fulfilled" ? alertS.value : [];
        const failed: string[] = [];
        if (sysS.status === "rejected") failed.push("syslog");
        if (trapS.status === "rejected") failed.push("SNMP traps");
        if (alertS.status === "rejected") failed.push("alerts");
        const out: Ev[] = [];
        for (const h of sys?.hits?.hits ?? []) out.push(mapSyslog(h));
        for (const h of traps?.hits?.hits ?? []) out.push(mapTrap(h));
        for (const a of (alerts as any[]) ?? []) {
          if (a.resolved_at) continue;
          out.push({ ts: parseTs(a), type: "alert", severity: a.severity || "warning", source: a.device_id || a.rule || "—", message: a.summary || a.rule || "alert" });
        }
        out.sort((x, y) => y.ts - x.ts);
        setBase(out);
        setSysTotal(sys?.hits?.total?.value ?? null);
        setTrapTotal(traps?.hits?.total?.value ?? null);
        setErr(
          failed.length === 0
            ? null
            : `${failed.join(" and ")} could not be read — this view is incomplete and an absent event does not mean it did not happen.`,
        );
      } catch (e) {
        if (alive) setErr((e as Error).message);
      }
    };
    load();
    const id = setInterval(load, 30_000);
    return () => { alive = false; clearInterval(id); };
  }, [since]);

  // Merged view: refreshed base + loaded older pages, deduped (a refresh can
  // re-include a row that was already loaded), newest first.
  const events = useMemo(() => {
    const seen = new Set(base.map(evKey));
    const merged = base.concat(extra.filter((e) => !seen.has(evKey(e))));
    merged.sort((x, y) => y.ts - x.ts);
    return merged;
  }, [base, extra]);

  const counts = useMemo(() => {
    const c = { syslog: 0, trap: 0, alert: 0 };
    for (const e of events) c[e.type]++;
    return c;
  }, [events]);

  // What exists vs what is loaded (alerts are always complete).
  const trueTotal = (sysTotal ?? counts.syslog) + (trapTotal ?? counts.trap) + counts.alert;
  const moreSys = sysTotal !== null && counts.syslog < sysTotal;
  const moreTrap = trapTotal !== null && counts.trap < trapTotal;
  const canLoadMore = moreSys || moreTrap;

  // "Load more" — pull the next page of syslog/traps at the current per-type
  // offsets (server-bounded). Dedup in the merge absorbs window drift.
  const loadMore = async () => {
    if (!canLoadMore || loadingMore) return;
    setLoadingMore(true);
    try {
      const from = new Date(Date.now() - since * 1000).toISOString();
      const [sys, traps] = await Promise.all([
        moreSys ? api.searchLogs({ query: "*", signal: "syslog", from, size: PAGE, offset: counts.syslog }).catch(() => null) : Promise.resolve(null),
        moreTrap ? api.searchLogs({ query: "*", signal: "snmptrap", from, size: PAGE, offset: counts.trap }).catch(() => null) : Promise.resolve(null),
      ]);
      const add: Ev[] = [];
      for (const h of sys?.hits?.hits ?? []) add.push(mapSyslog(h));
      for (const h of traps?.hits?.hits ?? []) add.push(mapTrap(h));
      setExtra((x) => x.concat(add));
      if (sys?.hits?.total?.value !== undefined) setSysTotal(sys.hits.total.value);
      if (traps?.hits?.total?.value !== undefined) setTrapTotal(traps.hits.total.value);
    } finally {
      setLoadingMore(false);
    }
  };

  const filtered = useMemo(() => {
    const needle = q.trim().toLowerCase();
    return events.filter((e) =>
      (!typeFilter || e.type === typeFilter) &&
      (!needle || e.message.toLowerCase().includes(needle) || e.source.toLowerCase().includes(needle)),
    );
  }, [events, typeFilter, q]);

  const [sel, setSel] = useState<Ev | null>(null);
  const cols = useMemo<Column<Ev>[]>(() => [
    { key: "ts", header: "Time", width: "176px", sortable: true, sortValue: (e) => e.ts, render: (e) => <LogTime ts={e.ts} /> },
    { key: "type", header: "Type", width: "84px", sortable: true, text: (e) => e.type, render: (e) => <span className="badge accent-badge">{e.type}</span> },
    { key: "severity", header: "Severity", width: "108px", sortable: true, text: (e) => e.severity, render: (e) => <LogLevel level={e.severity} /> },
    { key: "source", header: "Source", width: "180px", sortable: true, text: (e) => e.source, render: (e) => <LogSource source={e.source} /> },
    {
      key: "message", header: "Event", sortable: false, render: (e) => {
        const f = e.type === "syslog" ? humanizeSyslog(e.message) : null;
        const text = f ? f.summary : e.message;
        return (
          <span style={{ display: "inline-flex", gap: 8, alignItems: "baseline", minWidth: 0 }}>
            <LogMessage text={text} />
            {f?.subsystem && <span className="lf-source" style={{ fontSize: 11, flex: "none", opacity: .85 }}>{f.subsystem}</span>}
          </span>
        );
      },
    },
  ], []);

  return (
    <div className="dm-board cc-board">
      <NocHeader
        title="Events"
        subtitle="Raw signal stream — syslog, SNMP traps and active alerts on one timeline to correlate against metrics and flows."
        chips={<>
          <Chip label={trueTotal > events.length ? `${events.length.toLocaleString()} of ${trueTotal.toLocaleString()} signals loaded` : `${events.length.toLocaleString()} signals`} />
          <LiveChip detail="merged feed" />
        </>}
      >
        <NocKpis>
          {/* True window totals (hits.total), never the loaded page length. */}
          <NocKpi n={trueTotal.toLocaleString()} label="Total events" interp="in this window" />
          <NocKpi n={(sysTotal ?? counts.syslog).toLocaleString()} label="Syslog" interp="device log events" />
          <NocKpi n={(trapTotal ?? counts.trap).toLocaleString()} label="SNMP traps" interp="pushed notifications" />
          <NocKpi n={counts.alert} label="Active alerts" interp="monitor-rule fired" tone={counts.alert > 0 ? "var(--warn)" : undefined} />
        </NocKpis>
      </NocHeader>
      <div className="cc-panel">
        <div className="cc-panel-h">
          <h3 className="cc-panel-t">Signal stream</h3>
          <span className="cc-panel-meta">
            {trueTotal > events.length
              ? `showing ${filtered.length.toLocaleString()} of ${trueTotal.toLocaleString()} in window`
              : `${filtered.length.toLocaleString()}`}
          </span>
        </div>
        <div style={{ padding: "11px 13px" }}>
          <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap", marginBottom: 10 }}>
            <input className="flows-filter-input" placeholder="Search events…" value={q} onChange={(e) => setQ(e.target.value)}
              style={{ padding: "6px 9px", fontSize: 12.5, border: "1px solid var(--border)", borderRadius: "var(--radius-sm)", background: "var(--surface)", color: "var(--fg)", width: 220 }} />
            <span className="seg-mini" role="group" aria-label="Type">
              {(["", "syslog", "trap", "alert"] as const).map((t) => (
                <button key={t || "all"} className={typeFilter === t ? "on" : ""} onClick={() => setTypeFilter(t)}>{t || "All"}</button>
              ))}
            </span>
          </div>
          {/* The error is stated whether or not partial rows arrived; the "no
              events" hint is suppressed while it stands, so a failed read is
              never rendered as a quiet window. */}
          {err && <div className="empty" role="alert" style={{ color: "var(--bad)" }}>{err}</div>}
          {filtered.length > 0 ? (
            <DataTable<Ev> rows={filtered} columns={cols} rowKey={evKey} height={520} ariaLabel="Event stream" initialSort={{ key: "ts", dir: "desc" }} onRowClick={(e) => setSel(e)} />
          ) : err ? null : (
            <EmptyHint kind="logs" />
          )}
          {/* Every truncated feed SAYS it's truncated and offers the rest. */}
          {canLoadMore && !err && (
            <div style={{ display: "flex", justifyContent: "center", marginTop: 10 }}>
              <button type="button" className="chip" onClick={loadMore} disabled={loadingMore}
                title="Fetch the next page of syslog / SNMP-trap events in this window">
                {loadingMore
                  ? "Loading…"
                  : `Load more (${events.length.toLocaleString()} of ${trueTotal.toLocaleString()} loaded)`}
              </button>
            </div>
          )}
        </div>
      </div>
      {sel && (
        <div className="ev-detail-scrim" onClick={() => setSel(null)}>
          <aside className="ev-detail" onClick={(e) => e.stopPropagation()}>
            <header className="ev-detail-h">
              <LogLevel level={sel.severity} />
              <span className="badge accent-badge">{sel.type}</span>
              <button className="ev-detail-x" onClick={() => setSel(null)} aria-label="Close">×</button>
            </header>
            <dl className="ev-detail-grid">
              <dt>Time</dt><dd><LogTime ts={sel.ts} /></dd>
              <dt>Type</dt><dd>{sel.type === "syslog" ? "Syslog (raw signal)" : sel.type === "trap" ? "SNMP trap" : "Active alert"}</dd>
              <dt>Source</dt><dd><LogSource source={sel.source} /></dd>
              <dt>Linked to</dt><dd style={{ color: "var(--fg-muted)" }}>Pending correlation</dd>
            </dl>
            {(() => {
              const f = sel.type === "syslog" ? humanizeSyslog(sel.message) : null;
              return f && f.summary && f.summary !== sel.message ? (
                <>
                  <div className="ev-detail-msg-l">Message</div>
                  <div style={{ fontSize: 13, color: "var(--fg)", lineHeight: 1.5, marginBottom: 14 }}>
                    {f.severity && <span className="cc-badge" style={{ color: "var(--warn)", borderColor: "var(--warn)", marginRight: 8 }}>{f.severity}</span>}
                    {f.summary}
                  </div>
                </>
              ) : null;
            })()}
            <div className="ev-detail-msg-l">Raw message</div>
            <pre className="ev-detail-msg"><LogMessage text={sel.message} clamp={false} /></pre>
          </aside>
        </div>
      )}
    </div>
  );
}

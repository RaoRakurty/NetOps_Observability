import { useEffect, useMemo, useState } from "react";
import { api } from "../services/api";
import DataTable, { Column } from "../components/DataTable";
import { EmptyHint } from "../components/board/panels";
import { NocHeader, NocKpis, NocKpi, Chip, LiveChip } from "../components/noc";
import { humanizeSyslog } from "../lib/syslog";

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

// Normalize the various syslog severity spellings to our sev tone buckets.
const sevTone = (s: string): "" | "good" | "warn" | "bad" => {
  const x = (s || "").toLowerCase();
  if (["critical", "crit", "emergency", "emerg", "alert", "error", "err", "1", "2", "3"].includes(x)) return "bad";
  if (["warning", "warn", "4"].includes(x)) return "warn";
  if (["notice", "info", "informational", "5", "6"].includes(x)) return "";
  return "";
};

export default function Events({ sinceSeconds }: { sinceSeconds?: number } = {}) {
  const since = sinceSeconds ?? 3600;
  const [events, setEvents] = useState<Ev[]>([]);
  const [err, setErr] = useState<string | null>(null);
  const [typeFilter, setTypeFilter] = useState<"" | EvType>("");
  const [q, setQ] = useState("");

  useEffect(() => {
    let alive = true;
    const from = new Date(Date.now() - since * 1000).toISOString();
    const load = async () => {
      try {
        const [sys, traps, alerts] = await Promise.all([
          api.searchLogs({ query: "*", signal: "syslog", from, size: 200 }).catch(() => null),
          api.searchLogs({ query: "*", signal: "snmptrap", from, size: 200 }).catch(() => null),
          api.alerts().catch(() => []),
        ]);
        if (!alive) return;
        const out: Ev[] = [];
        for (const h of sys?.hits?.hits ?? []) {
          const s = h._source || {};
          out.push({ ts: parseTs(s), type: "syslog", severity: pick(s, ["severity", "level", "syslog_severity"], "info"), source: pick(s, ["host", "hostname", "device", "source"], "—"), message: pick(s, ["message", "msg", "content", "log"], JSON.stringify(s).slice(0, 200)) });
        }
        for (const h of traps?.hits?.hits ?? []) {
          const s = h._source || {};
          out.push({ ts: parseTs(s), type: "trap", severity: pick(s, ["severity", "ifOperStatus", "level"], "notice"), source: pick(s, ["device.ip", "device_ip", "host", "agent"], "—"), message: pick(s, ["snmpTrapName", "snmptrapname", "message", "content"], "SNMP trap") });
        }
        for (const a of (alerts as any[]) ?? []) {
          if (a.resolved_at) continue;
          out.push({ ts: parseTs(a), type: "alert", severity: a.severity || "warning", source: a.device_id || a.rule || "—", message: a.summary || a.rule || "alert" });
        }
        out.sort((x, y) => y.ts - x.ts);
        setEvents(out);
        setErr(null);
      } catch (e) {
        if (alive) setErr((e as Error).message);
      }
    };
    load();
    const id = setInterval(load, 30_000);
    return () => { alive = false; clearInterval(id); };
  }, [since]);

  const counts = useMemo(() => {
    const c = { syslog: 0, trap: 0, alert: 0 };
    for (const e of events) c[e.type]++;
    return c;
  }, [events]);

  const filtered = useMemo(() => {
    const needle = q.trim().toLowerCase();
    return events.filter((e) =>
      (!typeFilter || e.type === typeFilter) &&
      (!needle || e.message.toLowerCase().includes(needle) || e.source.toLowerCase().includes(needle)),
    );
  }, [events, typeFilter, q]);

  const [sel, setSel] = useState<Ev | null>(null);
  const cols = useMemo<Column<Ev>[]>(() => [
    { key: "ts", header: "Time", width: "160px", sortable: true, sortValue: (e) => e.ts, render: (e) => (e.ts ? new Date(e.ts).toLocaleString() : "—") },
    { key: "type", header: "Type", width: "84px", sortable: true, text: (e) => e.type, render: (e) => <span className="badge accent-badge">{e.type}</span> },
    { key: "severity", header: "Severity", width: "104px", sortable: true, text: (e) => e.severity, render: (e) => <span className={`badge ${sevTone(e.severity)}`}>{e.severity}</span> },
    { key: "source", header: "Source", width: "180px", sortable: true, text: (e) => e.source, render: (e) => <span style={{ fontFamily: "var(--font-mono, monospace)", fontSize: 12 }}>{e.source}</span> },
    {
      key: "message", header: "Event", sortable: false, render: (e) => {
        const f = e.type === "syslog" ? humanizeSyslog(e.message) : null;
        const text = f ? f.summary : e.message;
        return (
          <span title={e.message} style={{ display: "inline-flex", gap: 8, alignItems: "baseline", minWidth: 0 }}>
            <span style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{text}</span>
            {f?.subsystem && <span style={{ color: "var(--fg-subtle)", fontSize: 11, fontFamily: "var(--font-mono)", flex: "none" }}>{f.subsystem}</span>}
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
        chips={<><Chip label={`${events.length} signals`} /><LiveChip detail="merged feed" /></>}
      >
        <NocKpis>
          <NocKpi n={events.length} label="Total events" interp="raw signals ingested" />
          <NocKpi n={counts.syslog} label="Syslog" interp="device log events" />
          <NocKpi n={counts.trap} label="SNMP traps" interp="pushed notifications" />
          <NocKpi n={counts.alert} label="Active alerts" interp="monitor-rule fired" tone={counts.alert > 0 ? "var(--warn)" : undefined} />
        </NocKpis>
      </NocHeader>
      <div className="cc-panel">
        <div className="cc-panel-h">
          <h3 className="cc-panel-t">Signal stream</h3>
          <span className="cc-panel-meta">{filtered.length} shown · click a row for detail</span>
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
          {err ? (
            <div className="empty" style={{ color: "var(--bad)" }}>{err}</div>
          ) : filtered.length === 0 ? (
            <EmptyHint kind="logs" />
          ) : (
            <DataTable<Ev> rows={filtered} columns={cols} rowKey={(e) => `${e.ts}-${e.type}-${e.source}-${e.message.slice(0, 40)}`} height={520} ariaLabel="Event stream" initialSort={{ key: "ts", dir: "desc" }} onRowClick={(e) => setSel(e)} />
          )}
        </div>
      </div>
      {sel && (
        <div className="ev-detail-scrim" onClick={() => setSel(null)}>
          <aside className="ev-detail" onClick={(e) => e.stopPropagation()}>
            <header className="ev-detail-h">
              <span className={`badge ${sevTone(sel.severity)}`}>{sel.severity}</span>
              <span className="badge accent-badge">{sel.type}</span>
              <button className="ev-detail-x" onClick={() => setSel(null)} aria-label="Close">×</button>
            </header>
            <dl className="ev-detail-grid">
              <dt>Time</dt><dd className="ev-mono">{sel.ts ? new Date(sel.ts).toLocaleString() : "Unknown"}</dd>
              <dt>Type</dt><dd>{sel.type === "syslog" ? "Syslog (raw signal)" : sel.type === "trap" ? "SNMP trap" : "Active alert"}</dd>
              <dt>Source</dt><dd className="ev-mono">{sel.source || "Unknown"}</dd>
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
            <pre className="ev-detail-msg">{sel.message}</pre>
          </aside>
        </div>
      )}
    </div>
  );
}

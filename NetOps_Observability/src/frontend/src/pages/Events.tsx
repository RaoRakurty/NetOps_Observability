import { useEffect, useMemo, useState } from "react";
import { api } from "../services/api";
import { StatStrip, Stat } from "../components/ui";
import DataTable, { Column } from "../components/DataTable";
import { Group, Panel, EmptyHint } from "../components/board/panels";

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

  const cols = useMemo<Column<Ev>[]>(() => [
    { key: "ts", header: "Time", width: "160px", sortable: true, sortValue: (e) => e.ts, render: (e) => (e.ts ? new Date(e.ts).toLocaleString() : "—") },
    { key: "type", header: "Type", width: "84px", sortable: true, text: (e) => e.type, render: (e) => <span className="badge accent-badge">{e.type}</span> },
    { key: "severity", header: "Severity", width: "104px", sortable: true, text: (e) => e.severity, render: (e) => <span className={`badge ${sevTone(e.severity)}`}>{e.severity}</span> },
    { key: "source", header: "Source", width: "180px", sortable: true, text: (e) => e.source, render: (e) => <span style={{ fontFamily: "var(--font-mono, monospace)", fontSize: 12 }}>{e.source}</span> },
    { key: "message", header: "Event", sortable: false, render: (e) => <span title={e.message}>{e.message}</span> },
  ], []);

  return (
    <div className="dm-board">
      <Group title="Event stream" hue="#EC4899">
        <StatStrip>
          <Stat label="Total events" value={events.length} />
          <Stat label="Syslog" value={counts.syslog} />
          <Stat label="SNMP traps" value={counts.trap} />
          <Stat label="Active alerts" value={counts.alert} tone={counts.alert > 0 ? "warn" : "good"} />
        </StatStrip>
        <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
          <input className="flows-filter-input" placeholder="Filter events…" value={q} onChange={(e) => setQ(e.target.value)}
            style={{ padding: "6px 9px", fontSize: 12.5, border: "1px solid var(--border)", borderRadius: "var(--radius-sm)", background: "var(--surface)", color: "var(--fg)", width: 220 }} />
          <span className="seg-mini" role="group" aria-label="Type">
            {(["", "syslog", "trap", "alert"] as const).map((t) => (
              <button key={t || "all"} className={typeFilter === t ? "on" : ""} onClick={() => setTypeFilter(t)}>{t || "All"}</button>
            ))}
          </span>
          <span className="mini-meta" style={{ marginLeft: "auto" }}>Merged from syslog · SNMP traps · alerts</span>
        </div>
        <Panel title={`Events (${filtered.length})`}>
          {err ? (
            <div className="empty" style={{ color: "var(--bad)" }}>{err}</div>
          ) : filtered.length === 0 ? (
            <EmptyHint kind="logs" />
          ) : (
            <DataTable<Ev> rows={filtered} columns={cols} rowKey={(e) => `${e.ts}-${e.type}-${e.source}-${e.message.slice(0, 40)}`} height={520} ariaLabel="Event stream" initialSort={{ key: "ts", dir: "desc" }} />
          )}
        </Panel>
      </Group>
    </div>
  );
}

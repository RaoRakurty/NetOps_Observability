// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

import { fmtDateTime, parseTs } from "../lib/time";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { api, OSHit, CloudResourceRow, CloudChangeRow } from "../services/api";
import { severityColor } from "../theme/severity";
import { LogTime, LogMessage } from "../lib/logfmt";
import DataTable, { Column } from "../components/DataTable";
import { useWorkspace } from "../context/workspace";
import { listProviders, providerShort } from "./appobs/providers";

// ── Unified Cloud Logs ──────────────────────────────────────────────────────
// One screen showing every cloud log family together, a lane per family. The raw
// WAF / Load Balancer / DNS / Flow / Host / Change logs are indexed (tagged with
// cloud_family / cloud_provider / resource_id at ingest) into netops-cloudlogs-*
// and searched via /api/logs/search?signal=cloud — so they are REAL searchable
// logs, not only correlation signals. Inventory and Change reuse the existing
// tenant-scoped cloud surfaces. Honesty-first: a lane shows only what actually
// ingested; empty = "no logs in range", never fabricated.

type LaneSource = "log" | "inventory" | "change";
type Lane = { id: string; label: string; source: LaneSource; family?: string };

// Customer-facing labels (no schema kinds): "Load Balancer", "Web Application
// Firewall" — not "cloud_lb_log" / "cloud_waf_log".
const LANES: Lane[] = [
  { id: "inventory", label: "Inventory", source: "inventory" },
  { id: "flow", label: "Flow", source: "log", family: "flow" },
  { id: "lb", label: "Load Balancer", source: "log", family: "lb" },
  { id: "waf", label: "Web Application Firewall", source: "log", family: "waf" },
  { id: "dns", label: "DNS", source: "log", family: "dns" },
  { id: "change", label: "Change", source: "change" },
  { id: "host", label: "Host", source: "log", family: "host" },
];

// Registry-driven (appobs/providers.tsx): the filter offers every registered
// provider — adding a provider needs no edit here.
const PROVIDERS = [
  { id: "", label: "All providers" },
  ...listProviders().map((d) => ({ id: d.id, label: d.short })),
];

const RANGES = [
  { label: "Last 1h", minutes: 60 },
  { label: "Last 6h", minutes: 360 },
  { label: "Last 24h", minutes: 1440 },
  { label: "Last 7d", minutes: 10080 },
];

// Short display label for a provider token — registry-backed, "" stays "".
const providerShortLabel = (p: string): string => (p ? providerShort(p) : "");

// A single normalized row every lane maps onto, so one DataTable renders them all.
type CloudRow = {
  id: string;
  ts: string;
  provider: string;
  account: string;
  resource: string;
  detail: string;
  level: string;
  raw: Record<string, unknown>;
};

// Escape Lucene special characters in a user-supplied field value so a filter
// term can't change the query structure (defense-in-depth; the backend already
// tenant-scopes every cloud search).
function luceneEscape(s: string): string {
  return s.replace(/([+\-!(){}[\]^"~*?:\\/ ]|&&|\|\|)/g, "\\$1");
}

// Deep-link params (#/explore/logs/cloud?family=&provider=&resource_id=&account=). The
// path-causality RCA device-in-path drill (design §5) links here to open ONE
// device's family-tagged logs in context. Read once at mount; unknown family →
// falls back to the default lane (honest, never an empty tab).
function drillParams(): { family?: string; provider?: string; resourceId?: string; account?: string } {
  const qs = (typeof location !== "undefined" ? location.hash : "").split("?")[1] || "";
  const p = new URLSearchParams(qs);
  const family = p.get("family") || undefined;
  const laneMatch = family && LANES.some((l) => l.family === family || l.id === family) ? family : undefined;
  return {
    family: laneMatch,
    provider: p.get("provider") || undefined,
    resourceId: p.get("resource_id") || undefined,
    account: p.get("account") || undefined,
  };
}

export default function CloudLogs() {
  const drill = useMemo(drillParams, []);
  const [laneId, setLaneId] = useState<string>(() => {
    if (!drill.family) return "inventory";
    return LANES.find((l) => l.family === drill.family)?.id ?? drill.family;
  });
  const [provider, setProvider] = useState(() => drill.provider ?? "");
  const [account, setAccount] = useState(() => drill.account ?? "");
  const [resourceId, setResourceId] = useState(() => drill.resourceId ?? "");
  const [text, setText] = useState("");
  const [minutes, setMinutes] = useState(360);
  const [size, setSize] = useState(500);
  const [rows, setRows] = useState<CloudRow[]>([]);
  const [total, setTotal] = useState<number | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [detail, setDetail] = useState<CloudRow | null>(null);
  const ws = useWorkspace();

  const lane = useMemo(() => LANES.find((l) => l.id === laneId) ?? LANES[0], [laneId]);

  const osRow = (h: OSHit, i: number): CloudRow => {
    const s = h._source || {};
    const ts = String(s.timestamp || s["@timestamp"] || s.ts || s.time || "");
    return {
      id: h._id || `${h._index}#${i}`,
      ts,
      provider: String(s.cloud_provider || ""),
      account: String(s.account || ""),
      resource: String(s.resource_id || ""),
      detail: String(s.message || s.msg || ""),
      level: String(s.level || s.severity || ""),
      raw: s,
    };
  };

  const invRow = (r: CloudResourceRow, i: number): CloudRow => ({
    id: r.resource_id || `inv#${i}`,
    ts: String(r.last_seen_at || r.discovered_at || ""),
    provider: String(r.cloud_provider || ""),
    account: String(r.account_id || ""),
    resource: String(r.resource_name || r.resource_id || ""),
    detail: [r.resource_type, r.power_state, r.app_name || r.app_id].filter(Boolean).join(" · "),
    level: "",
    raw: r as unknown as Record<string, unknown>,
  });

  const changeRow = (c: CloudChangeRow, i: number): CloudRow => ({
    id: `${c.time}#${c.resource}#${i}`,
    ts: String(c.time || ""),
    provider: String(c.cloud_ref?.provider || c.source || ""),
    account: String(c.cloud_ref?.account || ""),
    resource: String(c.resource || c.cloud_ref?.resource_id || ""),
    detail: [c.change_type, c.actor ? `by ${c.actor}` : ""].filter(Boolean).join(" "),
    level: "",
    raw: c as unknown as Record<string, unknown>,
  });

  // Client-side facet filter (provider / account / resource) — applied to the
  // Inventory + Change lanes, which fetch a tenant-scoped set the server doesn't
  // pre-narrow. The log lanes narrow server-side in the Lucene query instead.
  const facetFilter = useCallback(
    (r: CloudRow) =>
      (!provider || r.provider.toLowerCase() === provider) &&
      (!account || r.account.toLowerCase().includes(account.toLowerCase())) &&
      (!resourceId || r.resource.toLowerCase().includes(resourceId.toLowerCase())),
    [provider, account, resourceId],
  );

  const reqId = useRef(0);
  const run = useCallback(async () => {
    const my = ++reqId.current;
    setBusy(true);
    setError(null);
    try {
      let out: CloudRow[] = [];
      let matched: number | null = null;
      if (lane.source === "log") {
        const end = new Date();
        const start = new Date(end.getTime() - minutes * 60_000);
        const clauses = [`cloud_family:${lane.family}`];
        if (provider) clauses.push(`cloud_provider:${provider}`);
        if (account.trim()) clauses.push(`account:${luceneEscape(account.trim())}`);
        if (resourceId.trim()) clauses.push(`resource_id:*${luceneEscape(resourceId.trim())}*`);
        if (text.trim() && text.trim() !== "*") clauses.push(`(${text.trim()})`);
        const r = await api.searchLogs({
          query: clauses.join(" AND "),
          from: start.toISOString(),
          to: end.toISOString(),
          size,
          signal: "cloud",
        });
        out = (r?.hits?.hits ?? []).map(osRow);
        matched = r?.hits?.total?.value ?? null;
      } else if (lane.source === "inventory") {
        const r = await api.cloudResources();
        out = (r?.resources ?? []).map(invRow).filter(facetFilter);
      } else {
        const r = await api.cloudChanges(undefined, size);
        out = (r?.changes ?? []).map(changeRow).filter(facetFilter);
      }
      if (my !== reqId.current) return; // a newer request superseded this one
      setRows(out);
      setTotal(matched);
    } catch (e) {
      if (my !== reqId.current) return;
      setError((e as Error).message);
      setRows([]);
      setTotal(null);
    } finally {
      if (my === reqId.current) setBusy(false);
    }
  }, [lane, minutes, provider, account, resourceId, text, size, facetFilter]);

  // Re-run whenever the lane or any filter changes.
  useEffect(() => {
    run();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [laneId, provider, account, resourceId, minutes, size]);

  // Free text: server-side for log lanes (re-query), client-side for the others
  // (DataTable's own filter). We pass it to DataTable only for non-log lanes.
  const tableFilter = lane.source === "log" ? "" : text;

  // UI-words sweep 5 (tracker 270): the row count is a STATED FACT, and a heading
  // is budgeted at four words — so it is built here and the <h2> renders the lane
  // name plus this one token.
  const countLabel = total !== null && total > rows.length
    ? `(${rows.length}/${total})`
    : `(${rows.length})`;

  const openDetail = (r: CloudRow) => {
    setDetail(r);
    if (ws.enabled) {
      ws.openInspector(<CloudRowDetail row={r} />, {
        title: r.resource || lane.label,
        subtitle: `${providerShortLabel(r.provider) || r.provider || "cloud"}${r.ts ? " · " + fmtDateTime(r.ts) : ""}`,
      });
    }
  };

  const columns = useMemo<Column<CloudRow>[]>(() => {
    const cols: Column<CloudRow>[] = [
      {
        key: "ts", header: "Time", width: 180, sortable: true,
        sortValue: (r) => parseTs(r.ts)?.getTime() || 0,
        text: (r) => r.ts,
        render: (r) => (r.ts ? <LogTime ts={r.ts} /> : <span style={{ color: "var(--muted)" }}>—</span>),
      },
      {
        key: "provider", header: "Provider", width: 96, sortable: true, text: (r) => r.provider,
        render: (r) => (
          <span className="clog-badge">{providerShortLabel(r.provider) || r.provider || "—"}</span>
        ),
      },
      {
        key: "account", header: "Account", width: 150, sortable: true, text: (r) => r.account,
        render: (r) => <span className="clog-mono">{r.account || "—"}</span>,
      },
      {
        key: "resource", header: lane.id === "dns" ? "Name" : "Resource", width: 240, sortable: true,
        text: (r) => r.resource,
        render: (r) => <span className="clog-mono" title={r.resource}>{r.resource || "—"}</span>,
      },
      {
        key: "detail", header: lane.source === "change" ? "Change" : "Detail",
        text: (r) => r.detail,
        render: (r) => <LogMessage text={r.detail} />,
      },
    ];
    return cols;
  }, [lane]);

  return (
    <>
      <style>{CLOG_CSS}</style>
      <div className="card">
        <div className="xpl-head">
          <h2>Cloud Logs</h2>
          <span className="xpl-sub">
            Every cloud log family in one place — raw, tagged, searchable. A lane
            shows only what actually ingested.
          </span>
        </div>

        <div className="clog-tabs" role="tablist" aria-label="Cloud log families">
          {LANES.map((l) => (
            <button
              key={l.id}
              role="tab"
              aria-selected={l.id === laneId}
              className={`clog-tab${l.id === laneId ? " active" : ""}`}
              onClick={() => setLaneId(l.id)}
            >
              {l.label}
            </button>
          ))}
        </div>

        <form
          className="xpl-bar clog-bar"
          onSubmit={(e) => { e.preventDefault(); run(); }}
        >
          <input
            className="xpl-q"
            value={text}
            onChange={(e) => setText(e.target.value)}
            placeholder={lane.source === "log" ? "Search — e.g. rcode:SERVFAIL" : "Filter loaded rows…"}
          />
          <select value={provider} onChange={(e) => setProvider(e.target.value)} aria-label="Provider">
            {PROVIDERS.map((p) => <option key={p.id} value={p.id}>{p.label}</option>)}
          </select>
          <input
            className="clog-facet"
            value={account}
            onChange={(e) => setAccount(e.target.value)}
            placeholder="Account"
            aria-label="Account"
          />
          <input
            className="clog-facet"
            value={resourceId}
            onChange={(e) => setResourceId(e.target.value)}
            placeholder="Resource id"
            aria-label="Resource id"
          />
          {lane.source === "log" && (
            <select value={minutes} onChange={(e) => setMinutes(Number(e.target.value))} aria-label="Time range">
              {RANGES.map((r) => <option key={r.minutes} value={r.minutes}>{r.label}</option>)}
            </select>
          )}
          <select value={size} onChange={(e) => setSize(Number(e.target.value))} aria-label="Result size">
            {[200, 500, 1000, 5000].map((n) => <option key={n} value={n}>{n} rows</option>)}
          </select>
          <button className="btn-primary" type="submit" disabled={busy}>
            {busy ? "Loading…" : "Refresh"}
          </button>
        </form>
        {error && (
          <p style={{ color: "var(--bad)", marginTop: 10, fontSize: 13 }}>
            <strong>Error:</strong> {error}
          </p>
        )}
      </div>

      <div className="card">
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 8, flexWrap: "wrap" }}>
          <h2 style={{ margin: 0 }}>{lane.label} {countLabel}</h2>
        </div>
        <DataTable<CloudRow>
          rows={rows}
          columns={columns}
          rowKey={(r) => r.id}
          filter={tableFilter}
          height="60vh"
          ariaLabel={`${lane.label} cloud logs`}
          initialSort={{ key: "ts", dir: "desc" }}
          onRowClick={openDetail}
          rowAccent={(r) => (r.level ? severityColor(r.level) : undefined)}
          rowClassName={(r) => (detail?.id === r.id ? "dtv-selected" : "")}
          empty={busy ? "Loading…" : "No log entries in this window."}
        />
        {!ws.enabled && detail && (
          <div style={{ marginTop: 12, borderTop: "1px solid var(--border, #2a2f3a)", paddingTop: 12 }}>
            <CloudRowDetail row={detail} />
          </div>
        )}
      </div>
    </>
  );
}

// The full record behind one row — the payoff of tagging raw cloud logs: the
// exact document, pretty-printed, one click from the lane.
export function CloudRowDetail({ row }: { row: CloudRow }) {
  const lbl = (s: string) => (
    <div style={{ fontSize: 11, color: "var(--muted)", textTransform: "uppercase", letterSpacing: 0.4, marginBottom: 4 }}>{s}</div>
  );
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
      <div style={{ display: "flex", gap: 12, flexWrap: "wrap", fontSize: 12 }}>
        <span><span style={{ color: "var(--muted)" }}>Provider </span>{providerShortLabel(row.provider) || row.provider || "—"}</span>
        <span><span style={{ color: "var(--muted)" }}>Account </span>{row.account || "—"}</span>
        <span><span style={{ color: "var(--muted)" }}>Resource </span>{row.resource || "—"}</span>
        {row.ts && <span><span style={{ color: "var(--muted)" }}>Time </span>{fmtDateTime(row.ts)}</span>}
      </div>
      <div>
        {lbl("Message")}
        <div style={{ whiteSpace: "pre-wrap", wordBreak: "break-word" }}><LogMessage text={row.detail} clamp={false} /></div>
      </div>
      <div>
        {lbl("Record")}
        <pre style={{ margin: 0, padding: 8, background: "var(--surface-2, rgba(127,127,127,.08))", borderRadius: 6, maxHeight: 320, overflow: "auto", fontSize: 12 }}>
          {JSON.stringify(row.raw, null, 2)}
        </pre>
      </div>
    </div>
  );
}

const CLOG_CSS = `
.clog-tabs { display: flex; flex-wrap: wrap; gap: 2px; margin: 4px 0 12px; border-bottom: 1px solid var(--border, #2a2f3a); }
.clog-tab { appearance: none; background: transparent; border: 0; border-bottom: 2px solid transparent; color: var(--muted, #8a94a6); padding: 8px 12px; font-size: 13px; font-weight: 600; cursor: pointer; white-space: nowrap; }
.clog-tab:hover { color: var(--text, inherit); }
.clog-tab.active { color: var(--accent, #2563eb); border-bottom-color: var(--accent, #2563eb); }
.clog-bar { flex-wrap: wrap; }
.clog-facet { width: 130px; padding: 6px 8px; border: 1px solid var(--border, #2a2f3a); border-radius: 6px; background: var(--surface, transparent); color: inherit; font-size: 13px; }
.clog-badge { font-size: 11px; font-weight: 700; letter-spacing: .3px; color: var(--muted, #8a94a6); }
.clog-mono { font-family: var(--font-mono, ui-monospace, monospace); font-size: 12px; }
`;

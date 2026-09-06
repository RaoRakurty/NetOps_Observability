// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

import { fmtDateTime, parseTs } from "../lib/time";
import { startTransition, useEffect, useMemo, useRef, useState } from "react";
import { api, OSHit, ExportFmt, LogRetention, LogSampling, LogSearchOpts } from "../services/api";
import { severityColor, severityRank } from "../theme/severity";
import { LogTime, LogSource, LogLevel, LogMessage, LogJson } from "../lib/logfmt";
import DataTable, { Column } from "../components/DataTable";
import { useWorkspace } from "../context/workspace";
import { useAuth } from "../hooks/useAuth";

const EXPORT_FORMATS: { id: ExportFmt; label: string }[] = [
  { id: "csv", label: "CSV" },
  { id: "json", label: "JSON" },
  { id: "ndjson", label: "NDJSON" },
  { id: "xlsx", label: "Excel" },
];
const EXPORT_COLUMNS = ["time", "source", "level", "application", "message"];

// triggerDownload navigates to a signed export URL; the server's
// Content-Disposition: attachment makes the browser download (not navigate).
function triggerDownload(url: string) {
  const a = document.createElement("a");
  a.href = url;
  a.rel = "noopener";
  document.body.appendChild(a);
  a.click();
  a.remove();
}

const RANGES: { label: string; minutes: number }[] = [
  { label: "Last 15m", minutes: 15 },
  { label: "Last 1h", minutes: 60 },
  { label: "Last 6h", minutes: 360 },
  { label: "Last 24h", minutes: 1440 },
];

type SignalId = "" | "applogs" | "syslog" | "snmptrap" | "flows" | "firewall";

const SIGNALS: { id: SignalId; label: string }[] = [
  { id: "", label: "All" },
  { id: "applogs", label: "App logs" },
  { id: "syslog", label: "Syslog (devices)" },
  { id: "firewall", label: "Firewall logs" },
  { id: "snmptrap", label: "SNMP traps" },
  { id: "flows", label: "Flows" },
];

// Sample honesty (finder 2026-08-14): the flows signal reads netops-flows-*,
// which holds the router's 1-in-N OpenSearch sample (ClickHouse keeps the
// canonical, unsampled flow store — the Flows tab). Fallback rate when a
// response predates the backend's sampling metadata; MUST match the router's
// flows_os_sample rate and logs.go flowsOSSampleRate
// (tests/test_ingest_contract.py pins all of them together).
const FLOWS_OS_SAMPLE_RATE = 50;

// #81 — "Firewall (all vendors)" is a convenience filter over the syslog index:
// it narrows to records a firewall vendor parser produced (FortiGate .fgt,
// Palo Alto .pan, Versa .versa) or that carry the vendor-neutral app contract
// (.app_id). Vendor-agnostic by construction; new vendors slot in by adding their
// parsed namespace here. (The bare `vendor` field is on every device, so it can't
// mark "firewall" — the parsed namespace is the reliable signal.)
const FIREWALL_FILTER = "(_exists_:fgt OR _exists_:pan OR _exists_:versa OR _exists_:app_id)";

type Props = {
  // Supplied by the shell so the global omni-search and time-range govern
  // this view. When undefined the component works standalone.
  initialQuery?: string;
  rangeMinutes?: number;
  // Device/alert pivots set this so the drawer opens scoped to the device's own
  // syslog (signal=syslog + a host: field query), NOT a free-text all-signals
  // search that would also surface internal app-logs mentioning the device.
  initialSignal?: SignalId;
};

export default function Logs({ initialQuery, rangeMinutes, initialSignal }: Props = {}) {
  const [query, setQuery] = useState(initialQuery ?? "*");
  const [signal, setSignal] = useState<SignalId>(initialSignal ?? "");
  const [minutes, setMinutes] = useState(rangeMinutes ?? 15);
  const [size, setSize] = useState(200);
  const [hits, setHits] = useState<OSHit[]>([]);
  const [total, setTotal] = useState<number | null>(null);
  const [busy, setBusy] = useState(false);
  const [loadingMore, setLoadingMore] = useState(false);
  // The exact request the current result set came from — "Load more" re-issues
  // it with an offset so the appended page belongs to the SAME window/query.
  const lastRun = useRef<LogSearchOpts | null>(null);
  // Retention floor: how far back the visible store goes + exact total stored.
  const [retention, setRetention] = useState<LogRetention | null>(null);
  // Sampling disclosure from the last search response (flows: 1:50 sample).
  const [sampling, setSampling] = useState<LogSampling | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [exporting, setExporting] = useState(false);
  const [exportMsg, setExportMsg] = useState<string | null>(null);
  const [detailId, setDetailId] = useState<string | null>(null);
  const ws = useWorkspace();
  const { user } = useAuth();
  // "App logs" are the platform's own container/API logs — platform-owner only.
  // Tenant-scoped users don't see the option (the backend also refuses the signal).
  const platform = !!user?.platform_admin;
  const signals = useMemo(
    () => SIGNALS.filter((s) => s.id !== "applogs" || platform),
    [platform],
  );

  const run = async (q = query, m = minutes, sig = signal, sz = size) => {
    setBusy(true);
    setError(null);
    try {
      const end = new Date();
      const start = new Date(end.getTime() - m * 60_000);
      // "Firewall (all vendors)" is a syslog query with a vendor-agnostic narrowing
      // filter applied — combine it with whatever the operator typed.
      const backendSignal = sig === "firewall" ? "syslog" : sig;
      const effQuery = sig === "firewall"
        ? (q && q.trim() && q.trim() !== "*" ? `(${q}) AND ${FIREWALL_FILTER}` : FIREWALL_FILTER)
        : q;
      const opts: LogSearchOpts = {
        query: effQuery,
        from: start.toISOString(),
        to: end.toISOString(),
        size: sz,
        signal: backendSignal,
      };
      const r = await api.searchLogs(opts);
      lastRun.current = opts;
      // A result set can be tens of thousands of rows; mapping and committing it
      // is the single most expensive thing this page does. As a transition it
      // yields to the operator's next keystroke or click instead of blocking it.
      startTransition(() => {
        setHits(r?.hits?.hits ?? []);
      });
      setTotal(r?.hits?.total?.value ?? null);
      // Sample honesty: trust the response's metadata; fall back to the known
      // rate so a flows result is NEVER presented as exact.
      setSampling(r?.sampling ?? (sig === "flows" ? { rate: FLOWS_OS_SAMPLE_RATE } : null));
      setSelected(new Set()); // a new result set invalidates row indices
    } catch (e) {
      setError((e as Error).message);
      setHits([]);
      setTotal(null);
      setSampling(null);
    } finally {
      setBusy(false);
    }
  };

  // React to the global search query / time range: re-run with the
  // external query (also fires once on mount).
  useEffect(() => {
    const q = initialQuery ?? "*";
    const m = rangeMinutes ?? minutes;
    setQuery(q);
    setMinutes(m);
    run(q, m, signal, size);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [initialQuery, rangeMinutes]);

  // Local filter changes (signal/size) re-run with whatever's in the box,
  // without clobbering a query the user typed here. Skips the mount run.
  const mounted = useRef(false);
  useEffect(() => {
    if (!mounted.current) {
      mounted.current = true;
      return;
    }
    run(query, minutes, signal, size);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [signal, size]);

  // Retention floor (owner directive: "how long back can I go?"). Re-read when
  // the signal changes — each signal is its own store with its own retention.
  useEffect(() => {
    let alive = true;
    const backendSignal = signal === "firewall" ? "syslog" : signal;
    api.logsRetention(backendSignal)
      .then((r) => { if (alive) setRetention(r ?? null); })
      .catch(() => { if (alive) setRetention(null); });
    return () => { alive = false; };
  }, [signal]);

  // "Load more" — append the next page of the SAME result set (same query +
  // frozen time window) via the server-bounded offset. OpenSearch's paging
  // window ends at 10k rows; past that the export path serves the full set.
  const OS_PAGE_WINDOW = 10000;
  const canLoadMore = total !== null && hits.length < total && hits.length < OS_PAGE_WINDOW && !!lastRun.current;
  const loadMore = async () => {
    const base = lastRun.current;
    if (!base || loadingMore) return;
    setLoadingMore(true);
    setError(null);
    try {
      const r = await api.searchLogs({ ...base, offset: hits.length });
      setHits((h) => h.concat(r?.hits?.hits ?? []));
      setTotal(r?.hits?.total?.value ?? total);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoadingMore(false);
    }
  };

  const saveSearch = async () => {
    const name = window.prompt("Name this saved search:", query === "*" ? "All logs" : query);
    if (!name) return;
    try {
      await api.createSaved("saved_search", name, { query, signal });
      window.alert(`Saved "${name}". Find it under Search → Saved.`);
    } catch (e) {
      window.alert(`Save failed: ${(e as Error).message}`);
    }
  };

  const lines = useMemo(() => {
    return hits.map((h, i) => {
      const src = h._source || {};
      const ts =
        src["@timestamp"] || src.timestamp || src.ts || src.time_received_ns || new Date().toISOString();
      // Prefer the normalized operator summary (traps/syslog now carry it) over
      // the raw body, so the row reads "Arista Layer-2 FDB trap …" not a raw OID.
      const message =
        src.summary || src.message || src.msg || JSON.stringify(src);
      // Flow records enter via the collector's stdout, so they carry its
      // container name — show the flow's real source host (src_addr) instead.
      const flowHost = src.src_addr ? String(src.src_addr) : "";
      const source =
        flowHost || src.compose_service || src.container_name || src.hostname || src.appname || h._index;
      const level = src.level || src.severity || "";
      // Application name (#81): the firewall/router/cloud classifier's app label,
      // surfaced so app traffic reads as "Teams / Zoom / Dropbox" not a raw 5-tuple.
      // Vendor-neutral app_id first (the fusion contract), then FortiGate's nested
      // fgt.app, then a bare app field — "" when the record carries no app identity.
      const fgt = (src.fgt && typeof src.fgt === "object") ? (src.fgt as Record<string, unknown>) : {};
      const app = String(src.app_id || src.app || (fgt.app ?? "") || "");
      // Stable id so selection survives DataTable's internal sort (was index).
      const id = h._id || `${h._index}#${i}`;
      return { id, ts: String(ts), message: String(message), source: String(source), level: String(level), app, index: h._index, raw: src };
    });
  }, [hits]);
  type Line = (typeof lines)[number];

  const allSelected = lines.length > 0 && selected.size === lines.length;
  const toggleRow = (id: string) =>
    setSelected((s) => {
      const n = new Set(s);
      if (n.has(id)) n.delete(id);
      else n.add(id);
      return n;
    });
  const toggleAll = () => setSelected(allSelected ? new Set() : new Set(lines.map((l) => l.id)));

  // Row body click (not the export checkbox) opens the full log document in the
  // dockable Inspector (shell-v2); v1 falls back to an inline detail card.
  const selectLine = (l: Line) => {
    setDetailId(l.id);
    if (ws.enabled) {
      ws.openInspector(<LogLineDetailBody line={l} />, {
        title: l.source,
        subtitle: `${l.level || "log"} · ${fmtDateTime(l.ts)}`,
      });
    }
  };
  const detailLine = !ws.enabled && detailId ? lines.find((l) => l.id === detailId) : undefined;

  // Mode A — render the selected (loaded) rows to a file via the server encoders.
  const exportSelected = async (format: ExportFmt) => {
    const rows = lines.filter((l) => selected.has(l.id)).map((l) => [l.ts, l.source, l.level, l.app, l.message]);
    if (rows.length === 0) return;
    setExporting(true);
    setExportMsg(null);
    try {
      await api.exportLogRows(format, EXPORT_COLUMNS, rows, "logs-selected");
    } catch (e) {
      setExportMsg((e as Error).message);
    } finally {
      setExporting(false);
    }
  };

  // Sample honesty: the flows signal serves a 1:N OpenSearch sample — every
  // count shown or exported for it is an estimate (multiply by N).
  const sampleRate = sampling?.rate ?? FLOWS_OS_SAMPLE_RATE;
  const flowsSampled = signal === "flows";
  const flowsExportNote = flowsSampled
    ? ` Flows are a 1:${sampleRate} sample — totals are estimates (×${sampleRate}).`
    : "";

  // Mode B — export the ENTIRE result set for the current query/time/signal.
  // Small sets download immediately; large sets queue and we poll for the link.
  const exportAll = async (format: ExportFmt) => {
    setExporting(true);
    setExportMsg(null);
    try {
      const end = new Date();
      const start = new Date(end.getTime() - minutes * 60_000);
      // Mirror run()'s "firewall" translation so an export matches the on-screen view.
      const backendSignal = signal === "firewall" ? "syslog" : signal;
      const effQuery = signal === "firewall"
        ? (query && query.trim() && query.trim() !== "*" ? `(${query}) AND ${FIREWALL_FILTER}` : FIREWALL_FILTER)
        : query;
      const { executionId, matched } = await api.exportLogQuery({
        format,
        query: effQuery,
        signal: backendSignal,
        from: start.toISOString(),
        to: end.toISOString(),
      });
      if (!executionId) {
        setExportMsg(`Export downloaded.${flowsExportNote}`);
        return;
      }
      setExportMsg(`Large export (${matched ?? "?"} rows) queued — preparing…${flowsExportNote}`);
      for (let i = 0; i < 160; i++) {
        await new Promise((r) => setTimeout(r, 1500));
        const st = await api.exportStatus(executionId);
        if (st.status === "completed" && st.download_url) {
          triggerDownload(st.download_url);
          setExportMsg(`Export ready — downloaded.${flowsExportNote}`);
          return;
        }
        if (st.status === "failed") throw new Error(st.error || "The export could not be produced.");
      }
      setExportMsg("Export still running — check back shortly.");
    } catch (e) {
      setExportMsg((e as Error).message);
    } finally {
      setExporting(false);
    }
  };

  const columns = useMemo<Column<Line>[]>(() => [
    {
      key: "sel", width: 30,
      header: <input type="checkbox" checked={allSelected} onChange={toggleAll} title="Select all rows in view" />,
      render: (l) => (
        <input type="checkbox" checked={selected.has(l.id)}
          onClick={(e) => e.stopPropagation()} onChange={() => toggleRow(l.id)} />
      ),
    },
    {
      key: "ts", header: "Time", width: 176, sortable: true,
      sortValue: (l) => parseTs(l.ts)?.getTime() || 0,
      render: (l) => <LogTime ts={l.ts} />,
    },
    {
      key: "source", header: "Source", width: 168, sortable: true, text: (l) => l.source,
      render: (l) => <LogSource source={l.source} />,
    },
    {
      key: "level", header: "Level", width: 100, sortable: true,
      text: (l) => l.level, sortValue: (l) => severityRank(l.level),
      render: (l) => <LogLevel level={l.level} />,
    },
    {
      // #81 — the identified application (firewall App-ID / NBAR2 / cloud), the
      // payoff of the fusion engine: app traffic named, not a raw 5-tuple.
      key: "app", header: "Application", width: 150, sortable: true, text: (l) => l.app,
      render: (l) => l.app
        ? <span title={l.app} style={{ fontFamily: "var(--font-mono, ui-monospace, monospace)", fontSize: 12.5, fontWeight: 600, color: "var(--accent, #2563eb)" }}>{l.app.replace(/_/g, " · ")}</span>
        : <span style={{ color: "var(--muted, #8a94a6)" }}>—</span>,
    },
    {
      key: "message", header: "Message", text: (l) => l.message,
      render: (l) => <LogMessage text={l.message} />,
    },
  ], [selected, allSelected]);

  return (
    <>
      <div className="card">
        <div className="xpl-head">
          <h2>Log search</h2>
          <span className="xpl-sub">
            Lucene <code>query_string</code> · e.g. <code>level:error</code>, <code>src_addr:10.0.0.5 AND dst_port:22</code>
          </span>
        </div>
        <form className="xpl-bar" onSubmit={(e) => { e.preventDefault(); run(); }}>
          <input
            className="xpl-q"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder='*  or  level:error  or  src_addr:10.0.0.5'
          />
          <select value={signal} onChange={(e) => setSignal(e.target.value as any)}>
            {signals.map((s) => (
              <option key={s.id} value={s.id}>
                {s.label}
              </option>
            ))}
          </select>
          {rangeMinutes === undefined && (
            <select value={minutes} onChange={(e) => setMinutes(Number(e.target.value))}>
              {RANGES.map((r) => (
                <option key={r.minutes} value={r.minutes}>
                  {r.label}
                </option>
              ))}
            </select>
          )}
          <select value={size} onChange={(e) => setSize(Number(e.target.value))}>
            {[100, 200, 500, 1000, 5000].map((n) => (
              <option key={n} value={n}>
                {n} hits
              </option>
            ))}
          </select>
          <button className="btn-primary" disabled={busy} type="submit">
            {busy ? "Searching…" : "Search"}
          </button>
          <button className="btn-ghost" type="button" onClick={saveSearch} title="Save this search">
            ★ Save
          </button>
        </form>
        {/* Retention floor (owner directive: DON'T HIDE how far back logs go). */}
        {retention && (
          <p style={{ color: "var(--muted)", fontSize: 12.5, marginTop: 10, marginBottom: 0 }}>
            {retention.total > 0 && retention.oldest ? (
              <>
                This store holds <strong style={{ color: "var(--fg)" }}>{retention.total.toLocaleString()}</strong> logs —
                going back to <strong style={{ color: "var(--fg)" }}>{fmtDateTime(retention.oldest)}</strong>
                {" "}({retention.days < 1 ? "less than a day" : `${retention.days} day${retention.days === 1 ? "" : "s"}`} of history).
                {(flowsSampled || retention.sampling) &&
                  ` A 1:${retention.sampling?.rate ?? sampleRate} sample — the stream holds ~${retention.sampling?.rate ?? sampleRate}× more.`}
              </>
            ) : (
              "No logs stored yet for this signal."
            )}
          </p>
        )}
        {error && (
          <p style={{ color: "var(--bad)", marginTop: 10, fontSize: 13 }}>
            <strong>Error:</strong> {error}
          </p>
        )}
      </div>

      <div className="card">
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", flexWrap: "wrap", gap: 8 }}>
          <div style={{ display: "flex", alignItems: "baseline", gap: 8, flexWrap: "wrap" }}>
            <h2 style={{ margin: 0 }}>Results</h2>
            <span className="fact-line">
              {total !== null && total > lines.length
                ? `${lines.length.toLocaleString()} of ${total.toLocaleString()} matched`
                : `${lines.length.toLocaleString()}${total !== null ? " · all matches" : ""}`}
            </span>
          </div>
          <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
            {selected.size > 0 && (
              <>
                <span style={{ color: "var(--muted)", fontSize: 12.5 }}>{selected.size} selected →</span>
                {EXPORT_FORMATS.map((f) => (
                  <button key={f.id} type="button" className="chip" disabled={exporting} onClick={() => exportSelected(f.id)} title={`Export ${selected.size} selected rows as ${f.label}`}>
                    {f.label}
                  </button>
                ))}
                <button type="button" className="chip" onClick={() => setSelected(new Set())}>Clear</button>
                <span style={{ color: "var(--border)" }}>|</span>
              </>
            )}
            {lines.length > 0 && (
              <>
                <span style={{ color: "var(--muted)", fontSize: 12.5 }}>
                  Export all{total !== null ? ` (${total})` : ""}:
                </span>
                {EXPORT_FORMATS.map((f) => (
                  <button key={`all-${f.id}`} type="button" className="chip" disabled={exporting} onClick={() => exportAll(f.id)} title={`Export the entire result set as ${f.label}`}>
                    {f.label}
                  </button>
                ))}
              </>
            )}
          </div>
        </div>
        {/* Sample honesty (owner directive: DON'T HIDE): the flows store is a
            1:N sample, so its "matched"/"total" figures are never exact. */}
        {flowsSampled && lines.length > 0 && (
          <p data-testid="flows-sampling-note" style={{ color: "var(--warn, #b45309)", fontSize: 12.5, marginTop: 6, marginBottom: 0 }}>
            Flow search reads a 1:{sampleRate} sample — totals are estimates (×{sampleRate}).
            Exact flow analytics live in the Flows tab (unsampled store).
          </p>
        )}
        {exportMsg && (
          <p style={{ color: "var(--muted)", fontSize: 12.5, marginTop: 6 }}>
            {exporting ? "⏳ " : ""}
            {exportMsg}
          </p>
        )}
        {lines.length === 0 ? (
          <div className="empty">
            {busy ? "Loading…" : "No results. Try widening the time range or relaxing the filter."}
          </div>
        ) : (
          <DataTable<Line>
            rows={lines}
            columns={columns}
            rowKey={(l) => l.id}
            height="60vh"
            ariaLabel="Log results"
            onRowClick={(l) => selectLine(l)}
            rowAccent={(l) => severityColor(l.level)}
            rowClassName={(l) => (detailId === l.id ? "dtv-selected" : "")}
            empty="No results."
          />
        )}
        {/* Every truncated list SAYS it's truncated and offers the rest. */}
        {canLoadMore && (
          <div style={{ display: "flex", justifyContent: "center", marginTop: 10 }}>
            <button type="button" className="chip" onClick={loadMore} disabled={loadingMore}
              title="Fetch the next page of this result set">
              {loadingMore
                ? "Loading…"
                : `Load ${Math.min(size, (total ?? 0) - hits.length).toLocaleString()} more (${hits.length.toLocaleString()} of ${(total ?? 0).toLocaleString()} loaded)`}
            </button>
          </div>
        )}
        {total !== null && total > lines.length && !canLoadMore && lines.length > 0 && (
          <p style={{ color: "var(--muted)", fontSize: 12.5, marginTop: 8, textAlign: "center" }}>
            Interactive paging ends at {(10000).toLocaleString()} rows — use “Export all” above to get the
            full {total.toLocaleString()}-row result set.
          </p>
        )}
        {detailLine && (
          <div style={{ marginTop: 12, borderTop: "1px solid var(--border, #2a2f3a)", paddingTop: 12 }}>
            <LogLineDetailBody line={detailLine} />
          </div>
        )}
      </div>
    </>
  );
}

// LogLineDetailBody — the full log document for one result row, rendered in the
// Inspector (shell-v2) or inline (v1): the headline fields plus the raw source
// pretty-printed (the value of having OpenSearch behind the search box).
export function LogLineDetailBody({ line: l }: { line: { ts: string; source: string; level: string; message: string; index: string; raw: Record<string, any> } }) {
  const lbl = (s: string) => (
    <div style={{ fontSize: 12.5, color: "var(--muted)", textTransform: "uppercase", letterSpacing: 0.4, marginBottom: 4 }}>{s}</div>
  );
  const row = (k: string, v: React.ReactNode) => (
    <div style={{ display: "flex", gap: 8, fontSize: 12.5, padding: "2px 0" }}>
      <span style={{ color: "var(--muted)", minWidth: 72 }}>{k}</span>
      <span style={{ wordBreak: "break-word" }}>{v}</span>
    </div>
  );
  // Same token vocabulary as the table row — the colour pattern carries through.
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
      <div style={{ display: "flex", gap: 10, alignItems: "center", flexWrap: "wrap" }}>
        <LogLevel level={l.level} />
        <LogSource source={l.source} />
      </div>
      <div>
        {row("Time", <LogTime ts={l.ts} />)}
        {row("Index", <span className="lf-source" style={{ color: "var(--muted)" }}>{l.index}</span>)}
      </div>
      <div>
        {lbl("Message")}
        <div style={{ whiteSpace: "pre-wrap", wordBreak: "break-word" }}><LogMessage text={l.message} clamp={false} /></div>
      </div>
      <div>
        {lbl("Document")}
        <div style={{ padding: 8, background: "var(--surface-2, rgba(127,127,127,.08))", borderRadius: 6, maxHeight: 320, overflow: "auto" }}>
          <LogJson value={l.raw} />
        </div>
      </div>
    </div>
  );
}

import { useEffect, useMemo, useRef, useState } from "react";
import { api, OSHit, ExportFmt } from "../services/api";
import { severityClass, severityColor, severityRank } from "../theme/severity";
import DataTable, { Column } from "../components/DataTable";
import { useWorkspace } from "../context/workspace";
import { useAuth } from "../hooks/useAuth";

const EXPORT_FORMATS: { id: ExportFmt; label: string }[] = [
  { id: "csv", label: "CSV" },
  { id: "json", label: "JSON" },
  { id: "ndjson", label: "NDJSON" },
  { id: "xlsx", label: "Excel" },
];
const EXPORT_COLUMNS = ["time", "source", "level", "message"];

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

const SIGNALS: { id: "" | "applogs" | "syslog" | "snmptrap" | "flows"; label: string }[] = [
  { id: "", label: "All" },
  { id: "applogs", label: "App logs" },
  { id: "syslog", label: "Syslog (devices)" },
  { id: "snmptrap", label: "SNMP traps" },
  { id: "flows", label: "Flows" },
];

type Props = {
  // Supplied by the shell so the global omni-search and time-range govern
  // this view. When undefined the component works standalone.
  initialQuery?: string;
  rangeMinutes?: number;
  // Device/alert pivots set this so the drawer opens scoped to the device's own
  // syslog (signal=syslog + a host: field query), NOT a free-text all-signals
  // search that would also surface internal app-logs mentioning the device.
  initialSignal?: "" | "applogs" | "syslog" | "snmptrap" | "flows";
};

export default function Logs({ initialQuery, rangeMinutes, initialSignal }: Props = {}) {
  const [query, setQuery] = useState(initialQuery ?? "*");
  const [signal, setSignal] = useState<"" | "applogs" | "syslog" | "snmptrap" | "flows">(initialSignal ?? "");
  const [minutes, setMinutes] = useState(rangeMinutes ?? 15);
  const [size, setSize] = useState(200);
  const [hits, setHits] = useState<OSHit[]>([]);
  const [total, setTotal] = useState<number | null>(null);
  const [busy, setBusy] = useState(false);
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
      const r = await api.searchLogs({
        query: q,
        from: start.toISOString(),
        to: end.toISOString(),
        size: sz,
        signal: sig,
      });
      setHits(r?.hits?.hits ?? []);
      setTotal(r?.hits?.total?.value ?? null);
      setSelected(new Set()); // a new result set invalidates row indices
    } catch (e) {
      setError((e as Error).message);
      setHits([]);
      setTotal(null);
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
      const message =
        src.message || src.msg || JSON.stringify(src);
      // Flow records enter via the collector's stdout, so they carry its
      // container name — show the flow's real source host (src_addr) instead.
      const flowHost = src.src_addr ? String(src.src_addr) : "";
      const source =
        flowHost || src.compose_service || src.container_name || src.hostname || src.appname || h._index;
      const level = src.level || src.severity || "";
      // Stable id so selection survives DataTable's internal sort (was index).
      const id = h._id || `${h._index}#${i}`;
      return { id, ts: String(ts), message: String(message), source: String(source), level: String(level), index: h._index, raw: src };
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
        subtitle: `${l.level || "log"} · ${new Date(l.ts).toLocaleString()}`,
      });
    }
  };
  const detailLine = !ws.enabled && detailId ? lines.find((l) => l.id === detailId) : undefined;

  // Mode A — render the selected (loaded) rows to a file via the server encoders.
  const exportSelected = async (format: ExportFmt) => {
    const rows = lines.filter((l) => selected.has(l.id)).map((l) => [l.ts, l.source, l.level, l.message]);
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

  // Mode B — export the ENTIRE result set for the current query/time/signal.
  // Small sets download immediately; large sets queue and we poll for the link.
  const exportAll = async (format: ExportFmt) => {
    setExporting(true);
    setExportMsg(null);
    try {
      const end = new Date();
      const start = new Date(end.getTime() - minutes * 60_000);
      const { executionId, matched } = await api.exportLogQuery({
        format,
        query,
        signal,
        from: start.toISOString(),
        to: end.toISOString(),
      });
      if (!executionId) {
        setExportMsg("Export downloaded.");
        return;
      }
      setExportMsg(`Large export (${matched ?? "?"} rows) queued — preparing…`);
      for (let i = 0; i < 160; i++) {
        await new Promise((r) => setTimeout(r, 1500));
        const st = await api.exportStatus(executionId);
        if (st.status === "completed" && st.download_url) {
          triggerDownload(st.download_url);
          setExportMsg("Export ready — downloaded.");
          return;
        }
        if (st.status === "failed") throw new Error(st.error || "export failed");
      }
      setExportMsg("Export still running — check back shortly.");
    } catch (e) {
      setExportMsg((e as Error).message);
    } finally {
      setExporting(false);
    }
  };

  const mono: React.CSSProperties = { fontFamily: "var(--font-mono)", fontSize: 12 };
  const columns = useMemo<Column<Line>[]>(() => [
    {
      key: "sel", width: 30,
      header: <input type="checkbox" checked={allSelected} onChange={toggleAll} title="Select all loaded" />,
      render: (l) => (
        <input type="checkbox" checked={selected.has(l.id)}
          onClick={(e) => e.stopPropagation()} onChange={() => toggleRow(l.id)} />
      ),
    },
    {
      key: "ts", header: "Time", width: 168, sortable: true,
      sortValue: (l) => new Date(l.ts).getTime() || 0,
      render: (l) => <span style={mono}>{new Date(l.ts).toLocaleString()}</span>,
    },
    {
      key: "source", header: "Source", width: 168, sortable: true, text: (l) => l.source,
      render: (l) => <span style={mono} title={l.source}>{l.source}</span>,
    },
    {
      key: "level", header: "Level", width: 92, sortable: true,
      text: (l) => l.level, sortValue: (l) => severityRank(l.level),
      render: (l) => <span className={`badge ${severityClass(l.level)}`}>{l.level || "—"}</span>,
    },
    {
      key: "message", header: "Message", text: (l) => l.message,
      render: (l) => <span style={mono} title={l.message}>{l.message}</span>,
    },
  ], [selected, allSelected]);

  return (
    <>
      <div className="card">
        <h2>Log search (OpenSearch)</h2>
        <p style={{ color: "var(--muted)", fontSize: 12, marginTop: 0 }}>
          Lucene <code>query_string</code> syntax. Examples:{" "}
          <code>severity:err AND host:router-01</code>,{" "}
          <code>level:error</code>,{" "}
          <code>src_addr:10.0.0.5 AND dst_port:22</code>.
        </p>
        <form
          onSubmit={(e) => {
            e.preventDefault();
            run();
          }}
          style={{ display: "grid", gridTemplateColumns: "1fr auto auto auto auto auto", gap: 8 }}
        >
          <input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder='*  or  level:error  or  src_addr:10.0.0.5'
            style={{ fontFamily: "var(--font-mono)", fontSize: 13 }}
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
          <button disabled={busy} type="submit">
            {busy ? "Searching…" : "Search"}
          </button>
          <button type="button" onClick={saveSearch} title="Save this search">
            ★ Save
          </button>
        </form>
        {error && (
          <p style={{ color: "var(--bad)", marginTop: 12 }}>
            <strong>Error:</strong> {error}
          </p>
        )}
      </div>

      <div className="card">
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", flexWrap: "wrap", gap: 8 }}>
          <h2 style={{ margin: 0 }}>
            Results ({lines.length}
            {total !== null && total > lines.length ? ` / ${total} matched` : ""})
          </h2>
          <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
            {selected.size > 0 && (
              <>
                <span style={{ color: "var(--muted)", fontSize: 12 }}>{selected.size} selected →</span>
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
                <span style={{ color: "var(--muted)", fontSize: 12 }}>
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
        {exportMsg && (
          <p style={{ color: "var(--muted)", fontSize: 12, marginTop: 6 }}>
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
  const mono: React.CSSProperties = { fontFamily: "var(--font-mono)", fontSize: 12 };
  const row = (k: string, v: React.ReactNode) => (
    <div style={{ display: "flex", gap: 8, fontSize: 12, padding: "2px 0" }}>
      <span style={{ color: "var(--muted)", minWidth: 72 }}>{k}</span>
      <span style={{ wordBreak: "break-word" }}>{v}</span>
    </div>
  );
  let pretty = "";
  try {
    pretty = JSON.stringify(l.raw ?? {}, null, 2);
  } catch {
    pretty = String(l.raw);
  }
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
      <div style={{ display: "flex", gap: 6, alignItems: "center", flexWrap: "wrap" }}>
        <span className={`badge ${severityClass(l.level)}`}>{l.level || "log"}</span>
        <span style={mono}>{l.source}</span>
      </div>
      <div>
        {row("Time", <span style={mono}>{new Date(l.ts).toLocaleString()}</span>)}
        {row("Index", <span style={mono}>{l.index}</span>)}
      </div>
      <div>
        <div style={{ fontSize: 11, color: "var(--muted)", textTransform: "uppercase", letterSpacing: 0.4, marginBottom: 4 }}>
          Message
        </div>
        <div style={{ ...mono, whiteSpace: "pre-wrap", wordBreak: "break-word" }}>{l.message}</div>
      </div>
      <div>
        <div style={{ fontSize: 11, color: "var(--muted)", textTransform: "uppercase", letterSpacing: 0.4, marginBottom: 4 }}>
          Document
        </div>
        <pre
          style={{
            ...mono,
            margin: 0,
            padding: 8,
            background: "var(--surface-2, rgba(127,127,127,.08))",
            borderRadius: 6,
            maxHeight: 320,
            overflow: "auto",
            whiteSpace: "pre-wrap",
            wordBreak: "break-word",
          }}
        >
          {pretty}
        </pre>
      </div>
    </div>
  );
}

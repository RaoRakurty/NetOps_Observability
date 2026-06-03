import { useEffect, useMemo, useRef, useState } from "react";
import { api, OSHit, ExportFmt } from "../services/api";
import { severityClass, severityRowClass } from "../theme/severity";

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

const SIGNALS: { id: "" | "applogs" | "syslog" | "flows"; label: string }[] = [
  { id: "", label: "All" },
  { id: "applogs", label: "App logs" },
  { id: "syslog", label: "Syslog (devices)" },
  { id: "flows", label: "Flows" },
];

type Props = {
  // Supplied by the shell so the global omni-search and time-range govern
  // this view. When undefined the component works standalone.
  initialQuery?: string;
  rangeMinutes?: number;
};

export default function Logs({ initialQuery, rangeMinutes }: Props = {}) {
  const [query, setQuery] = useState(initialQuery ?? "*");
  const [signal, setSignal] = useState<"" | "applogs" | "syslog" | "flows">("");
  const [minutes, setMinutes] = useState(rangeMinutes ?? 15);
  const [size, setSize] = useState(200);
  const [hits, setHits] = useState<OSHit[]>([]);
  const [total, setTotal] = useState<number | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [selected, setSelected] = useState<Set<number>>(new Set());
  const [exporting, setExporting] = useState(false);
  const [exportMsg, setExportMsg] = useState<string | null>(null);

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
    return hits.map((h) => {
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
      return { ts: String(ts), message: String(message), source: String(source), level: String(level), index: h._index };
    });
  }, [hits]);

  const allSelected = lines.length > 0 && selected.size === lines.length;
  const toggleRow = (i: number) =>
    setSelected((s) => {
      const n = new Set(s);
      if (n.has(i)) n.delete(i);
      else n.add(i);
      return n;
    });
  const toggleAll = () => setSelected(allSelected ? new Set() : new Set(lines.map((_, i) => i)));

  // Mode A — render the selected (loaded) rows to a file via the server encoders.
  const exportSelected = async (format: ExportFmt) => {
    const rows = lines.filter((_, i) => selected.has(i)).map((l) => [l.ts, l.source, l.level, l.message]);
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
            style={{ fontFamily: "ui-monospace, monospace", fontSize: 13 }}
          />
          <select value={signal} onChange={(e) => setSignal(e.target.value as any)}>
            {SIGNALS.map((s) => (
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
          <div style={{ maxHeight: "60vh", overflow: "auto" }}>
            <table>
              <thead>
                <tr>
                  <th style={{ width: 28 }}>
                    <input type="checkbox" checked={allSelected} onChange={toggleAll} title="Select all on page" />
                  </th>
                  <th style={{ width: 180 }}>Time</th>
                  <th style={{ width: 180 }}>Source</th>
                  <th style={{ width: 80 }}>Level</th>
                  <th>Message</th>
                </tr>
              </thead>
              <tbody>
                {lines.map((r, i) => (
                  <tr key={i} className={severityRowClass(r.level)}>
                    <td>
                      <input type="checkbox" checked={selected.has(i)} onChange={() => toggleRow(i)} />
                    </td>
                    <td style={{ fontFamily: "ui-monospace, monospace", fontSize: 12 }}>
                      {new Date(r.ts).toLocaleString()}
                    </td>
                    <td style={{ fontFamily: "ui-monospace, monospace", fontSize: 12 }}>
                      {r.source}
                    </td>
                    <td>
                      <span className={`badge ${severityClass(r.level)}`}>{r.level || "—"}</span>
                    </td>
                    <td
                      style={{
                        fontFamily: "ui-monospace, monospace",
                        fontSize: 12,
                        whiteSpace: "pre-wrap",
                        wordBreak: "break-all",
                      }}
                    >
                      {r.message}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </>
  );
}

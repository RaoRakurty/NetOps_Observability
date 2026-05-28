import { useEffect, useMemo, useRef, useState } from "react";
import { api, OSHit } from "../services/api";
import { severityClass, severityRowClass } from "../theme/severity";

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

  const lines = useMemo(() => {
    return hits.map((h) => {
      const src = h._source || {};
      const ts =
        src["@timestamp"] || src.timestamp || src.ts || src.time_received_ns || new Date().toISOString();
      const message =
        src.message || src.msg || JSON.stringify(src);
      const source =
        src.compose_service || src.container_name || src.hostname || src.appname || h._index;
      const level = src.level || src.severity || "";
      return { ts: String(ts), message: String(message), source: String(source), level: String(level), index: h._index };
    });
  }, [hits]);

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
          style={{ display: "grid", gridTemplateColumns: "1fr auto auto auto auto", gap: 8 }}
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
        </form>
        {error && (
          <p style={{ color: "var(--bad)", marginTop: 12 }}>
            <strong>Error:</strong> {error}
          </p>
        )}
      </div>

      <div className="card">
        <h2>
          Results ({lines.length}
          {total !== null && total > lines.length ? ` / ${total} matched` : ""})
        </h2>
        {lines.length === 0 ? (
          <div className="empty">
            {busy ? "Loading…" : "No results. Try widening the time range or relaxing the filter."}
          </div>
        ) : (
          <div style={{ maxHeight: "60vh", overflow: "auto" }}>
            <table>
              <thead>
                <tr>
                  <th style={{ width: 180 }}>Time</th>
                  <th style={{ width: 180 }}>Source</th>
                  <th style={{ width: 80 }}>Level</th>
                  <th>Message</th>
                </tr>
              </thead>
              <tbody>
                {lines.map((r, i) => (
                  <tr key={i} className={severityRowClass(r.level)}>
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

import { useMemo, useState } from "react";
import { api, OSHit } from "../services/api";

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

export default function Logs() {
  const [query, setQuery] = useState("*");
  const [signal, setSignal] = useState<"" | "applogs" | "syslog" | "flows">("");
  const [minutes, setMinutes] = useState(15);
  const [size, setSize] = useState(200);
  const [hits, setHits] = useState<OSHit[]>([]);
  const [total, setTotal] = useState<number | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const run = async () => {
    setBusy(true);
    setError(null);
    try {
      const end = new Date();
      const start = new Date(end.getTime() - minutes * 60_000);
      const r = await api.searchLogs({
        query,
        from: start.toISOString(),
        to: end.toISOString(),
        size,
        signal,
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
          <select value={minutes} onChange={(e) => setMinutes(Number(e.target.value))}>
            {RANGES.map((r) => (
              <option key={r.minutes} value={r.minutes}>
                {r.label}
              </option>
            ))}
          </select>
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
                  <tr key={i}>
                    <td style={{ fontFamily: "ui-monospace, monospace", fontSize: 12 }}>
                      {new Date(r.ts).toLocaleString()}
                    </td>
                    <td style={{ fontFamily: "ui-monospace, monospace", fontSize: 12 }}>
                      {r.source}
                    </td>
                    <td>
                      <span className={`badge ${badgeClass(r.level)}`}>{r.level || "—"}</span>
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

function badgeClass(level: string) {
  const l = level.toLowerCase();
  if (l.includes("err") || l === "critical" || l === "crit" || l === "alert" || l === "emerg") return "bad";
  if (l.includes("warn") || l === "notice") return "warn";
  return "good";
}

import { useEffect, useState } from "react";
import { api, CollectorStatus } from "../services/api";

export default function Collectors() {
  const [items, setItems] = useState<CollectorStatus[]>([]);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    let alive = true;
    const tick = async () => {
      try {
        const c = await api.collectors();
        if (alive) setItems(c ?? []);
      } catch (e) {
        if (alive) setErr((e as Error).message);
      }
    };
    tick();
    const id = setInterval(tick, 10000);
    return () => {
      alive = false;
      clearInterval(id);
    };
  }, []);

  return (
    <div className="card">
      <h2>Collectors</h2>
      {err && <p style={{ color: "var(--bad)" }}>{err}</p>}
      {items.length === 0 ? (
        <div className="empty">No collectors registered.</div>
      ) : (
        <table>
          <thead>
            <tr>
              <th>Name</th>
              <th>Enabled</th>
              <th>Healthy</th>
              <th>Targets</th>
              <th>Last tick</th>
            </tr>
          </thead>
          <tbody>
            {items.map((c) => (
              <tr key={c.name}>
                <td>{c.name}</td>
                <td>
                  <span className={`badge ${c.enabled ? "good" : "warn"}`}>
                    {c.enabled ? "on" : "off"}
                  </span>
                </td>
                <td>
                  <span className={`badge ${c.healthy ? "good" : "bad"}`}>
                    {c.healthy ? "ok" : "fail"}
                  </span>
                </td>
                <td>{c.targets}</td>
                <td>{c.last_tick ? new Date(c.last_tick).toLocaleString() : "—"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}

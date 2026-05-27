import { useEffect, useState } from "react";
import { api, Alert } from "../services/api";

export default function Alerts() {
  const [items, setItems] = useState<Alert[]>([]);
  useEffect(() => {
    let alive = true;
    const tick = async () => {
      try {
        const a = await api.alerts();
        if (alive) setItems(a ?? []);
      } catch {
        /* ignore — top-level health banner shows the failure */
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
      <h2>Active alerts</h2>
      {items.length === 0 ? (
        <div className="empty">No active alerts.</div>
      ) : (
        <table>
          <thead>
            <tr>
              <th>Rule</th>
              <th>Severity</th>
              <th>Device</th>
              <th>Summary</th>
              <th>Fired</th>
            </tr>
          </thead>
          <tbody>
            {items.map((a) => (
              <tr key={a.id}>
                <td>{a.rule}</td>
                <td>{a.severity}</td>
                <td>{a.device_id ?? "—"}</td>
                <td>{a.summary}</td>
                <td>{new Date(a.fired_at).toLocaleString()}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}

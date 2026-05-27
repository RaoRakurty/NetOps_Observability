import { useEffect, useState } from "react";
import { api, Alert, CollectorStatus, Device } from "../services/api";

export default function Dashboard() {
  const [devices, setDevices] = useState<Device[]>([]);
  const [collectors, setCollectors] = useState<CollectorStatus[]>([]);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let alive = true;
    const load = async () => {
      try {
        const [d, c, a] = await Promise.all([api.devices(), api.collectors(), api.alerts()]);
        if (!alive) return;
        setDevices(d ?? []);
        setCollectors(c ?? []);
        setAlerts(a ?? []);
        setError(null);
      } catch (e) {
        if (alive) setError((e as Error).message);
      }
    };
    load();
    const id = setInterval(load, 15000);
    return () => {
      alive = false;
      clearInterval(id);
    };
  }, []);

  const enabledCollectors = collectors.filter((c) => c.enabled).length;
  const criticalAlerts = alerts.filter((a) => a.severity === "critical").length;

  return (
    <>
      <div className="kpis">
        <Kpi label="Devices" value={devices.length} />
        <Kpi label="Collectors enabled" value={enabledCollectors} />
        <Kpi label="Active alerts" value={alerts.length} />
        <Kpi label="Critical" value={criticalAlerts} />
      </div>

      {error && (
        <div className="card">
          <h2>API error</h2>
          <p>{error}</p>
        </div>
      )}

      <div className="card">
        <h2>Recent alerts</h2>
        {alerts.length === 0 ? (
          <div className="empty">No active alerts. Nice and quiet.</div>
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
              {alerts.map((a) => (
                <tr key={a.id}>
                  <td>{a.rule}</td>
                  <td>
                    <span className={`badge ${severityClass(a.severity)}`}>{a.severity}</span>
                  </td>
                  <td>{a.device_id ?? "—"}</td>
                  <td>{a.summary}</td>
                  <td>{new Date(a.fired_at).toLocaleString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </>
  );
}

function Kpi({ label, value }: { label: string; value: number }) {
  return (
    <div className="kpi">
      <div className="label">{label}</div>
      <div className="value">{value}</div>
    </div>
  );
}

function severityClass(sev: string) {
  switch (sev) {
    case "critical":
      return "bad";
    case "warning":
      return "warn";
    default:
      return "good";
  }
}

import { useEffect, useState } from "react";
import { api, Device, Alert } from "../services/api";

// DeviceDetail — a per-device drill-down drawer opened from the Devices
// inventory: device metadata, labels, up/down status, and the device's active
// alerts (reusing existing endpoints; no backend change).

const DOWN_AFTER_MS = 5 * 60 * 1000;
function isDown(d: Device): boolean {
  const seen = new Date(d.last_seen).getTime();
  return !!seen && Date.now() - seen > DOWN_AFTER_MS;
}

export default function DeviceDetail({ device, onClose }: { device: Device; onClose: () => void }) {
  const [alerts, setAlerts] = useState<Alert[] | null>(null);

  useEffect(() => {
    api
      .alerts()
      .then((all) => setAlerts((all ?? []).filter((a) => a.device_id === device.id)))
      .catch(() => setAlerts([]));
  }, [device.id]);

  const rows: [string, string][] = [
    ["ID", device.id],
    ["Name", device.name || "—"],
    ["Address", device.address],
    ["Vendor", device.vendor || "—"],
    ["Model", device.model || "—"],
    ["OS", device.os || "—"],
    ["Preferred protocol", device.preferred_protocol || "—"],
    ["Source", device.source || "—"],
    ["Last seen", new Date(device.last_seen).toLocaleString()],
  ];

  return (
    <div
      className="modal-backdrop"
      style={{ position: "fixed", inset: 0, background: "rgba(0,0,0,0.45)", display: "flex", alignItems: "center", justifyContent: "center", zIndex: 1000 }}
      onClick={onClose}
    >
      <div className="card" style={{ width: "min(640px, 94vw)", maxHeight: "88vh", overflow: "auto" }} onClick={(e) => e.stopPropagation()}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
          <h3 style={{ margin: 0 }}>
            {device.name || device.id}
            {isDown(device) ? (
              <span className="badge" style={{ marginLeft: 8, background: "var(--bad)", color: "#fff" }}>Down</span>
            ) : (
              <span className="badge good" style={{ marginLeft: 8 }}>Up</span>
            )}
          </h3>
          <button className="btn" onClick={onClose}>Close</button>
        </div>

        <table style={{ marginTop: 10 }}>
          <tbody>
            {rows.map(([k, v]) => (
              <tr key={k}>
                <td style={{ color: "var(--muted)", width: 180 }}>{k}</td>
                <td>{v}</td>
              </tr>
            ))}
          </tbody>
        </table>

        {device.labels && Object.keys(device.labels).length > 0 && (
          <>
            <div className="mini-meta" style={{ fontWeight: 700, marginTop: 14 }}>Labels</div>
            <div style={{ display: "flex", flexWrap: "wrap", gap: 6, marginTop: 6 }}>
              {Object.entries(device.labels).map(([k, v]) => (
                <span key={k} className="badge">{k}={v}</span>
              ))}
            </div>
          </>
        )}

        <div className="mini-meta" style={{ fontWeight: 700, marginTop: 16 }}>Active alerts</div>
        {alerts === null ? (
          <div className="empty">Loading…</div>
        ) : alerts.length === 0 ? (
          <p className="mini-meta">No active alerts for this device.</p>
        ) : (
          <table style={{ marginTop: 6 }}>
            <thead>
              <tr>
                <th>Severity</th>
                <th>Rule</th>
                <th>Summary</th>
                <th>Fired</th>
              </tr>
            </thead>
            <tbody>
              {alerts.map((a) => (
                <tr key={a.id}>
                  <td><span className={`badge sev-${a.severity}`}>{a.severity}</span></td>
                  <td>{a.rule}</td>
                  <td>{a.summary}</td>
                  <td className="mini-meta">{new Date(a.fired_at).toLocaleString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}

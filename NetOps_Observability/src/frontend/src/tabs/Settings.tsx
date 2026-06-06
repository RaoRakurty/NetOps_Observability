import { useEffect, useState } from "react";
import { api } from "../services/api";
import { ExportPolicyForm } from "./admin";
import ChangePasswordCard from "../components/ChangePasswordCard";
import Icon from "../components/Icon";

export default function Settings() {
  const [creds, setCreds] = useState<Record<string, boolean>>({});
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<string | null>(null);

  useEffect(() => {
    (async () => setCreds((await api.credentials()) ?? {}))();
  }, []);

  const refresh = async () => {
    setBusy(true);
    setMsg(null);
    try {
      await api.refreshDiscovery();
      setMsg("Discovery refresh requested.");
    } catch (e) {
      setMsg((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <>
      <ChangePasswordCard />

      <div className="card">
        <h2>Integrations</h2>
        <p style={{ color: "var(--muted)", fontSize: 13 }}>
          Configure credentials via <code>deployment/docker/.env</code> or your secret manager.
          The API never echoes secrets back — only whether each integration is configured.
        </p>
        <table>
          <tbody>
            {Object.entries(creds).map(([k, v]) => (
              <tr key={k}>
                <td>{k}</td>
                <td>
                  <span className={`badge ${v ? "good" : "warn"}`}>
                    {v ? "configured" : "not configured"}
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <div className="card">
        <h2>Discovery</h2>
        <button className="btn" disabled={busy} onClick={refresh}>
          <Icon name="refresh" size={14} /> {busy ? "Refreshing…" : "Refresh now"}
        </button>
        {msg && <p style={{ marginTop: 12, color: "var(--muted)" }}>{msg}</p>}
      </div>

      <ExportPolicyForm />
    </>
  );
}

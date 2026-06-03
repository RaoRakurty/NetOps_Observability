import { useEffect, useState } from "react";
import { api } from "../services/api";
import { ExportPolicyForm } from "./admin";

export default function Settings() {
  const [creds, setCreds] = useState<Record<string, boolean>>({});
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<string | null>(null);

  // Change-password state
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [confirm, setConfirm] = useState("");
  const [pwBusy, setPwBusy] = useState(false);
  const [pwMsg, setPwMsg] = useState<string | null>(null);

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

  const changePassword = async (e: React.FormEvent) => {
    e.preventDefault();
    setPwMsg(null);
    if (next !== confirm) {
      setPwMsg("New password and confirmation do not match.");
      return;
    }
    if (next.length < 8) {
      setPwMsg("New password must be at least 8 characters.");
      return;
    }
    setPwBusy(true);
    try {
      await api.changePassword(current, next);
      setCurrent("");
      setNext("");
      setConfirm("");
      setPwMsg("Password updated.");
    } catch (e) {
      setPwMsg((e as Error).message);
    } finally {
      setPwBusy(false);
    }
  };

  return (
    <>
      <div className="card">
        <h2>Change password</h2>
        <form onSubmit={changePassword} style={{ display: "grid", gap: 8, maxWidth: 400 }}>
          <input
            type="password"
            placeholder="Current password"
            value={current}
            onChange={(e) => setCurrent(e.target.value)}
            autoComplete="current-password"
          />
          <input
            type="password"
            placeholder="New password (min 8 chars)"
            value={next}
            onChange={(e) => setNext(e.target.value)}
            autoComplete="new-password"
          />
          <input
            type="password"
            placeholder="Confirm new password"
            value={confirm}
            onChange={(e) => setConfirm(e.target.value)}
            autoComplete="new-password"
          />
          <button disabled={pwBusy} type="submit">
            {pwBusy ? "Updating…" : "Update password"}
          </button>
          {pwMsg && (
            <p style={{ marginTop: 8, color: pwMsg === "Password updated." ? "var(--good)" : "var(--bad)" }}>
              {pwMsg}
            </p>
          )}
        </form>
      </div>

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
        <button disabled={busy} onClick={refresh}>
          {busy ? "Refreshing…" : "Refresh now"}
        </button>
        {msg && <p style={{ marginTop: 12, color: "var(--muted)" }}>{msg}</p>}
      </div>

      <ExportPolicyForm />
    </>
  );
}

import { useEffect, useState } from "react";
import { api } from "../services/api";
import Icon from "./Icon";

// MfaCard — self-service two-factor (authenticator app) management for the signed-in
// LOCAL account. Enable: fetch a setup secret, add it to an authenticator app
// (manual key or otpauth link), confirm a code. Disable: re-enter a code.
export default function MfaCard() {
  const [status, setStatus] = useState<{ enabled: boolean; pending: boolean; local: boolean } | null>(null);
  const [setup, setSetup] = useState<{ secret: string; uri: string } | null>(null);
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [msg, setMsg] = useState<string | null>(null);

  const load = () => api.mfaStatus().then(setStatus).catch(() => setStatus(null));
  useEffect(() => { load(); }, []);

  const begin = async () => {
    setErr(null); setMsg(null); setBusy(true);
    try { setSetup(await api.mfaSetup()); } catch (e) { setErr((e as Error).message); } finally { setBusy(false); }
  };
  const activate = async () => {
    setErr(null); setBusy(true);
    try {
      await api.mfaActivate(code.trim());
      setSetup(null); setCode(""); setMsg("Two-factor authentication is on.");
      await load();
    } catch (e) { setErr((e as Error).message); } finally { setBusy(false); }
  };
  const disable = async () => {
    setErr(null); setBusy(true);
    try {
      await api.mfaDisable(code.trim());
      setCode(""); setMsg("Two-factor authentication is off.");
      await load();
    } catch (e) { setErr((e as Error).message); } finally { setBusy(false); }
  };

  if (!status) return <div className="card"><span className="mini-meta">Loading…</span></div>;

  if (!status.local) {
    return (
      <div className="card" style={{ fontSize: 13, color: "var(--muted)" }}>
        Your account signs in through an external identity provider — set up multi-factor authentication there.
      </div>
    );
  }

  return (
    <div className="card" style={{ maxWidth: 520 }}>
      <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 6 }}>
        <Icon name="lock" size={18} />
        <h3 style={{ margin: 0 }}>Two-factor authentication</h3>
        <span className={`badge ${status.enabled ? "good" : ""}`} style={{ marginLeft: "auto" }}>
          {status.enabled ? "On" : "Off"}
        </span>
      </div>
      <p style={{ color: "var(--muted)", fontSize: 13, marginTop: 0 }}>
        Add a one-time code from an authenticator app (Google Authenticator, 1Password, Authy…) on top of your password.
      </p>

      {msg && <p style={{ color: "var(--accent)", fontSize: 13 }}>{msg}</p>}
      {err && <p style={{ color: "var(--bad)", fontSize: 13 }}>{err}</p>}

      {/* ENABLE flow */}
      {!status.enabled && !setup && (
        <button className="dash-btn accent" disabled={busy} onClick={begin}>Enable two-factor</button>
      )}

      {!status.enabled && setup && (
        <div style={{ display: "grid", gap: 12 }}>
          <div>
            <div className="mini-meta">1. Add this key to your authenticator app</div>
            <code style={{ display: "block", padding: "10px 12px", background: "var(--bg)", border: "1px solid var(--panel-border)", borderRadius: 8, fontSize: 14, letterSpacing: "0.12em", wordBreak: "break-all", marginTop: 4 }}>
              {setup.secret.replace(/(.{4})/g, "$1 ").trim()}
            </code>
            <a href={setup.uri} style={{ fontSize: 12 }}>Open in authenticator app</a>
          </div>
          <label className="form-field" style={{ display: "grid", gap: 4 }}>
            <span className="mini-meta">2. Enter the 6-digit code it shows</span>
            <input
              inputMode="numeric" maxLength={6} placeholder="123456" autoComplete="one-time-code"
              value={code} onChange={(e) => setCode(e.target.value.replace(/\D/g, ""))}
              style={{ letterSpacing: "0.3em", fontSize: 16, textAlign: "center", maxWidth: 160 }}
            />
          </label>
          <div style={{ display: "flex", gap: 8 }}>
            <button className="dash-btn accent" disabled={busy || code.length < 6} onClick={activate}>Confirm &amp; turn on</button>
            <button className="dash-btn" disabled={busy} onClick={() => { setSetup(null); setCode(""); }}>Cancel</button>
          </div>
        </div>
      )}

      {/* DISABLE flow */}
      {status.enabled && (
        <div style={{ display: "grid", gap: 8, maxWidth: 220 }}>
          <span className="mini-meta">Enter a current code to turn it off</span>
          <input
            inputMode="numeric" maxLength={6} placeholder="123456" autoComplete="one-time-code"
            value={code} onChange={(e) => setCode(e.target.value.replace(/\D/g, ""))}
            style={{ letterSpacing: "0.3em", fontSize: 16, textAlign: "center" }}
          />
          <button className="dash-btn" disabled={busy || code.length < 6} onClick={disable}>Turn off two-factor</button>
        </div>
      )}
    </div>
  );
}

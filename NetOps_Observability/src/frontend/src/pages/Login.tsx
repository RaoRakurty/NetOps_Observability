import { useEffect, useState } from "react";
import { api, SSOConfig } from "../services/api";
import { BRAND, BRAND_TAGLINE } from "../brand";

export default function Login({ onLoggedIn }: { onLoggedIn: () => void }) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(
    () => sessionStorage.getItem("netops_sso_error"),
  );
  const [sso, setSso] = useState<SSOConfig | null>(null);

  useEffect(() => {
    sessionStorage.removeItem("netops_sso_error");
    api.ssoConfig().then(setSso).catch(() => setSso(null));
  }, []);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await api.login(username, password);
      onLoggedIn();
    } catch (e) {
      setError((e as Error).message.replace(/^401 Unauthorized: ?/, ""));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div
      style={{
        minHeight: "100vh",
        display: "grid",
        placeItems: "center",
        background: "var(--bg)",
      }}
    >
      <form
        onSubmit={submit}
        className="card"
        style={{ width: 360, padding: 32, margin: 0 }}
      >
        <h1 style={{ marginTop: 0, fontSize: 26, letterSpacing: "-0.02em" }}>{BRAND}</h1>
        <p style={{ color: "var(--muted)", fontSize: 13, marginTop: 2 }}>
          {BRAND_TAGLINE} · sign in to continue.
        </p>

        <label style={{ display: "block", marginTop: 12, fontSize: 12, color: "var(--muted)" }}>
          Username
        </label>
        <input
          autoFocus
          value={username}
          onChange={(e) => setUsername(e.target.value)}
          style={{ width: "100%", marginTop: 4, padding: 8 }}
          autoComplete="username"
        />

        <label style={{ display: "block", marginTop: 12, fontSize: 12, color: "var(--muted)" }}>
          Password
        </label>
        <input
          type="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          style={{ width: "100%", marginTop: 4, padding: 8 }}
          autoComplete="current-password"
        />

        {error && (
          <p style={{ color: "var(--bad)", marginTop: 12, fontSize: 13 }}>
            {error}
          </p>
        )}

        <button
          disabled={busy || !username || !password}
          type="submit"
          style={{ width: "100%", marginTop: 16, padding: 10 }}
        >
          {busy ? "Signing in…" : "Sign in"}
        </button>

        {sso?.enabled && sso.providers.length > 0 && (
          <>
            <div
              style={{
                display: "flex", alignItems: "center", gap: 8,
                margin: "16px 0 12px", color: "var(--muted)", fontSize: 11,
              }}
            >
              <span style={{ flex: 1, height: 1, background: "var(--border)" }} />
              or
              <span style={{ flex: 1, height: 1, background: "var(--border)" }} />
            </div>
            {sso.providers.map((p) => (
              <button
                key={p.id || "default"}
                type="button"
                onClick={() => { window.location.href = api.ssoLoginUrl(p.id); }}
                style={{ width: "100%", marginTop: 8, padding: 10 }}
                title={`Sign in via ${p.kind.toUpperCase()}`}
              >
                Sign in with {p.name}
              </button>
            ))}
          </>
        )}

        <p style={{ color: "var(--muted)", fontSize: 11, marginTop: 16 }}>
          First-time install? Initial credentials are in{" "}
          <code>deployment/docker/.env</code> as <code>ADMIN_USERNAME</code> and{" "}
          <code>ADMIN_INITIAL_PASSWORD</code>. Change your password on the
          Settings tab after signing in.
        </p>
      </form>
    </div>
  );
}

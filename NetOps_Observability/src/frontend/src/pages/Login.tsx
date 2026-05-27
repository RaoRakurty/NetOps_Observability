import { useState } from "react";
import { api } from "../services/api";

export default function Login({ onLoggedIn }: { onLoggedIn: () => void }) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

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
        <h1 style={{ marginTop: 0, fontSize: 20 }}>NetOps Observability</h1>
        <p style={{ color: "var(--muted)", fontSize: 13, marginTop: 0 }}>
          Sign in to continue.
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

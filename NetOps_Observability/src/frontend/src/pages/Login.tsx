import { useEffect, useState } from "react";
import { api, AuthMethods, takeSessionEndMessage } from "../services/api";
import { BRAND, BRAND_TAGLINE } from "../brand";
import Icon from "../components/Icon";
import ChangePasswordCard from "../components/ChangePasswordCard";
import eyeIris from "../assets/brand/eye-iris.webp";

// Served from public/ under a stable URL so index.html can <link rel="preload">
// it — the artwork starts downloading before the app bundle finishes parsing.
const EYE_HERO_URL = "/brand/eye-hero.webp";

type Method = "local" | "ldap" | "tacacs";

// The wordmark: CORRELIX with the O replaced by the iris of the eye artwork.
// Screen readers get the brand name once; the split glyphs are decorative.
function EyeWordmark() {
  return (
    <h1 className="login-wordmark" aria-label={BRAND}>
      <span aria-hidden="true">C</span>
      <span aria-hidden="true" className="login-wm-eye"><img src={eyeIris} alt="" /></span>
      <span aria-hidden="true">RRELIX</span>
    </h1>
  );
}

// Shared cinematic scene: brand stage on the left, glass form card on the
// right. All three login views (sign-in, MFA, change password) render inside
// it so the whole pre-auth experience is one continuous space. Two versions
// exist — the deep-space "Dark" scene and the calm white "Light" scene — and
// the visitor's pick persists across visits.
const SCENE_KEY = "netops.login.scene";
type Scene = "dark" | "light";

function LoginScene({ children }: { children: React.ReactNode }) {
  const [scene, setScene] = useState<Scene>(
    () => (localStorage.getItem(SCENE_KEY) === "light" ? "light" : "dark"),
  );
  const pick = (s: Scene) => {
    localStorage.setItem(SCENE_KEY, s);
    setScene(s);
  };
  return (
    <div className={scene === "light" ? "login-scene login-light" : "login-scene"}>
      {/* The eye artwork at full presence — the scene the glass card floats in. */}
      <img className="login-bg-eye" src={EYE_HERO_URL} alt="" decoding="async" />
      <div className="login-scene-toggle" role="group" aria-label="Background style">
        <button type="button" className={scene === "dark" ? "on" : ""} aria-pressed={scene === "dark"} onClick={() => pick("dark")}>Dark</button>
        <button type="button" className={scene === "light" ? "on" : ""} aria-pressed={scene === "light"} onClick={() => pick("light")}>Light</button>
      </div>
      <div className="login-stage">
        <header className="login-brandside">
          <p className="login-eyebrow">{BRAND_TAGLINE}</p>
          <EyeWordmark />
          <ul className="login-creed">
            <li><em>See</em> everything</li>
            <li><em>Correlate</em> everything</li>
            <li><em>Resolve</em> anything</li>
          </ul>
        </header>
        <div className="login-formside">{children}</div>
      </div>
    </div>
  );
}

export default function Login({ onLoggedIn }: { onLoggedIn: () => void }) {
  // The login window doubles as the self-service "Change password" entry point
  // for local accounts (federated users change it at their IdP).
  const [view, setView] = useState<"signin" | "changepw">("signin");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [showPw, setShowPw] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(
    () => sessionStorage.getItem("netops_sso_error"),
  );
  const [methods, setMethods] = useState<AuthMethods | null>(null);
  const [method, setMethod] = useState<Method>("local");
  // Why the user landed here, if a server-side session ended (idle/absolute/revoked).
  const [notice] = useState<string | null>(() => takeSessionEndMessage());
  // MFA challenge: set after a password succeeds for an MFA-enabled account.
  const [mfaToken, setMfaToken] = useState<string | null>(null);
  const [mfaCode, setMfaCode] = useState("");

  useEffect(() => {
    sessionStorage.removeItem("netops_sso_error");
    api.authMethods().then(setMethods).catch(() => setMethods(null));
  }, []);

  // Which password-based methods are available (local is always on).
  const directMethods: { id: Method; label: string }[] = [
    { id: "local", label: "Local account" },
    ...(methods?.ldap.enabled ? [{ id: "ldap" as Method, label: methods.ldap.name }] : []),
    ...(methods?.tacacs.enabled ? [{ id: "tacacs" as Method, label: methods.tacacs.name }] : []),
  ];
  const ssoProviders = methods?.sso.enabled ? methods.sso.providers : [];

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      if (method === "ldap") await api.ldapLogin(username, password);
      else if (method === "tacacs") await api.tacacsLogin(username, password);
      else {
        const r = await api.login(username, password);
        if (r.mfaRequired && r.mfaToken) { setMfaToken(r.mfaToken); return; } // → code step
      }
      onLoggedIn();
    } catch (e) {
      setError((e as Error).message.replace(/^401 Unauthorized: ?/, ""));
    } finally {
      setBusy(false);
    }
  };

  const submitMfa = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!mfaToken) return;
    setBusy(true);
    setError(null);
    try {
      await api.mfaLogin(mfaToken, mfaCode.trim());
      onLoggedIn();
    } catch (e) {
      setError((e as Error).message.replace(/^401 Unauthorized: ?/, ""));
    } finally {
      setBusy(false);
    }
  };

  // Step 2: authenticator code entry (after a password succeeds for an MFA account).
  if (mfaToken) {
    return (
      <LoginScene>
        <form onSubmit={submitMfa} className="card login-card">
          <h2 className="login-card-title">Two-step verification</h2>
          <p className="login-sub">Enter the 6-digit code from your authenticator app.</p>
          <div className="login-form">
            <div className="form-field">
              <label className="form-label" htmlFor="mfa-code">Authentication code</label>
              <input
                id="mfa-code"
                className="form-input"
                autoFocus
                inputMode="numeric"
                autoComplete="one-time-code"
                maxLength={6}
                placeholder="123456"
                value={mfaCode}
                onChange={(e) => setMfaCode(e.target.value.replace(/\D/g, ""))}
                style={{ letterSpacing: "0.3em", fontSize: 18, textAlign: "center" }}
              />
            </div>
            {error && <p className="login-msg" role="alert" aria-live="polite">{error}</p>}
            <button className="btn-accent" disabled={busy || mfaCode.length < 6} type="submit" style={{ width: "100%" }}>
              {busy ? "Verifying…" : "Verify"}
            </button>
            <button type="button" className="login-link" onClick={() => { setMfaToken(null); setMfaCode(""); setError(null); }}>
              Back to sign in
            </button>
          </div>
        </form>
      </LoginScene>
    );
  }

  if (view === "changepw") {
    return (
      <LoginScene>
        <ChangePasswordCard preAuth onDone={() => setView("signin")} />
      </LoginScene>
    );
  }

  return (
    <LoginScene>
      <form onSubmit={submit} className="card login-card">
        <h2 className="login-card-title">Sign in</h2>

        {notice && <p className="login-msg" role="status" aria-live="polite" style={{ color: "var(--muted)" }}>{notice}</p>}

        <div className="login-form">
          {/* Method selector only appears when a directory provider is enabled. */}
          {directMethods.length > 1 && (
            <div className="form-field">
              <label className="form-label" htmlFor="login-method">Sign in with</label>
              <select
                id="login-method"
                className="form-select"
                value={method}
                onChange={(e) => setMethod(e.target.value as Method)}
              >
                {directMethods.map((m) => (
                  <option key={m.id} value={m.id}>{m.label}</option>
                ))}
              </select>
            </div>
          )}

          <div className="form-field">
            <label className="form-label" htmlFor="login-user">Username</label>
            <input
              id="login-user"
              className="form-input"
              autoFocus
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              autoComplete="username"
            />
          </div>

          <div className="form-field">
            <label className="form-label" htmlFor="login-pw">Password</label>
            <div className="pw-input-wrap">
              <input
                id="login-pw"
                className="pw-input"
                type={showPw ? "text" : "password"}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                autoComplete="current-password"
              />
              <button
                type="button"
                className="pw-eye"
                onClick={() => setShowPw((s) => !s)}
                aria-label={showPw ? "Hide password" : "Show password"}
                aria-pressed={showPw}
                tabIndex={-1}
              >
                <Icon name={showPw ? "eye-off" : "eye"} size={16} />
              </button>
            </div>
          </div>

          {error && (
            <p className="login-msg" role="alert" aria-live="polite">{error}</p>
          )}

          <button className="btn-accent" disabled={busy || !username || !password} type="submit" style={{ width: "100%" }}>
            {busy ? "Signing in…" : "Sign in"}
          </button>

          <button type="button" className="login-link" onClick={() => setView("changepw")}>
            Change password
          </button>
        </div>

        {ssoProviders.length > 0 && (
          <div className="login-sso">
            <div className="login-divider">or</div>
            {ssoProviders.map((p) => (
              <button
                key={p.id || "default"}
                type="button"
                className="btn"
                onClick={() => { window.location.href = api.ssoLoginUrl(p.id); }}
                title={`Sign in via ${p.kind.toUpperCase()}`}
                style={{ width: "100%" }}
              >
                Sign in with {p.name}
              </button>
            ))}
          </div>
        )}
      </form>
    </LoginScene>
  );
}

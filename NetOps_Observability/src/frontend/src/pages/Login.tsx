// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

import { useEffect, useRef, useState } from "react";
import { api, AuthMethods, ServiceBusyError, takeSessionEndMessage } from "../services/api";
import { readAppearance, setAppearancePref } from "../theme/prefs";
import { BRAND } from "../brand";

// Sentence case, deliberately not BRAND_TAGLINE: that constant is title-case
// ("Network Observability") and feeds the document title and the installer
// docs, where title case is right. Here it is a caption under a wordmark.
const LOGIN_CAPTION = "Network observability";

// What a saturated server gets to say, after we have already retried for the
// operator (tracker 322). Deliberately not the raw envelope: "503 Service
// Unavailable" reads as a broken product, when what happened is that the box
// was too busy for a moment. No advice to "contact support" either — the thing
// that actually works is waiting a little.
const BUSY_MESSAGE = "The system is busy — try again shortly.";
import Icon from "../components/Icon";
import ChangePasswordCard from "../components/ChangePasswordCard";
import eyeIris from "../assets/brand/eye-iris.webp";

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

// The pre-auth stage: brand and form in ONE centred column on a uniform
// field. The oversized eye artwork and the pinprick starfield are gone — at
// 3 a.m. during an incident the login should be the calmest screen in the
// product, and a busy backdrop costs legibility on exactly the surface that
// can least afford it. What survives is the wordmark (with its iris detail)
// and a single pane of glass.
//
// The Dark/Light pick IS the app appearance (owner, 2026-07-10): both this
// control and the topbar knob read/write the shared theme pref, so signing in
// lands in the look chosen here and vice versa. The old scene-only key remains
// as a first-visit fallback, then converges onto the theme pref.
const SCENE_KEY = "netops.login.scene";
type Scene = "dark" | "light";

function LoginScene({ children }: { children: React.ReactNode }) {
  const [scene, setScene] = useState<Scene>(() => {
    if (localStorage.getItem("netops.theme")) return readAppearance();
    return localStorage.getItem(SCENE_KEY) === "light" ? "light" : "dark";
  });
  const pick = (s: Scene) => {
    localStorage.setItem(SCENE_KEY, s); // legacy readers
    setAppearancePref(s); // single source of truth — the app theme
    setScene(s);
  };
  return (
    <div className={scene === "light" ? "login-scene login-light" : "login-scene"}>
      <div className="login-scene-toggle" role="group" aria-label="Appearance">
        <button type="button" className={scene === "dark" ? "on" : ""} aria-pressed={scene === "dark"} onClick={() => pick("dark")}>Dark</button>
        <button type="button" className={scene === "light" ? "on" : ""} aria-pressed={scene === "light"} onClick={() => pick("light")}>Light</button>
      </div>
      <div className="login-stage">
        <header className="login-brandside">
          <EyeWordmark />
          <p className="login-caption">{LOGIN_CAPTION}</p>
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
  // Per-field errors. The button used to be disabled until both fields had
  // content, which is quiet but tells a keyboard or screen-reader user nothing
  // about WHY they cannot proceed. The button now submits and the form says
  // what is missing, focusing the first offending field.
  const [fieldErr, setFieldErr] = useState<{ user?: string; pw?: string }>({});
  const userRef = useRef<HTMLInputElement>(null);
  const pwRef = useRef<HTMLInputElement>(null);

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
  // Elevation doors are shown SEPARATELY, never mixed into the ordinary
  // sign-in list. They do not create accounts and they do not sign a new person
  // in — an operator who picks one because it looked like the front door gets
  // "sign in through your standing provider first", which is a confusing way to
  // learn the difference. Grouping them is the fix.
  const standingProviders = ssoProviders.filter((p) => p.access !== "elevation");
  const elevationProviders = ssoProviders.filter((p) => p.access === "elevation");

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (busy) return; // a second Enter while the request is in flight
    const fe: { user?: string; pw?: string } = {};
    if (!username.trim()) fe.user = "Enter your username.";
    if (!password) fe.pw = "Enter your password.";
    setFieldErr(fe);
    if (fe.user || fe.pw) {
      setError(null);
      (fe.user ? userRef : pwRef).current?.focus();
      return;
    }
    setBusy(true);
    setError(null);
    // ONE sign-in attempt. "halt" means the flow has already moved somewhere
    // else (the MFA step, the forced password change) and this submit is done.
    const attempt = async (): Promise<"in" | "halt"> => {
      if (method === "ldap") await api.ldapLogin(username, password);
      else if (method === "tacacs") await api.tacacsLogin(username, password);
      else {
        const r = await api.login(username, password);
        if (r.mfaRequired && r.mfaToken) { setMfaToken(r.mfaToken); return "halt"; } // → code step
        // F-68: credentials were right, but the scope's Security Settings
        // withhold the session until the password is reset (expiry /
        // reset-on-first-login). No token was issued — send the user to the
        // pre-auth change-password form rather than onLoggedIn().
        if (r.mustChangePassword) {
          setError(r.message ?? "A password reset is required before you can sign in.");
          setView("changepw");
          return "halt";
        }
      }
      return "in";
    };
    try {
      let outcome: "in" | "halt";
      try {
        outcome = await attempt();
      } catch (first) {
        // Tracker 322. A 503 is the server saying "not now", not "you got this
        // wrong": under IO pressure the session write misses its deadline and
        // the same credentials succeed seconds later. Wait the delay the server
        // advertised (the api clamps it to something a person will sit through)
        // and try exactly once more. The button stays busy throughout, so the
        // operator sees one continuous "Signing in…" instead of an error they
        // would have to act on.
        //
        // ONE retry, never a loop: a second refusal means the box really is
        // saturated, and a client that keeps hammering it is part of the
        // problem. Any other failure — a wrong password above all — is
        // re-thrown untouched, so nothing else is retried or reworded.
        if (!(first instanceof ServiceBusyError)) throw first;
        await new Promise((resolve) => setTimeout(resolve, first.retryAfterSeconds * 1000));
        try {
          outcome = await attempt();
        } catch (again) {
          if (!(again instanceof ServiceBusyError)) throw again;
          setError(BUSY_MESSAGE);
          return;
        }
      }
      if (outcome === "in") onLoggedIn();
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
        <h2 className="login-card-title">Sign in to {BRAND}</h2>
        {/* Per-tenant sign-in URL (/t/{slug}, /org/{org_id}): name the realm the
            visitor landed on, so a wrong link is obvious before they type a
            password. The name comes from the SERVER's resolution of the URL —
            the browser never asserts a tenant — and the provider list below is
            already filtered to that realm's identity providers. */}
        {methods?.locator && (
          <p className="login-msg" role="status" style={{ color: "var(--muted)" }}>
            Signing in to <strong>{methods.locator.name}</strong>
          </p>
        )}

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
            {/* "Username", not "Email": local, LDAP and TACACS all authenticate
                a username. Nothing in the auth path accepts an address, so
                calling it one would invite a value that always fails. */}
            <label className="form-label" htmlFor="login-user">Username</label>
            <input
              id="login-user"
              ref={userRef}
              className="form-input"
              autoFocus
              value={username}
              onChange={(e) => { setUsername(e.target.value); if (fieldErr.user) setFieldErr((f) => ({ ...f, user: undefined })); }}
              autoComplete="username"
              aria-invalid={fieldErr.user ? true : undefined}
              aria-describedby={fieldErr.user ? "login-user-err" : undefined}
            />
            {fieldErr.user && (
              <p className="login-field-err" id="login-user-err">
                <Icon name="alert-triangle" size={14} aria-hidden="true" />
                {fieldErr.user}
              </p>
            )}
          </div>

          <div className="form-field">
            <label className="form-label" htmlFor="login-pw">Password</label>
            <div className="pw-input-wrap">
              <input
                id="login-pw"
                ref={pwRef}
                className="pw-input"
                type={showPw ? "text" : "password"}
                value={password}
                onChange={(e) => { setPassword(e.target.value); if (fieldErr.pw) setFieldErr((f) => ({ ...f, pw: undefined })); }}
                autoComplete="current-password"
                aria-invalid={fieldErr.pw ? true : undefined}
                aria-describedby={fieldErr.pw ? "login-pw-err" : undefined}
              />
              <button
                type="button"
                className="pw-eye"
                onClick={() => setShowPw((s) => !s)}
                aria-label={showPw ? "Hide password" : "Show password"}
                aria-pressed={showPw}
              >
                <Icon name={showPw ? "eye-off" : "eye"} size={16} aria-hidden="true" />
              </button>
            </div>
            {fieldErr.pw && (
              <p className="login-field-err" id="login-pw-err">
                <Icon name="alert-triangle" size={14} aria-hidden="true" />
                {fieldErr.pw}
              </p>
            )}
          </div>

          {error && (
            <p className="login-msg" role="alert">
              <Icon name="alert-triangle" size={14} aria-hidden="true" />
              {error}
            </p>
          )}

          {/* Disabled only while the request is in flight — never as a stand-in
              for validation, which now speaks for itself above. */}
          <button className="btn-accent login-submit" disabled={busy} type="submit" aria-busy={busy || undefined}>
            {busy ? "Signing in…" : "Sign in"}
          </button>
          {/* The live region is separate from the button so the label change is
              announced without the button's accessible name churning. */}
          <span className="sr-only" role="status" aria-live="polite">{busy ? "Signing in, please wait." : ""}</span>

          {/* Wording verified against the flow it opens: ChangePasswordCard asks
              for the CURRENT password, so it is a change, not a recovery. It is
              not renamed "Forgot password?" — that would promise a reset this
              product does not perform. Recovery is an administrator action. */}
          <div className="login-help">
            <button type="button" className="login-link" onClick={() => setView("changepw")}>
              Change password
            </button>
            <p className="login-help-note">Locked out? Ask a Correlix administrator to reset your account.</p>
          </div>
        </div>

        {standingProviders.length > 0 && (
          <div className="login-sso">
            <div className="login-divider">or</div>
            {standingProviders.map((p) => (
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

        {elevationProviders.length > 0 && (
          <div className="login-sso">
            <div className="login-divider">Elevated access</div>
            {elevationProviders.map((p) => (
              <button
                key={p.id || "default"}
                type="button"
                className="btn"
                onClick={() => { window.location.href = api.ssoLoginUrl(p.id); }}
                title="Adds time-bound access to an existing account"
                style={{ width: "100%" }}
              >
                Elevate with {p.name}
              </button>
            ))}
          </div>
        )}
      </form>
    </LoginScene>
  );
}

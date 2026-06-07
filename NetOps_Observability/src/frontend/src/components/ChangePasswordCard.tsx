import { useEffect, useMemo, useState } from "react";
import { api } from "../services/api";
import Icon from "./Icon";

// ChangePasswordCard — a modern, theme-aware self-service password change.
// Reflects the caller's resolved Security Policy (#24) as live requirements,
// shows a strength meter, per-field show/hide, and accessible submit feedback.
// The server re-validates authoritatively; this UI is the friendly front door.

type Rules = { min_length: number; complexity_classes: number };

const CLASS_LABEL = "lowercase, uppercase, digit & symbol";

function classCount(pw: string): number {
  let lower = false, upper = false, digit = false, symbol = false;
  for (const ch of pw) {
    if (/[a-z]/.test(ch)) lower = true;
    else if (/[A-Z]/.test(ch)) upper = true;
    else if (/[0-9]/.test(ch)) digit = true;
    else symbol = true;
  }
  return [lower, upper, digit, symbol].filter(Boolean).length;
}

// strength: 0–4, blending length and character variety. Advisory only.
function strength(pw: string, minLen: number): number {
  if (!pw) return 0;
  let score = 0;
  if (pw.length >= minLen) score++;
  if (pw.length >= minLen + 4) score++;
  const classes = classCount(pw);
  if (classes >= 2) score++;
  if (classes >= 3) score++;
  return Math.min(4, score);
}

const STRENGTH = [
  { label: "Too short", cls: "s0" },
  { label: "Weak", cls: "s1" },
  { label: "Fair", cls: "s2" },
  { label: "Good", cls: "s3" },
  { label: "Strong", cls: "s4" },
];

function PasswordInput({
  label, value, onChange, autoComplete, id,
}: {
  label: string;
  value: string;
  onChange: (v: string) => void;
  autoComplete: string;
  id: string;
}) {
  const [show, setShow] = useState(false);
  return (
    <div className="pw-field">
      <label className="pw-label" htmlFor={id}>{label}</label>
      <div className="pw-input-wrap">
        <input
          id={id}
          className="pw-input"
          type={show ? "text" : "password"}
          value={value}
          onChange={(e) => onChange(e.target.value)}
          autoComplete={autoComplete}
        />
        <button
          type="button"
          className="pw-eye"
          onClick={() => setShow((s) => !s)}
          aria-label={show ? "Hide password" : "Show password"}
          aria-pressed={show}
          tabIndex={-1}
        >
          <Icon name={show ? "eye-off" : "eye"} size={16} />
        </button>
      </div>
    </div>
  );
}

function Req({ met, children }: { met: boolean; children: React.ReactNode }) {
  return (
    <li className={`pw-req${met ? " met" : ""}`}>
      <span className="pw-req-dot">{met && <Icon name="check" size={12} />}</span>
      {children}
    </li>
  );
}

// preAuth renders the card for the login window (no session yet): it adds a
// username field and posts it so the server can identify the account. onDone is
// called after a successful change (e.g. to return to the sign-in form).
export default function ChangePasswordCard({ preAuth = false, onDone }: { preAuth?: boolean; onDone?: () => void } = {}) {
  const [rules, setRules] = useState<Rules>({ min_length: 8, complexity_classes: 0 });
  const [username, setUsername] = useState("");
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [confirm, setConfirm] = useState("");
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<{ kind: "ok" | "err"; text: string } | null>(null);

  useEffect(() => {
    (async () => {
      try {
        setRules(await api.passwordPolicy());
      } catch {
        /* advisory fetch — fall back to the conservative defaults */
      }
    })();
  }, []);

  const lenOK = next.length >= rules.min_length;
  const classesOK = rules.complexity_classes === 0 || classCount(next) >= rules.complexity_classes;
  const matchOK = next.length > 0 && next === confirm;
  const valid = lenOK && classesOK && matchOK && current.length > 0 && (!preAuth || username.trim().length > 0);
  const score = useMemo(() => strength(next, rules.min_length), [next, rules.min_length]);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setMsg(null);
    if (!valid) return;
    setBusy(true);
    try {
      await api.changePassword(current, next, preAuth ? username.trim() : undefined);
      setCurrent(""); setNext(""); setConfirm("");
      setMsg({ kind: "ok", text: "Password updated." + (preAuth ? " You can sign in now." : "") });
      if (preAuth && onDone) setTimeout(onDone, 1200);
    } catch (err) {
      setMsg({ kind: "err", text: (err as Error).message });
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="card pw-card">
      <div className="pw-head">
        <span className="pw-head-icon"><Icon name="lock" size={18} /></span>
        <div>
          <h2>Change password</h2>
          <p className="pw-sub">
            {preAuth
              ? "Set a new password for your local account. Federated (SSO/LDAP) accounts change it at the identity provider."
              : "Choose a strong password that meets your organization's security policy."}
          </p>
        </div>
      </div>

      <form onSubmit={submit} className="pw-form">
        {preAuth && (
          <div className="pw-field">
            <label className="pw-label" htmlFor="pw-username">Username</label>
            <div className="pw-input-wrap">
              <input
                id="pw-username"
                className="pw-input"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                autoComplete="username"
              />
            </div>
          </div>
        )}
        <PasswordInput id="pw-current" label="Current password" value={current} onChange={setCurrent} autoComplete="current-password" />
        <PasswordInput id="pw-next" label="New password" value={next} onChange={setNext} autoComplete="new-password" />

        {next.length > 0 && (
          <div className={`pw-strength ${STRENGTH[score].cls}`}>
            <div className="pw-meter"><span style={{ width: `${(score / 4) * 100}%` }} /></div>
            <span className="pw-strength-label">{STRENGTH[score].label}</span>
          </div>
        )}

        <ul className="pw-reqs">
          <Req met={lenOK}>At least {rules.min_length} characters</Req>
          {rules.complexity_classes > 0 && (
            <Req met={classesOK}>
              At least {rules.complexity_classes} of: {CLASS_LABEL}
            </Req>
          )}
          <Req met={matchOK}>New password and confirmation match</Req>
        </ul>

        <PasswordInput id="pw-confirm" label="Confirm new password" value={confirm} onChange={setConfirm} autoComplete="new-password" />

        <div className="pw-actions">
          <button className="btn-accent" disabled={!valid || busy} type="submit">
            {busy ? "Updating…" : "Update password"}
          </button>
          {preAuth && onDone && (
            <button type="button" className="btn" onClick={onDone}>Back to sign in</button>
          )}
          {msg && (
            <p className={`pw-msg ${msg.kind}`} role={msg.kind === "err" ? "alert" : "status"} aria-live="polite">
              {msg.kind === "ok" && <Icon name="check" size={14} />} {msg.text}
            </p>
          )}
        </div>
      </form>
    </div>
  );
}

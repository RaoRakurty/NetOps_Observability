// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

import { useCallback, useEffect, useMemo, useState } from "react";
import { api } from "../services/api";
import { operatorError } from "../lib/errors";
import { encodeQR, qrPathData } from "../lib/qr";
import Icon from "./Icon";
import AskIris from "./AskIris";

// TwoFactorCard — self-service two-factor enrolment, reachable from either
// account menu. It follows ChangePasswordCard's shape (same modal body, same
// tokens, same message affordance) because they are the two halves of the same
// "my account" surface.
//
// HONESTY RULES THIS CARD FOLLOWS.
//   - It states the account's REAL state, read back from the server after every
//     change, so the card can never show a stale "on" after a turn-off.
//   - It does not promise recovery codes. The platform issues none; the actual
//     recovery path when a device is lost is an administrator reset, and the
//     card says exactly that rather than leaving an operator to find out at the
//     worst possible moment.
//   - A federated account gets no controls at all: its second factor lives at
//     the identity provider and any button here would be a lie.
//
// SECRET HANDLING. The enrolment secret is rendered only during the enrolment
// step, never logged, never placed in a URL, and dropped from component state
// the moment activation succeeds.
//
// UI-WORDS SWEEP 5 (tracker 270). What a one-time code IS, what "managed by your
// identity provider" means and the full recovery story are TEACHING: they live in
// ai/skills/explain/auth.two-factor.md, auth.provider-managed-mfa.md and
// auth.no-recovery-codes.md, behind the (i). What stays on the card is the
// account's STATE (.fact-line — a state is not a lesson) and the ONE warning an
// operator must read before enrolling: there are no recovery codes, and losing
// the device costs an administrator reset. That consequence was shortened in
// words, never in claim.

type Status = { enabled: boolean; pending: boolean; local: boolean };

/**
 * The enrolment URI as a QR code, drawn as real SVG elements from lib/qr.ts.
 * Nothing here goes near innerHTML: the matrix becomes a path `d` attribute and
 * React renders the element itself.
 *
 * Black on white is deliberate and theme-independent — a camera reading the
 * symbol needs the contrast the standard assumes, not the console's palette.
 */
function EnrolmentQR({ uri }: { uri: string }) {
  const drawn = useMemo(() => {
    try {
      const matrix = encodeQR(uri);
      return { d: qrPathData(matrix), n: matrix.length };
    } catch {
      return null;
    }
  }, [uri]);

  if (!drawn) {
    return (
      <p className="fact-line fact-warn">No code drawn. Use the setup key below.</p>
    );
  }

  const span = drawn.n + 8; // four light modules of quiet zone on every side
  return (
    <svg
      role="img"
      aria-label="Two-factor enrolment code for your authenticator app"
      viewBox={`-4 -4 ${span} ${span}`}
      width={188}
      height={188}
      shapeRendering="crispEdges"
      style={{ borderRadius: "var(--radius-sm, 6px)" }}
    >
      <title>Two-factor enrolment code for your authenticator app</title>
      <rect x={-4} y={-4} width={span} height={span} fill="white" />
      <path d={drawn.d} fill="black" />
    </svg>
  );
}

export default function TwoFactorCard({ onDone }: { onDone?: () => void } = {}) {
  const [status, setStatus] = useState<Status | null>(null);
  const [statusErr, setStatusErr] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  // Present only between "Set up" and a successful activation.
  const [enrolment, setEnrolment] = useState<{ secret: string; uri: string } | null>(null);
  const [turningOff, setTurningOff] = useState(false);
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<{ kind: "ok" | "err"; text: string } | null>(null);
  const [copied, setCopied] = useState(false);

  const readStatus = useCallback(async () => {
    try {
      setStatus(await api.mfaStatus());
      setStatusErr(null);
    } catch (e) {
      setStatus(null);
      setStatusErr(operatorError(e, "Whether two-factor is on for this account could not be read."));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { void readStatus(); }, [readStatus]);

  const startSetup = async () => {
    setBusy(true);
    setMsg(null);
    setCode("");
    setCopied(false);
    try {
      const started = await api.mfaSetup();
      setEnrolment({ secret: started.secret, uri: started.uri });
    } catch (e) {
      setMsg({ kind: "err", text: operatorError(e, "Two-factor enrolment could not be started.") });
    } finally {
      setBusy(false);
    }
  };

  const activate = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setMsg(null);
    try {
      await api.mfaActivate(code.trim());
      // The secret has done its job — it leaves the component before anything
      // else renders.
      setEnrolment(null);
      setCode("");
      setCopied(false);
      setMsg({ kind: "ok", text: "That code matched — two-factor is active from the next sign-in." });
      await readStatus();
    } catch (err) {
      setMsg({ kind: "err", text: operatorError(err, "Two-factor authentication was not turned on.") });
    } finally {
      setBusy(false);
    }
  };

  const disable = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setMsg(null);
    try {
      await api.mfaDisable(code.trim());
      setCode("");
      setTurningOff(false);
      setMsg({ kind: "ok", text: "That code matched — two-factor has been removed from this account." });
      await readStatus();
    } catch (err) {
      setMsg({ kind: "err", text: operatorError(err, "Two-factor authentication was not turned off.") });
    } finally {
      setBusy(false);
    }
  };

  // The key stays selectable text whatever happens here: a clipboard the browser
  // withholds must not look like a copy that worked.
  const copySecret = async () => {
    if (!enrolment) return;
    const clipboard = navigator.clipboard;
    const refuse = () => {
      setCopied(false);
      setMsg({ kind: "err", text: "The setup key was not copied — select it and copy it by hand." });
    };
    if (!clipboard) { refuse(); return; }
    try {
      await clipboard.writeText(enrolment.secret);
      setCopied(true);
    } catch {
      refuse();
    }
  };

  const codeReady = /^[0-9]{6}$/.test(code.trim());

  const head = (
    <div className="pw-head">
      <span className="pw-head-icon"><Icon name="shield" size={18} /></span>
      <div>
        <h2>
          Two-factor authentication
          <AskIris topic="auth.two-factor" label="Two-factor authentication" />
        </h2>
      </div>
    </div>
  );

  const message = msg && (
    <p className={`pw-msg ${msg.kind}`} role={msg.kind === "err" ? "alert" : "status"} aria-live="polite">
      {msg.kind === "ok" && <Icon name="check" size={14} />} {msg.text}
    </p>
  );

  const closeButton = onDone && (
    <button type="button" className="btn" onClick={onDone}>Close</button>
  );

  // The recovery truth, stated wherever an operator can act on it. There are no
  // recovery codes to write down, so the sentence names the only real path.
  const recoveryNote = (
    <p className="pw-sub">
      No recovery codes: an administrator resets two-factor if the device is lost.
      <AskIris topic="auth.no-recovery-codes" label="No recovery codes" />
    </p>
  );

  if (loading) {
    return (
      <div className="card pw-card" aria-busy="true">
        {head}
        <p className="fact-line">Reading two-factor state…</p>
      </div>
    );
  }

  if (statusErr || !status) {
    return (
      <div className="card pw-card">
        {head}
        <p className="pw-msg err" role="alert">{statusErr ?? "Whether two-factor is on for this account could not be read."}</p>
        <div className="pw-actions">
          <button type="button" className="btn" onClick={() => { setLoading(true); void readStatus(); }}>
            Try again
          </button>
          {closeButton}
        </div>
      </div>
    );
  }

  if (!status.local) {
    return (
      <div className="card pw-card">
        {head}
        <p className="fact-line">
          Managed by your identity provider, not here.
          <AskIris topic="auth.provider-managed-mfa" label="Managed by your identity provider" />
        </p>
        <div className="pw-actions">{closeButton}</div>
      </div>
    );
  }

  // ── enrolment in progress: a fresh secret in hand, or a pending one on the server
  const enrolling = enrolment !== null || (status.pending && !status.enabled);
  if (!status.enabled && enrolling) {
    return (
      <div className="card pw-card">
        {head}
        <form onSubmit={activate} className="pw-form">
          {enrolment ? (
            <>
              <p className="fact-line">Add this account to your authenticator app, then enter its code.</p>
              <EnrolmentQR uri={enrolment.uri} />
              <div className="pw-field">
                <span className="pw-label" id="tfa-key-label">Setup key</span>
                <div className="pw-input-wrap" style={{ gap: 8 }}>
                  <code className="mono" aria-labelledby="tfa-key-label" style={{ userSelect: "all", wordBreak: "break-all" }}>
                    {enrolment.secret}
                  </code>
                  <button type="button" className="btn" onClick={() => { void copySecret(); }}>
                    {copied ? "Copied" : "Copy setup key"}
                  </button>
                </div>
              </div>
            </>
          ) : (
            <p className="fact-line">Enrolment was started and not finished. Enter the code, or start over.</p>
          )}

          <div className="pw-field">
            <label className="pw-label" htmlFor="tfa-activate-code">Six-digit code</label>
            <div className="pw-input-wrap">
              <input
                id="tfa-activate-code"
                className="pw-input mono"
                value={code}
                onChange={(ev) => setCode(ev.target.value.replace(/[^0-9]/g, "").slice(0, 6))}
                inputMode="numeric"
                autoComplete="one-time-code"
                maxLength={6}
              />
            </div>
          </div>

          {recoveryNote}

          <div className="pw-actions">
            <button className="btn-accent" type="submit" disabled={!codeReady || busy}>
              {busy ? "Turning on…" : "Turn on two-factor"}
            </button>
            <button type="button" className="btn" onClick={() => { void startSetup(); }} disabled={busy}>
              Start over
            </button>
            {closeButton}
            {message}
          </div>
        </form>
      </div>
    );
  }

  // ── on: state it, and offer the turn-off that re-authenticates with a code
  if (status.enabled) {
    return (
      <div className="card pw-card">
        {head}
        <p className="fact-line">
          <Icon name="check" size={14} /> Two-factor authentication is on. Sign-in asks for a code.
        </p>
        {recoveryNote}
        {turningOff ? (
          <form onSubmit={disable} className="pw-form">
            <p className="fact-line">Turning it off needs a current code.</p>
            <div className="pw-field">
              <label className="pw-label" htmlFor="tfa-disable-code">Six-digit code</label>
              <div className="pw-input-wrap">
                <input
                  id="tfa-disable-code"
                  className="pw-input mono"
                  value={code}
                  onChange={(ev) => setCode(ev.target.value.replace(/[^0-9]/g, "").slice(0, 6))}
                  inputMode="numeric"
                  autoComplete="one-time-code"
                  maxLength={6}
                />
              </div>
            </div>
            <div className="pw-actions">
              <button className="btn-accent" type="submit" disabled={!codeReady || busy}>
                {busy ? "Turning off…" : "Turn off two-factor"}
              </button>
              <button type="button" className="btn" onClick={() => { setTurningOff(false); setCode(""); setMsg(null); }} disabled={busy}>
                Cancel
              </button>
              {message}
            </div>
          </form>
        ) : (
          <div className="pw-actions">
            <button type="button" className="btn" onClick={() => { setTurningOff(true); setMsg(null); }}>
              Turn off
            </button>
            {closeButton}
            {message}
          </div>
        )}
      </div>
    );
  }

  // ── off
  return (
    <div className="card pw-card">
      {head}
      <p className="fact-line">Two-factor authentication is off. Sign-in asks for your password only.</p>
      {recoveryNote}
      <div className="pw-actions">
        <button type="button" className="btn-accent" onClick={() => { void startSetup(); }} disabled={busy}>
          {busy ? "Starting…" : "Set up"}
        </button>
        {closeButton}
        {message}
      </div>
    </div>
  );
}

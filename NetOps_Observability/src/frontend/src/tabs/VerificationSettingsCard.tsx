// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// VerificationSettingsCard — Administration → Settings.
//
// Active verification is the platform logging in to a device to CHECK a
// hypothesis a correlation case made ("the interface really is down"), instead
// of inferring it from telemetry alone. It needs two things a tenant owns: the
// opt-in, and a read-only device sign-in. Both live behind
// GET/PUT /api/settings/verification, which had no panel while every sibling
// /api/settings/* had one — so the capability existed and no operator could
// turn it on. The refusal an operator hits without it names this page
// ("active verification is not enabled for this tenant — opt in under
// Settings"), which is the wording used here.
//
// THREE HONESTY RULES, all of them enforced in lib/verificationSettings.ts:
//
//  1. The stored sign-in is WRITE-ONLY. The server returns `ssh_configured` and
//     nothing else about it, so this card states whether a sign-in exists and
//     never renders, echoes or logs the material. A field left empty means
//     "unchanged", and the save omits the key entirely rather than sending an
//     empty string the operator might read as "cleared".
//  2. UNKNOWN IS NOT OFF. When the config store could not be read the server
//     says so (`config_unavailable` + `config_error`) and what it returned is
//     NOT the stored state. The card then shows the reason and disables every
//     control, because a save on top of an unread configuration would overwrite
//     a setting nobody has seen.
//  3. The tenant opt-in and the platform capability are separate facts. A
//     tenant that has opted in while FEATURE_ACTIVE_VERIFICATION is off has a
//     stored intent and nothing running; the card says exactly that rather than
//     showing a green "on".
//
// GATE. The write is requireAdmin and TENANT-scoped (a tenant admin configures
// its own tenant, never another's) and every save is audited server-side with
// booleans only — whether a secret was set, never the secret.

import { useCallback, useEffect, useState } from "react";
import { api, type VerificationSettings } from "../services/api";
import Icon from "../components/Icon";
import { Modal } from "../components/ui";
import { operatorError } from "../lib/errors";
import AskIris from "../components/AskIris";
import {
  EMPTY_FORM,
  canEdit,
  credentialState,
  formFrom,
  isDirty,
  patchFor,
  runState,
  validate,
  type FieldErrors,
  type VerificationForm,
} from "../lib/verificationSettings";

const TONE: Record<string, string> = {
  ok: "var(--ok)",
  warn: "var(--warn)",
  off: "var(--muted)",
  unknown: "var(--warn)",
};

function Field({ label, hint, error, children }: {
  label: string; hint?: string; error?: string; children: React.ReactNode;
}) {
  return (
    <label style={{ display: "block", marginBottom: 12 }}>
      <span style={{ display: "block", fontSize: "var(--fs-meta)", fontWeight: 600, marginBottom: 4 }}>{label}</span>
      {children}
      {hint && <span style={{ display: "block", fontSize: "var(--fs-meta)", color: "var(--muted)", marginTop: 3 }}>{hint}</span>}
      {error && <span role="alert" style={{ display: "block", fontSize: "var(--fs-meta)", color: "var(--crit)", marginTop: 3 }}>{error}</span>}
    </label>
  );
}

export function VerificationSettingsForm({ onSaved }: { onSaved?: (v: VerificationSettings) => void }) {
  const [stored, setStored] = useState<VerificationSettings | null>(null);
  const [form, setForm] = useState<VerificationForm>(EMPTY_FORM);
  const [errs, setErrs] = useState<FieldErrors>({});
  const [err, setErr] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);
  const [busy, setBusy] = useState(true);
  const [loadFailed, setLoadFailed] = useState(false);

  const load = useCallback(async () => {
    setBusy(true);
    try {
      const v = await api.verificationSettings();
      setStored(v);
      setForm(formFrom(v));
      setLoadFailed(false);
      setErr(null);
    } catch (e) {
      setLoadFailed(true);
      setErr(operatorError(e, "The verification settings could not be read."));
    } finally {
      setBusy(false);
    }
  }, []);

  useEffect(() => { void load(); }, [load]);

  const set = (k: keyof VerificationForm) => (e: { target: { value: string } }) =>
    setForm((f) => ({ ...f, [k]: e.target.value }));

  const editable = canEdit(stored) && !busy;

  const save = async (clearSSH: boolean) => {
    setSaved(false);
    setErr(null);
    const v = validate(form, clearSSH, stored);
    setErrs(v);
    if (Object.keys(v).length > 0) return;
    const patch = patchFor(form, stored, clearSSH);
    if (Object.keys(patch).length === 0) return;
    setBusy(true);
    try {
      const next = await api.setVerificationSettings(patch);
      setStored(next);
      // Re-derive from the SERVER's answer, which also drops every typed secret
      // from component state the moment it has been accepted.
      setForm(formFrom(next));
      setSaved(true);
      onSaved?.(next);
      setTimeout(() => setSaved(false), 2500);
    } catch (e) {
      // The typed values stay on screen: a refused save must not cost the
      // operator the credential they just entered.
      setErr(operatorError(e, "The verification settings were not saved."));
    } finally {
      setBusy(false);
    }
  };

  const state = runState(stored);

  return (
    <div>
      <p className="adm-line">
        Signs in to a device to check what a case claims.
        <AskIris topic="verify.active-verification" label="active verification" />
      </p>

      <p style={{ fontSize: "var(--fs-meta)", color: TONE[state.tone] ?? "var(--muted)" }} role="status">
        {state.text}
      </p>

      {stored?.config_unavailable && (
        <p role="alert" style={{ fontSize: "var(--fs-meta)", color: "var(--crit)" }}>
          {stored.config_error || "The stored verification settings could not be read."} These are not the stored settings.
        </p>
      )}

      {err && <p role="alert" style={{ fontSize: "var(--fs-meta)", color: "var(--crit)" }}>{err}</p>}
      {saved && <p role="status" style={{ fontSize: "var(--fs-meta)", color: "var(--ok)" }}>Saved.</p>}

      {loadFailed ? (
        <button className="btn" onClick={() => void load()}>Read the settings again</button>
      ) : (
        <>
          <Field label="Verification for this tenant">
            <label style={{ display: "inline-flex", alignItems: "center", gap: 8, fontSize: 13 }}>
              <input
                type="checkbox"
                checked={form.enabled}
                disabled={!editable}
                aria-label="Verify cases against this tenant's devices"
                onChange={(e) => setForm((f) => ({ ...f, enabled: e.target.checked }))}
              />
              <span>Verify cases against this tenant&apos;s devices</span>
            </label>
          </Field>

          <Field label="Device sign-in" hint={credentialState(stored)}>
            <input
              className="ccw-input"
              type="text"
              value={form.sshUser}
              disabled={!editable}
              maxLength={128}
              placeholder="read-only user, e.g. correlix-ro"
              aria-label="SSH user"
              onChange={set("sshUser")}
            />
          </Field>

          <Field label="SSH port" error={errs.ssh_port} hint="Empty uses the device profile's port.">
            <input
              className="ccw-input"
              type="text"
              inputMode="numeric"
              value={form.sshPort}
              disabled={!editable}
              maxLength={5}
              placeholder="22"
              aria-label="SSH port"
              onChange={set("sshPort")}
            />
          </Field>

          <Field
            label="Password"
            error={errs.ssh_secret}
            hint="Sealed, never shown again. Empty keeps the stored one."
          >
            <input
              className="ccw-input"
              type="password"
              autoComplete="new-password"
              value={form.sshPassword}
              disabled={!editable}
              aria-label="SSH password"
              onChange={set("sshPassword")}
            />
          </Field>

          <Field label="Private key" hint="Paste the key, not a path to it.">
            <textarea
              className="ccw-input"
              rows={3}
              value={form.sshPrivateKey}
              disabled={!editable}
              aria-label="SSH private key"
              onChange={set("sshPrivateKey")}
            />
          </Field>

          <Field label="Key passphrase" error={errs.ssh_passphrase}>
            <input
              className="ccw-input"
              type="password"
              autoComplete="new-password"
              value={form.sshPassphrase}
              disabled={!editable}
              aria-label="SSH key passphrase"
              onChange={set("sshPassphrase")}
            />
          </Field>

          {errs.clear_ssh && <p role="alert" style={{ fontSize: "var(--fs-meta)", color: "var(--crit)" }}>{errs.clear_ssh}</p>}

          <div style={{ display: "flex", gap: 8, alignItems: "center", marginTop: 8 }}>
            <button
              className="btn-primary"
              disabled={!editable || !isDirty(form, stored, false)}
              onClick={() => void save(false)}
            >
              Save
            </button>
            <button
              className="btn"
              disabled={!editable || !stored?.ssh_configured}
              title="Remove the stored user, port and secret for this tenant"
              onClick={() => void save(true)}
            >
              Remove the stored sign-in
            </button>
          </div>
        </>
      )}
    </div>
  );
}

export default function VerificationSettingsCard() {
  const [open, setOpen] = useState(false);
  const [state, setState] = useState<VerificationSettings | null>(null);

  useEffect(() => {
    let alive = true;
    api.verificationSettings()
      .then((v) => { if (alive) setState(v); })
      .catch(() => { if (alive) setState(null); });
    return () => { alive = false; };
  }, []);

  const summary = runState(state);

  return (
    <div className="card" style={{ display: "flex", alignItems: "center", gap: 12 }}>
      <div style={{ width: 34, height: 34, borderRadius: 8, background: "var(--surface-2)", display: "grid", placeItems: "center" }}>
        <Icon name="check" size={20} />
      </div>
      <div style={{ flex: 1 }}>
        <h3 style={{ fontWeight: 700, fontSize: "inherit", margin: 0 }}>Active verification</h3>
        <div className="adm-line">
          {summary.text}
          <AskIris topic="verify.active-verification" label="active verification" />
        </div>
      </div>
      <button className="btn" onClick={() => setOpen(true)}>Configure</button>
      {open && (
        <Modal title="Active verification" onClose={() => setOpen(false)}>
          <VerificationSettingsForm onSaved={setState} />
          <div style={{ textAlign: "right", marginTop: 8 }}>
            <button className="btn" onClick={() => setOpen(false)}>Close</button>
          </div>
        </Modal>
      )}
    </div>
  );
}

// verificationSettings.ts — the pure half of the Active Verification settings
// card (Administration → Settings). It builds the PATCH the card PUTs to
// /api/settings/verification and decides what the operator is allowed to do.
//
// WHY A PATCH AND NOT A FORM DUMP. The stored SSH credential is WRITE-ONLY: the
// GET never returns password, key or passphrase material, only the boolean
// `ssh_configured`. A "save the whole form" client would therefore have to send
// something for fields it cannot read, and the only two options are both wrong —
// an empty string (which the server reads as "unchanged", i.e. a silent no-op
// the operator believes was a change) or a re-sent placeholder (which would put
// a fake secret on the wire). So the card sends ONLY what the operator typed,
// and this module is where that rule is enforced and tested.
//
// The second rule here is that "unknown" is not "off". When the config store
// could not be read the server says so (`config_unavailable` + `config_error`)
// and the values in the response are NOT the stored state; writing on top of
// them would overwrite a configuration nobody has seen. `canEdit()` refuses.

import type { VerificationSettings, VerificationSettingsPatch } from "../services/api";

/** What the operator typed. Secrets are separate from the stored state on
 *  purpose — an empty string here means "left alone", never "clear it". */
export interface VerificationForm {
  enabled: boolean;
  sshUser: string;
  sshPort: string;
  /** One of the two credential kinds; the operator picks which to type. */
  sshPassword: string;
  sshPrivateKey: string;
  sshPassphrase: string;
}

export const EMPTY_FORM: VerificationForm = {
  enabled: false,
  sshUser: "",
  sshPort: "",
  sshPassword: "",
  sshPrivateKey: "",
  sshPassphrase: "",
};

/** The form as it stands when the stored settings are read back. */
export function formFrom(v: VerificationSettings | null): VerificationForm {
  if (!v) return { ...EMPTY_FORM };
  return {
    ...EMPTY_FORM,
    enabled: !!v.enabled,
    sshUser: v.ssh_user ?? "",
    sshPort: v.ssh_port ? String(v.ssh_port) : "",
  };
}

/**
 * canEdit is false when the stored configuration could not be read. The card
 * then shows what it knows plus the reason and disables every control, rather
 * than letting a save overwrite a configuration it never saw.
 */
export function canEdit(v: VerificationSettings | null): boolean {
  return !!v && !v.config_unavailable;
}

/** True when the operator typed a new credential of either kind. */
export function hasNewSecret(f: VerificationForm): boolean {
  return f.sshPassword !== "" || f.sshPrivateKey !== "";
}

/** Field name → message. An empty object means the form is submittable. */
export type FieldErrors = Record<string, string>;

/**
 * validate mirrors the server's guards (verify/service_store.go Set): the port
 * range, and the two shapes the server would reject or silently ignore. It is a
 * UX affordance only — the server re-validates every PUT.
 */
export function validate(
  f: VerificationForm,
  clearSSH: boolean,
  stored: VerificationSettings | null = null,
): FieldErrors {
  const errs: FieldErrors = {};
  // Removing the sign-in wipes user, port and secret together, so pairing it
  // with edits in the same save would make the result depend on the server's
  // field order. The test is "did the operator change anything else", not "is
  // the field non-empty" — the user field is pre-filled from the stored state.
  if (clearSSH && Object.keys(patchFor(f, stored, false)).length > 0) {
    errs.clear_ssh = "Removing the stored sign-in cannot be combined with setting a new one. Do one, save, then the other.";
  }
  if (f.sshPort.trim() !== "") {
    const n = Number(f.sshPort.trim());
    if (!Number.isInteger(n) || n < 0 || n > 65535) {
      errs.ssh_port = "The SSH port is a whole number between 0 and 65535.";
    }
  }
  if (f.sshPassword !== "" && f.sshPrivateKey !== "") {
    errs.ssh_secret = "Set either a password or a private key for this tenant, not both.";
  }
  if (f.sshPassphrase !== "" && f.sshPrivateKey === "") {
    errs.ssh_passphrase = "A passphrase applies to a private key. Add the key, or leave the passphrase empty.";
  }
  return errs;
}

/**
 * patchFor builds the PUT body: ONLY what changed against the stored state,
 * with secrets included only when the operator actually typed one.
 *
 * `clear_ssh` is returned on its own — the server wipes user, password, key,
 * passphrase and port together, so pairing it with new values in one request
 * would make the outcome depend on the server's field order.
 */
export function patchFor(
  f: VerificationForm,
  stored: VerificationSettings | null,
  clearSSH: boolean,
): VerificationSettingsPatch {
  if (clearSSH) return { clear_ssh: true };
  const patch: VerificationSettingsPatch = {};
  if (!stored || f.enabled !== !!stored.enabled) patch.enabled = f.enabled;
  const user = f.sshUser.trim();
  if (user !== (stored?.ssh_user ?? "")) patch.ssh_user = user;
  const portRaw = f.sshPort.trim();
  if (portRaw !== "") {
    const n = Number(portRaw);
    if (Number.isInteger(n) && n !== (stored?.ssh_port ?? 0)) patch.ssh_port = n;
  }
  // Write-only fields: sent only when typed. Never an empty string, which the
  // store reads as "leave it alone" and the operator would read as "cleared".
  if (f.sshPassword !== "") patch.ssh_password = f.sshPassword;
  if (f.sshPrivateKey !== "") patch.ssh_private_key = f.sshPrivateKey;
  if (f.sshPassphrase !== "" && f.sshPrivateKey !== "") patch.ssh_passphrase = f.sshPassphrase;
  return patch;
}

/** Nothing to send — the save button stays inert rather than issuing a no-op PUT. */
export function isDirty(
  f: VerificationForm,
  stored: VerificationSettings | null,
  clearSSH: boolean,
): boolean {
  return Object.keys(patchFor(f, stored, clearSSH)).length > 0;
}

/**
 * credentialState is the ONE sentence the card may make about stored secrets:
 * the server tells us whether a credential exists, never what it is.
 */
export function credentialState(v: VerificationSettings | null): string {
  if (!v) return "Not read yet.";
  if (v.config_unavailable) return "Unknown — the stored settings could not be read.";
  if (!v.ssh_configured) return "No sign-in stored. Verification checks that need one are skipped.";
  const where = v.ssh_user ? ` as ${v.ssh_user}` : "";
  const port = v.ssh_port ? ` on port ${v.ssh_port}` : "";
  return `A sign-in is stored${where}${port}. The password or key itself is never shown again.`;
}

/**
 * runState says whether the opt-in currently has any effect. The tenant flag and
 * the platform capability are two separate facts and the card must not collapse
 * them: a tenant that has opted in while the platform capability is off has a
 * stored intent and nothing running.
 */
export function runState(v: VerificationSettings | null): {
  tone: "ok" | "warn" | "off" | "unknown";
  text: string;
} {
  if (!v) return { tone: "unknown", text: "Not read yet." };
  if (v.config_unavailable) {
    return { tone: "unknown", text: "The stored settings could not be read, so this state is unknown." };
  }
  if (!v.feature) {
    return {
      tone: "warn",
      text: "The platform has not turned on active verification, so nothing runs yet. What you set here is stored and takes effect when it is turned on.",
    };
  }
  if (!v.enabled) {
    return { tone: "off", text: "This tenant has not opted in, so no verification runs against its devices." };
  }
  return { tone: "ok", text: "Verification runs against this tenant's devices when a case asks for it." };
}

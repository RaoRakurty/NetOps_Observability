import { describe, it, expect } from "vitest";
import {
  EMPTY_FORM,
  canEdit,
  credentialState,
  formFrom,
  hasNewSecret,
  isDirty,
  patchFor,
  runState,
  validate,
  type VerificationForm,
} from "./verificationSettings";
import type { VerificationSettings } from "../services/api";

const stored = (over: Partial<VerificationSettings> = {}): VerificationSettings => ({
  tenant_id: "t-1",
  enabled: false,
  feature: true,
  ssh_configured: false,
  ssh_user: "",
  ssh_port: 0,
  ...over,
});

const form = (over: Partial<VerificationForm> = {}): VerificationForm => ({ ...EMPTY_FORM, ...over });

describe("formFrom", () => {
  it("carries the readable state and never a secret", () => {
    const f = formFrom(stored({ enabled: true, ssh_user: "netops", ssh_port: 2222, ssh_configured: true }));
    expect(f).toEqual({
      enabled: true,
      sshUser: "netops",
      sshPort: "2222",
      sshPassword: "",
      sshPrivateKey: "",
      sshPassphrase: "",
    });
  });

  it("renders port 0 as empty rather than as a configured zero", () => {
    expect(formFrom(stored()).sshPort).toBe("");
  });

  it("survives a settings read that never answered", () => {
    expect(formFrom(null)).toEqual(EMPTY_FORM);
  });
});

describe("canEdit", () => {
  it("refuses while the stored config could not be read", () => {
    expect(canEdit(stored({ config_unavailable: true, config_error: "unreadable" }))).toBe(false);
  });
  it("allows a normal read", () => {
    expect(canEdit(stored())).toBe(true);
  });
  it("refuses before the first read", () => {
    expect(canEdit(null)).toBe(false);
  });
});

describe("patchFor", () => {
  it("sends only the opt-in when only the opt-in changed", () => {
    expect(patchFor(form({ enabled: true }), stored(), false)).toEqual({ enabled: true });
  });

  it("never sends a secret the operator did not type", () => {
    const p = patchFor(form({ enabled: true, sshUser: "netops" }), stored(), false);
    expect(p).toEqual({ enabled: true, ssh_user: "netops" });
    expect("ssh_password" in p).toBe(false);
    expect("ssh_private_key" in p).toBe(false);
    expect("ssh_passphrase" in p).toBe(false);
  });

  it("sends a typed password and nothing else secret", () => {
    const p = patchFor(form({ sshPassword: "hunter-correct-horse" }), stored(), false);
    expect(p.ssh_password).toBe("hunter-correct-horse");
    expect("ssh_private_key" in p).toBe(false);
    expect("ssh_passphrase" in p).toBe(false);
  });

  it("sends a passphrase only alongside the key it unlocks", () => {
    expect(patchFor(form({ sshPassphrase: "p" }), stored(), false)).toEqual({});
    const withKey = patchFor(form({ sshPrivateKey: "KEY", sshPassphrase: "p" }), stored(), false);
    expect(withKey).toEqual({ ssh_private_key: "KEY", ssh_passphrase: "p" });
  });

  it("omits an unchanged user and port", () => {
    const s = stored({ enabled: true, ssh_user: "netops", ssh_port: 22 });
    expect(patchFor(form({ enabled: true, sshUser: "netops", sshPort: "22" }), s, false)).toEqual({});
  });

  it("trims the user before comparing and sending", () => {
    expect(patchFor(form({ sshUser: "  netops  " }), stored(), false)).toEqual({ ssh_user: "netops" });
  });

  it("clears the credential on its own, never mixed with new values", () => {
    const p = patchFor(form({ enabled: true, sshUser: "netops", sshPassword: "x" }), stored(), true);
    expect(p).toEqual({ clear_ssh: true });
  });

  it("sends an emptied user as an empty string so it is actually removed", () => {
    const s = stored({ ssh_user: "netops" });
    expect(patchFor(form({ sshUser: "" }), s, false)).toEqual({ ssh_user: "" });
  });
});

describe("validate", () => {
  it("accepts an untouched form", () => {
    expect(validate(form(), false)).toEqual({});
  });

  it("rejects a port outside the server's range", () => {
    expect(validate(form({ sshPort: "70000" }), false).ssh_port).toMatch(/between 0 and 65535/);
    expect(validate(form({ sshPort: "-1" }), false).ssh_port).toBeTruthy();
    expect(validate(form({ sshPort: "22.5" }), false).ssh_port).toBeTruthy();
    expect(validate(form({ sshPort: "2222" }), false).ssh_port).toBeUndefined();
  });

  it("rejects two credential kinds at once", () => {
    expect(validate(form({ sshPassword: "a", sshPrivateKey: "b" }), false).ssh_secret).toBeTruthy();
  });

  it("rejects a passphrase with no key", () => {
    expect(validate(form({ sshPassphrase: "p" }), false).ssh_passphrase).toBeTruthy();
  });

  it("rejects removing and setting a sign-in in one save", () => {
    const s = stored({ ssh_configured: true, ssh_user: "netops", ssh_port: 22 });
    const asStored = form({ sshUser: "netops", sshPort: "22" });
    // The pre-filled user is not an edit: only a real change conflicts.
    expect(validate(asStored, true, s)).toEqual({});
    expect(validate({ ...asStored, sshPassword: "a" }, true, s).clear_ssh).toBeTruthy();
    expect(validate({ ...asStored, sshUser: "other" }, true, s).clear_ssh).toBeTruthy();
  });
});

describe("isDirty", () => {
  it("is false for a form that matches the stored state", () => {
    const s = stored({ enabled: true, ssh_user: "netops", ssh_port: 22 });
    expect(isDirty(form({ enabled: true, sshUser: "netops", sshPort: "22" }), s, false)).toBe(false);
  });
  it("is true once a secret is typed", () => {
    expect(isDirty(form({ sshPassword: "x" }), stored(), false)).toBe(true);
  });
  it("is true for a clear request", () => {
    expect(isDirty(form(), stored(), true)).toBe(true);
  });
});

describe("hasNewSecret", () => {
  it("sees either credential kind", () => {
    expect(hasNewSecret(form())).toBe(false);
    expect(hasNewSecret(form({ sshPassword: "x" }))).toBe(true);
    expect(hasNewSecret(form({ sshPrivateKey: "x" }))).toBe(true);
  });
});

describe("credentialState", () => {
  it("says stored without ever describing the secret", () => {
    const s = credentialState(stored({ ssh_configured: true, ssh_user: "netops", ssh_port: 2222 }));
    expect(s).toMatch(/stored as netops on port 2222/);
    expect(s).toMatch(/never shown again/);
  });
  it("separates unknown from absent", () => {
    expect(credentialState(stored({ config_unavailable: true }))).toMatch(/^Unknown/);
    expect(credentialState(stored({ ssh_configured: false }))).toMatch(/No sign-in stored/);
  });
});

describe("runState", () => {
  it("keeps the tenant opt-in and the platform capability apart", () => {
    expect(runState(stored({ feature: false, enabled: true })).tone).toBe("warn");
    expect(runState(stored({ feature: false, enabled: true })).text).toMatch(/stored and takes effect/);
    expect(runState(stored({ feature: true, enabled: false })).tone).toBe("off");
    expect(runState(stored({ feature: true, enabled: true })).tone).toBe("ok");
  });
  it("reports unknown when the settings could not be read", () => {
    expect(runState(stored({ config_unavailable: true, enabled: true })).tone).toBe("unknown");
  });
});

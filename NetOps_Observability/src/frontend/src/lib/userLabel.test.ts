// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// userLabel — a federated `fed_…` username must NEVER reach the screen
// (tracker 300 §4.7 / design §5's frontend requirement).
//
// A federated account has no login handle: its username IS its opaque principal
// id, derived from the identity tuple. Rendering it would put a 26-character
// base32 hash where an operator expects a person's name — so the rule is a
// function, tested here, and every display site calls it.

import { describe, it, expect } from "vitest";
import { userLabel, isLocalAccount } from "./userLabel";

// The real shape the API returns for a JIT-provisioned SSO account: username ==
// id, no display name unless the IdP sent one.
const FEDERATED = {
  username: "fed_acme123_exgxo2oz3niujwsm47sjktjhyu",
  auth_source: "oidc",
  email: "alice@acme.example",
  display_name: "Alice Alvarez",
};

describe("userLabel", () => {
  it("never renders a fed_ username", () => {
    for (const u of [
      FEDERATED,
      { ...FEDERATED, display_name: "" },
      { ...FEDERATED, display_name: "", email: "" },
      { ...FEDERATED, display_name: undefined, email: undefined },
      { ...FEDERATED, auth_source: "ldap", display_name: "" },
      { ...FEDERATED, auth_source: "tacacs", display_name: "", email: "" },
      { ...FEDERATED, auth_source: "saml", display_name: "" },
    ]) {
      const label = userLabel(u);
      expect(label).not.toContain("fed_");
      expect(label).not.toBe(u.username);
      expect(label.length).toBeGreaterThan(0);
    }
  });

  it("prefers the display name, then the e-mail, then a neutral fallback", () => {
    expect(userLabel(FEDERATED)).toBe("Alice Alvarez");
    expect(userLabel({ ...FEDERATED, display_name: "" })).toBe("alice@acme.example");
    expect(userLabel({ ...FEDERATED, display_name: "", email: "" })).toBe("Signed in");
    expect(userLabel({ ...FEDERATED, display_name: "  ", email: "  " })).toBe("Signed in");
    expect(userLabel(undefined)).toBe("Signed in");
  });

  it("shows a LOCAL account's username, which is the name someone types", () => {
    expect(userLabel({ username: "admin", auth_source: "local" })).toBe("admin");
    // An empty auth_source is a legacy local account (the backend predicate).
    expect(userLabel({ username: "admin" })).toBe("admin");
    // …and a display name still wins, because an operator may have set one.
    expect(userLabel({ username: "admin", auth_source: "local", display_name: "Platform Owner" }))
      .toBe("Platform Owner");
  });

  it("classifies the auth source the way the backend does", () => {
    expect(isLocalAccount({ username: "a" })).toBe(true);
    expect(isLocalAccount({ username: "a", auth_source: "" })).toBe(true);
    expect(isLocalAccount({ username: "a", auth_source: " LOCAL " })).toBe(true);
    expect(isLocalAccount({ username: "a", auth_source: "oidc" })).toBe(false);
    expect(isLocalAccount(null)).toBe(true);
  });
});

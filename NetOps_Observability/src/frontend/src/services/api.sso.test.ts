// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// api.sso.test.ts — login-CSRF / session-fixation regression for the SSO
// fragment capture (M20, wave-3 second pass). captureSSORedirect used to
// accept ANY `#token=…` fragment unconditionally: a page that navigated the
// victim's browser to `app/#token=<attacker session>` silently signed the
// victim into the attacker's account and overwrote a real session. The fix
// binds the fragment to a browser-side nonce (SSO_STATE_KEY) that only
// ssoLoginUrl() — i.e. an SSO login actually started from this tab — arms.

import { describe, it, expect, beforeEach } from "vitest";
import {
  api,
  captureSSORedirect,
  SSO_STATE_KEY,
  getToken,
  getRefresh,
  setToken,
  setRefresh,
} from "./api";

function clearCookies() {
  for (const part of document.cookie.split(";")) {
    const name = part.split("=")[0].trim();
    if (name) document.cookie = `${name}=; Path=/; Max-Age=0`;
  }
}

beforeEach(() => {
  localStorage.clear();
  sessionStorage.clear();
  clearCookies();
  window.location.hash = "";
});

describe("M20 — captureSSORedirect requires a tab-armed SSO state", () => {
  it("ignores a token fragment when no SSO login was started from this tab", () => {
    window.location.hash = "#token=attacker-token&refresh=attacker-refresh&sso=1";
    const err = captureSSORedirect();
    expect(getToken()).toBeNull();
    expect(getRefresh()).toBeNull();
    expect(err).toMatch(/sign in again/i);
  });

  it("never overwrites an existing session with an unsolicited fragment (fixation)", () => {
    setToken("victims-real-token");
    setRefresh("victims-real-refresh");
    window.location.hash = "#token=attacker-token&refresh=attacker-refresh&sso=1";
    captureSSORedirect();
    expect(getToken()).toBe("victims-real-token");
    expect(getRefresh()).toBe("victims-real-refresh");
  });

  it("rejects a fragment whose state echo does not match the pending nonce", () => {
    sessionStorage.setItem(SSO_STATE_KEY, "nonce-armed-by-this-tab");
    window.location.hash = "#token=tok&refresh=ref&state=some-other-state";
    const err = captureSSORedirect();
    expect(getToken()).toBeNull();
    expect(err).toMatch(/state mismatch/i);
    // The nonce is single-use: consumed even on rejection.
    expect(sessionStorage.getItem(SSO_STATE_KEY)).toBeNull();
  });

  it("accepts the fragment when the echoed state matches the pending nonce", () => {
    sessionStorage.setItem(SSO_STATE_KEY, "nonce-armed-by-this-tab");
    window.location.hash = "#token=tok&refresh=ref&state=nonce-armed-by-this-tab&sso=1";
    const err = captureSSORedirect();
    expect(err).toBeNull();
    expect(getToken()).toBe("tok");
    expect(getRefresh()).toBe("ref");
    expect(sessionStorage.getItem(SSO_STATE_KEY)).toBeNull();
  });

  it("transitional: accepts a state-less fragment ONLY when this tab armed a nonce", () => {
    // The backend does not echo the nonce yet (coordination pending). Until it
    // does, "this tab started an SSO login" is the control that blocks a
    // delivered fragment — pin that it still works without an echo.
    sessionStorage.setItem(SSO_STATE_KEY, "nonce-armed-by-this-tab");
    window.location.hash = "#token=tok&refresh=ref&sso=1";
    expect(captureSSORedirect()).toBeNull();
    expect(getToken()).toBe("tok");
  });

  it("sweeps the previous principal's scoped UI state before storing the session", () => {
    localStorage.setItem("netops.fp.kpihist.tenant-a", "[1,2,3]");
    localStorage.setItem("netops.activeScope", "tenant-a");
    sessionStorage.setItem(SSO_STATE_KEY, "n1");
    window.location.hash = "#token=tok&refresh=ref&state=n1";
    captureSSORedirect();
    expect(localStorage.getItem("netops.fp.kpihist.tenant-a")).toBeNull();
    expect(localStorage.getItem("netops.activeScope")).toBeNull();
    expect(getToken()).toBe("tok");
  });

  it("ssoLoginUrl arms a fresh nonce and carries it as fe_state", () => {
    const u1 = api.ssoLoginUrl("okta");
    const armed1 = sessionStorage.getItem(SSO_STATE_KEY);
    expect(armed1).toBeTruthy();
    expect(u1).toContain(`fe_state=${armed1}`);
    expect(u1).toContain("idp=okta");
    const u2 = api.ssoLoginUrl();
    const armed2 = sessionStorage.getItem(SSO_STATE_KEY);
    // Fresh nonce per navigation — no replayable fixed value.
    expect(armed2).toBeTruthy();
    expect(armed2).not.toBe(armed1);
    expect(u2).toContain(`fe_state=${armed2}`);
  });

  it("still reports sso_error fragments verbatim", () => {
    window.location.hash = "#sso_error=upstream%20said%20no";
    expect(captureSSORedirect()).toBe("upstream said no");
  });
});

describe("F3 — bookmark / IdP-initiated login (cookie-backed nonce)", () => {
  it("accepts the fragment when the netops_sso_pending cookie matches the echoed state", () => {
    // Okta dashboard tile: the full-page nav went straight to /sso/login, so
    // ssoLoginUrl() never armed SSO_STATE_KEY. The backend set a JS-readable
    // single-use cookie and echoed the same value as `state`.
    document.cookie = "netops_sso_pending=abc; Path=/";
    window.location.hash = "#token=tok&refresh=ref&sso=1&state=abc";
    const err = captureSSORedirect();
    expect(err).toBeNull();
    expect(getToken()).toBe("tok");
    expect(getRefresh()).toBe("ref");
    // Cookie is single-use: consumed on capture.
    expect(document.cookie).not.toContain("netops_sso_pending=abc");
  });

  it("drops an attacker-delivered fragment when neither nonce nor cookie is present", () => {
    window.location.hash = "#token=attacker-token&refresh=attacker-refresh&sso=1&state=whatever";
    const err = captureSSORedirect();
    expect(getToken()).toBeNull();
    expect(getRefresh()).toBeNull();
    expect(err).toMatch(/sign in again/i);
  });

  it("rejects a bookmark fragment whose state does not match the cookie", () => {
    document.cookie = "netops_sso_pending=abc; Path=/";
    window.location.hash = "#token=tok&refresh=ref&sso=1&state=not-abc";
    const err = captureSSORedirect();
    expect(getToken()).toBeNull();
    expect(err).toMatch(/state mismatch/i);
  });

  it("prefers the sessionStorage nonce over the cookie (SP-initiated unchanged)", () => {
    sessionStorage.setItem(SSO_STATE_KEY, "sp-nonce");
    document.cookie = "netops_sso_pending=cookie-nonce; Path=/";
    window.location.hash = "#token=tok&refresh=ref&sso=1&state=sp-nonce";
    const err = captureSSORedirect();
    expect(err).toBeNull();
    expect(getToken()).toBe("tok");
    // The cookie was NOT consumed — the SP path never touched it.
    expect(document.cookie).toContain("netops_sso_pending=cookie-nonce");
  });
});

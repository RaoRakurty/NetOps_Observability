// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Login.locator.test.tsx — per-tenant sign-in URLs on the sign-in page
// (design §6.1, tracker 276).
//
// What is pinned here:
//   - loginLocatorPath parses /t/{slug} and /org/{org_id} and nothing else;
//   - authMethods RESOLVES the locator before asking for the methods, so the
//     provider list comes back already filtered by the server;
//   - the sign-in page names the candidate tenant when there is one, and names
//     nobody when there is not;
//   - the provider buttons rendered are exactly the ones the server returned —
//     the page never filters, and never widens;
//   - a deep link survives the SSO round trip.

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import Login from "./Login";
import { api, loginLocatorPath, SSO_RETURN_KEY, SSO_STATE_KEY, captureSSORedirect } from "../services/api";

type Call = { url: string };
let calls: Call[] = [];

// stubMethods answers /api/auth/locator and /api/auth/methods, recording order.
function stubMethods(locator: unknown, providers: { id: string; name: string; kind: string }[]) {
  vi.stubGlobal("fetch", vi.fn(async (url: string) => {
    calls.push({ url });
    if (url.startsWith("/api/auth/locator")) {
      return new Response(JSON.stringify({ locator }), { status: 200, headers: { "Content-Type": "application/json" } });
    }
    if (url.startsWith("/api/auth/methods")) {
      return new Response(JSON.stringify({
        local: true,
        ldap: { enabled: false, name: "LDAP / Active Directory" },
        tacacs: { enabled: false, name: "TACACS+" },
        sso: { enabled: providers.length > 0, providers },
        ...(locator ? { locator } : {}),
      }), { status: 200, headers: { "Content-Type": "application/json" } });
    }
    return new Response("{}", { status: 200, headers: { "Content-Type": "application/json" } });
  }));
}

beforeEach(() => {
  calls = [];
  localStorage.clear();
  sessionStorage.clear();
  history.replaceState(null, "", "/");
});
afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe("loginLocatorPath — the entry URL is parsed, never trusted", () => {
  it("accepts the two live locator shapes", () => {
    expect(loginLocatorPath("/t/acme")).toBe("/t/acme");
    expect(loginLocatorPath("/t/acme/")).toBe("/t/acme");
    expect(loginLocatorPath("/t/acme/sso/okta/callback")).toBe("/t/acme");
    expect(loginLocatorPath("/org/org_abc123")).toBe("/org/org_abc123");
  });
  it("rejects everything else, including traversal and encoded separators", () => {
    for (const p of ["/", "/t", "/t/", "/org/", "/api/auth/login", "/t/..", "/t/a%2fb", "/t/a.b", "/tenant/acme", "/t/" + "x".repeat(80)]) {
      expect(loginLocatorPath(p)).toBeNull();
    }
  });
});

describe("authMethods — the candidate is armed before the doors are asked for", () => {
  it("resolves the locator first, then the methods", async () => {
    history.replaceState(null, "", "/t/acme");
    stubMethods({ kind: "tenant", name: "Acme Corporation", path: "/t/acme" }, [{ id: "acme-idp", name: "Acme SSO", kind: "oidc" }]);
    const m = await api.authMethods();
    expect(calls[0].url).toBe("/api/auth/locator?path=%2Ft%2Facme");
    expect(calls[1].url).toBe("/api/auth/methods");
    expect(m.locator?.name).toBe("Acme Corporation");
  });

  it("clears a stale candidate on the generic sign-in page", async () => {
    history.replaceState(null, "", "/");
    stubMethods(null, [{ id: "a", name: "A", kind: "oidc" }]);
    const m = await api.authMethods();
    // A blank path is how the page says "no candidate" — the server expires any
    // cookie an earlier tenant link left behind, so / never shows that tenant's
    // filtered list.
    expect(calls.map((c) => c.url)).toEqual(["/api/auth/locator?path=", "/api/auth/methods"]);
    expect(m.locator).toBeUndefined();
  });

  it("falls back to the generic page when the locator does not resolve", async () => {
    history.replaceState(null, "", "/t/no-such-customer");
    stubMethods(null, [{ id: "a", name: "A", kind: "oidc" }]);
    const m = await api.authMethods();
    expect(m.locator).toBeUndefined();
  });
});

describe("the sign-in page", () => {
  it("names the candidate tenant and offers only the providers the server returned", async () => {
    history.replaceState(null, "", "/t/acme");
    stubMethods({ kind: "tenant", name: "Acme Corporation", path: "/t/acme" }, [{ id: "acme-idp", name: "Acme SSO", kind: "oidc" }]);
    render(<Login onLoggedIn={() => {}} />);
    await waitFor(() => expect(screen.getByText("Acme Corporation")).toBeInTheDocument());
    expect(screen.getByText(/Signing in to/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Sign in with Acme SSO/ })).toBeInTheDocument();
    // The page renders what it was given: another tenant's provider is not
    // present because the SERVER did not send it.
    expect(screen.queryByRole("button", { name: /Globex/ })).toBeNull();
  });

  it("names nobody on the generic sign-in page", async () => {
    history.replaceState(null, "", "/");
    stubMethods(null, [{ id: "a", name: "Corporate SSO", kind: "oidc" }]);
    render(<Login onLoggedIn={() => {}} />);
    await waitFor(() => expect(screen.getByRole("button", { name: /Sign in with Corporate SSO/ })).toBeInTheDocument());
    expect(screen.queryByText(/Signing in to/)).toBeNull();
  });
});

describe("deep links keep their page across the IdP round trip", () => {
  it("stashes the hash route on the way out and restores it on the way back", () => {
    history.replaceState(null, "", "/t/acme#/incidents/abc123");
    const url = api.ssoLoginUrl("acme-idp");
    expect(url).toContain("idp=acme-idp");
    const st = sessionStorage.getItem(SSO_STATE_KEY)!;
    expect(sessionStorage.getItem(SSO_RETURN_KEY)).toBe("#/incidents/abc123");

    // The callback drops us back on the tenant path with the session fragment.
    history.replaceState(null, "", `/t/acme#token=tok&refresh=ref&sso=1&state=${st}`);
    expect(captureSSORedirect()).toBeNull();
    expect(window.location.pathname).toBe("/t/acme");
    expect(window.location.hash).toBe("#/incidents/abc123");
    expect(sessionStorage.getItem(SSO_RETURN_KEY)).toBeNull(); // single use
  });

  it("stashes nothing when there is no deep link, and never restores a foreign URL", () => {
    history.replaceState(null, "", "/t/acme");
    api.ssoLoginUrl("acme-idp");
    expect(sessionStorage.getItem(SSO_RETURN_KEY)).toBeNull();

    // A hostile value planted in storage is re-validated on the way out.
    sessionStorage.setItem(SSO_RETURN_KEY, "#//evil.example.com");
    const st = "abc";
    sessionStorage.setItem(SSO_STATE_KEY, st);
    history.replaceState(null, "", `/t/acme#token=tok&refresh=ref&sso=1&state=${st}`);
    captureSSORedirect();
    expect(window.location.hash).toBe("");
  });
});

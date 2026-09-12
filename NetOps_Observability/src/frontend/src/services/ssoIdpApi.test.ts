// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// SSO IdP admin API methods — wire shapes for the Keycloak-automation contract:
//   GET    /api/auth/sso/idp                     → { idps, keycloak }
//   PUT    /api/auth/sso/idp/{alias}             → { idp, applied, warnings }
//   DELETE /api/auth/sso/idp/{alias}             → 204
//   POST   /api/auth/sso/idp/{alias}/test        → { ok, checks, cert_not_after? }
// The alias is caller-supplied text and MUST be URL-encoded into the path.

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { api, SsoIdP } from "./api";

type Call = { url: string; init?: RequestInit };
const calls: Call[] = [];

function stubFetch(status: number, body: unknown) {
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string, init?: RequestInit) => {
      calls.push({ url, init });
      return status === 204
        ? new Response(null, { status: 204 })
        : new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
    }),
  );
}

const IDP: SsoIdP = {
  alias: "okta",
  display_name: "Okta",
  protocol: "saml",
  enabled: true,
  metadata_url: "https://idp.example.com/metadata.xml",
  groups_attr: "groups",
  attr_mappings: [{ idp_attr: "email", user_attr: "email" }],
  role_mappings: [{ value: "cn=admins", role: "super-admin" }],
};

beforeEach(() => {
  calls.length = 0;
  localStorage.clear();
});
afterEach(() => {
  vi.unstubAllGlobals();
});

describe("sso idp api methods", () => {
  it("ssoIdps GETs the collection and returns idps + keycloak status", async () => {
    const payload = { idps: [IDP], keycloak: { reachable: true, realm: "correlix" } };
    stubFetch(200, payload);
    const r = await api.ssoIdps();
    expect(calls).toHaveLength(1);
    expect(calls[0].url).toBe("/api/auth/sso/idp");
    expect(calls[0].init?.method).toBeUndefined(); // GET
    expect(r.keycloak.realm).toBe("correlix");
    expect(r.idps[0].alias).toBe("okta");
  });

  it("saveSsoIdp PUTs the full IdP to its alias path", async () => {
    stubFetch(200, { idp: IDP, applied: false, warnings: ["keycloak unreachable"] });
    const r = await api.saveSsoIdp(IDP);
    expect(calls[0].url).toBe("/api/auth/sso/idp/okta");
    expect(calls[0].init?.method).toBe("PUT");
    expect(JSON.parse(String(calls[0].init?.body))).toEqual(IDP);
    expect(r.applied).toBe(false);
    expect(r.warnings).toEqual(["keycloak unreachable"]);
  });

  it("URL-encodes the alias in the path", async () => {
    stubFetch(200, { idp: IDP, applied: true, warnings: [] });
    await api.saveSsoIdp({ ...IDP, alias: "my idp/x" });
    expect(calls[0].url).toBe("/api/auth/sso/idp/my%20idp%2Fx");
  });

  it("deleteSsoIdp DELETEs and resolves on 204 with no body", async () => {
    stubFetch(204, null);
    await expect(api.deleteSsoIdp("okta")).resolves.toBeUndefined();
    expect(calls[0].url).toBe("/api/auth/sso/idp/okta");
    expect(calls[0].init?.method).toBe("DELETE");
  });

  it("testSsoIdp POSTs to /test and returns per-check results + cert_not_after", async () => {
    stubFetch(200, {
      ok: true,
      checks: [{ name: "metadata", ok: true, detail: "fetched 1 descriptor" }],
      cert_not_after: "2036-08-01T06:27:36Z",
    });
    const r = await api.testSsoIdp("okta");
    expect(calls[0].url).toBe("/api/auth/sso/idp/okta/test");
    expect(calls[0].init?.method).toBe("POST");
    expect(r.checks[0].ok).toBe(true);
    expect(r.cert_not_after).toBe("2036-08-01T06:27:36Z");
  });

  it("surfaces server errors as thrown Errors (Wizard/editor rely on this)", async () => {
    stubFetch(500, { error: "boom" });
    await expect(api.testSsoIdp("okta")).rejects.toThrow(/500/);
  });
});

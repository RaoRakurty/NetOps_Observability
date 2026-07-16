// scope.test.ts — how the global scope filters apply per surface (Wave 2 #5).
//
// Acceptance: OR within a dimension, AND across; filters only ever NARROW the
// tenant view; a row that cannot be placed on a dimension stays visible (an
// incident never disappears because attribution is incomplete) — but a RESOLVED
// non-cloud investigation is excluded by a provider filter; an active scope
// that matches nothing is a distinct, detectable state.

import { describe, it, expect } from "vitest";
import {
  scopeOptions, resourceInScope, appInScope, buildScopeIndex, signalInScope,
  healthScopeKey, changeScopeKey, evidenceScopeKey, objectInScope,
  unknownInScope, scopedToNothing,
} from "./scope";
import { emptyScope } from "./scopeUrl";
import type { App, CloudResource } from "./types";
import type { CloudRcaObject } from "./api";

const S = (over: Partial<ReturnType<typeof emptyScope>> = {}) => ({ ...emptyScope(), ...over });

const res = (over: Partial<CloudResource> = {}): CloudResource => ({
  id: "r1", name: "web-1", type: "ec2", provider: "aws", account: "111",
  region: "us-east-1", app: "billing", owner: "core", env: "prod",
  source: "cloud_tag", confidence: "confirmed", health: "unknown",
  powerState: "running", trafficBps: -1, lastSeen: "2026-07-15T10:00:00Z",
  missingTags: [], tags: {}, resourceId: "i-123", ...over,
} as CloudResource);

const app = (over: Partial<App> = {}): App => ({
  id: "billing", name: "billing", health: "unknown", owner: "core", env: "prod",
  confidence: "confirmed", source: "cloud_tag", provider: "aws", providers: ["aws"],
  account: "111", region: "us-east-1", resources: 3, trafficBps: -1, errorPct: -1,
  p95ms: -1, unknownPct: -1, lastSeen: "", primarySymptom: "—",
  rootDomain: "unknown", underlayImpacted: false, ...over,
} as App);

describe("scopeOptions", () => {
  it("offers only values that exist, sorted, with dashes dropped", () => {
    const opts = scopeOptions([
      { provider: "azure", account: "sub-9", region: "eastus", env: "—" },
      { provider: "aws", account: "111", region: "us-east-1", env: "prod" },
      { provider: "aws", account: "111", region: "us-east-1", env: "prod" },
    ]);
    expect(opts.providers).toEqual(["aws", "azure"]);
    expect(opts.accounts).toEqual(["111", "sub-9"]);
    expect(opts.envs).toEqual(["prod"]); // "—" is an absence, not an option
  });
});

describe("resourceInScope — AND across dims, OR within", () => {
  it("empty scope matches everything", () => {
    expect(resourceInScope(res(), S())).toBe(true);
  });
  it("ORs values inside a dimension", () => {
    expect(resourceInScope(res(), S({ providers: ["azure", "aws"] }))).toBe(true);
    expect(resourceInScope(res(), S({ providers: ["azure", "gcp"] }))).toBe(false);
  });
  it("ANDs across dimensions", () => {
    expect(resourceInScope(res(), S({ providers: ["aws"], envs: ["dev"] }))).toBe(false);
    expect(resourceInScope(res(), S({ providers: ["aws"], envs: ["prod"] }))).toBe(true);
  });
  it("provider matching is case-insensitive", () => {
    expect(resourceInScope(res(), S({ providers: ["AWS"] }))).toBe(true);
  });
});

describe("appInScope — multi-cloud services", () => {
  it("keeps a dual-cloud app when ANY of its clouds is scoped", () => {
    const a = app({ providers: ["aws", "azure"] });
    expect(appInScope(a, S({ providers: ["azure"] }))).toBe(true);
    expect(appInScope(a, S({ providers: ["gcp"] }))).toBe(false);
  });
  it("splits merged account/region cells ('111 · sub-9')", () => {
    const a = app({ account: "111 · sub-9", region: "us-east-1 · eastus" });
    expect(appInScope(a, S({ accounts: ["sub-9"] }))).toBe(true);
    expect(appInScope(a, S({ regions: ["eastus"] }))).toBe(true);
    expect(appInScope(a, S({ accounts: ["222"] }))).toBe(false);
  });
});

describe("signalInScope — the honesty rules", () => {
  const idx = buildScopeIndex([res(), res({ id: "r2", name: "db-1", resourceId: "i-999", provider: "azure", account: "sub-9", region: "eastus", env: "dev" })]);

  it("filters a health signal by its own provider stamp", () => {
    expect(signalInScope(healthScopeKey({ source: "aws", resource: "web-1" }), S({ providers: ["aws"] }), idx)).toBe(true);
    expect(signalInScope(healthScopeKey({ source: "aws", resource: "web-1" }), S({ providers: ["azure"] }), idx)).toBe(false);
  });

  it("resolves account/region/env through the inventory by resource name", () => {
    const k = healthScopeKey({ source: "azure", resource: "db-1" });
    expect(signalInScope(k, S({ accounts: ["sub-9"] }), idx)).toBe(true);
    expect(signalInScope(k, S({ accounts: ["111"] }), idx)).toBe(false);
    expect(signalInScope(k, S({ envs: ["dev"] }), idx)).toBe(true);
    expect(signalInScope(k, S({ envs: ["prod"] }), idx)).toBe(false);
  });

  it("keeps a row it CANNOT place (unknown resource) visible — never hidden by a filter it never met", () => {
    const k = healthScopeKey({ source: "cloud", resource: "mystery-host" });
    expect(signalInScope(k, S({ accounts: ["111"], regions: ["us-east-1"], envs: ["prod"] }), idx)).toBe(true);
  });

  it("prefers a change's own cloud_ref account/region over the join", () => {
    const k = changeScopeKey({ resource: "web-1", cloudRef: { provider: "aws", account: "222", region: "us-west-2" } });
    expect(signalInScope(k, S({ accounts: ["222"] }), idx)).toBe(true);
    expect(signalInScope(k, S({ accounts: ["111"] }), idx)).toBe(false); // its OWN stamp wins
  });

  it("evidence falls back from cloud_ref to source for the provider", () => {
    const k = evidenceScopeKey({ source: "gcp", resource: "web-x" });
    expect(signalInScope(k, S({ providers: ["gcp"] }))).toBe(true);
    expect(signalInScope(k, S({ providers: ["aws"] }))).toBe(false);
  });
});

describe("objectInScope — investigations", () => {
  const obj = (providers: ("aws" | "azure" | "gcp")[], primary = ""): CloudRcaObject => ({
    correlationId: "cid-1", verdictTier: "suspected", confidence: 0.7,
    topHypothesis: "x", signalCount: 3, state: "open", windowStart: "", apps: [],
    origin: { providers, primaryResource: primary },
  });
  it("matches by the providers derived from the object's own evidence", () => {
    expect(objectInScope(obj(["aws"]), S({ providers: ["aws"] }))).toBe(true);
    expect(objectInScope(obj(["azure"]), S({ providers: ["aws"] }))).toBe(false);
  });
  it("a RESOLVED non-cloud object is excluded by a provider filter (providers=[] is a positive claim)", () => {
    expect(objectInScope(obj([]), S({ providers: ["aws"] }))).toBe(false);
    expect(objectInScope(obj([]), S())).toBe(true); // unfiltered: visible
  });
  it("resolves account through the primary affected resource when the inventory knows it", () => {
    const idx = buildScopeIndex([res()]);
    expect(objectInScope(obj(["aws"], "web-1"), S({ accounts: ["111"] }), idx)).toBe(true);
    expect(objectInScope(obj(["aws"], "web-1"), S({ accounts: ["999"] }), idx)).toBe(false);
    // unresolvable primary → stays visible
    expect(objectInScope(obj(["aws"], "ghost"), S({ accounts: ["999"] }), idx)).toBe(true);
  });
});

describe("unknownInScope", () => {
  it("applies resolved dims strictly; env never applies (it's what's missing)", () => {
    const u = { provider: "aws", account: "111", region: "us-east-1" };
    expect(unknownInScope(u, S({ providers: ["aws"] }))).toBe(true);
    expect(unknownInScope(u, S({ regions: ["eastus"] }))).toBe(false);
    expect(unknownInScope(u, S({ envs: ["prod"] }))).toBe(true);
  });
});

describe("scopedToNothing — the empty-scope state", () => {
  it("true only when a scope is ACTIVE and hid everything that exists", () => {
    expect(scopedToNothing(S({ providers: ["gcp"] }), 5, 0)).toBe(true);
    expect(scopedToNothing(S(), 5, 0)).toBe(false);       // no scope → not a scope problem
    expect(scopedToNothing(S({ providers: ["gcp"] }), 0, 0)).toBe(false); // nothing ingested at all
    expect(scopedToNothing(S({ providers: ["gcp"] }), 5, 2)).toBe(false); // matches exist
  });
});

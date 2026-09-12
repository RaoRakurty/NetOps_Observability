// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// ingestion.test.ts — the ingestion model groups the live inventory by account
// and account×region, and reports readiness HONESTLY: inventory flows where
// resources exist, every other source is "off". (#81 P3F+1 Phase 2)
// Wave 2 #4 adds the connector-first merged account rows: identity vs telemetry
// judged separately, silent-but-connected accounts red and never dropped.

import { describe, it, expect } from "vitest";
import { buildAccounts, buildMatrix, mergeAccounts, accountsInScope, matrixInScope } from "./ingestion";
import type { CloudResourceRow, CloudConnectorView } from "../../services/api";

function row(p: Partial<CloudResourceRow>): CloudResourceRow {
  return {
    tenant_id: "", cloud_provider: "aws", account_id: "111", region: "us-east-1",
    resource_id: "r1", resource_type: "AWS::EC2::Instance",
    discovered_at: "2026-06-25T00:00:00Z", last_seen_at: "2026-06-25T00:00:00Z",
    source: "cloud_tag", confidence: "confirmed", ...p,
  };
}

const rows: CloudResourceRow[] = [
  row({ account_id: "111", region: "us-east-1", resource_id: "a", last_seen_at: "2026-06-25T10:00:00Z" }),
  row({ account_id: "111", region: "us-east-1", resource_id: "b", last_seen_at: "2026-06-25T11:00:00Z" }),
  row({ account_id: "111", region: "us-west-2", resource_id: "c" }),
  row({ cloud_provider: "azure", account_id: "sub-1", region: "eastus", resource_id: "d" }),
];

describe("buildAccounts", () => {
  it("groups by provider+account with deduped regions and a count", () => {
    const accts = buildAccounts(rows);
    expect(accts).toHaveLength(2); // aws/111, azure/sub-1
    const aws = accts.find((a) => a.accountId === "111")!;
    expect(aws.provider).toBe("aws");
    expect(aws.regions).toEqual(["us-east-1", "us-west-2"]);
    expect(aws.resourceCount).toBe(3);
    expect(aws.status).toBe("flowing");
    expect(aws.enabledSources).toBe(1); // only inventory is live today
    expect(aws.lastSyncIso).toBe("2026-06-25T11:00:00Z"); // freshest
  });
  it("returns nothing for an empty inventory", () => {
    expect(buildAccounts([])).toEqual([]);
  });
});

describe("buildMatrix", () => {
  it("one row per provider×account×region, inventory flowing, rest off", () => {
    const m = buildMatrix(rows);
    expect(m).toHaveLength(3); // 111/use1, 111/usw2, azure/eastus
    const use1 = m.find((x) => x.accountId === "111" && x.region === "us-east-1")!;
    expect(use1.resourceCount).toBe(2);
    const inv = use1.readiness.find((r) => r.sourceType === "inventory")!;
    expect(inv.status).toBe("flowing");
    expect(inv.volume).toBe(2);
    expect(use1.readiness.filter((r) => r.sourceType !== "inventory").every((r) => r.status === "off")).toBe(true);
  });
  it("is stably sorted by provider, account, region", () => {
    const m = buildMatrix(rows);
    const keys = m.map((x) => `${x.provider}/${x.accountId}/${x.region}`);
    expect(keys).toEqual([...keys].sort());
  });
  it("carries the poller-reported failure context onto the source chip", () => {
    const m = buildMatrix(rows, {
      aws: [{
        source_type: "flow_logs", status: "permission_denied",
        detail: "IAM denied logs:FilterLogEvents", since_iso: "2026-06-23T08:00:00Z",
      }],
    });
    const use1 = m.find((x) => x.accountId === "111" && x.region === "us-east-1")!;
    const flow = use1.readiness.find((r) => r.sourceType === "flow_logs")!;
    expect(flow.status).toBe("permission_denied");
    expect(flow.lastError).toBe("IAM denied logs:FilterLogEvents");
    expect(flow.sinceIso).toBe("2026-06-23T08:00:00Z");
  });
});

// ── mergeAccounts (Wave 2 #4) ─────────────────────────────────────────────────

const NOW = new Date("2026-07-16T12:00:00Z").getTime();

function conn(over: Partial<CloudConnectorView> = {}): CloudConnectorView {
  return {
    id: "ccn_a", provider: "aws", display_name: "Prod", auth_method: "cloud_role",
    auth_federated: true, auth_legacy: false, capability_pack: "aws-observer-v1",
    state: "ACTIVE", collecting: true,
    identity: { has_legacy_secret: false },
    scopes: [{ type: "account", ref: "111", regions: ["us-east-1"] }],
    identity_health: { state: "healthy" }, telemetry_health: { state: "unknown" },
    last_validation: { ok: true, findings: [] }, version: 1,
    created_at: "2026-07-01T00:00:00Z", updated_at: "2026-07-15T00:00:00Z",
    ...over,
  } as CloudConnectorView;
}

describe("mergeAccounts", () => {
  it("a configured account with NO data is a red attention row — never dropped", () => {
    const out = mergeAccounts([conn()], [], undefined, NOW);
    expect(out).toHaveLength(1);
    expect(out[0].accountId).toBe("111");
    expect(out[0].connection).toBe("ok");
    expect(out[0].telemetry).toBe("silent");
    expect(out[0].state.attention).toBe(true);
    expect(out[0].state.label).toBe("Connected — no data arriving");
  });

  it("connection OK + fresh inventory = healthy; identity and telemetry stay split", () => {
    const fresh = new Date(NOW - 5 * 60_000).toISOString();
    const out = mergeAccounts([conn()], [row({ account_id: "111", last_seen_at: fresh })], undefined, NOW);
    expect(out).toHaveLength(1);
    expect(out[0].connection).toBe("ok");
    expect(out[0].telemetry).toBe("flowing");
    expect(out[0].state).toEqual({ label: "Healthy", tone: "var(--ok)", attention: false });
    expect(out[0].resourceCount).toBe(1);
  });

  it("old data downgrades to stale (amber), not silent and not green", () => {
    const old = new Date(NOW - 3 * 3600_000).toISOString();
    const out = mergeAccounts([conn()], [row({ account_id: "111", last_seen_at: old })], undefined, NOW);
    expect(out[0].telemetry).toBe("stale");
    expect(out[0].state.label).toBe("Data stale");
    expect(out[0].state.attention).toBe(false);
  });

  it("a broken connection is red even when stale data still exists", () => {
    const old = new Date(NOW - 3 * 3600_000).toISOString();
    const out = mergeAccounts(
      [conn({ state: "REAUTHORIZATION_REQUIRED" })],
      [row({ account_id: "111", last_seen_at: old })], undefined, NOW);
    expect(out[0].connection).toBe("broken");
    expect(out[0].state.attention).toBe(true);
    expect(out[0].state.label).toBe("Connection broken");
    expect(out[0].connectionLabel).toBe("Needs re-authorization");
  });

  it("setup-stage connectors are amber 'not collecting yet', not red", () => {
    const out = mergeAccounts([conn({ state: "DRAFT", collecting: false, last_validation: { ok: false, findings: null } })], [], undefined, NOW);
    expect(out[0].connection).toBe("setup");
    expect(out[0].state.attention).toBe(false);
    expect(out[0].state.label).toMatch(/not collecting yet/);
  });

  it("a connector's telemetry-health check counts as delivery proof (no inventory rows needed)", () => {
    const checked = new Date(NOW - 4 * 60_000).toISOString();
    const out = mergeAccounts(
      [conn({ telemetry_health: { state: "healthy", checked } })], [], undefined, NOW);
    expect(out[0].telemetry).toBe("flowing");
    expect(out[0].state.label).toBe("Healthy");
  });

  it("discovered accounts without a connector stay visible as platform-managed", () => {
    const fresh = new Date(NOW - 60_000).toISOString();
    const out = mergeAccounts([], [row({ account_id: "999", last_seen_at: fresh })], undefined, NOW);
    expect(out).toHaveLength(1);
    expect(out[0].connection).toBe("platform");
    expect(out[0].connectionLabel).toBe("Platform managed");
    expect(out[0].state.label).toBe("Healthy");
  });

  it("a connector and its arrived inventory merge into ONE row (attention rows sort first)", () => {
    const fresh = new Date(NOW - 60_000).toISOString();
    const out = mergeAccounts(
      [conn(), conn({ id: "ccn_dark", display_name: "Dark", scopes: [{ type: "account", ref: "222" }] })],
      [row({ account_id: "111", last_seen_at: fresh })], undefined, NOW);
    expect(out).toHaveLength(2); // no duplicate 111 row
    expect(out[0].accountId).toBe("222"); // the silent one leads
    expect(out[0].state.attention).toBe(true);
    expect(out[1].accountId).toBe("111");
  });

  it("a scoped-less draft forms no account row (it lives in the Connections list)", () => {
    const out = mergeAccounts([conn({ state: "DRAFT", scopes: [] })], [], undefined, NOW);
    expect(out).toEqual([]);
  });
});

// ── Wave 2 #5 — the global scope narrows the Data sources matrices ───────────
describe("accountsInScope / matrixInScope", () => {
  const noScope = { providers: [], accounts: [], regions: [] };
  it("empty scope passes every row through", () => {
    const accts = mergeAccounts([], rows);
    expect(accountsInScope(accts, noScope)).toHaveLength(accts.length);
    const matrix = buildMatrix(rows);
    expect(matrixInScope(matrix, noScope)).toHaveLength(matrix.length);
  });
  it("filters accounts by provider (case-insensitive) and account id", () => {
    const accts = mergeAccounts([], rows);
    expect(accountsInScope(accts, { ...noScope, providers: ["AWS"] }).map((a) => a.accountId)).toEqual(["111"]);
    expect(accountsInScope(accts, { ...noScope, accounts: ["sub-1"] }).map((a) => a.provider)).toEqual(["azure"]);
  });
  it("a region scope keeps any account that REACHES a scoped region", () => {
    const accts = mergeAccounts([], rows);
    expect(accountsInScope(accts, { ...noScope, regions: ["us-west-2"] }).map((a) => a.accountId)).toEqual(["111"]);
    expect(accountsInScope(accts, { ...noScope, regions: ["nowhere"] })).toHaveLength(0);
  });
  it("the matrix filters exactly per account×region row (AND across dims)", () => {
    const matrix = buildMatrix(rows);
    const scoped = matrixInScope(matrix, { providers: ["aws"], accounts: ["111"], regions: ["us-east-1"] });
    expect(scoped).toHaveLength(1);
    expect(scoped[0].region).toBe("us-east-1");
  });
});

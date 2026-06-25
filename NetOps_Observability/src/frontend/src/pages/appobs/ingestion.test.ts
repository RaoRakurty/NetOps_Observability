// ingestion.test.ts — the ingestion model groups the live inventory by account
// and account×region, and reports readiness HONESTLY: inventory flows where
// resources exist, every other source is "off". (#81 P3F+1 Phase 2)

import { describe, it, expect } from "vitest";
import { buildAccounts, buildMatrix } from "./ingestion";
import type { CloudResourceRow } from "../../services/api";

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
});

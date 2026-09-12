// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// attribution.test.ts — pure coverage/structure analytics over the live inventory
// (#81 P3F+1 gap close). All derivable from identity alone, no telemetry.

import { describe, it, expect } from "vitest";
import { resourceCategory, coverageByScope, funnelSteps, groupByApp, isAttributed, workloadClass, WORKLOAD_CLASSES, WORKLOAD_CLASS_META } from "./attribution";
import type { CloudResource, Coverage } from "./types";

function res(p: Partial<CloudResource>): CloudResource {
  return {
    id: "r", name: "r", type: "AWS::EC2::Instance", provider: "aws", account: "1", region: "us-east-1",
    app: "billing", owner: "pay", env: "prod", source: "cloud_tag", confidence: "confirmed",
    health: "unknown", trafficBps: -1, lastSeen: "", missingTags: [], tags: {}, resourceId: "r", ...p,
  };
}

describe("resourceCategory", () => {
  it("buckets common types", () => {
    expect(resourceCategory("LoadBalancer")).toBe("Network");
    expect(resourceCategory("NatGateway")).toBe("Network");
    expect(resourceCategory("Instance")).toBe("Compute");
    expect(resourceCategory("Task")).toBe("Compute");
    expect(resourceCategory("Function")).toBe("Compute");
    expect(resourceCategory("DBInstance")).toBe("Data");
    expect(resourceCategory("CacheCluster")).toBe("Data");
    expect(resourceCategory("Microsoft.Sql/databases")).toBe("Data");
    expect(resourceCategory("virtualMachines")).toBe("Compute");
    expect(resourceCategory("SomethingWeird")).toBe("Other");
  });

  it("buckets the Wave 5 #15 workload types", () => {
    expect(resourceCategory("run:service")).toBe("Compute");
    expect(resourceCategory("web:site")).toBe("Compute");
    expect(resourceCategory("web:serverFarm")).toBe("Compute");
    expect(resourceCategory("containerservice:agentPool")).toBe("Compute");
    expect(resourceCategory("sqladmin:instance")).toBe("Data");
  });
});

describe("workloadClass (Wave 5 #15)", () => {
  it("maps the discovery lanes' exact types, case-insensitively", () => {
    expect(workloadClass("eks:cluster")).toBe("k8s");
    expect(workloadClass("eks:nodegroup")).toBe("k8s");
    expect(workloadClass("containerservice:managedCluster")).toBe("k8s");
    expect(workloadClass("container:nodePool")).toBe("k8s");
    expect(workloadClass("lambda:function")).toBe("serverless");
    expect(workloadClass("web:serverFarm")).toBe("serverless");
    expect(workloadClass("run:service")).toBe("serverless");
    expect(workloadClass("rds:instance")).toBe("db");
    expect(workloadClass("sql:database")).toBe("db");
    expect(workloadClass("sqladmin:instance")).toBe("db");
  });

  it("returns null for non-workload types — never guesses a class", () => {
    expect(workloadClass("ec2:instance")).toBeNull();
    expect(workloadClass("elbv2:loadbalancer")).toBeNull();
    expect(workloadClass("")).toBeNull();
  });

  it("every class carries an honest empty state naming the needed permission", () => {
    for (const c of WORKLOAD_CLASSES) {
      const meta = WORKLOAD_CLASS_META[c];
      expect(meta.label.length).toBeGreaterThan(0);
      expect(meta.emptyTitle).toMatch(/^No /);
      expect(meta.emptyHint).toContain("the collector needs");
    }
    expect(WORKLOAD_CLASS_META.k8s.emptyHint).toContain("eks:ListClusters");
    expect(WORKLOAD_CLASS_META.serverless.emptyHint).toContain("lambda:ListFunctions");
    expect(WORKLOAD_CLASS_META.db.emptyHint).toContain("rds:DescribeDBInstances");
  });
});

describe("isAttributed", () => {
  it("requires an app and a non-unknown confidence", () => {
    expect(isAttributed(res({ app: "billing", confidence: "confirmed" }))).toBe(true);
    expect(isAttributed(res({ app: "", confidence: "unknown" }))).toBe(false);
    expect(isAttributed(res({ app: "x", confidence: "unknown" }))).toBe(false);
  });
});

describe("coverageByScope", () => {
  it("computes attributed % per scope, sorted", () => {
    const rows = [
      res({ region: "us-east-1", app: "billing", confidence: "confirmed" }),
      res({ region: "us-east-1", app: "", confidence: "unknown" }),
      res({ region: "us-west-2", app: "checkout", confidence: "strong" }),
    ];
    const byRegion = coverageByScope(rows, (r) => r.region);
    expect(byRegion).toEqual([
      { scope: "us-east-1", total: 2, attributed: 1, pct: 50 },
      { scope: "us-west-2", total: 1, attributed: 1, pct: 100 },
    ]);
  });
});

describe("funnelSteps", () => {
  it("turns coverage counts into % steps over total", () => {
    const c: Coverage = { confirmedTag: 50, strongGraph: 25, firewallAppId: 0, suspectedDomainIp: 15, unknown: 10, total: 100 };
    const steps = funnelSteps(c);
    expect(steps.map((s) => s.pct)).toEqual([50, 25, 0, 15, 10]);
    expect(steps[0].label).toBe("Confirmed by tag");
    expect(steps[4].label).toBe("Unknown");
  });
});

describe("groupByApp", () => {
  it("groups resources by app, unattributed bucket last, categorized", () => {
    const rows = [
      res({ id: "a", app: "billing", type: "LoadBalancer" }),
      res({ id: "b", app: "billing", type: "DBInstance" }),
      res({ id: "c", app: "", confidence: "unknown", type: "Instance" }),
    ];
    const groups = groupByApp(rows);
    expect(groups.map((g) => g.app)).toEqual(["billing", ""]); // unattributed last
    const billing = groups[0];
    expect(billing.byCategory.Network).toHaveLength(1);
    expect(billing.byCategory.Data).toHaveLength(1);
  });
});

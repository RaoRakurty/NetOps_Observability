// costContext.test.ts (Wave 5 #18 slice 3) — the pure cost-context math:
// scope derivation, window anchoring, honest aggregation (no fabricated
// figures, currencies never mixed, unbilled days never read as 0).

import { describe, it, expect } from "vitest";
import {
  costScope, costWindow, fmtAmount, summarizeCosts,
  MAX_COST_ACCOUNTS, type CostRow,
} from "./costContext";
import type { InvestigationChange } from "./api";

function change(provider: string, account: string): InvestigationChange {
  return {
    time: "t", app: "a", resource: "r", changeType: "deploy", actor: "u",
    source: "s", confidence: "confirmed", relatedSymptoms: [], offsetSeconds: 0,
    cloudRef: { provider, resourceId: "id", account, region: "", consoleUrl: "", logUrl: "" },
  };
}

describe("costScope", () => {
  it("derives unique provider/account pairs from recorded changes only", () => {
    const scope = costScope([
      change("aws", "111"), change("aws", "111"), change("azure", "sub-1"),
    ]);
    expect(scope).toEqual([
      { provider: "aws", account: "111" },
      { provider: "azure", account: "sub-1" },
    ]);
  });

  it("ignores changes without a provider/account — nothing is guessed", () => {
    const noRef = { ...change("aws", "111"), cloudRef: undefined };
    expect(costScope([noRef, change("", "111"), change("aws", "")])).toEqual([]);
  });

  it("is bounded", () => {
    const many = Array.from({ length: 10 }, (_, i) => change("aws", `acct-${i}`));
    expect(costScope(many)).toHaveLength(MAX_COST_ACCOUNTS);
  });
});

describe("costWindow", () => {
  const now = new Date("2026-07-18T12:00:00Z");

  it("anchors onset ± 7d", () => {
    expect(costWindow("2026-07-10T06:00:00Z", now)).toEqual({
      from: "2026-07-03", to: "2026-07-17", onsetDay: "2026-07-10",
    });
  });

  it("caps the forward edge at now", () => {
    const w = costWindow("2026-07-17T06:00:00Z", now);
    expect(w?.to).toBe("2026-07-18");
  });

  it("returns null for an unparseable onset — no window is invented", () => {
    expect(costWindow("", now)).toBeNull();
    expect(costWindow("junk", now)).toBeNull();
  });
});

describe("summarizeCosts", () => {
  const rows: CostRow[] = [
    { day: "2026-07-03", provider: "aws", account: "111", service: "EC2", amount: 10, currency: "USD" },
    { day: "2026-07-04", provider: "aws", account: "111", service: "EC2", amount: 11, currency: "USD" },
    { day: "2026-07-10", provider: "aws", account: "111", service: "EC2", amount: 30, currency: "USD" },
    { day: "2026-07-05", provider: "aws", account: "111", service: "S3", amount: 1, currency: "USD" },
  ];

  it("sums real rows and derives the baseline over CALENDAR days", () => {
    const [ec2, s3] = summarizeCosts(rows, "2026-07-03", "2026-07-10");
    expect(ec2.service).toBe("EC2");
    expect(ec2.total).toBe(51);
    // baseline = pre-onset total (21) / 7 calendar days, NOT /2 rows
    expect(ec2.baselineDaily).toBeCloseTo(3);
    expect(ec2.onsetDayAmount).toBe(30);
    expect(s3.total).toBe(1);
  });

  it("an unbilled onset day is null (not yet billed), never 0", () => {
    const [s3] = summarizeCosts(
      rows.filter((r) => r.service === "S3"), "2026-07-03", "2026-07-10");
    expect(s3.onsetDayAmount).toBeNull();
  });

  it("never mixes currencies into one figure", () => {
    const mixed: CostRow[] = [
      { day: "2026-07-04", provider: "azure", account: "s", service: "VM", amount: 5, currency: "USD" },
      { day: "2026-07-04", provider: "azure", account: "s", service: "VM", amount: 5, currency: "EUR" },
    ];
    const out = summarizeCosts(mixed, "2026-07-03", "2026-07-10");
    expect(out).toHaveLength(2);
    expect(out.map((s) => s.currency).sort()).toEqual(["EUR", "USD"]);
  });

  it("carries credits (negative amounts) as real figures and caps topN", () => {
    const many: CostRow[] = Array.from({ length: 8 }, (_, i) => ({
      day: "2026-07-04", provider: "aws", account: "1",
      service: `svc-${i}`, amount: i === 0 ? -50 : i, currency: "USD",
    }));
    const out = summarizeCosts(many, "2026-07-03", "2026-07-10", 5);
    expect(out).toHaveLength(5);
    expect(out[0].service).toBe("svc-0"); // |−50| ranks first — a credit is a real figure
    expect(out[0].total).toBe(-50);
  });

  it("drops non-numeric amounts rather than guessing", () => {
    const bad = [{ day: "2026-07-04", provider: "aws", account: "1", service: "X",
      amount: Number.NaN, currency: "USD" }] as CostRow[];
    expect(summarizeCosts(bad, "2026-07-03", "2026-07-10")).toEqual([]);
  });
});

describe("fmtAmount", () => {
  it("renders plain billed figures", () => {
    expect(fmtAmount(12.345, "USD")).toBe("12.35 USD");
    expect(fmtAmount(-1, "EUR")).toBe("-1.00 EUR");
  });
});

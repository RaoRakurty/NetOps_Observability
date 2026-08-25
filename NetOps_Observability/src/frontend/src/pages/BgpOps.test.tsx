// BgpOps helper tests (item 10, 2026-08-25): the verdict/visibility/path/churn
// logic is pure and carries the page's correctness — the panels only render
// what these produce.
import { describe, expect, it } from "vitest";
import {
  rpkiVerdict, visibilityFraction, compressPath, groupPaths, bucketUpdates, rdapContacts,
} from "./BgpOps";

describe("rpkiVerdict", () => {
  it("maps the RIPEstat statuses onto honest chips", () => {
    expect(rpkiVerdict("valid").label).toBe("RPKI VALID");
    expect(rpkiVerdict("invalid").tone).toBe("var(--crit)");
    expect(rpkiVerdict("invalid_asn").label).toContain("origin");
    expect(rpkiVerdict("unknown").label).toBe("No ROA");
  });
  it("an absent status renders as unavailable, never as valid", () => {
    const v = rpkiVerdict(undefined);
    expect(v.label).not.toContain("VALID");
    expect(v.tone).toBe("var(--muted)");
  });
});

describe("visibilityFraction", () => {
  it("combines v4+v6 peers", () => {
    expect(
      visibilityFraction({
        visibility: {
          v4: { total_ris_peers: 300, ris_peers_seeing: 270 },
          v6: { total_ris_peers: 100, ris_peers_seeing: 90 },
        },
      }),
    ).toBeCloseTo(0.9);
  });
  it("returns null (never 0%) when totals are unknown — absence of data is not an outage", () => {
    expect(visibilityFraction({})).toBeNull();
    expect(visibilityFraction(undefined)).toBeNull();
  });
});

describe("compressPath / groupPaths", () => {
  it("collapses AS-path prepending", () => {
    expect(compressPath("3333 1234 1234 1234 64500")).toEqual(["3333", "1234", "64500"]);
  });
  it("groups identical compressed paths and sorts by prevalence", () => {
    const g = groupPaths({
      rrcs: [
        { rrc: "RRC00", peers: [{ as_path: "1 2 3" }, { as_path: "1 2 2 3" }] },
        { rrc: "RRC01", peers: [{ as_path: "9 8 3" }] },
      ],
    });
    expect(g[0]).toEqual({ path: ["1", "2", "3"], count: 2 });
    expect(g[1].count).toBe(1);
  });
});

describe("bucketUpdates", () => {
  it("buckets announces and withdrawals per hour, sorted", () => {
    const b = bucketUpdates({
      updates: [
        { type: "A", timestamp: "2026-08-25T10:01:00" },
        { type: "W", timestamp: "2026-08-25T10:31:00" },
        { type: "W", timestamp: "2026-08-25T09:59:00" },
      ],
    });
    expect(b).toEqual([
      ["2026-08-25T09", 0, 1],
      ["2026-08-25T10", 1, 1],
    ]);
  });
  it("tolerates absent data", () => {
    expect(bucketUpdates(undefined)).toEqual([]);
  });
});

describe("rdapContacts", () => {
  it("pulls fn + roles from vcards and never throws on junk", () => {
    const c = rdapContacts({
      entities: [
        { roles: ["registrant"], vcardArray: ["vcard", [["fn", {}, "text", "Example NOC"]]] },
        { roles: ["abuse"] },
        { vcardArray: "garbage" },
      ],
    });
    expect(c[0]).toEqual({ name: "Example NOC", roles: ["registrant"] });
    expect(c[1].roles).toEqual(["abuse"]);
    expect(rdapContacts(null)).toEqual([]);
    expect(rdapContacts("nonsense")).toEqual([]);
  });
});

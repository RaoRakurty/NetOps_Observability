// wanCircuits.model.test.ts — the derivation and intent rules of WAN Paths.
//
// Two things are pinned here that a screenshot would never catch:
//
//   * THE HONEST BUCKET. An interface with no derived target is its own answer,
//     with its own count and its own words. A regression that folds it into
//     "anchor" (or drops it from the summary) makes an unmeasured network look
//     fully measured, which is the expensive lie on this page.
//   * THE PUT BODY. `policyPatch` is the ONLY thing that builds the write, and
//     tenant / author / time are stamped by the server from the token. If any of
//     those ever leak back into the body we are asserting ownership we do not
//     have, so the exact key set is asserted, not just the values.

import { describe, it, expect } from "vitest";
import type { WanCircuit, WanEndpoint, WanMeasurementPolicy } from "../services/api";
import {
  DEFAULT_ANCHORS,
  DEFAULT_WAN_PATTERN,
  MAX_ANCHORS,
  MAX_NEXT_HOPS,
  TARGET_KIND_ORDER,
  blankNextHopRow,
  duplicateNextHopKeys,
  endpointKind,
  formFromPolicy,
  formatAnchors,
  isDirty,
  isPlausibleHost,
  matchesCircuit,
  matchesEndpoint,
  nextHopMap,
  nextHopRows,
  nextHopScope,
  noTargetCount,
  parseAnchors,
  parseNextHopKey,
  policyPatch,
  provenanceCounts,
  sortCircuits,
  sortEndpoints,
  targetKindChip,
  targetKindLabel,
  targetKindMeaning,
  targetKindRank,
  validateAnchors,
  validateForm,
  validateNextHops,
  validatePattern,
  type NextHopRow,
  type PolicyForm,
} from "./wanCircuits.model";

function ep(over: Partial<WanEndpoint> = {}): WanEndpoint {
  return {
    device: "wan-edge-1",
    interface: "Ethernet1",
    address: "10.1.1.1",
    measurable_addr: "10.1.1.1",
    ...over,
  };
}

function circuit(over: Partial<WanCircuit> = {}): WanCircuit {
  return {
    id: "wan-edge-1|Ethernet1|10.1.1.2",
    local: ep(),
    remote: ep({ device: "spine-1", interface: "Ethernet9", address: "10.1.1.2", measurable_addr: "10.1.1.2" }),
    kind: "direct_peer",
    source: "registry",
    enabled: true,
    ...over,
  };
}

function row(key: string, target: string): NextHopRow {
  return { id: `r-${key}-${target}`, key, target };
}

function form(over: Partial<PolicyForm> = {}): PolicyForm {
  return {
    pattern: DEFAULT_WAN_PATTERN,
    anchorsText: formatAnchors([...DEFAULT_ANCHORS]),
    includeConnected: true,
    nextHops: [],
    ...over,
  };
}

// ── provenance ──────────────────────────────────────────────────────────────

describe("provenance labels", () => {
  it("uses the operator's words for each derivation, matching the server's own labels", () => {
    expect(targetKindLabel("direct_peer")).toBe("Directly-connected peer");
    expect(targetKindLabel("next_hop")).toBe("ISP next-hop");
    expect(targetKindLabel("anchor")).toBe("Reachability anchor");
  });

  it("names the absent case rather than blanking it", () => {
    expect(targetKindLabel("")).toBe("No target derived");
    expect(targetKindLabel(undefined)).toBe("No target derived");
    expect(targetKindLabel(null)).toBe("No target derived");
  });

  it("passes an unrecognised kind through instead of inventing a friendly word", () => {
    expect(targetKindLabel("satellite_uplink")).toBe("satellite_uplink");
    expect(targetKindChip("satellite_uplink")).toBe("satellite_uplink");
    expect(targetKindMeaning("satellite_uplink")).toMatch(/does not recognise/);
  });

  // UI-words sweep 4 (tracker 270): the tooltip NAMES the target; where ownership
  // hands off to the ISP is ai/skills/explain/wan.next-hop.md, reached from the
  // `(i)` on the section — the claim did not move, only the word count.
  it("says a next-hop is the ISP next-hop the operator declared", () => {
    expect(targetKindMeaning("next_hop")).toMatch(/ISP next-hop you declared/);
    expect(targetKindMeaning("next_hop")).not.toMatch(/boundary/i);
  });

  it("never uses hub or spoke vocabulary — every interface measures 1:1", () => {
    const all = TARGET_KIND_ORDER.map((k) => `${targetKindLabel(k)} ${targetKindChip(k)} ${targetKindMeaning(k)}`).join(" ");
    expect(all).not.toMatch(/\bhub\b|\bspoke\b/i);
  });

  it("ranks operator knowledge above a guessed anchor, and the absent case last", () => {
    expect(targetKindRank("direct_peer")).toBeLessThan(targetKindRank("next_hop"));
    expect(targetKindRank("next_hop")).toBeLessThan(targetKindRank("anchor"));
    expect(targetKindRank("anchor")).toBeLessThan(targetKindRank(""));
    expect(targetKindRank("satellite_uplink")).toBeGreaterThanOrEqual(targetKindRank(""));
  });
});

describe("endpointKind", () => {
  it("reads the wire kind when there is a target", () => {
    expect(endpointKind(ep({ target: "1.1.1.1", target_kind: "anchor" }))).toBe("anchor");
  });

  it("is the honest bucket when no target address was derived, whatever the kind says", () => {
    expect(endpointKind(ep({ target: "", target_kind: "anchor" }))).toBe("");
    expect(endpointKind(ep({}))).toBe("");
  });

  it("is the honest bucket when a target exists but its kind is missing", () => {
    expect(endpointKind(ep({ target: "10.0.0.1" }))).toBe("");
  });
});

describe("provenanceCounts", () => {
  it("keeps all four buckets on an empty derivation, so zero is visible", () => {
    const counts = provenanceCounts([]);
    expect(counts.map((c) => c.kind)).toEqual(["direct_peer", "next_hop", "anchor", ""]);
    expect(counts.every((c) => c.count === 0)).toBe(true);
  });

  it("counts how many interfaces measure to a peer, an ISP next-hop, an anchor and nothing", () => {
    const counts = provenanceCounts([
      ep({ target: "10.1.1.2", target_kind: "direct_peer" }),
      ep({ interface: "Ethernet2", target: "10.1.1.6", target_kind: "direct_peer" }),
      ep({ interface: "Ethernet3", target: "203.0.113.1", target_kind: "next_hop" }),
      ep({ interface: "Ethernet4", target: "1.1.1.1", target_kind: "anchor" }),
      ep({ interface: "Ethernet5" }),
    ]);
    expect(counts).toEqual([
      { kind: "direct_peer", label: "Directly-connected peer", count: 2 },
      { kind: "next_hop", label: "ISP next-hop", count: 1 },
      { kind: "anchor", label: "Reachability anchor", count: 1 },
      { kind: "", label: "No target derived", count: 1 },
    ]);
  });

  it("appends an unknown kind after the known ones rather than dropping it", () => {
    const counts = provenanceCounts([ep({ target: "x", target_kind: "satellite_uplink" as never })]);
    expect(counts).toHaveLength(5);
    expect(counts[4]).toEqual({ kind: "satellite_uplink", label: "satellite_uplink", count: 1 });
  });

  it("noTargetCount agrees with the honest bucket", () => {
    const eps = [ep({ target: "1.1.1.1", target_kind: "anchor" }), ep({ interface: "Ethernet7" })];
    expect(noTargetCount(eps)).toBe(1);
    expect(provenanceCounts(eps).find((c) => c.kind === "")?.count).toBe(1);
  });
});

// ── ordering + search ───────────────────────────────────────────────────────

describe("ordering and search", () => {
  it("orders endpoints by device then interface", () => {
    const sorted = sortEndpoints([
      ep({ device: "wan-edge-2", interface: "Ethernet1" }),
      ep({ device: "wan-edge-1", interface: "Ethernet2" }),
      ep({ device: "wan-edge-1", interface: "Ethernet1" }),
    ]);
    expect(sorted.map((e) => `${e.device}/${e.interface}`)).toEqual([
      "wan-edge-1/Ethernet1", "wan-edge-1/Ethernet2", "wan-edge-2/Ethernet1",
    ]);
  });

  it("orders circuits by their local end and does not mutate the input", () => {
    const input = [
      circuit({ id: "b", local: ep({ device: "wan-edge-2" }) }),
      circuit({ id: "a", local: ep({ device: "wan-edge-1" }) }),
    ];
    expect(sortCircuits(input).map((c) => c.id)).toEqual(["a", "b"]);
    expect(input.map((c) => c.id)).toEqual(["b", "a"]);
  });

  it("matches an endpoint on device, interface, address, site and target", () => {
    const e = ep({ site: "London", target: "203.0.113.1", target_label: "ISP next-hop 203.0.113.1" });
    expect(matchesEndpoint(e, "london")).toBe(true);
    expect(matchesEndpoint(e, "203.0.113")).toBe(true);
    expect(matchesEndpoint(e, "ethernet1")).toBe(true);
    expect(matchesEndpoint(e, "nowhere")).toBe(false);
    expect(matchesEndpoint(e, "   ")).toBe(true);
  });

  it("matches a circuit on either end", () => {
    const c = circuit();
    expect(matchesCircuit(c, "spine-1")).toBe(true);
    expect(matchesCircuit(c, "wan-edge-1")).toBe(true);
    expect(matchesCircuit(c, "leaf-9")).toBe(false);
  });
});

// ── next-hop overrides ──────────────────────────────────────────────────────

describe("next-hop keys", () => {
  it("reads a bare device key as covering every interface on it", () => {
    expect(parseNextHopKey("wan-edge-1")).toEqual({ device: "wan-edge-1", ifName: "" });
    expect(nextHopScope("wan-edge-1")).toBe("Every WAN interface on wan-edge-1");
  });

  it("reads a device/interface key, splitting on the FIRST slash only", () => {
    expect(parseNextHopKey("wan-edge-1/Ethernet1/0/1")).toEqual({
      device: "wan-edge-1", ifName: "Ethernet1/0/1",
    });
    expect(nextHopScope("wan-edge-1/Ethernet1")).toBe("wan-edge-1 Ethernet1");
  });

  it("trims both halves and says plainly when a key names no device", () => {
    expect(parseNextHopKey("  wan-edge-1 / Ethernet1 ")).toEqual({ device: "wan-edge-1", ifName: "Ethernet1" });
    expect(nextHopScope("   ")).toMatch(/no device/);
  });
});

describe("next-hop rows ⇄ map", () => {
  it("turns the stored map into rows in a stable order", () => {
    const rows = nextHopRows({ "wan-edge-2": "198.51.100.1", "wan-edge-1/Ethernet1": "203.0.113.1" });
    expect(rows.map((r) => r.key)).toEqual(["wan-edge-1/Ethernet1", "wan-edge-2"]);
    expect(rows.map((r) => r.target)).toEqual(["203.0.113.1", "198.51.100.1"]);
    expect(new Set(rows.map((r) => r.id)).size).toBe(2);
  });

  it("treats a missing map as no overrides", () => {
    expect(nextHopRows(undefined)).toEqual([]);
    expect(nextHopRows(null)).toEqual([]);
  });

  it("drops blank rows and trims what it keeps", () => {
    expect(nextHopMap([row(" wan-edge-1 ", " 203.0.113.1 "), row("", ""), row("wan-edge-2", "")]))
      .toEqual({ "wan-edge-1": "203.0.113.1" });
  });

  it("hands out unique ids for blank rows the operator adds", () => {
    const a = blankNextHopRow();
    const b = blankNextHopRow();
    expect(a.id).not.toBe(b.id);
    expect(a).toMatchObject({ key: "", target: "" });
  });
});

describe("next-hop validation", () => {
  it("accepts an empty table and a well-formed one", () => {
    expect(validateNextHops([])).toEqual([]);
    expect(validateNextHops([row("wan-edge-1", "203.0.113.1")])).toEqual([]);
  });

  it("ignores a wholly blank row — an unused slot is not a mistake", () => {
    expect(validateNextHops([row("", ""), row("wan-edge-1", "203.0.113.1")])).toEqual([]);
  });

  it("names a row with an address but no device", () => {
    expect(validateNextHops([row("", "203.0.113.1")]).join(" ")).toMatch(/no device/);
  });

  it("names a row with a device but no ISP next-hop address", () => {
    expect(validateNextHops([row("wan-edge-1", "")]).join(" ")).toMatch(/no ISP next-hop address/);
  });

  it("finds duplicate keys and reports each key once", () => {
    const rows = [
      row("wan-edge-1", "203.0.113.1"),
      row("wan-edge-1", "198.51.100.1"),
      row("wan-edge-1", "192.0.2.1"),
    ];
    expect(duplicateNextHopKeys(rows)).toEqual(["wan-edge-1"]);
    const problems = validateNextHops(rows);
    expect(problems).toHaveLength(1);
    expect(problems[0]).toMatch(/both apply to wan-edge-1/);
  });

  it("does not call two different keys duplicates", () => {
    expect(duplicateNextHopKeys([row("wan-edge-1", "a"), row("wan-edge-1/Ethernet1", "b")])).toEqual([]);
  });

  it("caps the table so a paste cannot build a body the server refuses", () => {
    const rows = Array.from({ length: MAX_NEXT_HOPS + 1 }, (_, i) => row(`wan-edge-${i}`, "203.0.113.1"));
    expect(validateNextHops(rows).join(" ")).toMatch(new RegExp(`${MAX_NEXT_HOPS} or fewer`));
  });
});

// ── anchors ─────────────────────────────────────────────────────────────────

describe("anchors", () => {
  it("parses a comma-separated list", () => {
    expect(parseAnchors("1.1.1.1, 8.8.8.8")).toEqual(["1.1.1.1", "8.8.8.8"]);
  });

  it("parses a newline-separated list", () => {
    expect(parseAnchors("1.1.1.1\n8.8.8.8\n")).toEqual(["1.1.1.1", "8.8.8.8"]);
  });

  it("trims, drops empties and de-duplicates", () => {
    expect(parseAnchors(" 1.1.1.1 ,, ,\n 1.1.1.1 , dns.example.net ")).toEqual(["1.1.1.1", "dns.example.net"]);
  });

  it("round-trips through the formatted form", () => {
    expect(parseAnchors(formatAnchors(["1.1.1.1", "8.8.8.8"]))).toEqual(["1.1.1.1", "8.8.8.8"]);
    expect(formatAnchors(undefined)).toBe("");
  });

  it("accepts addresses and host names, rejects anything with spaces or punctuation", () => {
    expect(isPlausibleHost("1.1.1.1")).toBe(true);
    expect(isPlausibleHost("2606:4700:4700::1111")).toBe(true);
    expect(isPlausibleHost("dns.example.net")).toBe(true);
    expect(isPlausibleHost("")).toBe(false);
    expect(isPlausibleHost("...")).toBe(false);
    expect(isPlausibleHost("http://1.1.1.1")).toBe(false);
    expect(isPlausibleHost("a".repeat(254))).toBe(false);
  });

  it("refuses an empty anchor list and names the baseline instead", () => {
    const problems = validateAnchors("   ");
    expect(problems).toHaveLength(1);
    expect(problems[0]).toContain("1.1.1.1");
    expect(problems[0]).toContain("8.8.8.8");
  });

  it("names the entries that are not host names", () => {
    expect(validateAnchors("1.1.1.1, http://x").join(" ")).toMatch(/http:\/\/x/);
  });

  it("caps the anchor list", () => {
    const many = Array.from({ length: MAX_ANCHORS + 1 }, (_, i) => `10.0.0.${i}`).join(",");
    expect(validateAnchors(many).join(" ")).toMatch(new RegExp(`${MAX_ANCHORS} or fewer`));
  });
});

// ── the WAN device name pattern ─────────────────────────────────────────────

describe("pattern pre-flight", () => {
  it("accepts the measurement baseline", () => {
    expect(validatePattern(DEFAULT_WAN_PATTERN)).toEqual([]);
  });

  it("refuses an empty pattern", () => {
    expect(validatePattern("  ").join(" ")).toMatch(/which devices are WAN devices/);
  });

  it("catches an obviously unusable pattern before a round trip", () => {
    expect(validatePattern("wan(").length).toBe(1);
  });
});

// ── the form and the PUT body ───────────────────────────────────────────────

describe("formFromPolicy", () => {
  it("gives an unconfigured tenant the measurement baseline", () => {
    expect(formFromPolicy(null)).toEqual({
      pattern: DEFAULT_WAN_PATTERN,
      anchorsText: "1.1.1.1, 8.8.8.8",
      includeConnected: true,
      nextHops: [],
    });
  });

  it("reads a stored policy, including include_connected turned off", () => {
    const stored: WanMeasurementPolicy = {
      tenant_id: "acme",
      wan_pattern: "edge|dia",
      anchors: ["9.9.9.9"],
      next_hops: { "wan-edge-1": "203.0.113.1" },
      include_connected: false,
      updated_by: "rao",
      updated_at: "2026-09-04T10:00:00Z",
    };
    const f = formFromPolicy(stored);
    expect(f.pattern).toBe("edge|dia");
    expect(f.anchorsText).toBe("9.9.9.9");
    expect(f.includeConnected).toBe(false);
    expect(f.nextHops).toEqual([expect.objectContaining({ key: "wan-edge-1", target: "203.0.113.1" })]);
  });

  it("falls back to the baseline for an empty pattern or an empty anchor list", () => {
    const f = formFromPolicy({ wan_pattern: "  ", anchors: [] });
    expect(f.pattern).toBe(DEFAULT_WAN_PATTERN);
    expect(f.anchorsText).toBe("1.1.1.1, 8.8.8.8");
  });
});

describe("policyPatch — the exact PUT body", () => {
  it("sends the four intent fields and nothing else", () => {
    const body = policyPatch(form({
      pattern: " edge|dia ",
      anchorsText: "9.9.9.9\n1.1.1.1",
      includeConnected: false,
      nextHops: [row("wan-edge-1/Ethernet1", "203.0.113.1")],
    }));
    expect(Object.keys(body).sort()).toEqual(["anchors", "include_connected", "next_hops", "wan_pattern"]);
    expect(body).toEqual({
      wan_pattern: "edge|dia",
      anchors: ["9.9.9.9", "1.1.1.1"],
      next_hops: { "wan-edge-1/Ethernet1": "203.0.113.1" },
      include_connected: false,
    });
  });

  it("never carries tenant, author or time — the server stamps those from the token", () => {
    const body = policyPatch(formFromPolicy({
      tenant_id: "acme", updated_by: "rao", updated_at: "2026-09-04T10:00:00Z",
      wan_pattern: "edge", anchors: ["1.1.1.1"], include_connected: true,
    }));
    expect(body).not.toHaveProperty("tenant_id");
    expect(body).not.toHaveProperty("updated_by");
    expect(body).not.toHaveProperty("updated_at");
  });

  it("sends an empty override map when the last override is removed, so it clears", () => {
    expect(policyPatch(form({ nextHops: [] })).next_hops).toEqual({});
  });
});

describe("validateForm", () => {
  it("passes the baseline form", () => {
    expect(validateForm(form())).toEqual([]);
  });

  it("collects every problem, in field order", () => {
    const problems = validateForm(form({
      pattern: "",
      anchorsText: "",
      nextHops: [row("wan-edge-1", ""), row("wan-edge-1", "203.0.113.1")],
    }));
    expect(problems.length).toBeGreaterThanOrEqual(3);
    expect(problems[0]).toMatch(/which devices are WAN devices/);
    expect(problems[1]).toMatch(/reachability anchor/);
    expect(problems.slice(2).join(" ")).toMatch(/wan-edge-1/);
  });
});

describe("isDirty", () => {
  const stored: WanMeasurementPolicy = {
    tenant_id: "acme",
    wan_pattern: "edge|dia",
    anchors: ["9.9.9.9"],
    next_hops: { "wan-edge-1": "203.0.113.1" },
    include_connected: true,
    updated_by: "rao",
  };

  it("is clean for the form as it was read", () => {
    expect(isDirty(formFromPolicy(stored), stored)).toBe(false);
  });

  it("ignores whitespace and override row order — those are not changes", () => {
    const f = formFromPolicy(stored);
    expect(isDirty({ ...f, pattern: "  edge|dia  ", anchorsText: " 9.9.9.9 " }, stored)).toBe(false);
    expect(isDirty({
      ...f,
      nextHops: [row("wan-edge-2", "198.51.100.1"), row("wan-edge-1", "203.0.113.1")],
    }, { ...stored, next_hops: { "wan-edge-1": "203.0.113.1", "wan-edge-2": "198.51.100.1" } })).toBe(false);
  });

  it("sees each field change on its own", () => {
    const f = formFromPolicy(stored);
    expect(isDirty({ ...f, pattern: "edge" }, stored)).toBe(true);
    expect(isDirty({ ...f, anchorsText: "1.1.1.1" }, stored)).toBe(true);
    expect(isDirty({ ...f, includeConnected: false }, stored)).toBe(true);
    expect(isDirty({ ...f, nextHops: [] }, stored)).toBe(true);
    expect(isDirty({ ...f, nextHops: [row("wan-edge-1", "198.51.100.1")] }, stored)).toBe(true);
  });

  it("compares an unconfigured tenant against the baseline, not against nothing", () => {
    expect(isDirty(formFromPolicy(null), null)).toBe(false);
    expect(isDirty(form({ includeConnected: false }), null)).toBe(true);
  });

  it("keeps a rejected pattern dirty, so a failed save leaves the edit in place", () => {
    // The server refuses `wan(` with its own sentence; the form must still be
    // holding the operator's text afterwards, which is what "dirty" encodes.
    const bad = form({ pattern: "wan(" });
    expect(isDirty(bad, null)).toBe(true);
    expect(policyPatch(bad).wan_pattern).toBe("wan(");
    expect(validatePattern("wan(")).toHaveLength(1);
  });
});

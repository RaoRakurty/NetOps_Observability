// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// prefix.test.ts — the input boundary of the BGP page.
//
// Owner, 2026-09-08: `1.1.1.1/24` must be checked as `1.1.1.0/24`. These cases
// are the contract for that, and the PARITY table below is deliberately the
// same table the server carries (src/backend/bgp_ops_test.go
// TestBGPNormalizeResource + internal/bgpwatch/helpers_test.go): the client must
// never tell an operator it checked a string the API would have canonicalised
// differently.

import { describe, it, expect } from "vitest";
import { normalizeResource, parseIPv4, parseIPv6, maskBytes } from "./prefix";

describe("normalizeResource — IPv4", () => {
  it("checks a host address carrying a mask as its NETWORK address", () => {
    const n = normalizeResource("1.1.1.1/24");
    expect(n.kind).toBe("prefix");
    expect(n.resource).toBe("1.1.1.0/24");
    expect(n.changed).toBe(true);   // the page prints "Checked as 1.1.1.0/24"
    expect(n.error).toBe("");
  });

  it("leaves an already-canonical prefix alone, and says nothing changed", () => {
    const n = normalizeResource("203.0.113.0/24");
    expect(n.resource).toBe("203.0.113.0/24");
    expect(n.changed).toBe(false);
  });

  it("masks on any bit boundary, not just octets", () => {
    expect(normalizeResource("193.0.7.7/21").resource).toBe("193.0.0.0/21");
    expect(normalizeResource("10.1.2.3/9").resource).toBe("10.0.0.0/9");
    expect(normalizeResource("10.1.2.3/31").resource).toBe("10.1.2.2/31");
    expect(normalizeResource("10.1.2.3/0").resource).toBe("0.0.0.0/0");
    expect(normalizeResource("10.1.2.3/32").resource).toBe("10.1.2.3/32");
  });

  it("reads a bare address as the host prefix it is", () => {
    const n = normalizeResource("203.0.113.9");
    expect(n.resource).toBe("203.0.113.9/32");
    expect(n.changed).toBe(true);
  });

  it("trims what was typed before reading it", () => {
    expect(normalizeResource("  193.0.0.0/21  ").resource).toBe("193.0.0.0/21");
  });
});

describe("normalizeResource — IPv6", () => {
  it("checks a host address carrying a mask as its network address", () => {
    const n = normalizeResource("2001:db8::1/32");
    expect(n.resource).toBe("2001:db8::/32");
    expect(n.changed).toBe(true);
  });

  it("keeps the canonical text form Go's netip prints", () => {
    expect(normalizeResource("2001:0DB8:0000:0000:0000:0000:0000:0001/128").resource)
      .toBe("2001:db8::1/128");
    expect(normalizeResource("2001:db8:0:0:1:0:0:1/128").resource).toBe("2001:db8::1:0:0:1/128");
    expect(normalizeResource("::").resource).toBe("::/128");
    expect(normalizeResource("::1").resource).toBe("::1/128");
    expect(normalizeResource("2001:db8::1/64").resource).toBe("2001:db8::/64");
    expect(normalizeResource("fe80::1234:5678/10").resource).toBe("fe80::/10");
    // A single zero group is NOT elided (netip does not either) — "::" that
    // saves no characters only makes an address harder to compare by eye.
    expect(normalizeResource("1:2:3:4:5:6:7::").resource).toBe("1:2:3:4:5:6:7:0/128");
  });

  it("reads a bare address as its /128, and an embedded IPv4 the way netip does", () => {
    expect(normalizeResource("2001:db8::1").resource).toBe("2001:db8::1/128");
    expect(normalizeResource("::ffff:1.1.1.1/120").resource).toBe("::ffff:1.1.1.0/120");
    expect(normalizeResource("64:ff9b::1.1.1.1/126").resource).toBe("64:ff9b::101:100/126");
  });
});

describe("normalizeResource — AS numbers", () => {
  it("canonicalises the AS spelling", () => {
    expect(normalizeResource("AS64500")).toMatchObject({ kind: "asn", resource: "AS64500", changed: false });
    expect(normalizeResource("as64500")).toMatchObject({ kind: "asn", resource: "AS64500", changed: true });
    expect(normalizeResource(" As64500 ")).toMatchObject({ kind: "asn", resource: "AS64500" });
  });

  it("refuses the reserved AS0 and anything past 32 bits", () => {
    expect(normalizeResource("AS0").kind).toBe("invalid");
    expect(normalizeResource("AS4294967296").kind).toBe("invalid");
    expect(normalizeResource("AS4294967295").resource).toBe("AS4294967295");
  });
});

describe("normalizeResource — a refusal names the entry", () => {
  const bad = [
    "3333",                       // a bare number is ambiguous — AS or address?
    "193.0.0.0/33",
    "2001:db8::/129",
    "1.1.1.01/24",                // a leading zero changes which address is meant
    "1.1.1.1/024",
    "1.1.1",
    "1.1.1.256",
    "2001:db8:::1/64",
    "1:2:3:4:5:6:7:8::",          // "::" standing for no group at all
    "fe80::1%eth0",               // a zone id is not routable address space
    "evil.example/../../x",
    "'; DROP TABLE bgp_watchlist;--",
  ];
  it.each(bad)("refuses %s and says which entry it refused", (entry) => {
    const n = normalizeResource(entry);
    expect(n.kind).toBe("invalid");
    expect(n.resource).toBe("");
    expect(n.error).toContain(entry.trim().slice(0, 20));
    expect(n.error).toMatch(/not a prefix or an AS/);
  });

  it("asks for an entry rather than naming an empty one", () => {
    const n = normalizeResource("   ");
    expect(n.kind).toBe("invalid");
    expect(n.error).toBe("Type a prefix or an AS number.");
  });

  it("bounds the echo of a very long entry", () => {
    const n = normalizeResource("x".repeat(500));
    expect(n.kind).toBe("invalid");
    expect(n.error.length).toBeLessThan(90);
  });
});

// ── the primitives, so a masking bug is reported where it lives ──────────────

describe("address primitives", () => {
  it("parses and refuses IPv4 the way netip does", () => {
    expect(parseIPv4("1.2.3.4")).toEqual([1, 2, 3, 4]);
    expect(parseIPv4("0.0.0.0")).toEqual([0, 0, 0, 0]);
    expect(parseIPv4("255.255.255.255")).toEqual([255, 255, 255, 255]);
    expect(parseIPv4("1.2.3.04")).toBeNull();
    expect(parseIPv4("1.2.3")).toBeNull();
    expect(parseIPv4("1.2.3.4.5")).toBeNull();
  });

  it("parses IPv6 elision, embedded IPv4, and refuses the ambiguous forms", () => {
    expect(parseIPv6("::")).toEqual(new Array(16).fill(0));
    expect(parseIPv6("::1")?.slice(14)).toEqual([0, 1]);
    expect(parseIPv6("::ffff:1.1.1.1")?.slice(10)).toEqual([0xff, 0xff, 1, 1, 1, 1]);
    expect(parseIPv6("1:2:3:4:5:6:7:8")?.length).toBe(16);
    expect(parseIPv6("1:2:3:4:5:6:7:8:9")).toBeNull();
    expect(parseIPv6("1:2:3:4:5:6:7")).toBeNull();
    expect(parseIPv6("1.1.1.1")).toBeNull();
    expect(parseIPv6("::gggg")).toBeNull();
  });

  it("clears every bit past the prefix length", () => {
    expect(maskBytes([255, 255, 255, 255], 12)).toEqual([255, 240, 0, 0]);
    expect(maskBytes([255, 255, 255, 255], 0)).toEqual([0, 0, 0, 0]);
    expect(maskBytes([255, 255, 255, 255], 32)).toEqual([255, 255, 255, 255]);
  });
});

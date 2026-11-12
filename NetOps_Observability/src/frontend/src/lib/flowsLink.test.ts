// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

import { describe, it, expect } from "vitest";
import { parseDeepLink, tabFromHash, tabHash, flowsHref, hashQuery } from "./flowsLink";

describe("flowsLink — the Flows route and its deep link", () => {
  it("carries the tab in the third route segment", () => {
    expect(tabFromHash("#/explore/flows")).toBe("now");
    expect(tabFromHash("#/explore/flows/talking?device=10.0.0.1")).toBe("talking");
    expect(tabFromHash("#/explore/flows/capacity")).toBe("capacity");
    expect(tabFromHash("#/explore/flows/bogus")).toBe("now");
    expect(tabHash("talking")).toBe("#/explore/flows/talking");
    expect(tabHash("now", "?a=1")).toBe("#/explore/flows?a=1");
    expect(hashQuery("#/explore/flows?x=1&y=2")).toBe("?x=1&y=2");
    expect(hashQuery("#/explore/flows")).toBe("");
  });

  it("round-trips device, interface and window", () => {
    const from = Date.parse("2026-11-12T03:00:00Z");
    const to = Date.parse("2026-11-12T03:15:00Z");
    const h = flowsHref({ device: "10.1.0.1", ifIndex: "7", from, to });
    expect(h).toBe("#/explore/flows?device=10.1.0.1&if=7&from=2026-11-12T03%3A00%3A00.000Z&to=2026-11-12T03%3A15%3A00.000Z");
    expect(parseDeepLink(h)).toEqual({ device: "10.1.0.1", ifIndex: "7", from, to });
    expect(parseDeepLink(flowsHref({ device: "fd00::1" }, "talking"))).toEqual({ device: "fd00::1" });
  });

  it("accepts epoch seconds or milliseconds for from/to", () => {
    expect(parseDeepLink("#/explore/flows?from=1762916400")).toEqual({ from: 1762916400_000 });
    expect(parseDeepLink("#/explore/flows?from=1762916400000")).toEqual({ from: 1762916400_000 });
  });

  it("drops anything malformed instead of passing it to the API", () => {
    expect(parseDeepLink("#/explore/flows?device=10.0.0.1'--&if=7")).toEqual({});
    expect(parseDeepLink("#/explore/flows?device=<script>&if=7")).toEqual({});
    expect(parseDeepLink("#/explore/flows?device=10.0.0.1&if=-1")).toEqual({ device: "10.0.0.1" });
    expect(parseDeepLink("#/explore/flows?device=10.0.0.1&if=1e3")).toEqual({ device: "10.0.0.1" });
    // An interface without a device means nothing (one ifIndex on two devices is two ports).
    expect(parseDeepLink("#/explore/flows?if=7")).toEqual({});
    expect(parseDeepLink("#/explore/flows?from=yesterday")).toEqual({});
    // A "to" before "from" is dropped; the window then runs to now.
    const p = parseDeepLink("#/explore/flows?from=2026-11-12T03:00:00Z&to=2026-11-12T02:00:00Z");
    expect(p.to).toBeUndefined();
    expect(flowsHref({ device: "not an ip", ifIndex: "x" })).toBe("#/explore/flows");
  });
});

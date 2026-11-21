// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

import { describe, it, expect } from "vitest";
import {
  PATHS_TABS, SITE_STORAGE_KEY, loadSite, matchesSite, pathDataItems, saveSite, siteKey, siteOptions,
  tabFromHash, tabHash, type PathDataFacts,
} from "./pathsModel";

describe("tabs and the hash", () => {
  it("reads the tab from the third segment, Measured paths by default", () => {
    expect(tabFromHash("#/investigate/paths/tunnels")).toBe("tunnels");
    expect(tabFromHash("#/investigate/paths/wan-circuits?q=x")).toBe("wan-circuits");
    expect(tabFromHash("#/investigate/paths")).toBe("measured");
    expect(tabFromHash("#/investigate/paths/nonsense")).toBe("measured");
    expect(tabFromHash("")).toBe("measured");
  });

  it("round-trips every tab", () => {
    for (const t of PATHS_TABS) expect(tabFromHash(tabHash(t.id))).toBe(t.id);
  });
});

describe("site key — mirrors the backend's siteSlug", () => {
  it("makes a label and its slug compare equal", () => {
    expect(siteKey("DC East")).toBe("dc-east");
    expect(siteKey("dc-east")).toBe("dc-east");
    expect(siteKey("  Branch_50 / Floor.2  ")).toBe("branch-50-floor-2");
    expect(siteKey("Site 50 · from vManage")).toBe("site-50-from-vmanage");
  });

  it("drops what is not a letter or digit and trims dashes", () => {
    expect(siteKey("--HQ--")).toBe("hq");
    // "/" is a separator in siteSlug too.
    expect(siteKey("<b>HQ</b>")).toBe("bhq-b");
    expect(siteKey("")).toBe("");
    expect(siteKey(null)).toBe("");
  });
});

describe("site options", () => {
  it("one per site whatever the spelling, the readable one shown, sorted", () => {
    expect(siteOptions(["dc-east", "Branch 50", "DC East", "", null, "branch-50", "HQ"])).toEqual([
      { key: "branch-50", label: "Branch 50" },
      { key: "dc-east", label: "DC East" },
      { key: "hq", label: "HQ" },
    ]);
  });

  it("no rows, no sites", () => {
    expect(siteOptions([])).toEqual([]);
    expect(siteOptions(["", "   "])).toEqual([]);
  });
});

describe("matchesSite", () => {
  it("All sites keeps everything, including rows with no site", () => {
    expect(matchesSite("", undefined)).toBe(true);
    expect(matchesSite("", "DC East")).toBe(true);
  });

  it("a site keeps rows with any end there, by label or slug", () => {
    expect(matchesSite("dc-east", "DC East")).toBe(true);
    expect(matchesSite("dc-east", "Branch 50", "dc-east")).toBe(true);
    expect(matchesSite("dc-east", "Branch 50", "HQ")).toBe(false);
    expect(matchesSite("dc-east", undefined, null)).toBe(false);
  });
});

describe("remembered site", () => {
  const mem = () => {
    const m = new Map<string, string>();
    return {
      getItem: (k: string) => m.get(k) ?? null,
      setItem: (k: string, v: string) => { m.set(k, v); },
      removeItem: (k: string) => { m.delete(k); },
      m,
    };
  };

  it("saves, loads and forgets", () => {
    const s = mem();
    saveSite(s, "dc-east");
    expect(s.m.get(SITE_STORAGE_KEY)).toBe("dc-east");
    expect(loadSite(s)).toBe("dc-east");
    saveSite(s, "");
    expect(loadSite(s)).toBe("");
  });

  it("a storage that throws or is missing is not an error", () => {
    const bad = {
      getItem: () => { throw new Error("blocked"); },
      setItem: () => { throw new Error("full"); },
      removeItem: () => { throw new Error("blocked"); },
    };
    expect(loadSite(bad)).toBe("");
    expect(() => saveSite(bad, "hq")).not.toThrow();
    expect(loadSite(null)).toBe("");
    expect(() => saveSite(undefined, "hq")).not.toThrow();
  });

  it("a stored value is normalised, never trusted as-is", () => {
    const s = mem();
    s.m.set(SITE_STORAGE_KEY, "<script>DC East</script>");
    expect(loadSite(s)).toBe("scriptdc-east-script");
  });
});

describe("Path data drawer", () => {
  const facts = (over: Partial<PathDataFacts> = {}): PathDataFacts => ({
    pathDiscovery: true, activeProbe: true, tracing: 3, tunnels: 12, wanInterfaces: 4, wanMeasured: 2, ...over,
  });
  const byId = (f: PathDataFacts) => Object.fromEntries(pathDataItems(f).map((i) => [i.id, i]));

  it("lists the four sources in order", () => {
    expect(pathDataItems(facts()).map((i) => i.id)).toEqual(["discovery", "stamp", "tunnels", "wan"]);
  });

  it("says what is on, with the numbers", () => {
    const i = byId(facts());
    expect(i.discovery.state).toBe("on");
    expect(i.discovery.text).toContain("3 targets");
    expect(i.tunnels.text).toContain("12 tunnels");
    expect(i.tunnels.text).toContain("30–60 minutes");
    expect(i.wan.text).toBe("2 of 4 interfaces measured.");
  });

  it("says what is off and points at the console page that turns it on", () => {
    const i = byId(facts({ pathDiscovery: false, activeProbe: false, tunnels: 0, wanMeasured: 0 }));
    expect(i.discovery.state).toBe("off");
    expect(i.discovery.href).toBe("#/platform/features");
    expect(i.stamp.state).toBe("off");
    expect(i.tunnels.state).toBe("off");
    expect(i.tunnels.href).toBe("#/infrastructure/nms");
    expect(i.tunnels.where).toBe("Infrastructure › NMS Integrations");
    expect(i.wan.state).toBe("off");
  });

  it("a source that could not be read is unknown, never off", () => {
    const i = byId({ pathDiscovery: null, activeProbe: null, tracing: null, tunnels: null, wanInterfaces: null, wanMeasured: null });
    for (const id of ["discovery", "stamp", "tunnels", "wan"]) {
      expect(i[id].state).toBe("unknown");
      expect(i[id].text).toBe("Could not be read.");
    }
  });

  it("names no environment variable and no API path", () => {
    const all = [facts(), facts({ pathDiscovery: false, activeProbe: false, tunnels: 0, wanInterfaces: 0, wanMeasured: 0 })]
      .flatMap((f) => pathDataItems(f))
      .map((i) => `${i.title} ${i.text} ${i.where}`)
      .join(" ");
    expect(all).not.toMatch(/FEATURE_|PROBE_|\/api\/|\.env/);
  });
});

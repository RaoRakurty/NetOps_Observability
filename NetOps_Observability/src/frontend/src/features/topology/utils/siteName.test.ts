// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

import { describe, it, expect } from "vitest";
import { siteName, isDiscoveredSite, isDiscoveredGroup, siteProvenance } from "./siteName";

describe("site grouping labels", () => {
  it("reads a discovered site by its label, never its key", () => {
    const n = { site: "discovered:acme:sdwan:50", site_label: "Site 50 · from vManage", site_source: "discovered" };
    expect(siteName(n)).toBe("Site 50 · from vManage");
    expect(isDiscoveredSite(n)).toBe(true);
    expect(siteProvenance(n)).toMatch(/discovered/);
  });

  it("a declared or labelled site reads as itself", () => {
    expect(siteName({ site: "dc-east" })).toBe("dc-east");
    expect(siteName({ site: "nyc", site_label: "New York" })).toBe("New York");
    expect(siteProvenance({ site_source: "manual" })).toBe("placed by an operator");
    expect(siteProvenance({ site_source: "label" })).toMatch(/site label/);
    expect(siteName({})).toBe("");
  });

  it("marks only discovered SITE groups", () => {
    expect(isDiscoveredGroup({ group_type: "site", source: "discovered" })).toBe(true);
    expect(isDiscoveredGroup({ group_type: "site", source: "manual" })).toBe(false);
    expect(isDiscoveredGroup({ group_type: "site" })).toBe(false);
    expect(isDiscoveredGroup({ group_type: "vpc", source: "discovered" })).toBe(false);
  });
});

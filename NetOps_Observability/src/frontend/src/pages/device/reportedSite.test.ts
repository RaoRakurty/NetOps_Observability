// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix
import { describe, it, expect } from "vitest";
import { reportedSiteTitle } from "./reportedSite";

describe("reportedSiteTitle", () => {
  it("names who reported the site id", () => {
    expect(reportedSiteTitle("device")).toBe("Site ID reported by the device itself");
    expect(reportedSiteTitle(undefined)).toBe("Site ID reported by the device itself");
    expect(reportedSiteTitle("vmanage")).toBe("Site ID reported by vManage");
    expect(reportedSiteTitle("meraki")).toBe("Site ID reported by meraki");
  });
});

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

import { describe, expect, it } from "vitest";
import { instanceDisplay, isDefaultInstance, vrfTerm, vrfTermPlural } from "./vendorTerms";

describe("vrfTerm", () => {
  it("speaks each vendor's dialect", () => {
    expect(vrfTerm("cisco")).toBe("VRF");
    expect(vrfTerm("Juniper")).toBe("routing-instance");
    expect(vrfTerm("JunOS")).toBe("routing-instance");
    expect(vrfTerm("SR Linux")).toBe("VPRN");
    expect(vrfTerm("huawei")).toBe("VPN instance");
    expect(vrfTerm(undefined)).toBe("VRF");
  });
  it("pluralizes headers naturally", () => {
    expect(vrfTermPlural("cisco")).toBe("VRFs");
    expect(vrfTermPlural("juniper")).toBe("Routing instances");
    expect(vrfTermPlural("nokia")).toBe("VPRNs");
  });
});

describe("isDefaultInstance / instanceDisplay", () => {
  it("knows each vendor's name for the default table", () => {
    for (const [name, vendor] of [
      ["default", "arista"], ["default", "sonic"], ["default", "srlinux"], ["default", "cisco"],
      ["master", "juniper"], ["inet.0", "Junos"], ["Base", "nokia"], ["global", "cisco"],
    ]) {
      expect(isDefaultInstance(name, vendor), `${vendor}/${name}`).toBe(true);
    }
  });
  it("does not borrow another vendor's word", () => {
    expect(isDefaultInstance("master", "cisco")).toBe(false);
    expect(isDefaultInstance("Base", "arista")).toBe(false);
    expect(isDefaultInstance("CORP-WAN", "juniper")).toBe(false);
  });
  it("never assumes an unnamed instance is the default table", () => {
    expect(isDefaultInstance("", "arista")).toBe(false);
    expect(isDefaultInstance(undefined, "arista")).toBe(false);
  });
  it("shows the label with the device's own word as the tooltip", () => {
    expect(instanceDisplay("Base", "nokia")).toEqual({ text: "Global (default)", title: "The device's default routing table (“Base”)" });
    expect(instanceDisplay("CUST-A", "nokia")).toEqual({ text: "CUST-A" });
  });
});

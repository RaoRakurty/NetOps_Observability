// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

import { describe, expect, it } from "vitest";
import { vrfTerm, vrfTermPlural } from "./vendorTerms";

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

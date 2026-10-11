// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

import { describe, it, expect, vi } from "vitest";

vi.mock("../components/EChart", () => ({ default: () => null }));

import { servicePortLabel } from "./Flows";

describe("servicePortLabel — the likely-service key read back for humans", () => {
  it("names a well-known port and its protocol", () => {
    expect(servicePortLabel("6/443")).toBe("443/tcp · HTTPS");
    expect(servicePortLabel("17/161")).toBe("161/udp · SNMP");
    expect(servicePortLabel("17/3784")).toBe("3784/udp · BFD");
  });
  it("shows an unnamed port without inventing a name", () => {
    expect(servicePortLabel("17/40000")).toBe("40000/udp");
  });
  it("leaves any other shape verbatim", () => {
    expect(servicePortLabel("<b>x</b>")).toBe("<b>x</b>");
    expect(servicePortLabel("6/443/1")).toBe("6/443/1");
  });
});

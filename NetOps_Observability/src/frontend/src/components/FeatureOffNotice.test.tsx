// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix
import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import FeatureOffNotice, { featureOffTip } from "./FeatureOffNotice";

describe("FeatureOffNotice", () => {
  it("names the switch, what it gives, and where it is turned on", () => {
    render(<FeatureOffNotice feature="Packet capture" purpose="Capture packets on request." />);
    const box = screen.getByRole("status");
    expect(screen.getByText("Packet capture is off.")).toBeTruthy();
    expect(box.textContent).toContain("Capture packets on request.");
    expect(box.textContent).toContain("A platform administrator can turn it on in Platform › Features.");
  });

  it("never names an environment variable", () => {
    render(<FeatureOffNotice feature="Configuration backup" purpose="Back up configurations." />);
    expect(screen.getByRole("status").textContent).not.toMatch(/FEATURE_|ENABLE_/);
    expect(featureOffTip("SSH to devices")).not.toMatch(/FEATURE_|ENABLE_/);
  });
});

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// badges.test.tsx — the evidence-category ledger badge renders every category
// with a human label (#81 P3F+1 Phase 4). The categories are the anti-black-box
// vocabulary: grounded / contradicting / discriminating / missing / recovery.

import { describe, it, expect, afterEach } from "vitest";
import { render, screen, cleanup } from "@testing-library/react";
import { EvidenceCategoryBadge, ProviderBadge } from "./badges";
import type { EvidenceCategory } from "./types";

afterEach(cleanup);

const CASES: Record<EvidenceCategory, string> = {
  grounded: "Grounded",
  contradicting: "Contradicting",
  discriminating: "Discriminating",
  missing: "Missing",
  recovery: "Recovery",
};

describe("EvidenceCategoryBadge", () => {
  it("renders a human label for each evidence category", () => {
    for (const [cat, label] of Object.entries(CASES) as [EvidenceCategory, string][]) {
      render(<EvidenceCategoryBadge category={cat} />);
      expect(screen.getByText(label)).toBeTruthy();
      cleanup();
    }
  });
});

// Licence audit D5 (2026-09-04): the origin badge used to render the providers'
// trademark logos (brand path data + brand colours, inlined into the SPA). It
// now draws the ORIGINAL Correlix cloud glyph. This is the guard that the marks
// cannot come back silently.
describe("ProviderBadge cloud mark", () => {
  const BRAND_COLOURS = ["#ff9900", "#0078d4", "#4285f4", "#ea4335", "#34a853", "#fbbc05"];

  it("draws an inline cloud glyph with no provider brand colour or logo asset", () => {
    for (const provider of ["aws", "azure", "gcp", "oracle"]) {
      const { container } = render(<ProviderBadge provider={provider} />);
      const html = container.innerHTML.toLowerCase();
      expect(container.querySelector(".ao-prov-mark svg"), provider).toBeTruthy();
      expect(container.querySelector("img"), provider).toBeNull();
      for (const hex of BRAND_COLOURS) {
        expect(html, `${provider} leaked ${hex}`).not.toContain(hex);
      }
      for (const asset of ["assets/cloud/", "aws.svg", "azure.svg", "gcp.svg"]) {
        expect(html, `${provider} leaked ${asset}`).not.toContain(asset);
      }
      expect(html).not.toContain("lineargradient");
      cleanup();
    }
  });

  it("keeps the mark decorative — the provider name is said ONCE, by the label", () => {
    const { container } = render(<ProviderBadge provider="aws" />);
    // the glyph carries no letter tag here, so "AWS" appears exactly once
    expect(screen.getAllByText("AWS")).toHaveLength(1);
    expect(container.querySelector(".ao-prov-mark svg text")).toBeNull();
    expect(container.querySelector(".ao-prov-mark")!.getAttribute("aria-hidden")).toBe("true");
  });
});

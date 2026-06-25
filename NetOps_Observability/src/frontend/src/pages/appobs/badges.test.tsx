// badges.test.tsx — the evidence-category ledger badge renders every category
// with a human label (#81 P3F+1 Phase 4). The categories are the anti-black-box
// vocabulary: supporting / contradicting / discriminating / missing / recovery.

import { describe, it, expect, afterEach } from "vitest";
import { render, screen, cleanup } from "@testing-library/react";
import { EvidenceCategoryBadge } from "./badges";
import type { EvidenceCategory } from "./types";

afterEach(cleanup);

const CASES: Record<EvidenceCategory, string> = {
  supporting: "Supporting",
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

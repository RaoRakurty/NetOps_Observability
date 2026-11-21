// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

import { describe, it, expect } from "vitest";
import { troubleshootingCaseHref } from "./caseLink";
import { parseInvestigationHash } from "../pages/troubleshoot/investigationModel";

describe("troubleshootingCaseHref", () => {
  it("round-trips through the Troubleshooting page's own parser", () => {
    const id = "3f2b8c1e-9a4d-4c55-8e21-7d0a6b1c2f90";
    const href = troubleshootingCaseHref(id);
    expect(href).toBe(`#/investigate/troubleshooting?case=${id}`);
    expect(parseInvestigationHash(href).caseId).toBe(id);
  });

  it("refuses an id the page would ignore, rather than linking to nothing", () => {
    for (const bad of ["", undefined, null, "a b", "<x>", "x".repeat(65), "id?case=other"]) {
      expect(troubleshootingCaseHref(bad as string)).toBe("");
    }
  });
});

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

import { describe, expect, it } from "vitest";
import { mergeCorrPages } from "./Correlations";
import type { CorrObject } from "../services/api";

const o = (id: string): CorrObject => ({ correlation_id: id } as CorrObject);

describe("mergeCorrPages", () => {
  it("appends loaded pages after the base page", () => {
    const out = mergeCorrPages([o("a"), o("b")], [o("c"), o("d")]);
    expect(out.map((x) => x.correlation_id)).toEqual(["a", "b", "c", "d"]);
  });

  it("dedupes rows the refreshed base page re-includes", () => {
    // Auto-refresh can pull a previously-loaded row into page 1 — it must not
    // render twice (DataTable keys on correlation_id).
    const out = mergeCorrPages([o("a"), o("c")], [o("c"), o("d")]);
    expect(out.map((x) => x.correlation_id)).toEqual(["a", "c", "d"]);
  });

  it("handles empty pages", () => {
    expect(mergeCorrPages([], [])).toEqual([]);
    expect(mergeCorrPages([o("a")], []).map((x) => x.correlation_id)).toEqual(["a"]);
    expect(mergeCorrPages([], [o("b")]).map((x) => x.correlation_id)).toEqual(["b"]);
  });
});

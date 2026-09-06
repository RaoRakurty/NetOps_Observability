// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

import { describe, expect, it } from "vitest";
import { fromLegacy, mergeHits, groupHits, OMNI_KIND_ORDER, OmniHit } from "./omniSearch";
import { GlobalResult, SearchHit } from "../services/api";

// Pure grouping/merge logic behind the topbar box AND the ⌘K palette — one
// client, one truth (Wave 6 #20).

const hit = (kind: SearchHit["kind"], id: string, label = id): SearchHit => ({
  kind, id, label, href: `x/${id}`,
});

describe("fromLegacy", () => {
  it("keeps only alert/saved kinds and maps field names", () => {
    const legacy: GlobalResult[] = [
      { kind: "device", id: "d1", title: "dev", sub: "", route: "infrastructure/devices" },
      { kind: "alert", id: "a1", title: "CPU high", sub: "critical", route: "monitoring/triggered" },
      { kind: "saved", id: "s1", title: "My board", sub: "dashboard", route: "overview/dashboards" },
      { kind: "logs", id: "", title: "Search logs", sub: "OpenSearch", route: "logs/logs" },
    ];
    const out = fromLegacy(legacy);
    expect(out.map((h) => h.kind)).toEqual(["alert", "saved"]);
    expect(out[0]).toEqual({ kind: "alert", id: "a1", label: "CPU high", sublabel: "critical", href: "monitoring/triggered" });
  });

  it("drops empty sublabels", () => {
    const out = fromLegacy([{ kind: "alert", id: "a", title: "t", sub: "", route: "r" }]);
    expect(out[0].sublabel).toBeUndefined();
  });
});

describe("mergeHits", () => {
  it("preserves the backend's unified ranking verbatim, legacy after", () => {
    const unified = [hit("resource", "r1"), hit("device", "d1"), hit("case", "c1")];
    const legacy: GlobalResult[] = [{ kind: "alert", id: "a1", title: "alert", sub: "", route: "r" }];
    const out = mergeHits(unified, legacy);
    expect(out.map((h) => h.id)).toEqual(["r1", "d1", "c1", "a1"]);
  });
});

describe("groupHits", () => {
  it("groups by kind in canonical order, preserving in-group order", () => {
    const hits: OmniHit[] = [
      hit("case", "c1"),
      hit("device", "d2"),
      hit("resource", "r1"),
      hit("device", "d1"),
      { kind: "alert", id: "a1", label: "a1", href: "x/a1" },
    ];
    const groups = groupHits(hits);
    expect(groups.map((g) => g.kind)).toEqual(["device", "resource", "case", "alert"]);
    // in-group order preserved (backend ranking), NOT re-sorted
    expect(groups[0].hits.map((h) => h.id)).toEqual(["d2", "d1"]);
  });

  it("omits empty groups and drops unknown kinds instead of guessing", () => {
    const groups = groupHits([
      hit("app", "checkout"),
      { kind: "mystery" as OmniHit["kind"], id: "m", label: "m", href: "x" },
    ]);
    expect(groups).toHaveLength(1);
    expect(groups[0].kind).toBe("app");
    expect(groups[0].label).toBe("Services");
  });

  it("covers every kind in the canonical order exactly once", () => {
    expect(new Set(OMNI_KIND_ORDER).size).toBe(OMNI_KIND_ORDER.length);
    const groups = groupHits(OMNI_KIND_ORDER.map((k) => ({ kind: k, id: k, label: k, href: k })));
    expect(groups.map((g) => g.kind)).toEqual([...OMNI_KIND_ORDER]);
  });
});

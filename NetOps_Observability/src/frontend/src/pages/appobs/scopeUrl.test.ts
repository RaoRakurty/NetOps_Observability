// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// scopeUrl.test.ts — the scope bar's URL state (Wave 2 #5).
//
// Acceptance: a scope round-trips through the hash losslessly; links/refresh
// preserve it; it coexists with the drawer's ?inv= param; junk degrades to the
// default rather than claiming a range the reads won't honor.

import { describe, it, expect } from "vitest";
import {
  scopeFromHash, hashWithScope, emptyScope, isScopeActive, scopeKey,
} from "./scopeUrl";
import { hashWithInv, invFromHash } from "./investigationUrl";
import { CLOUD_WINDOW_MINUTES, CLOUD_WINDOW_MAX_MINUTES } from "./range";

const PATH = "#/monitoring/appobs";

describe("scopeFromHash", () => {
  it("reads an empty scope (all defaults) from a bare hash", () => {
    const s = scopeFromHash(PATH);
    expect(s).toEqual(emptyScope());
    expect(isScopeActive(s)).toBe(false);
    expect(s.rangeMinutes).toBe(CLOUD_WINDOW_MINUTES);
  });

  it("parses multi-value dims and the range label", () => {
    const s = scopeFromHash(`${PATH}?provider=aws,azure&account=111&region=us-east-1,eastus&env=prod&range=7d`);
    expect(s.providers).toEqual(["aws", "azure"]);
    expect(s.accounts).toEqual(["111"]);
    expect(s.regions).toEqual(["us-east-1", "eastus"]);
    expect(s.envs).toEqual(["prod"]);
    expect(s.rangeMinutes).toBe(CLOUD_WINDOW_MAX_MINUTES);
  });

  it("degrades junk safely: unknown range → default, empties dropped, dupes deduped", () => {
    const s = scopeFromHash(`${PATH}?range=99y&provider=aws,,aws, `);
    expect(s.rangeMinutes).toBe(CLOUD_WINDOW_MINUTES); // never claim a range the read won't honor
    expect(s.providers).toEqual(["aws"]);
  });
});

describe("hashWithScope round-trip", () => {
  it("writes and reads back the same scope", () => {
    const s = { providers: ["gcp"], accounts: ["proj-x"], regions: [], envs: ["dev"], rangeMinutes: 60 };
    const h = hashWithScope(PATH, s);
    expect(scopeFromHash(h)).toEqual(s);
  });

  it("omits defaults so a clean scope is a clean URL", () => {
    expect(hashWithScope(`${PATH}?provider=aws&range=7d`, emptyScope())).toBe(PATH);
  });

  it("preserves the investigation drawer's inv param (and vice versa)", () => {
    const withInv = hashWithInv(PATH, "P-027379");
    const both = hashWithScope(withInv, { ...emptyScope(), providers: ["aws"] });
    expect(invFromHash(both)).toBe("P-027379");
    expect(scopeFromHash(both).providers).toEqual(["aws"]);
    // and the drawer codec leaves the scope alone too
    const rewritten = hashWithInv(both, "P-000001");
    expect(scopeFromHash(rewritten).providers).toEqual(["aws"]);
  });
});

describe("scopeKey", () => {
  it("is order-insensitive within a dimension (stable cache/effect key)", () => {
    const a = { ...emptyScope(), providers: ["aws", "azure"] };
    const b = { ...emptyScope(), providers: ["azure", "aws"] };
    expect(scopeKey(a)).toBe(scopeKey(b));
  });
  it("changes when the range changes", () => {
    expect(scopeKey(emptyScope())).not.toBe(scopeKey({ ...emptyScope(), rangeMinutes: 60 }));
  });
});

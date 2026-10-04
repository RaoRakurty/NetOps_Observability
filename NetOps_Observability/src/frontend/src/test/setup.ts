// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

import "@testing-library/jest-dom";

// happy-dom implements no modal dialogs: window.confirm/alert/prompt are
// undefined. Vitest 4's vi.spyOn refuses to spy on a missing property
// ("can only spy on a function"), so give the three browser globals a body.
// Each THROWS when called un-stubbed — the same fail-loud outcome as calling
// the old undefined global — so a test that pops a dialog it did not expect
// still fails; tests that mean to answer one keep doing
// vi.spyOn(window, "confirm").mockReturnValue(...).
for (const name of ["confirm", "alert", "prompt"] as const) {
  if (typeof window[name] !== "function") {
    Object.defineProperty(window, name, {
      configurable: true,
      writable: true,
      value: () => {
        throw new Error(`window.${name}() called in a test without a vi.spyOn stub`);
      },
    });
  }
}

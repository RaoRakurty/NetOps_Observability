// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

import "@testing-library/jest-dom";
import { afterEach } from "vitest";

// No test reaches the network (tracker 426). happy-dom's fetch is a REAL client:
// an unmocked request goes to http://localhost:3000, and if the test ends while
// it is in flight, the environment's teardown aborts it — vitest reports that as
// an unhandled AbortError and fails the run with every test green, naming no
// file (seen on main aa69b4a6 and on #260; the culprit was a device-page test
// whose new Iris entry read /api/features). So the default fetch answers at once
// with a rejection — nothing is ever left pending — and the test that sent it
// fails here, by name, with the URL. A test that means to exercise fetch stubs
// it as before (vi.stubGlobal / vi.spyOn), which replaces this guard.
const unmockedFetches: string[] = [];
globalThis.fetch = ((input: RequestInfo | URL) => {
  const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
  unmockedFetches.push(url);
  return Promise.reject(new TypeError(`network access in a unit test: ${url} was not mocked`));
}) as typeof fetch;
afterEach(() => {
  if (unmockedFetches.length === 0) return;
  const urls = unmockedFetches.splice(0).join(", ");
  throw new Error(`this test sent a real network request (${urls}); mock the api call or stub fetch`);
});

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

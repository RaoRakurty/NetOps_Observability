// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { printHtmlDocument } from "./printHtml";

// printHtmlDocument is the Export-PDF path on every install without the PDF
// sidecar (all customer bundles). It must open ONE print dialog on the given
// document, never a new tab, and the frame must not be able to run script.
describe("printHtmlDocument", () => {
  beforeEach(() => { vi.useFakeTimers(); });
  afterEach(() => {
    vi.useRealTimers();
    vi.restoreAllMocks();
    document.body.innerHTML = "";
  });

  const frame = (): HTMLIFrameElement => {
    const f = document.querySelector("iframe");
    if (!f) throw new Error("no iframe");
    return f;
  };

  it("writes the document into an off-screen sandboxed frame without opening a tab", () => {
    const open = vi.spyOn(window, "open");
    expect(printHtmlDocument("<!doctype html><title>Report P-1</title><p>body</p>")).toBe(true);
    const f = frame();
    expect(open).not.toHaveBeenCalled();
    expect(f.contentDocument?.title).toBe("Report P-1");
    expect(f.contentDocument?.body.textContent).toContain("body");
    // No allow-scripts: nothing inside the report may run with the app origin.
    const sandbox = (f.getAttribute("sandbox") || "").split(/\s+/);
    expect(sandbox).toEqual(expect.arrayContaining(["allow-same-origin", "allow-modals"]));
    expect(sandbox).not.toContain("allow-scripts");
    expect(f.getAttribute("aria-hidden")).toBe("true");
    // Real size, off-screen: a 0×0 frame clips the printed page.
    expect(f.style.width).toBe("820px");
    expect(f.style.left).toBe("-10000px");
  });

  it("prints exactly once even when load and the fallback timer both fire", () => {
    printHtmlDocument("<p>x</p>");
    const f = frame();
    const print = vi.fn();
    Object.defineProperty(f.contentWindow as Window, "print", { value: print, configurable: true });
    f.dispatchEvent(new Event("load"));
    vi.advanceTimersByTime(1_000);
    f.dispatchEvent(new Event("load"));
    vi.advanceTimersByTime(1_000);
    expect(print).toHaveBeenCalledTimes(1);
  });

  it("survives a browser that refuses print() and still removes the frame", () => {
    printHtmlDocument("<p>x</p>");
    const f = frame();
    Object.defineProperty(f.contentWindow as Window, "print", {
      value: () => { throw new Error("blocked"); }, configurable: true,
    });
    expect(() => vi.advanceTimersByTime(1_000)).not.toThrow();
    vi.advanceTimersByTime(60_000);
    expect(document.querySelector("iframe")).toBeNull();
  });
});

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, act, cleanup } from "@testing-library/react";
import { useRefreshTick } from "./refreshTick";

function setVisibility(state: "visible" | "hidden") {
  Object.defineProperty(document, "visibilityState", { configurable: true, get: () => state });
  document.dispatchEvent(new Event("visibilitychange"));
}

function Probe({ ms = 1000, enabled = true }: { ms?: number; enabled?: boolean }) {
  const t = useRefreshTick(ms, enabled);
  return <span data-testid="tick">{t}</span>;
}
const tick = () => Number(screen.getByTestId("tick").textContent);

beforeEach(() => {
  vi.useFakeTimers();
  setVisibility("visible");
});
afterEach(() => {
  cleanup();
  vi.useRealTimers();
  setVisibility("visible");
});

describe("useRefreshTick — one page clock that stops when nobody is looking", () => {
  it("ticks on the interval while the document is visible", () => {
    render(<Probe />);
    expect(tick()).toBe(0);
    act(() => { vi.advanceTimersByTime(3000); });
    expect(tick()).toBe(3);
  });

  it("does not tick while hidden, and ticks once on return", () => {
    render(<Probe />);
    act(() => { vi.advanceTimersByTime(1000); });
    expect(tick()).toBe(1);
    act(() => { setVisibility("hidden"); });
    act(() => { vi.advanceTimersByTime(10_000); });
    expect(tick()).toBe(1); // nothing while hidden
    act(() => { setVisibility("visible"); });
    expect(tick()).toBe(2); // one catch-up tick on return
    act(() => { vi.advanceTimersByTime(1000); });
    expect(tick()).toBe(3); // and the clock runs again
  });

  it("does not start while the page is hidden at mount", () => {
    setVisibility("hidden");
    render(<Probe />);
    act(() => { vi.advanceTimersByTime(5000); });
    expect(tick()).toBe(0);
  });

  it("disabled means no clock at all", () => {
    render(<Probe enabled={false} />);
    act(() => { vi.advanceTimersByTime(5000); });
    expect(tick()).toBe(0);
  });

  it("stops its timer on unmount", () => {
    const { unmount } = render(<Probe />);
    unmount();
    expect(vi.getTimerCount()).toBe(0);
  });
});

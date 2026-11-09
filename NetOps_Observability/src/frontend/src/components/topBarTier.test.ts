// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

import { act, renderHook } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { readTopBarTier, tierFrom, TOPBAR_MEDIUM_QUERY, TOPBAR_PHONE_QUERY, useTopBarTier } from "./topBarTier";
import { installViewport } from "../test/fakeViewport";

describe("topBarTier", () => {
  const original = window.matchMedia;
  afterEach(() => {
    window.matchMedia = original;
    vi.restoreAllMocks();
  });

  it("maps the two breakpoints to a tier; phone wins over medium", () => {
    expect(tierFrom(false, false)).toBe("full");
    expect(tierFrom(true, false)).toBe("medium");
    expect(tierFrom(true, true)).toBe("phone");
    // A phone match alone (cannot happen with nested max-widths) is still phone.
    expect(tierFrom(false, true)).toBe("phone");
  });

  it("uses 1000 px and 720 px — the widths the header was measured against", () => {
    expect(TOPBAR_MEDIUM_QUERY).toBe("(max-width: 1000px)");
    expect(TOPBAR_PHONE_QUERY).toBe("(max-width: 720px)");
  });

  it("reads the tier from the window width at each boundary", () => {
    const vp = installViewport(1280);
    expect(readTopBarTier()).toBe("full");
    vp.resize(1001);
    expect(readTopBarTier()).toBe("full");
    vp.resize(1000);
    expect(readTopBarTier()).toBe("medium");
    vp.resize(721);
    expect(readTopBarTier()).toBe("medium");
    vp.resize(720);
    expect(readTopBarTier()).toBe("phone");
    vp.resize(360);
    expect(readTopBarTier()).toBe("phone");
  });

  it("falls back to the desktop header without media-query support", () => {
    // @ts-expect-error — simulating an environment without matchMedia
    window.matchMedia = undefined;
    expect(readTopBarTier()).toBe("full");
    window.matchMedia = () => {
      throw new Error("blocked");
    };
    expect(readTopBarTier()).toBe("full");
  });

  it("re-renders when the window crosses a breakpoint, and unsubscribes on unmount", () => {
    const vp = installViewport(1280);
    const { result, unmount } = renderHook(() => useTopBarTier());
    expect(result.current).toBe("full");
    act(() => vp.resize(800));
    expect(result.current).toBe("medium");
    act(() => vp.resize(390));
    expect(result.current).toBe("phone");
    act(() => vp.resize(1600));
    expect(result.current).toBe("full");
    unmount();
    expect(vp.listenerCount()).toBe(0);
  });

  it("supports the legacy addListener API (Safari < 14)", () => {
    const vp = installViewport(1280, { legacy: true });
    const { result, unmount } = renderHook(() => useTopBarTier());
    act(() => vp.resize(500));
    expect(result.current).toBe("phone");
    unmount();
    expect(vp.listenerCount()).toBe(0);
  });
});

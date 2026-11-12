// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

import { describe, it, expect, afterEach } from "vitest";
import { render, cleanup } from "@testing-library/react";
import { Sparkline, UtilMeter, sparkPaths } from "./viz";

afterEach(cleanup);

describe("UtilMeter — the band comes from the token scale, never a colour", () => {
  it.each([
    [10, "u1", ""], [30, "u2", ""], [60, "u3", ""], [80, "warn", "warn"], [95, "crit", "crit"],
  ])("%s%% reads band %s", (pct, band, tone) => {
    const { container } = render(<UtilMeter pct={pct} />);
    const root = container.querySelector(".tr-util")!;
    expect(root.getAttribute("data-band")).toBe(band);
    expect(root.className.trim()).toBe(`tr-util ${tone}`.trim());
    expect(container.querySelector(`.tr-meter.${band}`)).not.toBeNull();
    expect(container.innerHTML).not.toMatch(/#[0-9a-f]{3,8}\b|rgb\(/i);
  });

  it("no figure → a dash and no bar; the bar is clamped to its track", () => {
    const none = render(<UtilMeter />);
    expect(none.container.textContent).toBe("—");
    expect(none.container.querySelector(".tr-meter")).toBeNull();
    cleanup();
    const over = render(<UtilMeter pct={140} />);
    expect((over.container.querySelector(".tr-meter > span") as HTMLElement).style.width).toBe("100%");
  });
});

describe("Sparkline — smooth line, area, emphasised endpoint", () => {
  it("draws a cubic path through the points, closes the area, and marks the last point", () => {
    const p = sparkPaths([1, 3, 2, 5], 100, 20, 0)!;
    expect(p.line.startsWith("M0.0,")).toBe(true);
    expect((p.line.match(/ C/g) ?? []).length).toBe(3);
    expect(p.area.endsWith("Z")).toBe(true);
    expect(p.end).toEqual([100, 0]); // the maximum sits at the top edge
  });

  it("needs two finite points, and survives a flat series", () => {
    expect(sparkPaths([5], 100, 20)).toBeNull();
    expect(sparkPaths([NaN, 2], 100, 20)).toBeNull();
    expect(sparkPaths([2, 2, 2], 100, 20)).not.toBeNull();
  });

  it("renders the three marks with token classes, or a dash without data", () => {
    const { container } = render(<Sparkline values={[1, 2, 3]} label="Trend" />);
    expect(container.querySelector("svg[aria-label='Trend'] .tr-spark-area")).not.toBeNull();
    expect(container.querySelector(".tr-spark-line")).not.toBeNull();
    expect(container.querySelector("circle.tr-spark-end")).not.toBeNull();
    cleanup();
    expect(render(<Sparkline label="x" />).container.textContent).toBe("—");
  });
});

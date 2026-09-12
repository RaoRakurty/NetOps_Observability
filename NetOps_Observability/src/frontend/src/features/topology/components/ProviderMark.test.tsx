// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// ProviderMark.test.tsx — the cloud mark is provider-parametric, degrades
// honestly, and carries NO provider trademark.
//
// CONTRACT CHANGE (licence audit D5, 2026-09-04): this used to assert that an
// `<img>` rendered for aws/azure/gcp, because the component loaded the
// providers' official vendored icons as asset URLs. Those trademark assets were
// deleted; the mark is now ORIGINAL Correlix artwork drawn INLINE as <svg> —
// one cloud silhouette whose ONLY provider-specific element is a plain letter
// tag. So the contract these tests hold is: an inline <svg> (never an <img>,
// never an asset URL), the right tag per provider, the untagged generic cloud
// for anything unknown, and not one provider brand colour anywhere.

import { describe, it, expect, afterEach } from "vitest";
import { render, cleanup } from "@testing-library/react";
import ProviderMark, { providerAccent, PROVIDER_ACCENT, GENERIC_CLOUD_ACCENT } from "./ProviderMark";

afterEach(cleanup);

/** Every hex the providers' marks used, plus the Azure gradient's stops. */
const BRAND_COLOURS = [
  "#ff9900", // AWS orange
  "#0078d4", // Azure blue
  "#4285f4", // Google blue
  "#ea4335", // Google red
  "#34a853", // Google green
  "#fbbc05", // Google yellow
  "#114a8b", "#0669bc", "#3ccbf4", "#2892df", // Azure gradient stops
];

/** Asset paths that would mean a vendored provider logo came back. */
const BRAND_ASSETS = ["assets/cloud/", "aws.svg", "azure.svg", "gcp.svg"];

const TAGS: Record<string, string> = { aws: "AWS", azure: "AZ", gcp: "GCP" };

describe("ProviderMark", () => {
  it("renders an INLINE <svg> — never an <img> or an asset URL — for aws, azure and gcp", () => {
    for (const provider of Object.keys(TAGS)) {
      const { container } = render(<ProviderMark provider={provider} />);
      expect(container.querySelector("svg"), provider).toBeTruthy();
      expect(container.querySelector("img"), provider).toBeNull();
      expect(container.querySelector("image"), provider).toBeNull();
      cleanup();
    }
  });

  it("distinguishes providers ONLY by the letter tag — same silhouette for all", () => {
    const paths = new Set<string>();
    for (const [provider, tag] of Object.entries(TAGS)) {
      const { container } = render(<ProviderMark provider={provider} />);
      expect(container.querySelector("text")?.textContent, provider).toBe(tag);
      paths.add(container.querySelector("path")?.getAttribute("d") ?? "");
      cleanup();
    }
    expect(paths.size, "all providers must share one silhouette").toBe(1);
    expect([...paths][0]).toMatch(/^M6\.6 14\.5H/);
  });

  it("renders the UNTAGGED generic cloud for an unknown provider (never a hyperscaler mark)", () => {
    for (const provider of [undefined, "nifcloud", ""]) {
      const { container } = render(<ProviderMark provider={provider} />);
      expect(container.querySelector("img")).toBeNull();
      expect(container.querySelector("svg")).toBeTruthy();
      expect(container.querySelector("path")).toBeTruthy();
      expect(container.querySelector("text"), `${provider} must carry no tag`).toBeNull();
      cleanup();
    }
  });

  // The regression guard: the trademark marks cannot come back silently.
  it("renders NO provider brand colour and NO provider-logo asset path", () => {
    for (const provider of [...Object.keys(TAGS), "nifcloud", undefined]) {
      const { container } = render(<ProviderMark provider={provider} />);
      const html = container.innerHTML.toLowerCase();
      for (const hex of BRAND_COLOURS) {
        expect(html, `${provider} leaked brand colour ${hex}`).not.toContain(hex);
      }
      for (const asset of BRAND_ASSETS) {
        expect(html, `${provider} leaked brand asset ${asset}`).not.toContain(asset);
      }
      // No gradient/fill machinery at all — the glyph is currentColor only.
      expect(html).not.toContain("lineargradient");
      expect(html).toContain("currentcolor");
      cleanup();
    }
  });

  it("maps provider → accent, generic for unknown", () => {
    expect(providerAccent("aws")).toBe(PROVIDER_ACCENT.aws);
    expect(providerAccent("azure")).toBe(PROVIDER_ACCENT.azure);
    expect(providerAccent(undefined)).toBe(GENERIC_CLOUD_ACCENT);
    expect(providerAccent("nifcloud")).toBe(GENERIC_CLOUD_ACCENT);
  });

  it("accents are PRODUCT tokens, not provider brand hexes", () => {
    for (const [provider, hex] of Object.entries(PROVIDER_ACCENT)) {
      expect(BRAND_COLOURS, `${provider} accent is a brand hex`).not.toContain(hex.toLowerCase());
    }
    expect(BRAND_COLOURS).not.toContain(GENERIC_CLOUD_ACCENT.toLowerCase());
    // distinct per provider — the accent still sorts a multi-cloud canvas
    expect(new Set(Object.values(PROVIDER_ACCENT)).size).toBe(Object.keys(PROVIDER_ACCENT).length);
  });
});

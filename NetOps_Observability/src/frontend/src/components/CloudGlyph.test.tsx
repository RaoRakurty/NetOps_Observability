// CloudGlyph.test.tsx — the ORIGINAL cloud-glyph family (licence audit D5).
//
// This is the anti-regression guard for the whole family: one silhouette, four
// variants that differ ONLY by a plain letter tag, no provider trademark asset
// and no provider brand colour anywhere in the rendered output. If a
// hyperscaler mark is ever reintroduced, these fail.

import { describe, it, expect, afterEach } from "vitest";
import { render, cleanup } from "@testing-library/react";
import CloudGlyph, {
  CloudGlyphShape,
  CLOUD_SILHOUETTE_PATH,
  CLOUD_TAG,
  cloudTag,
} from "./CloudGlyph";

afterEach(cleanup);

const BRAND_COLOURS = [
  "#ff9900", "#0078d4", "#4285f4", "#ea4335", "#34a853", "#fbbc05",
  "#114a8b", "#0669bc", "#3ccbf4", "#2892df",
];

describe("cloudTag", () => {
  it("maps the three known providers to a plain letter tag", () => {
    expect(cloudTag("aws")).toBe("AWS");
    expect(cloudTag("AZURE")).toBe("AZ");
    expect(cloudTag(" gcp ")).toBe("GCP");
  });

  it("returns null for unknown / empty providers (generic cloud, honestly)", () => {
    for (const p of [undefined, null, "", "  ", "nifcloud", "oracle"]) {
      expect(cloudTag(p), String(p)).toBeNull();
    }
  });
});

describe("CloudGlyph", () => {
  it("draws ONE silhouette for every variant — the tag is the only difference", () => {
    const ds = new Set<string>();
    for (const p of [undefined, ...Object.keys(CLOUD_TAG)]) {
      const { container } = render(<CloudGlyph provider={p} />);
      ds.add(container.querySelector("path")!.getAttribute("d")!);
      cleanup();
    }
    expect(ds.size).toBe(1);
    expect([...ds][0]).toBe(CLOUD_SILHOUETTE_PATH);
  });

  it("renders the tag for a known provider and no tag for a generic cloud", () => {
    for (const [provider, tag] of Object.entries(CLOUD_TAG)) {
      const { container } = render(<CloudGlyph provider={provider} />);
      expect(container.querySelector("text")?.textContent, provider).toBe(tag);
      cleanup();
    }
    const { container } = render(<CloudGlyph />);
    expect(container.querySelector("text")).toBeNull();
  });

  it("is inline SVG with no external asset reference", () => {
    const { container } = render(<CloudGlyph provider="aws" size={32} />);
    const svg = container.querySelector("svg")!;
    expect(svg.getAttribute("viewBox")).toBe("0 0 24 24");
    expect(svg.getAttribute("width")).toBe("32");
    expect(container.querySelector("img")).toBeNull();
    expect(container.querySelector("image")).toBeNull();
    expect(container.querySelector("use")).toBeNull();
  });

  it("carries NO provider brand colour and NO provider-logo asset path", () => {
    for (const p of [undefined, "aws", "azure", "gcp", "nifcloud"]) {
      const { container } = render(<CloudGlyph provider={p} />);
      const html = container.innerHTML.toLowerCase();
      for (const hex of BRAND_COLOURS) {
        expect(html, `${p} leaked ${hex}`).not.toContain(hex);
      }
      for (const asset of ["assets/cloud/", "aws.svg", "azure.svg", "gcp.svg", "data:image"]) {
        expect(html, `${p} leaked ${asset}`).not.toContain(asset);
      }
      expect(html).not.toContain("lineargradient");
      // colour comes from the theme, not from a literal
      expect(html).toContain("currentcolor");
      expect(html).not.toMatch(/(stroke|fill)="#/);
      cleanup();
    }
  });

  it("is theme-aware: hidden from a11y unless labelled, labelled glyphs get a <title>", () => {
    const plain = render(<CloudGlyph provider="aws" />).container.querySelector("svg")!;
    expect(plain.getAttribute("aria-hidden")).toBe("true");
    expect(plain.querySelector("title")).toBeNull();
    cleanup();
    const labelled = render(<CloudGlyph provider="aws" label="aws resource" />).container.querySelector("svg")!;
    expect(labelled.getAttribute("role")).toBe("img");
    expect(labelled.getAttribute("aria-hidden")).toBeNull();
    expect(labelled.querySelector("title")?.textContent).toBe("aws resource");
  });
});

describe("CloudGlyphShape", () => {
  it("is embeddable in a parent SVG (no wrapper element of its own)", () => {
    const { container } = render(
      <svg viewBox="0 0 100 100">
        <g transform="translate(26 26) scale(2)">
          <CloudGlyphShape tag="GCP" />
        </g>
      </svg>,
    );
    expect(container.querySelectorAll("svg").length).toBe(1);
    expect(container.querySelector("g > path")).toBeTruthy();
    expect(container.querySelector("g > text")?.textContent).toBe("GCP");
  });
});

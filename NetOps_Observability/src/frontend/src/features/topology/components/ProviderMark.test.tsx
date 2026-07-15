// ProviderMark.test.tsx — the official-mark renderer is provider-parametric and
// degrades honestly (official img → monogram → generic glyph).

import { describe, it, expect, afterEach } from "vitest";
import { render, cleanup } from "@testing-library/react";
import ProviderMark, { providerAccent, PROVIDER_ACCENT, GENERIC_CLOUD_ACCENT } from "./ProviderMark";

afterEach(cleanup);

describe("ProviderMark", () => {
  it("renders the OFFICIAL mark (an <img>) for aws, azure and gcp", () => {
    for (const provider of ["aws", "azure", "gcp"]) {
      const { container } = render(<ProviderMark provider={provider} />);
      expect(container.querySelector("img"), provider).toBeTruthy();
      cleanup();
    }
  });

  it("renders a generic cloud glyph for an unknown provider (never iconless)", () => {
    const { container } = render(<ProviderMark provider={undefined} />);
    expect(container.querySelector("img")).toBeNull();
    expect(container.querySelector("svg")).toBeTruthy();
  });

  it("maps provider → accent, generic for unknown", () => {
    expect(providerAccent("aws")).toBe(PROVIDER_ACCENT.aws);
    expect(providerAccent("azure")).toBe(PROVIDER_ACCENT.azure);
    expect(providerAccent(undefined)).toBe(GENERIC_CLOUD_ACCENT);
    expect(providerAccent("nifcloud")).toBe(GENERIC_CLOUD_ACCENT);
  });
});

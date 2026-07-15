// ProviderMark.test.tsx — the official-mark renderer is provider-parametric and
// degrades honestly (official img → monogram → generic glyph).

import { describe, it, expect, afterEach } from "vitest";
import { render, screen, cleanup } from "@testing-library/react";
import ProviderMark, { providerAccent, PROVIDER_ACCENT, GENERIC_CLOUD_ACCENT } from "./ProviderMark";

afterEach(cleanup);

describe("ProviderMark", () => {
  it("renders the OFFICIAL mark (an <img>) for aws and azure", () => {
    const { container: aws } = render(<ProviderMark provider="aws" />);
    expect(aws.querySelector("img")).toBeTruthy();
    cleanup();
    const { container: az } = render(<ProviderMark provider="azure" />);
    expect(az.querySelector("img")).toBeTruthy();
  });

  it("falls back to a monogram badge for gcp (no vendored official mark)", () => {
    const { container } = render(<ProviderMark provider="gcp" />);
    expect(container.querySelector("img")).toBeNull();
    expect(screen.getByText("G")).toBeTruthy();
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

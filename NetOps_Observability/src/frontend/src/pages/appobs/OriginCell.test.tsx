// OriginCell.test.tsx — the "Origin" column on Open Investigations (owner review
// #5: "where does this issue come from?"), and the FeedBar that discloses the
// window/count/liveness of a signal feed (review #2).
//
// Acceptance: a provider is rendered only when the object's evidence carries it;
// a multi-cloud object shows every cloud; an object with no cloud evidence reads
// as on-prem (with the reason), not as a blank or a fabricated cloud.

import { describe, it, expect, afterEach, vi } from "vitest";
import { render, screen, cleanup, fireEvent } from "@testing-library/react";
import { OriginCell, ProviderBadge } from "./badges";
import { FeedBar } from "./FeedBar";
import { deriveObjectOrigins } from "./origin";
import { feedCount } from "./range";
import type { EvidenceRow } from "./types";

afterEach(cleanup);

const ev = (over: Partial<EvidenceRow> = {}): EvidenceRow => ({
  time: "2026-07-15T10:00:00.000Z", category: "grounded", signalType: "cloud_health",
  app: "billing", resource: "web-1", source: "aws", confidence: "suspected",
  reason: "cpu high", grounded: true, rcaGroup: "cid-1", evidenceRef: "sig-1", ...over,
});

describe("ProviderBadge", () => {
  it("labels each cloud with its product name", () => {
    for (const [p, label] of [["aws", "AWS"], ["azure", "Azure"], ["gcp", "Google Cloud"]] as const) {
      render(<ProviderBadge provider={p} />);
      expect(screen.getByText(label)).toBeTruthy();
      cleanup();
    }
  });
});

describe("OriginCell", () => {
  it("renders the provider derived from the investigation's own evidence", () => {
    const origins = deriveObjectOrigins([ev({ source: "azure" })]);
    render(<OriginCell providers={origins.get("cid-1")!.providers} />);
    expect(screen.getByText("Azure")).toBeTruthy();
    expect(screen.queryByText("AWS")).toBeNull();
  });

  it("shows EVERY cloud of a multi-cloud investigation", () => {
    const origins = deriveObjectOrigins([
      ev({ source: "aws" }),
      ev({ source: "gcp", evidenceRef: "sig-2" }),
    ]);
    render(<OriginCell providers={origins.get("cid-1")!.providers} />);
    expect(screen.getByText("AWS")).toBeTruthy();
    expect(screen.getByText("Google Cloud")).toBeTruthy();
  });

  it("reads as on-prem — with the reason — when no cloud is in the evidence", () => {
    // a pure network/on-prem incident: honest, and explicitly NOT "unknown cloud"
    const origins = deriveObjectOrigins([ev({ source: "cloud", cloudRef: undefined })]);
    render(<OriginCell providers={origins.get("cid-1")!.providers} />);
    const cell = screen.getByText("On-prem");
    expect(cell).toBeTruthy();
    expect(cell.getAttribute("title")).toMatch(/no cloud signal/i);
  });
});

describe("FeedBar", () => {
  const base = {
    minutes: 60, onRange: () => {}, loadedAt: Date.now(),
    onRefresh: () => {}, label: "Alerts time range",
  };

  it("discloses how many events are shown of how many exist", () => {
    render(<FeedBar {...base} count={feedCount(12, 48, 60)} />);
    expect(screen.getByText("showing 12 of 48 · last 1 hour")).toBeTruthy();
  });

  it("shows the live cue with a seconds-resolution freshness", () => {
    render(<FeedBar {...base} loadedAt={Date.now() - 8_000} count={feedCount(5, 5, 60)} />);
    expect(screen.getByText(/live · updated \d+s ago/)).toBeTruthy();
  });

  it("offers only windows the backend actually ingests, and reports a change", () => {
    const onRange = vi.fn();
    render(<FeedBar {...base} onRange={onRange} count={feedCount(5, 5, 60)} />);
    // no 7d button: the cloud endpoints read a fixed 24h (see range.ts)
    expect(screen.queryByText("7d")).toBeNull();
    fireEvent.click(screen.getByText("15m"));
    expect(onRange).toHaveBeenCalledWith(15);
  });

  it("names the range control for assistive tech", () => {
    render(<FeedBar {...base} count={feedCount(5, 5, 60)} />);
    expect(screen.getByLabelText("Alerts time range")).toBeTruthy();
  });
});

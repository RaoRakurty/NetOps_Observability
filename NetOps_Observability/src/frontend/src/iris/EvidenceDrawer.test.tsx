// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// EvidenceDrawer.test.tsx — "Why am I seeing this?": provenance in plain words,
// never the physical query, safe entity links, honest gaps.

import { describe, it, expect, afterEach, vi } from "vitest";
import { render, screen, cleanup, fireEvent } from "@testing-library/react";
import EvidenceDrawer, { EvidenceDetails } from "./EvidenceDrawer";
import { humanize, normalizeResult, type ResultSet } from "./presentation";
import { HOSTILE, baseResult } from "../test/irisFixtures";

afterEach(cleanup);

function result(over: Record<string, unknown> = {}): ResultSet {
  const n = normalizeResult(baseResult(over));
  if (!n.ok) throw new Error("fixture");
  return n.result;
}

describe("EvidenceDrawer", () => {
  it("shows source, window, scope, adjustments and the query reference", () => {
    const rs = result({
      provenance: {
        source: "change_ledger+clickhouse:corr_current",
        executed_at: "2026-09-20T12:00:01Z",
        duration_ms: 42,
        entities: [{ type: "device", id: "core-sw-1" }, { type: "tunnel", id: "t1" }],
      },
      constraints_applied: [{ path: "limit", from: "5000", to: "500", reason: "row limit" }],
    });
    render(<EvidenceDrawer result={rs} onClose={() => {}} />);
    expect(screen.getByRole("dialog", { name: "Why am I seeing this?" })).toBeInTheDocument();
    expect(screen.getByText("Change record, Incident store")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "core-sw-1" })).toHaveAttribute("href", "/#/infrastructure/devices?q=core-sw-1");
    // A kind without a page is text, not a guessed link.
    expect(screen.queryByRole("link", { name: "t1" })).toBeNull();
    expect(screen.getByText(/Limit: 5000 → 500 — row limit/)).toBeInTheDocument();
    expect(screen.getByText("q-123")).toBeInTheDocument();
    expect(screen.getByText(/took 42 ms/)).toBeInTheDocument();
  });

  it("never renders the physical query, even when the server leaks one", () => {
    const rs = result({ provenance: { source: "victoriametrics", physical: ['up{tenant="other"}'], executed_at: "", entities: [] } });
    const { container } = render(<EvidenceDrawer result={rs} onClose={() => {}} />);
    expect(container.textContent).not.toContain("tenant=");
    expect(screen.getByText("Metrics store")).toBeInTheDocument();
  });

  it("states missing provenance instead of leaving blanks", () => {
    const n = normalizeResult({});
    if (!n.ok) throw new Error("x");
    render(<EvidenceDetails result={n.result} />);
    expect(screen.getAllByText("Not stated").length).toBeGreaterThanOrEqual(3);
    expect(screen.getByText("Everything you are allowed to see")).toBeInTheDocument();
  });

  it("names the row it was opened for", () => {
    render(<EvidenceDetails result={result()} row={{ change_id: "chg-7" }} />);
    expect(screen.getByText("chg-7")).toBeInTheDocument();
  });

  it("renders a hostile source tag and entity as text", () => {
    const rs = result({ provenance: { source: HOSTILE, executed_at: "", entities: [{ type: "device", id: HOSTILE }] } });
    const { container } = render(<EvidenceDetails result={rs} />);
    expect(container.querySelector("script")).toBeNull();
    expect(screen.getByText("Other source")).toBeInTheDocument();
    expect(container.textContent).toContain(HOSTILE);
  });

  it("does not resolve prototype names as words", () => {
    expect(humanize("constructor")).toBe("Constructor");
    expect(humanize("__proto__")).toBe("Proto");
  });

  it("closes", () => {
    const onClose = vi.fn();
    render(<EvidenceDrawer result={result()} onClose={onClose} />);
    fireEvent.click(screen.getByRole("button", { name: "Close" }));
    expect(onClose).toHaveBeenCalled();
  });
});

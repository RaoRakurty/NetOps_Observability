// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// CommandCenter.test.tsx — the Action Queue's OPERATOR AFFORDANCES (owner live
// review, 2026-07): the queue used to hand-roll its own <table>, so it never
// inherited the shared DataTable's visible resize grip or sortable headers.
// It now renders THROUGH components/DataTable. These tests pin the three gaps
// the owner found — a visible drag mark, every column sortable, an absolute date
// column — plus the expandable detail row that migration had to preserve.
//
// Sort assertions are deliberately SEMANTIC (operator urgency), not lexical: a
// lexical sort would put "Blocked" before "Confirmed", which is wrong for a NOC.

import { describe, it, expect, vi, afterEach, beforeEach } from "vitest";
import { render, screen, cleanup, fireEvent, waitFor, within } from "@testing-library/react";
import { corrObject } from "../test/factories";

const correlations = vi.fn();
const listIncidents = vi.fn();
const permissions = vi.fn();
const rcaPathView = vi.fn();

vi.mock("../services/api", () => ({
  api: {
    correlations: (...a: unknown[]) => correlations(...a),
    listIncidents: (...a: unknown[]) => listIncidents(...a),
    permissions: (...a: unknown[]) => permissions(...a),
    rcaPathView: (...a: unknown[]) => rcaPathView(...a),
    correlationTicketCreate: vi.fn(),
  },
}));

import CommandCenter from "./CommandCenter";

// Four real, actionable correlation groups covering the WHOLE severity ladder
// (crit/major/warn/ok) at start times in three different months. Both are chosen
// so a lexical sort and the semantic sort produce DIFFERENT orders — otherwise
// these tests would pass on a broken implementation:
//
//   severity  semantic asc: crit, major, warn, ok   → A B D C
//             lexical  asc: crit, major, ok, warn   → A B C D   ✗ differs
//   started   chronological: May, Jun 21, Jun 25, Jul → C B D A
//             by rendered label ("Jul 02" < "Jun 21" < "May 20") → A B D C  ✗ differs
const T_MAY = "2026-05-20T08:00:00Z"; // C — oldest
const T_JUN = "2026-06-21T08:00:00Z"; // B
const T_JUN_LATE = "2026-06-25T08:00:00Z"; // D
const T_JUL = "2026-07-02T08:00:00Z"; // A — newest

const rows = [
  // A — crit (confirmed), and the NEWEST, so a date sort must move it off the top.
  corrObject({
    correlation_id: "aaaaaa11-0000-0000-0000-000000000001",
    verdict_tier: "confirmed", signal_count: 5, node_count: 3, owner: "",
    top_hypothesis: "bgp.session.flap", top_confidence: 0.9,
    affected: JSON.stringify({ devices: ["leaf-1", "spine-2"], sites: ["hq"] }),
    window_start: T_JUL,
  }),
  // C — ok (undetermined, low confidence), the OLDEST.
  corrObject({
    correlation_id: "cccccc33-0000-0000-0000-000000000003",
    verdict_tier: "undetermined", signal_count: 2, node_count: 1, owner: "isp",
    top_hypothesis: "dns.resolution.slow", top_confidence: 0.2,
    affected: JSON.stringify({ devices: ["edge-1"], sites: ["br1"] }),
    window_start: T_MAY,
  }),
  // B — major (suspected).
  corrObject({
    correlation_id: "bbbbbb22-0000-0000-0000-000000000002",
    verdict_tier: "suspected", signal_count: 3, node_count: 2, owner: "netops",
    top_hypothesis: "link.state.change", top_confidence: 0.5,
    affected: JSON.stringify({ devices: ["sw-9"], sites: ["dc2"] }),
    window_start: T_JUN,
  }),
  // D — warn (undetermined but ≥0.6 confidence): the row that separates the
  // semantic severity ladder from the alphabetical one ("warn" sorts after "ok").
  corrObject({
    correlation_id: "dddddd44-0000-0000-0000-000000000004",
    verdict_tier: "undetermined", signal_count: 2, node_count: 1, owner: "cloudops",
    top_hypothesis: "cloud.path.change", top_confidence: 0.7,
    affected: JSON.stringify({ devices: ["vgw-1"], sites: ["aws"] }),
    window_start: T_JUN_LATE,
  }),
];

// The queue's rendered row order, read off the Problem ID handle in each row.
const rowOrder = (): string[] =>
  screen.getAllByRole("row")
    .map((r) => within(r).queryByText(/^P-[0-9A-F]{6}$/)?.textContent ?? "")
    .filter(Boolean);

const header = (name: string): HTMLElement =>
  screen.getByRole("columnheader", { name: new RegExp(name, "i") });

afterEach(cleanup);

beforeEach(() => {
  correlations.mockReset();
  listIncidents.mockReset();
  permissions.mockReset();
  rcaPathView.mockReset();
  correlations.mockResolvedValue({ data: rows });
  listIncidents.mockResolvedValue([]);
  permissions.mockResolvedValue({ permissions: { infrastructure: 2 } });
  rcaPathView.mockResolvedValue({ path: { edges: [] }, summary: "", title: "" });
});

describe("Action Queue — renders through the shared DataTable", () => {
  it("exposes a VISIBLE, keyboard-operable resize grip per column (owner gap #1)", async () => {
    render(<CommandCenter />);
    await screen.findByRole("grid", { name: /Action Queue/i });

    // The grip is the shared primitive's, not a hand-rolled one: a labelled
    // separator carrying the visible .dtv-resize-grip mark and ←/→ support.
    const grips = screen.getAllByRole("separator", { name: /Resize .* column/i });
    expect(grips.length).toBeGreaterThan(0);

    const started = screen.getByRole("separator", { name: /Resize Started column/i });
    expect(started.querySelector(".dtv-resize-grip")).toBeTruthy(); // the visible mark
    expect(started.getAttribute("tabindex")).toBe("0");             // reachable by keyboard
    expect(started.getAttribute("title")).toMatch(/Resize column/);          // discoverable affordance
  });

  it("keeps the queue's severity row-accent treatment after migration", async () => {
    const { container } = render(<CommandCenter />);
    await screen.findByRole("grid", { name: /Action Queue/i });
    // crit → --crit accent, major → --warn (was .cc-row.sev-*, now rowAccent).
    const accents = [...container.querySelectorAll(".dtv-row")].map((r) => (r as HTMLElement).style.boxShadow);
    expect(accents.some((s) => s.includes("--crit"))).toBe(true);
    expect(accents.some((s) => s.includes("--warn"))).toBe(true);
  });
});

describe("Every column is sortable, with a visible indicator + aria-sort", () => {
  it("marks each column sortable and announces the sort state", async () => {
    render(<CommandCenter />);
    await screen.findByRole("grid", { name: /Action Queue/i });

    // Column headers were cut to <= 2 words in the 2026-09-06 word sweep.
    const names = ["Sev", "Problem", "Incident", "RCA", "Impact",
      "Domain", "Evidence", "Owner", "Started", "Age", "Ticket", "Next"];
    for (const n of names) {
      const th = header(n);
      expect(th.className, `${n} must be sortable`).toContain("sortable");
      expect(th.querySelector(".dtv-arrow"), `${n} needs a visible sort indicator`).toBeTruthy();
    }

    // aria-sort is unset until sorted, then reflects the direction.
    const sev = header("Sev");
    expect(sev.getAttribute("aria-sort")).toBeNull();
    fireEvent.click(sev);
    expect(header("Sev").getAttribute("aria-sort")).toBe("ascending");
    fireEvent.click(header("Sev"));
    expect(header("Sev").getAttribute("aria-sort")).toBe("descending");
  });

  it("sorts Severity by the OPERATOR ladder (crit→major→warn→ok), not alphabetically", async () => {
    render(<CommandCenter />);
    await screen.findByRole("grid", { name: /Action Queue/i });

    fireEvent.click(header("Sev"));
    // Semantic: crit(A) → major(B) → warn(D) → ok(C).
    // A LEXICAL sort of "crit"/"major"/"ok"/"warn" would give A, B, C, D — it
    // would put the benign `ok` row ABOVE the `warn` row. This assertion fails
    // on that implementation, which is the whole point.
    expect(rowOrder()).toEqual(["P-AAAAAA", "P-BBBBBB", "P-DDDDDD", "P-CCCCCC"]);
    fireEvent.click(header("Sev"));
    expect(rowOrder()).toEqual(["P-CCCCCC", "P-DDDDDD", "P-BBBBBB", "P-AAAAAA"]);
  });

  it("sorts RCA state by the triage ladder, not lexically", async () => {
    render(<CommandCenter />);
    await screen.findByRole("grid", { name: /Action Queue/i });

    fireEvent.click(header("RCA"));
    // Ladder: Confirmed(0) → Suspected(1) → Correlated(3) ×2.
    // A LEXICAL sort would give Confirmed, Correlated, Correlated, Suspected —
    // burying Suspected below two benign correlated groups.
    // The two Correlated rows (D=warn, C=ok) TIE, and the sort is STABLE, so they
    // keep their incoming bySeverityThenAge order (warn D above ok C).
    expect(rowOrder()).toEqual(["P-AAAAAA", "P-BBBBBB", "P-DDDDDD", "P-CCCCCC"]);
  });

  it("sorts Started chronologically by epoch, not by the rendered label", async () => {
    render(<CommandCenter />);
    await screen.findByRole("grid", { name: /Action Queue/i });

    fireEvent.click(header("Started"));
    // Chronological: May 20(C) → Jun 21(B) → Jun 25(D) → Jul 02(A).
    // Sorting the DISPLAY string would give "Jul 02" < "Jun 21" < "Jun 25" <
    // "May 20" → A, B, D, C. This pins the epoch ordering instead.
    expect(rowOrder()).toEqual(["P-CCCCCC", "P-BBBBBB", "P-DDDDDD", "P-AAAAAA"]);
    fireEvent.click(header("Started"));
    expect(rowOrder()).toEqual(["P-AAAAAA", "P-DDDDDD", "P-BBBBBB", "P-CCCCCC"]);
  });
});

describe("Started column — the incident's real start time (owner gap #3)", () => {
  it("renders the actual window_start value, never an invented date", async () => {
    render(<CommandCenter />);
    await screen.findByRole("grid", { name: /Action Queue/i });

    // The shared LogTime renderer titles the cell with a tooltip that BEGINS
    // with the exact ISO instant (followed by the labeled local rendering), so
    // the absolute date is provably each row's own window_start — not a "now"
    // stamp and not an invented value.
    for (const iso of [T_JUL, T_JUN, T_JUN_LATE, T_MAY]) {
      expect(screen.getByTitle(new RegExp(`^${new Date(iso).toISOString()}`))).toBeTruthy();
    }
    // And it renders the real calendar date to the operator.
    expect(screen.getByText(/May 20/)).toBeTruthy();
  });

  it("falls back to created_at when window_start is absent (same source as age)", async () => {
    correlations.mockResolvedValue({
      data: [corrObject({
        correlation_id: "eeeeee55-0000-0000-0000-000000000005",
        verdict_tier: "confirmed", signal_count: 4, window_start: "", created_at: T_JUN,
        affected: JSON.stringify({ devices: ["leaf-3"] }),
      })],
    });
    render(<CommandCenter />);
    await screen.findByRole("grid", { name: /Action Queue/i });
    expect(screen.getByTitle(new RegExp(`^${new Date(T_JUN).toISOString()}`))).toBeTruthy();
  });

  it("keeps the relative Age affordance alongside the absolute date", async () => {
    render(<CommandCenter />);
    await screen.findByRole("grid", { name: /Action Queue/i });
    expect(header("Age")).toBeTruthy();
    expect(header("Started")).toBeTruthy();
  });
});

describe("Row expansion survives the DataTable migration (hard constraint)", () => {
  it("expands a detail panel on row click and collapses it again", async () => {
    render(<CommandCenter />);
    await screen.findByRole("grid", { name: /Action Queue/i });

    expect(screen.queryByText("Next action")).toBeNull();

    fireEvent.click(screen.getByText("Routing adjacency change"));

    // The detail row renders the real ExpandPanel content for that correlation.
    expect(await screen.findByText("Next action")).toBeTruthy();
    expect(screen.getByText("Impacted entities")).toBeTruthy();
    await waitFor(() => expect(rcaPathView).toHaveBeenCalledWith("aaaaaa11-0000-0000-0000-000000000001"));

    // Clicking the same row again collapses it.
    fireEvent.click(screen.getByText("Routing adjacency change"));
    expect(screen.queryByText("Next action")).toBeNull();
  });

  it("marks the expanded row with aria-expanded for assistive tech", async () => {
    const { container } = render(<CommandCenter />);
    await screen.findByRole("grid", { name: /Action Queue/i });

    const rowsEls = () => [...container.querySelectorAll(".dtv-row")];
    expect(rowsEls().every((r) => r.getAttribute("aria-expanded") === "false")).toBe(true);

    fireEvent.click(screen.getByText("Routing adjacency change"));
    expect(rowsEls().filter((r) => r.getAttribute("aria-expanded") === "true")).toHaveLength(1);
  });

  it("a deep-link inside a row does not toggle the row (stopPropagation holds)", async () => {
    render(<CommandCenter />);
    await screen.findByRole("grid", { name: /Action Queue/i });

    fireEvent.click(screen.getByText("P-AAAAAA")); // the Problem ID → RCA deep link
    expect(screen.queryByText("Next action")).toBeNull();
  });
});

describe("Filtering still narrows the queue (no regression)", () => {
  it("a KPI sets the filter and the queue shows only those rows", async () => {
    render(<CommandCenter />);
    await screen.findByRole("grid", { name: /Action Queue/i });
    expect(rowOrder()).toHaveLength(4);

    fireEvent.click(screen.getByRole("button", { name: /^\d+\s*Critical$/ }));
    await waitFor(() => expect(rowOrder()).toEqual(["P-AAAAAA"]));
  });

  it("the Severity facet filters the rendered rows", async () => {
    render(<CommandCenter />);
    await screen.findByRole("grid", { name: /Action Queue/i });

    fireEvent.change(screen.getByLabelText("Severity"), { target: { value: "major" } });
    await waitFor(() => expect(rowOrder()).toEqual(["P-BBBBBB"]));
  });
});

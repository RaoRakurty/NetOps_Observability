// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// ChangeTable.test.tsx — the change drill-down table and its drawer: the
// required columns, the conditional Before/After column, the honest relation
// wording, row → drawer, provenance without the physical query, and hostile
// text/hrefs.

import { describe, it, expect, afterEach } from "vitest";
import { render, screen, cleanup, fireEvent, within } from "@testing-library/react";
import ChangeTable from "./ChangeTable";
import ChangeDrawer from "./ChangeDrawer";
import { normalizeResult, validatePlan, type ResultSet } from "./presentation";
import { automationText, beforeAfterShort, changeSourceText, relationText } from "./changes";
import { HOSTILE, baseResult, changeRow } from "../test/irisFixtures";

afterEach(cleanup);

function result(over: Record<string, unknown> = {}): ResultSet {
  const n = normalizeResult(baseResult(over));
  if (!n.ok) throw new Error("fixture");
  return n.result;
}

describe("change wording", () => {
  it("never calls a temporal relation a cause", () => {
    expect(relationText({ relation: "temporal" })).toBe("Happened before — not proven cause");
    expect(relationText({ relation: "causal" })).toBe("Linked by the root-cause engine");
    expect(relationText({ relation: HOSTILE })).toBe("Not stated");
    expect(relationText({})).toBe("Not stated");
  });

  it("states automation only when recorded", () => {
    expect(automationText({ automated: true })).toBe("Automation");
    expect(automationText({ automated: false })).toBe("Manual");
    expect(automationText({ origin: "manual" })).toBe("Manual");
    expect(automationText({})).toBe("Not recorded");
  });

  it("names the source and summarises before/after", () => {
    expect(changeSourceText({ source: "ledger" })).toBe("Change record");
    expect(changeSourceText({})).toBe("Not recorded");
    expect(beforeAfterShort({})).toBeNull();
    expect(beforeAfterShort({ before: "1500", after: "9000" })).toBe("1500 → 9000");
    expect(beforeAfterShort({ before: "", after: "x".repeat(60) })).toBe(`(none) → ${"x".repeat(40)}…`);
  });
});

describe("ChangeTable", () => {
  it("shows the required columns and no Before/After when none is recorded", () => {
    render(<ChangeTable rows={[changeRow()]} />);
    const headers = screen.getAllByRole("columnheader").map((h) => h.textContent?.replace(/[↕▲▼]/g, "").trim());
    expect(headers).toEqual(["Time", "Actor", "Source", "Change type", "Site", "Object", "Ticket", "Automation / manual", "Relation"]);
    expect(screen.getByText("Happened before — not proven cause")).toBeInTheDocument();
    expect(screen.getByText("Change record")).toBeInTheDocument();
  });

  it("adds Before / After when a row carries it", () => {
    render(<ChangeTable rows={[changeRow({ before: "1500", after: "9000" }), changeRow({ change_id: "c2" })]} />);
    expect(screen.getByRole("columnheader", { name: /Before \/ After/ })).toBeInTheDocument();
    expect(screen.getByText("1500 → 9000")).toBeInTheDocument();
  });

  it("marks a highlighted critical change in words", () => {
    const plan = validatePlan({ primary_view: "TABLE", highlight: [{ kind: "critical_change", ids: ["chg-1"] }] });
    render(<ChangeTable rows={[changeRow()]} plan={plan} />);
    expect(screen.getByText(/Critical change ·/)).toBeInTheDocument();
  });

  it("links the site through the safe map", () => {
    render(<ChangeTable rows={[changeRow()]} />);
    expect(screen.getByRole("link", { name: "DFW" })).toHaveAttribute("href", "/#/infrastructure/sites/sites?q=DFW");
  });

  it("opens the drawer on a row click with provenance but never the physical query", () => {
    const rs = result({ provenance: { source: "change_ledger", physical: ["SELECT secret"], executed_at: "2026-09-20T12:00:01Z", duration_ms: 42, entities: [] } });
    render(<ChangeTable rows={[changeRow()]} result={rs} />);
    fireEvent.click(screen.getAllByRole("row")[1]);
    const dialog = screen.getByRole("dialog");
    expect(within(dialog).getByText("Raised BGP hold timer")).toBeInTheDocument();
    expect(within(dialog).getByRole("region", { name: "Why am I seeing this?" })).toHaveTextContent("Change record");
    expect(within(dialog).getByText("q-123")).toBeInTheDocument();
    expect(dialog.textContent).not.toContain("SELECT");
    fireEvent.click(within(dialog).getByRole("button", { name: "Close" }));
    expect(screen.queryByRole("dialog")).toBeNull();
  });

  it("states an empty list honestly", () => {
    render(<ChangeTable rows={[]} />);
    expect(screen.getByRole("status")).toHaveTextContent("No changes in this window.");
  });

  it("renders missing fields as 'Not recorded', not blank", () => {
    render(<ChangeTable rows={[{ change_id: "c" }]} />);
    expect(screen.getAllByText("Not recorded").length).toBeGreaterThan(3);
  });

  it("renders hostile values as text", () => {
    const { container } = render(<ChangeTable rows={[changeRow({ actor: HOSTILE, object: HOSTILE, site: HOSTILE })]} />);
    expect(container.querySelector("script")).toBeNull();
    expect(container.textContent).toContain(HOSTILE);
  });
});

describe("ChangeDrawer", () => {
  it("shows the diff when the change carries before/after", () => {
    render(<ChangeDrawer row={changeRow({ before: { mtu: 1500 }, after: { mtu: 9000 } })} onClose={() => {}} />);
    expect(screen.getByRole("table", { name: /side by side/ })).toBeInTheDocument();
  });

  it("says a diff exists elsewhere when only has_diff is set", () => {
    render(<ChangeDrawer row={changeRow({ has_diff: true })} onClose={() => {}} />);
    expect(screen.getByText(/Before\/after not included here/)).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Open the change record" })).toHaveAttribute(
      "href",
      "/#/operations/digital-experience/changes?id=chg-1",
    );
  });

  it("names the incident a change was found near, in time only", () => {
    render(<ChangeDrawer row={changeRow({ incident_id: "inc-9", minutes_before_incident: 12 })} onClose={() => {}} />);
    expect(screen.getByText(/Happened before — not proven cause/)).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "inc-9" })).toHaveAttribute("href", "/#/investigate/rca?id=inc-9");
    expect(screen.getByText(/12 minutes before it started/)).toBeInTheDocument();
  });

  it("copes with a row missing almost everything", () => {
    render(<ChangeDrawer row={{}} onClose={() => {}} />);
    expect(screen.getByRole("dialog", { name: "Change" })).toBeInTheDocument();
    expect(screen.getByText("Time not recorded")).toBeInTheDocument();
    expect(screen.getByText("No before/after was recorded for this change.")).toBeInTheDocument();
  });
});

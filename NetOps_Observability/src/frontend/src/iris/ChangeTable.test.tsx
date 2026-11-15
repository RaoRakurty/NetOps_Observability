// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// ChangeTable.test.tsx — the change drill-down table and its drawer: the
// required columns, the conditional Before/After column, the honest relation
// wording, row → drawer, provenance without the physical query, and hostile
// text/hrefs.

import { describe, it, expect, afterEach, beforeEach, vi } from "vitest";
import { render, screen, cleanup, fireEvent, within } from "@testing-library/react";

// The change ledger read (/api/changes/{id}/diff) the drawer and a one-change
// answer make. Another workspace's id answers 404 from the server.
const changeDiff = vi.fn();
vi.mock("../services/api", () => ({ api: { changeDiff: (...a: unknown[]) => changeDiff(...a) } }));

import ChangeTable from "./ChangeTable";
import ChangeDrawer from "./ChangeDrawer";
import { normalizeResult, validatePlan, type ResultSet } from "./presentation";
import { automationText, beforeAfterShort, changeSourceText, changeTitle, changeTypeText, diffableChangeId, relationText } from "./changes";
import { HOSTILE, baseResult, changeRow } from "../test/irisFixtures";

beforeEach(() => {
  changeDiff.mockReset();
  changeDiff.mockResolvedValue({ change_id: "chg-1", kind: "values", before: "hold 90", after: "hold 180" });
});
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

  it("names the change type in words, the same everywhere", () => {
    expect(changeTypeText({ type: "NETWORK_CHANGE" })).toBe("Network change");
    expect(changeTypeText({ type: "ROUTE_CHANGE" })).toBe("Routing change");
    expect(changeTypeText({ type: "config_change" })).toBe("Config change");
    expect(changeTypeText({ type: "WIDGET_CHANGE" })).toBe("Widget change"); // unknown: humanized, never raw
    expect(changeTypeText({ type: "__proto__" })).not.toContain("function");
    expect(changeTypeText({})).toBe("");
    expect(changeTitle({ type: "NETWORK_CHANGE", object: "dfw-edge-1" })).toBe("Network change · dfw-edge-1");
  });

  it("fetches a diff only when the row says one exists and carries none", () => {
    expect(diffableChangeId({ change_id: "chg-1", has_diff: true })).toBe("chg-1");
    expect(diffableChangeId({ change_id: "chg-1", has_diff: false })).toBe("");
    expect(diffableChangeId({ change_id: "chg-1", has_diff: true, before: "a", after: "b" })).toBe("");
    expect(diffableChangeId({ change_id: "../../admin", has_diff: true })).toBe("");
    expect(diffableChangeId({ has_diff: true })).toBe("");
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

  it("shows the change type in words, never the raw ledger code", () => {
    render(<ChangeTable rows={[changeRow({ type: "NETWORK_CHANGE" }), changeRow({ change_id: "c2", type: "ROUTE_CHANGE" })]} />);
    expect(screen.getByRole("gridcell", { name: "Network change" })).toBeInTheDocument();
    expect(screen.getByRole("gridcell", { name: "Routing change" })).toBeInTheDocument();
    expect(screen.queryByText("NETWORK_CHANGE")).toBeNull();
  });

  it("shows what a single change did, read from the ledger, right in the answer", async () => {
    render(<ChangeTable rows={[changeRow({ has_diff: true })]} />);
    const what = screen.getByRole("region", { name: "What this change did" });
    expect(await within(what).findByText("hold 90 → hold 180")).toBeInTheDocument();
    expect(changeDiff).toHaveBeenCalledWith("chg-1");
  });

  it("reads no diff for a list of several changes", () => {
    render(<ChangeTable rows={[changeRow({ has_diff: true }), changeRow({ change_id: "c2", has_diff: true })]} />);
    expect(screen.queryByRole("region", { name: "What this change did" })).toBeNull();
    expect(changeDiff).not.toHaveBeenCalled();
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

  it("reads the diff from the change ledger when the row only says one exists", async () => {
    render(<ChangeDrawer row={changeRow({ has_diff: true })} onClose={() => {}} />);
    const what = screen.getByRole("region", { name: "What this change did" });
    expect(await within(what).findByText("hold 90 → hold 180")).toBeInTheDocument();
    expect(changeDiff).toHaveBeenCalledTimes(1);
    expect(changeDiff).toHaveBeenCalledWith("chg-1");
    expect(screen.queryByText(/Before\/after not included here/)).toBeNull();
    expect(screen.getByRole("link", { name: "Open the change record" })).toHaveAttribute(
      "href",
      "/#/operations/digital-experience/changes?id=chg-1",
    );
  });

  it("says plainly when the change is not the caller's (404), and shows no diff", async () => {
    changeDiff.mockRejectedValue(new Error("404 Not Found: not found"));
    render(<ChangeDrawer row={changeRow({ change_id: "chg-other", has_diff: true })} onClose={() => {}} />);
    expect(await screen.findByRole("alert")).toHaveTextContent("This change is not in your workspace, or it no longer exists.");
    expect(screen.queryByText(/→/)).toBeNull();
  });

  it("shows the change type in words, as the table does", () => {
    render(<ChangeDrawer row={changeRow({ type: "NETWORK_CHANGE" })} onClose={() => {}} />);
    expect(screen.getAllByText(/Network change/).length).toBeGreaterThanOrEqual(1);
    expect(screen.queryByText("NETWORK_CHANGE")).toBeNull();
  });

  it("never reads the ledger when there is no diff to read", () => {
    render(<ChangeDrawer row={changeRow({ has_diff: false })} onClose={() => {}} />);
    expect(screen.getByText("No before/after was recorded for this change.")).toBeInTheDocument();
    expect(changeDiff).not.toHaveBeenCalled();
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

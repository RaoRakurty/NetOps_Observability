// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// TenantRunbooks.test.tsx — Administration → Iris → Runbooks (N-F2).
//
// What has to hold: an author is never offered "Approve" on their own runbook;
// a reviewer's approval carries the version and hash of the text on screen;
// failing cases show their problems in plain language and change nothing;
// runbook text is rendered as TEXT; a runbook the platform outgrew offers a
// re-check, and one that runs does not.

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, cleanup, fireEvent, waitFor } from "@testing-library/react";

const runbooks = vi.fn();
const runbookCreate = vi.fn();
const runbookDraft = vi.fn();
const runbookDiscard = vi.fn();
const runbookCheck = vi.fn();
const runbookRecheck = vi.fn();
const runbookAct = vi.fn();
const runbookLinks = vi.fn();
const runbookLink = vi.fn();

vi.mock("../../services/api", () => ({
  api: {
    runbooks: (...a: unknown[]) => runbooks(...a),
    runbookCreate: (...a: unknown[]) => runbookCreate(...a),
    runbookDraft: (...a: unknown[]) => runbookDraft(...a),
    runbookDiscard: (...a: unknown[]) => runbookDiscard(...a),
    runbookCheck: (...a: unknown[]) => runbookCheck(...a),
    runbookRecheck: (...a: unknown[]) => runbookRecheck(...a),
    runbookAct: (...a: unknown[]) => runbookAct(...a),
    runbookLinks: (...a: unknown[]) => runbookLinks(...a),
    runbookLink: (...a: unknown[]) => runbookLink(...a),
  },
}));

import TenantRunbooks from "./TenantRunbooks";

function rb(id: string, author: string, state: string, extra: Record<string, unknown> = {}, rbExtra: Record<string, unknown> = {}) {
  return {
    id,
    name: `rb-${id}`,
    kind: "investigative",
    when_to_use: "acme carrier fault",
    created_by: author,
    created_at: "2026-11-13T09:00:00Z",
    updated_at: "2026-11-13T09:00:00Z",
    runs_in_iris: false,
    needs_recheck: false,
    versions: [
      {
        version: 1,
        skill_md: `---\nname: rb-${id}\n---\nbody of ${id}`,
        cases_yaml: "case: one",
        body_sha256: `sha-${id}`,
        state,
        author,
        harness_passed: state !== "draft",
        created_at: "2026-11-13T09:00:00Z",
        ...extra,
      },
    ],
    ...rbExtra,
  };
}

function serve(list: unknown[], you = "alice") {
  runbooks.mockResolvedValue({ runbooks: list, you, limits: { runbooks: 30, versions: 50, cases: 40, links: 20 } });
}

beforeEach(() => {
  vi.clearAllMocks();
  runbookAct.mockResolvedValue({});
  runbookCreate.mockResolvedValue({});
  runbookLinks.mockResolvedValue({ links: [] });
});
afterEach(cleanup);

describe("TenantRunbooks", () => {
  it("never offers the author an approval of their own runbook", async () => {
    serve([rb("a", "alice", "pending")]);
    render(<TenantRunbooks />);
    await screen.findByText(/Waiting for another administrator/);
    expect(screen.queryByRole("button", { name: "Approve" })).toBeNull();
    expect(screen.getByText("Nothing is waiting for your review.")).toBeTruthy();
  });

  it("approves exactly the version and hash on screen", async () => {
    serve([rb("b", "bob", "pending")]);
    render(<TenantRunbooks />);
    fireEvent.click(await screen.findByRole("button", { name: "Approve" }));
    await waitFor(() => expect(runbookAct).toHaveBeenCalled());
    expect(runbookAct).toHaveBeenCalledWith("b", "approve", { version: 1, body_sha256: "sha-b", reason: "" });
  });

  it("shows failing cases in plain language and changes nothing", async () => {
    serve([rb("c", "alice", "draft")]);
    runbookAct.mockRejectedValue(
      new Error('422 Unprocessable Entity: {"error":"the runbook\'s cases did not pass","problems":[{"case":"logs naming the carrier","message":"the verdict did not hold"}]}'),
    );
    render(<TenantRunbooks />);
    fireEvent.click(await screen.findByRole("button", { name: "Send for review" }));
    const list = await screen.findByTestId("rbk-problems");
    expect(list.textContent).toContain("logs naming the carrier");
    expect(list.textContent).toContain("the verdict did not hold");
    expect(screen.getByRole("alert").textContent).toMatch(/nothing was changed/i);
  });

  it("renders runbook text as text, never markup", async () => {
    serve([rb("d", "bob", "pending", { skill_md: "<img src=x onerror=alert(1)>" })]);
    const { container } = render(<TenantRunbooks />);
    await screen.findByText("<img src=x onerror=alert(1)>");
    expect(container.querySelector("img")).toBeNull();
  });

  it("offers a re-check only for a runbook the platform outgrew", async () => {
    serve([
      rb("e", "alice", "active", { approver: "bob" }, { runs_in_iris: true }),
      rb("f", "alice", "active", { approver: "bob" }, { needs_recheck: true }),
    ]);
    runbookRecheck.mockResolvedValue({ version: 1, passed: true, already_current: false, cases: 2, problems: [] });
    render(<TenantRunbooks />);
    const status = await screen.findByTestId("rbk-status");
    expect(status.textContent).toContain("rb-e (version 1) — Iris can run it");
    expect(status.textContent).toContain("rb-f (version 1) — not running");
    const buttons = screen.getAllByRole("button", { name: "Re-run its cases" });
    expect(buttons).toHaveLength(1);
    fireEvent.click(buttons[0]);
    await waitFor(() => expect(runbookRecheck).toHaveBeenCalledWith("f"));
    await screen.findByText("Its cases pass again. Iris runs it.");
  });

  it("refuses a name the server would refuse before sending anything", async () => {
    serve([]);
    render(<TenantRunbooks />);
    const name = await screen.findByPlaceholderText("my-wan-check");
    fireEvent.change(name, { target: { value: "Bad Name" } });
    expect((screen.getByRole("button", { name: "Save draft" }) as HTMLButtonElement).disabled).toBe(true);
  });
});

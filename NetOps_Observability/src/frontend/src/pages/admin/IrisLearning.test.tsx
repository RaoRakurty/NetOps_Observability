// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// IrisLearning.test.tsx — Administration → Iris → Learning (N-F5).
//
// What has to hold: a suggestion with parts still to fill in cannot be
// adopted; adopting sends only what the person changed; the person who adopted
// a suggestion is never offered "Approve" on it, a second administrator is;
// a runbook is approved on its own page, never here; an operator's note is
// shown as a quote for the reviewer, as TEXT; dismissing needs a reason.

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, cleanup, fireEvent, waitFor } from "@testing-library/react";

const learning = vi.fn();
const learningRefresh = vi.fn();
const learningAdopt = vi.fn();
const learningApprove = vi.fn();
const learningDismiss = vi.fn();

vi.mock("../../services/api", () => ({
  api: {
    learning: (...a: unknown[]) => learning(...a),
    learningRefresh: (...a: unknown[]) => learningRefresh(...a),
    learningAdopt: (...a: unknown[]) => learningAdopt(...a),
    learningApprove: (...a: unknown[]) => learningApprove(...a),
    learningDismiss: (...a: unknown[]) => learningDismiss(...a),
  },
}));

import IrisLearning from "./IrisLearning";

function proposal(id: string, extra: Record<string, unknown> = {}) {
  return {
    id,
    target: "org_context",
    generator: "resolution_pattern",
    subject: `resolution|${id}`,
    title: `cEdge-80: 3 incidents fixed by a ticket with the provider (${id})`,
    why: "Operators recorded the same fix for 3 incidents.",
    context: {
      scope: "tenant",
      kind: "carrier_relationship",
      key: "cEdge-80 provider",
      body: "cEdge-80: 3 incidents were fixed by a ticket with the provider. The circuit is {{circuit id}}.",
    },
    evidence: [
      { kind: "resolution", ref: "case-1", at: "2026-11-13T09:00:00Z", label: "Case fixed by a ticket", quote: "<b>Carrier X</b> ticket 4411" },
    ],
    evidence_count: 3,
    state: "proposed",
    created_at: "2026-11-13T09:00:00Z",
    updated_at: "2026-11-13T09:00:00Z",
    ...extra,
  };
}

function serve(list: unknown[], you = "alice") {
  learning.mockResolvedValue({
    proposals: list,
    you,
    limits: { proposals: 200, open: 50 },
    thresholds: { resolutions: 3, alias_people: 2, misses: 5 },
  });
}

beforeEach(() => {
  for (const f of [learning, learningRefresh, learningAdopt, learningApprove, learningDismiss]) f.mockReset();
});
afterEach(() => cleanup());

describe("IrisLearning", () => {
  it("does not adopt a draft with parts still to fill in, and sends only what changed", async () => {
    serve([proposal("p1")]);
    learningAdopt.mockResolvedValue(proposal("p1", { state: "adopted" }));
    render(<IrisLearning />);
    const adopt = await screen.findByRole("button", { name: "Adopt" });
    expect((adopt as HTMLButtonElement).disabled).toBe(true);
    const fact = screen.getByLabelText("Fact") as HTMLTextAreaElement;
    fireEvent.change(fact, { target: { value: "cEdge-80 rides circuit CX-7781 run by Carrier X." } });
    expect((adopt as HTMLButtonElement).disabled).toBe(false);
    fireEvent.click(adopt);
    await waitFor(() => expect(learningAdopt).toHaveBeenCalledTimes(1));
    expect(learningAdopt).toHaveBeenCalledWith("p1", { body: "cEdge-80 rides circuit CX-7781 run by Carrier X." });
  });

  it("never offers Approve to the person who adopted it; offers it to a second administrator", async () => {
    const adopted = proposal("p2", { state: "adopted", adopted_by: "alice", target_state: "pending" });
    serve([adopted], "alice");
    render(<IrisLearning />);
    expect(await screen.findByText("Another administrator approves this one.")).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Approve" })).toBeNull();
    cleanup();

    serve([adopted], "bob");
    learningApprove.mockResolvedValue({ ...adopted, state: "applied", target_state: "active" });
    render(<IrisLearning />);
    fireEvent.click(await screen.findByRole("button", { name: "Approve" }));
    await waitFor(() => expect(learningApprove).toHaveBeenCalledWith("p2"));
  });

  it("sends a runbook to its own page to be approved", async () => {
    serve(
      [
        proposal("p3", {
          target: "runbook",
          context: undefined,
          runbook: { name: "iris-gap-flow-top", skill_md: "---" },
          state: "adopted",
          adopted_by: "alice",
          target_state: "draft",
        }),
      ],
      "bob",
    );
    render(<IrisLearning />);
    expect(await screen.findByText("Approve it on the Runbooks page.")).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Approve" })).toBeNull();
  });

  it("shows an operator's note as a quote, as text", async () => {
    serve([proposal("p4")]);
    render(<IrisLearning />);
    const quote = await screen.findByTestId("lrn-quote");
    expect(quote.textContent).toContain("<b>Carrier X</b> ticket 4411");
    expect(quote.querySelector("b")).toBeNull();
    expect(quote.textContent).toContain("never sent to Iris");
  });

  it("needs a reason to dismiss", async () => {
    serve([proposal("p5")]);
    learningDismiss.mockResolvedValue(proposal("p5", { state: "dismissed", reason: "not ours" }));
    render(<IrisLearning />);
    const dismiss = await screen.findByRole("button", { name: "Dismiss" });
    expect((dismiss as HTMLButtonElement).disabled).toBe(true);
    fireEvent.change(screen.getByLabelText("Reason to dismiss"), { target: { value: "  not ours " } });
    fireEvent.click(dismiss);
    await waitFor(() => expect(learningDismiss).toHaveBeenCalledWith("p5", "not ours"));
  });
});

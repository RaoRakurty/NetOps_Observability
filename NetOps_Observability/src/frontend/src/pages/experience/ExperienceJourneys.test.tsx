// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// ExperienceJourneys.test.tsx — the journey editor edits the journey it says
// it is editing.
//
// The guarantee: opening Edit on one journey and then Edit on another must not
// carry the first one's values into the second one's save. A journey is the
// thing every other number on this surface is built on, so writing A's name,
// objective, value and step graph over B is a silent, durable data loss the
// operator has no way to see happen.

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, cleanup, fireEvent, waitFor } from "@testing-library/react";
import type { DemJourneyDefinition, DemJourneysResponse, DemTargetsResponse } from "../../services/api";

const mockApi = vi.hoisted(() => ({
  demJourneys: vi.fn(),
  demTargets: vi.fn(),
  demCreateJourney: vi.fn(),
  demUpdateJourney: vi.fn(),
  demDeleteJourney: vi.fn(),
}));

vi.mock("../../services/api", () => ({
  api: mockApi,
  DEM_BAND_GOOD_AT: 70,
  DEM_BAND_POOR_AT: 30,
}));

import ExperienceJourneys from "./ExperienceJourneys";

function journey(over: Partial<DemJourneyDefinition>): DemJourneyDefinition {
  return {
    id: "j-a", tenant_id: "t1", name: "Checkout", business_importance: "critical",
    business_value_per_success: 12, currency: "USD",
    entry_step_id: "s1",
    steps: [{ id: "s1", label: "Open basket", next: [], terminal_success: true }],
    slo: { success_pct: 99, latency_ms: 800, window: "1h" },
    version: 1, created_at: "2026-09-05T10:00:00Z", updated_at: "2026-09-05T10:00:00Z",
    ...over,
  };
}

const A = journey({ id: "j-a", name: "Checkout", slo: { success_pct: 99, latency_ms: 800, window: "1h" } });
const B = journey({
  id: "j-b", name: "Login", business_importance: "high", business_value_per_success: 3, currency: "EUR",
  entry_step_id: "b1",
  steps: [{ id: "b1", label: "Enter password", next: [], terminal_success: true }],
  slo: { success_pct: 95, latency_ms: 400, window: "1h" },
});

const JOURNEYS: DemJourneysResponse = {
  window: "1h", measured: true, journeys: [A, B], health: [], count: 2, limit: 100,
};
const TARGETS: DemTargetsResponse = { targets: [], count: 0, limit: 50, enabled: true };

afterEach(() => { cleanup(); vi.clearAllMocks(); });

beforeEach(() => {
  mockApi.demJourneys.mockResolvedValue(JOURNEYS);
  mockApi.demTargets.mockResolvedValue(TARGETS);
  mockApi.demUpdateJourney.mockResolvedValue({ journey: B });
});

async function openEditorFor(name: string) {
  const card = await screen.findByLabelText(`Journey ${name}`);
  fireEvent.click(within(card).getByRole("button", { name: "Edit" }));
  await screen.findByRole("heading", { name: `Edit ${name}` });
}

// `within` is imported separately to keep the helper above readable.
import { within } from "@testing-library/react";

describe("editing one journey after another", () => {
  it("saves the second journey's own values, never the first one's", async () => {
    render(<ExperienceJourneys window="1h" />);

    // Open A, and touch it the way an operator would before changing their mind.
    await openEditorFor("Checkout");
    fireEvent.change(screen.getByLabelText("Name"), { target: { value: "Checkout, renamed" } });
    fireEvent.change(screen.getByLabelText("Objective, success percent"), { target: { value: "42" } });

    // Straight to B without closing the editor first.
    await openEditorFor("Login");

    // The form must now be showing B, not A's edited values.
    expect((screen.getByLabelText("Name") as HTMLInputElement).value).toBe("Login");
    expect((screen.getByLabelText("Objective, success percent") as HTMLInputElement).value).toBe("95");
    expect((screen.getByLabelText("Step id") as HTMLInputElement).value).toBe("b1");

    const save = screen.getByRole("button", { name: "Save changes" }) as HTMLButtonElement;
    expect(save.disabled).toBe(false);
    fireEvent.submit(save.closest("form")!);
    await waitFor(() => expect(mockApi.demUpdateJourney).toHaveBeenCalled());

    const [id, body] = mockApi.demUpdateJourney.mock.calls[0];
    expect(id).toBe("j-b");
    expect(body.name).toBe("Login");
    expect(body.slo.success_pct).toBe(95);
    expect(body.business_value_per_success).toBe(3);
    expect(body.currency).toBe("EUR");
    expect(body.entry_step_id).toBe("b1");
    expect(body.steps.map((s: { id: string }) => s.id)).toEqual(["b1"]);
  });

  it("starts a new declaration empty after an edit, and never as the edited journey", async () => {
    render(<ExperienceJourneys window="1h" />);
    await openEditorFor("Checkout");
    fireEvent.change(screen.getByLabelText("Name"), { target: { value: "Checkout, renamed" } });

    fireEvent.click(screen.getByRole("button", { name: "Declare a journey" }));
    await screen.findByRole("heading", { name: "Declare a journey" });
    expect((screen.getByLabelText("Name") as HTMLInputElement).value).toBe("");
  });
});

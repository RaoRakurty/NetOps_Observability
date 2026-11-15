// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import IrisTriggers, { runOutcome } from "./IrisTriggers";
import { api, type InvestigationTriggerOverview, type InvestigationTriggerRun } from "../services/api";

afterEach(() => vi.restoreAllMocks());

const overview = (over: Partial<InvestigationTriggerOverview> = {}): InvestigationTriggerOverview => ({
  settings: { enabled: false, max_runs_per_day: 20, max_tokens_per_day: 200000 },
  triggers: [],
  runs: [],
  tokens_today: 0,
  investigations_on: true,
  durable: true,
  limits: { max_triggers: 20, min_every_minutes: 15, max_every_minutes: 1440, max_runs_per_day: 100, max_tokens_per_day: 1000000 },
  ...over,
});

const run = (over: Partial<InvestigationTriggerRun>): InvestigationTriggerRun => ({
  id: "r1", trigger_id: "t1", trigger_name: "Critical BGP", status: "done", tokens: 0,
  started_at: "2026-11-14T10:00:00Z", ...over,
});

describe("IrisTriggers", () => {
  it("adds an incident trigger with the admin's conditions", async () => {
    vi.spyOn(api, "investigationTriggers").mockResolvedValue(overview());
    const create = vi.spyOn(api, "createInvestigationTrigger").mockResolvedValue({
      id: "t1", name: "Critical BGP", kind: "incident", enabled: true, filter: { min_severity: "critical", signature: "bgp" },
      schedule: { every_minutes: 0 }, created_by: "carol", created_at: "", updated_at: "",
    });
    render(<IrisTriggers />);
    await waitFor(() => expect(screen.getByTestId("trigger-add")).toBeTruthy());
    expect(screen.getByText("No triggers yet.")).toBeTruthy();
    fireEvent.change(screen.getByLabelText("Trigger name"), { target: { value: " Critical BGP " } });
    fireEvent.change(screen.getByLabelText("Text in the incident"), { target: { value: "bgp" } });
    fireEvent.click(screen.getByRole("button", { name: "Add" }));
    await waitFor(() => expect(create).toHaveBeenCalledTimes(1));
    expect(create.mock.calls[0][0]).toMatchObject({
      name: "Critical BGP", kind: "incident", filter: { min_severity: "critical", signature: "bgp" },
    });
  });

  it("adds a schedule trigger with its interval", async () => {
    vi.spyOn(api, "investigationTriggers").mockResolvedValue(overview());
    const create = vi.spyOn(api, "createInvestigationTrigger").mockResolvedValue({} as never);
    render(<IrisTriggers />);
    await waitFor(() => expect(screen.getByTestId("trigger-add")).toBeTruthy());
    fireEvent.change(screen.getByLabelText("Trigger name"), { target: { value: "Hourly sweep" } });
    fireEvent.change(screen.getByLabelText("When it runs"), { target: { value: "schedule" } });
    fireEvent.change(screen.getByLabelText("Minutes between runs"), { target: { value: "30" } });
    fireEvent.click(screen.getByRole("button", { name: "Add" }));
    await waitFor(() => expect(create).toHaveBeenCalledTimes(1));
    expect(create.mock.calls[0][0]).toMatchObject({ kind: "schedule", schedule: { every_minutes: 30 }, filter: {} });
  });

  it("turns the workspace switch on with the caps", async () => {
    vi.spyOn(api, "investigationTriggers").mockResolvedValue(overview({ tokens_today: 1234 }));
    const save = vi.spyOn(api, "saveInvestigationTriggerSettings").mockResolvedValue({ enabled: true, max_runs_per_day: 5, max_tokens_per_day: 200000 });
    render(<IrisTriggers />);
    await waitFor(() => expect(screen.getByTestId("trigger-settings")).toBeTruthy());
    expect(screen.getByText(/1,234 used today/)).toBeTruthy();
    fireEvent.click(screen.getByLabelText(/Let Iris investigate on its own/));
    fireEvent.change(screen.getByLabelText("Runs per day"), { target: { value: "5" } });
    fireEvent.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(save).toHaveBeenCalledWith({ enabled: true, max_runs_per_day: 5, max_tokens_per_day: 200000 }));
  });

  it("shows runs with their outcome, server text escaped", async () => {
    vi.spyOn(api, "investigationTriggers").mockResolvedValue(overview({
      triggers: [{ id: "t1", name: "<i>Critical</i>", kind: "incident", enabled: false, filter: { min_severity: "error" },
        schedule: { every_minutes: 0 }, created_by: "c", created_at: "", updated_at: "" }],
      runs: [
        run({ id: "r1", reason: "concluded", summary: "Iris found a supported explanation." }),
        run({ id: "r2", status: "skipped", reason: "model_unavailable" }),
      ],
    }));
    const toggle = vi.spyOn(api, "setInvestigationTriggerEnabled").mockResolvedValue({} as never);
    render(<IrisTriggers />);
    await waitFor(() => expect(screen.getByTestId("trigger-runs")).toBeTruthy());
    expect(screen.getByText(/Explanation found/)).toBeTruthy();
    expect(screen.getByText(/Skipped — no AI model answered/)).toBeTruthy();
    expect(screen.getByText(/<i>Critical<\/i>/)).toBeTruthy();
    expect(document.querySelector("i")).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "Turn on" }));
    await waitFor(() => expect(toggle).toHaveBeenCalledWith("t1", true));
  });

  it("says what is missing instead of failing", async () => {
    vi.spyOn(api, "investigationTriggers").mockResolvedValue(overview({ investigations_on: false, durable: false }));
    render(<IrisTriggers />);
    await waitFor(() => expect(screen.getByTestId("triggers-need-investigations")).toBeTruthy());
    expect(screen.getByText(/a restart clears them/)).toBeTruthy();
  });

  it("tells a non-admin who sets it up", async () => {
    vi.spyOn(api, "investigationTriggers").mockRejectedValue(new Error("403 Forbidden: forbidden"));
    render(<IrisTriggers />);
    await waitFor(() => expect(screen.getByText(/Workspace admins set up triggered investigations/)).toBeTruthy());
  });

  it("names every run outcome", () => {
    expect(runOutcome(run({ status: "skipped", reason: "daily_run_cap" }))).toMatch(/daily run limit/);
    expect(runOutcome(run({ status: "skipped", reason: "daily_token_cap" }))).toMatch(/daily token limit/);
    expect(runOutcome(run({ status: "done", reason: "no_evidence" }))).toBe("Nothing to read");
    expect(runOutcome(run({ status: "failed" }))).toBe("Failed");
  });
});

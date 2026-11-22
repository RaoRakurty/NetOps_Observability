// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Integrations → Paging for problems: this tenant's own Microsoft Teams
// channel. The webhook is write-only (never shown, a blank save keeps it), the
// watch-alert choice defaults ON like Slack, and a refused save says so.

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, cleanup, waitFor, fireEvent } from "@testing-library/react";

const itsmConfig = vi.fn();
const saveItsmTeamsRCA = vi.fn();

vi.mock("../services/api", () => ({
  api: {
    itsmConfig: (...a: unknown[]) => itsmConfig(...a),
    saveItsmTeamsRCA: (...a: unknown[]) => saveItsmTeamsRCA(...a),
  },
}));
vi.mock("../components/AskIris", () => ({ default: () => null }));
vi.mock("../hooks/useAuth", () => ({
  useAuth: () => ({ user: { username: "tadmin", tenant_id: "acme" }, loading: false }),
}));

import { TeamsChannelConnection } from "./admin";

const cfg = (teams: Record<string, unknown> | undefined) => ({ servicenow: {}, jira: {}, ...(teams ? { teams } : {}) });

beforeEach(() => { itsmConfig.mockReset(); saveItsmTeamsRCA.mockReset(); });
afterEach(cleanup);

describe("Teams channel connection", () => {
  it("starts unset: disabled, watches ON, and saves the typed webhook once", async () => {
    itsmConfig.mockResolvedValue(cfg(undefined));
    saveItsmTeamsRCA.mockResolvedValue(cfg({ enabled: true, has_webhook: true, configured: true, watch_alerts: true }));
    render(<TeamsChannelConnection />);
    await waitFor(() => expect(itsmConfig).toHaveBeenCalled());
    const enabled = screen.getByRole("checkbox", { name: /enabled/i }) as HTMLInputElement;
    const watch = screen.getByRole("checkbox", { name: /post my own watches here/i }) as HTMLInputElement;
    expect(enabled.checked).toBe(false);
    expect(watch.checked).toBe(true);
    const url = screen.getByLabelText("Teams webhook URL") as HTMLInputElement;
    expect(url.type).toBe("password");
    fireEvent.click(enabled);
    fireEvent.change(url, { target: { value: "  https://contoso.webhook.office.com/webhookb2/x  " } });
    fireEvent.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(saveItsmTeamsRCA).toHaveBeenCalled());
    expect(saveItsmTeamsRCA.mock.calls[0][0]).toEqual({ enabled: true, watch_alerts: true, webhook_url: "https://contoso.webhook.office.com/webhookb2/x" });
    await screen.findByText("Saved.");
    expect(url.value).toBe(""); // never kept in the form after a save
    expect(screen.getByText(/webhook stored \(write-only\)/)).toBeTruthy();
  });

  it("a stored webhook is never sent back: a blank save keeps it and carries the opt-out", async () => {
    itsmConfig.mockResolvedValue(cfg({ enabled: true, has_webhook: true, configured: true, watch_alerts: true }));
    saveItsmTeamsRCA.mockResolvedValue(cfg({ enabled: true, has_webhook: true, configured: true, watch_alerts: false }));
    render(<TeamsChannelConnection />);
    const watch = await screen.findByRole("checkbox", { name: /post my own watches here/i }) as HTMLInputElement;
    await waitFor(() => expect((screen.getByRole("checkbox", { name: /enabled/i }) as HTMLInputElement).checked).toBe(true));
    expect((screen.getByLabelText("Teams webhook URL") as HTMLInputElement).placeholder).toMatch(/leave blank to keep it/);
    fireEvent.click(watch);
    fireEvent.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(saveItsmTeamsRCA).toHaveBeenCalled());
    expect(saveItsmTeamsRCA.mock.calls[0][0]).toEqual({ enabled: true, watch_alerts: false });
    await waitFor(() => expect(watch.checked).toBe(false));
  });

  it("a refused save is said, in the operator's words", async () => {
    itsmConfig.mockResolvedValue(cfg(undefined));
    saveItsmTeamsRCA.mockRejectedValue(new Error("Teams (RCA): webhook URL must be an https URL"));
    render(<TeamsChannelConnection />);
    await waitFor(() => expect(itsmConfig).toHaveBeenCalled());
    fireEvent.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(saveItsmTeamsRCA).toHaveBeenCalled());
    expect(await screen.findByRole("alert")).toBeTruthy();
    expect(screen.queryByText("Saved.")).toBeNull();
  });
});

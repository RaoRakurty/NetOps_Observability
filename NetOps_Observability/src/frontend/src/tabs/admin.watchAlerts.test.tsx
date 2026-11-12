// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Integrations → Paging and chat: the "my own watches" choice per lane
// (tracker 359). The server sends the EFFECTIVE value (Slack defaults on,
// PagerDuty off); the card shows it and saves the operator's choice back.

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, cleanup, waitFor, fireEvent } from "@testing-library/react";

const itsmConfig = vi.fn();
const saveItsmPagerDutyRCA = vi.fn();
const saveItsmSlackRCA = vi.fn();

vi.mock("../services/api", () => ({
  api: {
    itsmConfig: (...a: unknown[]) => itsmConfig(...a),
    saveItsmPagerDutyRCA: (...a: unknown[]) => saveItsmPagerDutyRCA(...a),
    saveItsmSlackRCA: (...a: unknown[]) => saveItsmSlackRCA(...a),
  },
}));
vi.mock("../components/AskIris", () => ({ default: () => null }));
vi.mock("../hooks/useAuth", () => ({
  useAuth: () => ({ user: { username: "tadmin", tenant_id: "acme" }, loading: false }),
}));

import { PagerDutyPagingConnection, SlackChannelConnection } from "./admin";

const cfg = (pdWatch: boolean, slackWatch: boolean) => ({
  servicenow: {}, jira: {},
  pagerduty: { enabled: true, has_routing_key: true, configured: true, watch_alerts: pdWatch },
  slack: { enabled: true, has_webhook: true, configured: true, watch_alerts: slackWatch },
});

beforeEach(() => {
  itsmConfig.mockReset(); saveItsmPagerDutyRCA.mockReset(); saveItsmSlackRCA.mockReset();
});
afterEach(cleanup);

describe("own-watch alerts on the tenant's lanes", () => {
  it("PagerDuty shows OFF by default and saves an explicit opt-in", async () => {
    itsmConfig.mockResolvedValue(cfg(false, true));
    saveItsmPagerDutyRCA.mockResolvedValue(cfg(true, true));
    render(<PagerDutyPagingConnection />);
    const box = await screen.findByRole("checkbox", { name: /page for my own watches/i });
    await waitFor(() => expect(itsmConfig).toHaveBeenCalled());
    expect((box as HTMLInputElement).checked).toBe(false);
    fireEvent.click(box);
    fireEvent.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(saveItsmPagerDutyRCA).toHaveBeenCalled());
    expect(saveItsmPagerDutyRCA.mock.calls[0][0]).toMatchObject({ enabled: true, watch_alerts: true });
    // The routing key is never echoed back into the form.
    expect(saveItsmPagerDutyRCA.mock.calls[0][0]).not.toHaveProperty("routing_key");
  });

  it("Slack shows ON by default and saves an explicit opt-out", async () => {
    itsmConfig.mockResolvedValue(cfg(false, true));
    saveItsmSlackRCA.mockResolvedValue(cfg(false, false));
    render(<SlackChannelConnection />);
    const box = await screen.findByRole("checkbox", { name: /post my own watches here/i });
    await waitFor(() => expect((box as HTMLInputElement).checked).toBe(true));
    fireEvent.click(box);
    fireEvent.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(saveItsmSlackRCA).toHaveBeenCalled());
    expect(saveItsmSlackRCA.mock.calls[0][0]).toMatchObject({ enabled: true, watch_alerts: false });
    await waitFor(() => expect((box as HTMLInputElement).checked).toBe(false));
  });
});

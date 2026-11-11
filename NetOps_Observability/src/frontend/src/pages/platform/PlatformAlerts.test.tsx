// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import type { PlatformAlertRoute } from "../../services/api";
import { draftFrom, isDirty, parseNumbers, routeBanner, toUpdate, validateDraft, receivesLine } from "./platformAlertsModel";

const route = (o: Partial<PlatformAlertRoute> = {}): PlatformAlertRoute => ({
  ntfy: { enabled: false, server: "https://ntfy.sh", topic: "", token_set: false, tiers: { page: true, warning: true } },
  sms: { enabled: false, account_sid: "", auth_token_set: false, from: "", to: [], tiers: { page: true, warning: false }, max_per_hour: 10 },
  page_routed: false,
  warning_routed: false,
  store_status: "ok",
  ignored_env: [],
  sms_budget_remaining: -1,
  ...o,
});

const sid = "AC" + "a1".repeat(16);

const apiMock = vi.hoisted(() => ({
  platformAlertRoute: vi.fn(),
  savePlatformAlertRoute: vi.fn(),
  testPlatformAlertRoute: vi.fn(),
}));
vi.mock("../../services/api", () => ({ api: apiMock }));

import PlatformAlerts from "./PlatformAlerts";
import { PlatformAlertsNotice } from "../../components/PlatformAlertsNotice";

describe("platformAlertsModel", () => {
  it("parses numbers typed one per line or with commas", () => {
    expect(parseNumbers("+14155550100\n+14155550101, +14155550102 ;")).toEqual(["+14155550100", "+14155550101", "+14155550102"]);
  });

  it("refuses the obvious mistakes with the server's sentences", () => {
    const base = route();
    const d = draftFrom(base);
    d.ntfy.enabled = true;
    expect(validateDraft(d, base)).toMatch(/enter a topic/);
    d.ntfy.topic = "bad topic";
    expect(validateDraft(d, base)).toMatch(/letters, digits/);
    d.ntfy.topic = "corr-ok";
    d.ntfy.server = "http://ntfy.sh";
    expect(validateDraft(d, base)).toMatch(/https:\/\//);
    d.ntfy.server = "https://ntfy.sh";
    expect(validateDraft(d, base)).toBeNull();
    d.sms.enabled = true;
    expect(validateDraft(d, base)).toMatch(/To turn on text messages/);
    d.sms.accountSid = sid;
    d.sms.authToken = "placeholder-" + "x".repeat(16);
    d.sms.from = "+14155550199";
    d.sms.toText = "4155550100";
    expect(validateDraft(d, base)).toMatch(/international format/);
    d.sms.toText = "+14155550100\n+14155550100";
    expect(validateDraft(d, base)).toMatch(/without repeats/);
    d.sms.toText = "+14155550100";
    d.sms.maxPerHour = "0";
    expect(validateDraft(d, base)).toMatch(/limit must be between/);
    d.sms.maxPerHour = "10";
    expect(validateDraft(d, base)).toBeNull();
  });

  it("keeps a saved secret when the field is left empty, and clears it only when asked", () => {
    const saved = route({ sms: { ...route().sms, enabled: true, account_sid: sid, auth_token_set: true, from: "+14155550199", to: ["+14155550100"] } });
    const d = draftFrom(saved);
    expect(d.sms.authToken).toBe("");
    expect(validateDraft(d, saved)).toBeNull(); // the saved token counts
    const u = toUpdate(d);
    expect(u.sms.auth_token).toBe("");
    expect(u.sms.clear_auth_token).toBe(false);
    d.sms.clearAuthToken = true;
    expect(validateDraft(d, saved)).toMatch(/auth token/);
    expect(toUpdate(d).sms.clear_auth_token).toBe(true);
  });

  it("knows when the form differs from what is saved", () => {
    const saved = route();
    const d = draftFrom(saved);
    expect(isDirty(d, saved)).toBe(false);
    d.ntfy.topic = "x";
    expect(isDirty(d, saved)).toBe(true);
  });

  it("puts 'reaches nobody' in the banner", () => {
    expect(routeBanner(route())).toMatch(/reach nobody/);
    expect(routeBanner(route({ page_routed: true }))).toBeNull();
    expect(routeBanner(route({ page_routed: true, store_status: "unreadable" }))).toMatch(/could not be read/);
    expect(receivesLine({ page: true, warning: false })).toBe("Receives pages only.");
  });
});

describe("Platform alerts page", () => {
  beforeEach(() => {
    apiMock.platformAlertRoute.mockReset();
    apiMock.savePlatformAlertRoute.mockReset();
    apiMock.testPlatformAlertRoute.mockReset();
  });

  it("tells a non-platform administrator plainly, without failing", async () => {
    apiMock.platformAlertRoute.mockRejectedValue(new Error("403 Forbidden: forbidden"));
    render(<PlatformAlerts />);
    expect(await screen.findByText(/Only the platform administrator/)).toBeTruthy();
  });

  it("shows the reaches-nobody banner, the retired env, and the watchdog line", async () => {
    apiMock.platformAlertRoute.mockResolvedValue(route({ ignored_env: ["PLATFORM_ALERTS_NTFY_TOPIC"] }));
    render(<PlatformAlerts />);
    expect((await screen.findByTestId("platform-alerts-banner")).textContent).toMatch(/reach nobody/);
    expect(screen.getByTestId("ignored-env").textContent).toMatch(/PLATFORM_ALERTS_NTFY_TOPIC/);
    expect(screen.getByText(/host watchdog keeps its own settings/)).toBeTruthy();
  });

  it("never shows a saved secret, and saves without sending one back", async () => {
    const saved = route({ page_routed: true, ntfy: { ...route().ntfy, enabled: true, topic: "corr-a", token_set: true } });
    apiMock.platformAlertRoute.mockResolvedValue(saved);
    apiMock.savePlatformAlertRoute.mockResolvedValue({ ...saved, ntfy: { ...saved.ntfy, topic: "corr-b" } });
    const { container } = render(<PlatformAlerts />);
    const tokenField = (await screen.findByPlaceholderText(/Saved — leave empty to keep it/)) as HTMLInputElement;
    expect(tokenField.value).toBe("");
    expect(container.innerHTML).not.toMatch(/placeholder-/);
    const topic = screen.getByDisplayValue("corr-a");
    fireEvent.change(topic, { target: { value: "corr-b" } });
    fireEvent.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(apiMock.savePlatformAlertRoute).toHaveBeenCalledTimes(1));
    const body = apiMock.savePlatformAlertRoute.mock.calls[0][0];
    expect(body.ntfy.topic).toBe("corr-b");
    expect(body.ntfy.token).toBe("");
    expect(body.ntfy.clear_token).toBe(false);
    expect(await screen.findByText(/Saved. The new settings are in use now/)).toBeTruthy();
  });

  it("blocks a bad number before the round trip", async () => {
    apiMock.platformAlertRoute.mockResolvedValue(route());
    render(<PlatformAlerts />);
    fireEvent.click(await screen.findByRole("switch", { name: "Use text messages" }));
    fireEvent.click(screen.getByRole("button", { name: "Save" }));
    expect(await screen.findByText(/To turn on text messages/)).toBeTruthy();
    expect(apiMock.savePlatformAlertRoute).not.toHaveBeenCalled();
  });

  it("sends a test through the saved settings and shows the plain verdict", async () => {
    apiMock.platformAlertRoute.mockResolvedValue(route({ page_routed: true, ntfy: { ...route().ntfy, enabled: true, topic: "corr-a" } }));
    apiMock.testPlatformAlertRoute.mockResolvedValue({ channel: "ntfy", verdict: "auth_rejected", message: "The ntfy server refused access." });
    render(<PlatformAlerts />);
    fireEvent.click(await screen.findByRole("button", { name: "Send test push" }));
    expect((await screen.findByTestId("verdict-ntfy")).textContent).toBe("The ntfy server refused access.");
    expect(apiMock.testPlatformAlertRoute).toHaveBeenCalledWith("ntfy");
  });

  it("disables the test while there are unsaved changes", async () => {
    apiMock.platformAlertRoute.mockResolvedValue(route({ ntfy: { ...route().ntfy, enabled: true, topic: "corr-a" }, page_routed: true }));
    render(<PlatformAlerts />);
    fireEvent.change(await screen.findByDisplayValue("corr-a"), { target: { value: "corr-z" } });
    expect((screen.getByRole("button", { name: "Send test push" }) as HTMLButtonElement).disabled).toBe(true);
    expect(screen.getAllByText(/Save first/).length).toBe(2);
  });
});

describe("PlatformAlertsNotice", () => {
  // Braces matter: a function RETURNED from beforeEach is run as a teardown,
  // and mockReset() returns the mock itself.
  beforeEach(() => {
    apiMock.platformAlertRoute.mockReset();
  });

  it("renders nothing for anyone the route refuses", async () => {
    apiMock.platformAlertRoute.mockImplementation(() => Promise.reject(new Error("403 Forbidden: forbidden")));
    const { container } = render(<PlatformAlertsNotice />);
    await waitFor(() => expect(apiMock.platformAlertRoute).toHaveBeenCalled());
    expect(container.innerHTML).toBe("");
  });

  it("links the platform admin to the page when pages reach nobody", async () => {
    apiMock.platformAlertRoute.mockResolvedValue(route());
    render(<PlatformAlertsNotice />);
    const link = await screen.findByRole("link", { name: "Set up platform alerts" });
    expect(link.getAttribute("href")).toBe("#/platform/platform-alerts");
  });

  it("stays quiet once pages are routed", async () => {
    apiMock.platformAlertRoute.mockResolvedValue(route({ page_routed: true }));
    const { container } = render(<PlatformAlertsNotice />);
    await waitFor(() => expect(apiMock.platformAlertRoute).toHaveBeenCalled());
    expect(container.querySelector("[data-testid=platform-alerts-notice]")).toBeNull();
  });
});

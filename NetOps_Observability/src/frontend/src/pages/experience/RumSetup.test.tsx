// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

import { afterEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, within } from "@testing-library/react";
import RumSetup from "./RumSetup";
import { api } from "../../services/api";
import type { DemRumSourcesResponse } from "../../services/api";

const OK: DemRumSourcesResponse = {
  status: "ok", window_s: 86400, lookback_s: 604800, reporting: 1, quiet: 1, truncated: false,
  sources: [
    { app: "hr.example.com", app_source: "hostname", state: "quiet", events_24h: 0, page_views_24h: 0, errors_24h: 0, last_seen: "2026-11-20T10:00:00Z" },
    { app: "<b>checkout</b>", app_source: "attribute", state: "reporting", events_24h: 120, page_views_24h: 40, errors_24h: 3, last_seen: "2026-11-22T10:00:00Z" },
  ],
};

afterEach(() => vi.restoreAllMocks());

describe("RumSetup", () => {
  it("walks the four steps and lists which apps send data and which went quiet", async () => {
    vi.spyOn(api, "demRumSources").mockResolvedValue(OK);
    render(<RumSetup />);
    for (const h of ["Get a key", "The tag", "Add it once", "Is it working?"]) {
      expect(screen.getByRole("heading", { name: h })).toBeTruthy();
    }
    expect(await screen.findByText("1 app is sending real-user data; 1 went quiet (nothing in the last 24 hours).")).toBeTruthy();
    const table = screen.getByRole("table", { name: "Apps sending real-user data" });
    expect(within(table).getByText("Went quiet")).toBeTruthy();
    expect(within(table).getByText("Named by its web address")).toBeTruthy();
    // An app name is text, never markup.
    expect(within(table).getByText("<b>checkout</b>")).toBeTruthy();
    expect(table.querySelector("b")).toBeNull();
  });

  it("generates a send-only key, shows it once, and puts it in the tag and the rules", async () => {
    vi.spyOn(api, "demRumSources").mockResolvedValue(OK);
    const create = vi.spyOn(api, "createApiKey").mockResolvedValue({ key: {} as never, secret: "cx_secret_123" });
    render(<RumSetup />);
    fireEvent.click(screen.getByRole("button", { name: "Generate a key" }));
    expect(await screen.findByLabelText("Ingest key")).toBeTruthy();
    expect(create).toHaveBeenCalledWith({ label: "Real-user monitoring", scopes: ["ingest:experience"] });
    expect(screen.getByLabelText("Real-user tag").textContent).toContain("data-key='cx_secret_123'");
    expect(screen.getByLabelText("NGINX rule").textContent).toContain("cx_secret_123");
  });

  it("tells a non-administrator who can create the key, instead of a raw error", async () => {
    vi.spyOn(api, "demRumSources").mockResolvedValue(OK);
    vi.spyOn(api, "createApiKey").mockRejectedValue(new Error("403 Forbidden: administration admin permission required"));
    render(<RumSetup />);
    fireEvent.click(screen.getByRole("button", { name: "Generate a key" }));
    expect((await screen.findByRole("alert")).textContent).toMatch(/Only an administrator can create keys/);
  });

  it("switches the rule shown per layer", async () => {
    vi.spyOn(api, "demRumSources").mockResolvedValue(OK);
    render(<RumSetup />);
    fireEvent.click(screen.getByRole("tab", { name: "Google Tag Manager" }));
    expect(screen.getByLabelText("Google Tag Manager rule").textContent).toContain("window.CorrelixRUM");
  });

  it("says the store could not be read, never 'nothing installed'", async () => {
    vi.spyOn(api, "demRumSources").mockResolvedValue({ ...OK, status: "unavailable", sources: [], reporting: 0, quiet: 0 });
    render(<RumSetup />);
    expect((await screen.findByTestId("rum-summary")).textContent).toMatch(/could not be read/);
  });

  it("names no deployment variable in anything a person reads", async () => {
    vi.spyOn(api, "demRumSources").mockResolvedValue(OK);
    const { container } = render(<RumSetup />);
    await screen.findByTestId("rum-summary");
    expect(container.textContent).not.toMatch(/CORS_ALLOWED_ORIGINS|\.env\b/);
  });

  it("links the allow step to the Cross-origin access setting (tracker 439)", async () => {
    vi.spyOn(api, "demRumSources").mockResolvedValue(OK);
    render(<RumSetup />);
    const step = screen.getByTestId("rum-cors-step");
    const link = step.querySelector("a");
    expect(link?.getAttribute("href")).toBe("#/platform/cors-origins");
    expect(step.textContent).toMatch(/Cross-origin access/);
  });
});

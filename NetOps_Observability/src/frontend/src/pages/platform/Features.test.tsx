// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import type { PlatformFeature, PlatformFeatures } from "../../services/api";
import { groupFeatures, sourceLine, pendingLine, applyLabel } from "./featuresModel";

const feat = (o: Partial<PlatformFeature>): PlatformFeature => ({
  env: "FEATURE_X", label: "X", group: "Collection", help: "Does X.", apply: "live", risky: false,
  running: false, desired: false, restart_pending: false, source: "default", install_value: null, ...o,
});

const apiMock = vi.hoisted(() => ({
  platformFeatures: vi.fn(),
  setPlatformFeature: vi.fn(),
  restartPlatform: vi.fn(),
  // The Connect-a-model step (tracker 337 C4) has its own tests
  // (src/iris/ConnectModelStep.test.tsx); here it is a non-admin's 403.
  copilotConfig: vi.fn(() => Promise.reject(new Error("403"))),
  // The platform-alerts notice has its own tests (PlatformAlerts.test.tsx).
  platformAlertRoute: vi.fn(() => Promise.reject(new Error("403"))),
}));
vi.mock("../../services/api", () => ({ api: apiMock }));

import Features from "./Features";

describe("featuresModel", () => {
  it("groups in server order", () => {
    const g = groupFeatures([feat({ env: "A", group: "Collection" }), feat({ env: "B", group: "Discovery" }), feat({ env: "C", group: "Collection" })]);
    expect(g.map((x) => x.name)).toEqual(["Collection", "Discovery"]);
    expect(g[0].features.map((f) => f.env)).toEqual(["A", "C"]);
  });
  it("says where a value came from, in plain words", () => {
    expect(sourceLine(feat({ source: "install", install_value: true }), (s) => s)).toBe("Set at install (on).");
    expect(sourceLine(feat({ source: "console", updated_by: "admin", updated_at: "T" }), (s) => s)).toBe("Changed here by admin on T.");
    expect(sourceLine(feat({}), (s) => s)).toMatch(/default/);
  });
  it("never shows a restart-class change as running before the restart", () => {
    expect(pendingLine(feat({ apply: "restart", running: true, desired: false, restart_pending: true }))).toBe("Running on now; off after restart.");
    expect(pendingLine(feat({}))).toBeNull();
    expect(applyLabel(feat({ apply: "restart" }))).toBe("Applies after restart");
  });
});

describe("Features page", () => {
  const data = (o: Partial<PlatformFeatures> = {}, features: PlatformFeature[] = []): PlatformFeatures => ({
    features, restart_pending: false, can_restart: true, store_load_error: "", ...o,
  });
  beforeEach(() => {
    apiMock.platformFeatures.mockReset();
    apiMock.setPlatformFeature.mockReset();
    apiMock.restartPlatform.mockReset();
  });

  it("asks before turning on a risky feature, and sends the acknowledgement", async () => {
    apiMock.platformFeatures.mockResolvedValue(data({}, [feat({ env: "FEATURE_DEVICE_SSH", label: "SSH to devices", risky: true })]));
    apiMock.setPlatformFeature.mockResolvedValue({});
    render(<Features />);
    fireEvent.click(await screen.findByRole("switch", { name: "SSH to devices" }));
    expect(apiMock.setPlatformFeature).not.toHaveBeenCalled();
    fireEvent.click(await screen.findByRole("button", { name: "Turn on" }));
    await waitFor(() => expect(apiMock.setPlatformFeature).toHaveBeenCalledWith("FEATURE_DEVICE_SSH", true, "FEATURE_DEVICE_SSH"));
  });

  it("locks an AI switch the licence does not cover, and says which add-on it needs", async () => {
    apiMock.platformFeatures.mockResolvedValue(data({}, [feat({
      env: "IRIS_AI_MODELS", label: "Iris AI models", group: "Iris AI", risky: true, console_only: true,
      requires: "iris_model", available: false, unavailable_reason: "not included",
    })]));
    render(<Features />);
    const sw = await screen.findByRole("switch", { name: "Iris AI models" });
    expect(sw).toBeDisabled();
    expect(screen.getByTestId("feature-locked-IRIS_AI_MODELS").textContent).toMatch(/Iris AI add-on/);
    expect(screen.getByText(/Set on this page only/)).toBeTruthy();
  });

  it("asks before sending data to the AI provider, in those words", async () => {
    apiMock.platformFeatures.mockResolvedValue(data({}, [feat({
      env: "IRIS_AI_MODELS", label: "Iris AI models", risky: true, console_only: true, requires: "iris_model", available: true,
    })]));
    apiMock.setPlatformFeature.mockResolvedValue({});
    render(<Features />);
    fireEvent.click(await screen.findByRole("switch", { name: "Iris AI models" }));
    expect(await screen.findByText(/sent to the AI provider/)).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Turn on" }));
    await waitFor(() => expect(apiMock.setPlatformFeature).toHaveBeenCalledWith("IRIS_AI_MODELS", true, "IRIS_AI_MODELS"));
  });

  it("lets a locked switch that was on be turned off", async () => {
    apiMock.platformFeatures.mockResolvedValue(data({}, [feat({
      env: "IRIS_AI_MODELS", label: "Iris AI models", risky: true, requires: "iris_model", available: false, desired: true,
    })]));
    apiMock.setPlatformFeature.mockResolvedValue({});
    render(<Features />);
    const sw = await screen.findByRole("switch", { name: "Iris AI models" });
    expect(sw).not.toBeDisabled();
    expect(screen.getByTestId("feature-locked-IRIS_AI_MODELS").textContent).toMatch(/come back on/);
    fireEvent.click(sw);
    await waitFor(() => expect(apiMock.setPlatformFeature).toHaveBeenCalledWith("IRIS_AI_MODELS", false, undefined));
  });

  it("turns a feature off without asking", async () => {
    apiMock.platformFeatures.mockResolvedValue(data({}, [feat({ env: "FEATURE_DEVICE_SSH", label: "SSH to devices", risky: true, desired: true, running: true })]));
    apiMock.setPlatformFeature.mockResolvedValue({});
    render(<Features />);
    fireEvent.click(await screen.findByRole("switch", { name: "SSH to devices" }));
    await waitFor(() => expect(apiMock.setPlatformFeature).toHaveBeenCalledWith("FEATURE_DEVICE_SSH", false, undefined));
  });

  it("offers a restart only when the install can restart itself", async () => {
    const pending = feat({ env: "ENABLE_X", label: "X", apply: "restart", running: true, desired: false, restart_pending: true });
    apiMock.platformFeatures.mockResolvedValue(data({ restart_pending: true, can_restart: false }, [pending]));
    const { unmount } = render(<Features />);
    expect(await screen.findByText(/Restart the Correlix service from the host/)).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Restart now" })).toBeNull();
    expect(screen.getByText("Running on now; off after restart.")).toBeTruthy();
    unmount();
    apiMock.platformFeatures.mockResolvedValue(data({ restart_pending: true, can_restart: true }, [pending]));
    apiMock.restartPlatform.mockResolvedValue({ status: "restarting" });
    render(<Features />);
    fireEvent.click(await screen.findByRole("button", { name: "Restart now" }));
    expect(await screen.findByText(/Restarting Correlix/)).toBeTruthy();
  });

  it("tells a non-owner plainly", async () => {
    apiMock.platformFeatures.mockRejectedValue(new Error("403 Forbidden: platform administrator required"));
    render(<Features />);
    expect(await screen.findByText(/Only the platform administrator/)).toBeTruthy();
  });
});

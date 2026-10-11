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

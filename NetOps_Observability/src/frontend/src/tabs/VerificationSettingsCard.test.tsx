// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// VerificationSettingsCard.test.tsx — Administration → Settings → Active verification.
//
// The four things that can go wrong on a settings card holding a credential,
// and one test each:
//
//   1. A SECRET LEAKING. The stored one is write-only, so the card may only say
//      whether one exists; a typed one must leave component state the moment the
//      server accepts it, and must never reach the console.
//   2. A SAVE SENDING MORE THAN THE OPERATOR CHANGED. The PUT is a patch: the
//      opt-in toggle sends the opt-in and nothing else, and an untouched
//      password field sends no password key at all.
//   3. UNKNOWN RENDERING AS OFF. When the stored config could not be read, the
//      values shown are not the stored state — the card says so and refuses to
//      write over a configuration nobody has seen.
//   4. A REFUSED SAVE COSTING THE OPERATOR THEIR TYPING.

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, cleanup, fireEvent, waitFor } from "@testing-library/react";
import { scanCopy } from "../copyVoice.test";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import type { VerificationSettings } from "../services/api";

const mockApi = vi.hoisted(() => ({
  verificationSettings: vi.fn(),
  setVerificationSettings: vi.fn(),
}));
vi.mock("../services/api", () => ({ api: mockApi }));

import { VerificationSettingsForm } from "./VerificationSettingsCard";

const stored = (over: Partial<VerificationSettings> = {}): VerificationSettings => ({
  tenant_id: "t-1",
  enabled: false,
  feature: true,
  ssh_configured: false,
  ssh_user: "",
  ssh_port: 0,
  ...over,
});

beforeEach(() => {
  mockApi.verificationSettings.mockReset();
  mockApi.setVerificationSettings.mockReset();
});
afterEach(cleanup);

const SECRET = "correct-horse-battery-staple";

describe("VerificationSettingsCard", () => {
  it("reads the tenant's settings from /api/settings/verification on mount", async () => {
    mockApi.verificationSettings.mockResolvedValue(stored());
    render(<VerificationSettingsForm />);
    await waitFor(() => expect(mockApi.verificationSettings).toHaveBeenCalledTimes(1));
  });

  it("sends only the opt-in when only the opt-in changed", async () => {
    mockApi.verificationSettings.mockResolvedValue(stored());
    mockApi.setVerificationSettings.mockResolvedValue(stored({ enabled: true }));
    render(<VerificationSettingsForm />);
    const box = await screen.findByLabelText("Verify cases against this tenant's devices");
    fireEvent.click(box);
    fireEvent.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(mockApi.setVerificationSettings).toHaveBeenCalledWith({ enabled: true }));
  });

  it("sends a typed password and no other secret key", async () => {
    mockApi.verificationSettings.mockResolvedValue(stored({ ssh_user: "netops" }));
    mockApi.setVerificationSettings.mockResolvedValue(stored({ ssh_user: "netops", ssh_configured: true }));
    render(<VerificationSettingsForm />);
    fireEvent.change(await screen.findByLabelText("SSH password"), { target: { value: SECRET } });
    fireEvent.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(mockApi.setVerificationSettings).toHaveBeenCalledTimes(1));
    const body = mockApi.setVerificationSettings.mock.calls[0][0];
    expect(body).toEqual({ ssh_password: SECRET });
    expect("ssh_private_key" in body).toBe(false);
    expect("ssh_passphrase" in body).toBe(false);
  });

  it("clears the stored sign-in on its own request", async () => {
    mockApi.verificationSettings.mockResolvedValue(stored({ ssh_configured: true, ssh_user: "netops" }));
    mockApi.setVerificationSettings.mockResolvedValue(stored());
    render(<VerificationSettingsForm />);
    fireEvent.click(await screen.findByRole("button", { name: "Remove the stored sign-in" }));
    await waitFor(() => expect(mockApi.setVerificationSettings).toHaveBeenCalledWith({ clear_ssh: true }));
  });

  it("drops a typed secret from the form once the server accepts it, and never logs it", async () => {
    const log = vi.spyOn(console, "log").mockImplementation(() => {});
    const errLog = vi.spyOn(console, "error").mockImplementation(() => {});
    mockApi.verificationSettings.mockResolvedValue(stored());
    mockApi.setVerificationSettings.mockResolvedValue(stored({ ssh_configured: true }));
    const { container } = render(<VerificationSettingsForm />);
    const pw = await screen.findByLabelText("SSH password");
    fireEvent.change(pw, { target: { value: SECRET } });
    fireEvent.click(screen.getByRole("button", { name: "Save" }));
    await screen.findByText("Saved.");
    expect((screen.getByLabelText("SSH password") as HTMLInputElement).value).toBe("");
    expect(container.innerHTML).not.toContain(SECRET);
    for (const spy of [log, errLog]) {
      for (const call of spy.mock.calls) {
        expect(JSON.stringify(call)).not.toContain(SECRET);
      }
    }
    log.mockRestore();
    errLog.mockRestore();
  });

  it("keeps the typed values and shows an operator sentence when the save is refused", async () => {
    mockApi.verificationSettings.mockResolvedValue(stored());
    mockApi.setVerificationSettings.mockRejectedValue(new Error('400 Bad Request: {"error":"ssh_port out of range"}'));
    render(<VerificationSettingsForm />);
    fireEvent.change(await screen.findByLabelText("SSH user"), { target: { value: "netops" } });
    fireEvent.click(screen.getByRole("button", { name: "Save" }));
    expect(await screen.findByText(/out of range/i)).toBeTruthy();
    expect((screen.getByLabelText("SSH user") as HTMLInputElement).value).toBe("netops");
  });

  it("refuses a port outside the server's range before the round trip", async () => {
    mockApi.verificationSettings.mockResolvedValue(stored());
    render(<VerificationSettingsForm />);
    fireEvent.change(await screen.findByLabelText("SSH port"), { target: { value: "70000" } });
    fireEvent.click(screen.getByRole("button", { name: "Save" }));
    await screen.findByText(/between 0 and 65535/);
    expect(mockApi.setVerificationSettings).not.toHaveBeenCalled();
  });

  it("says the sign-in exists without describing it", async () => {
    mockApi.verificationSettings.mockResolvedValue(
      stored({ ssh_configured: true, ssh_user: "netops", ssh_port: 2222 }),
    );
    render(<VerificationSettingsForm />);
    expect(await screen.findByText(/A sign-in is stored as netops on port 2222/)).toBeTruthy();
    // The password field carries the same promise, so both matches are expected.
    expect(screen.getAllByText(/never shown again/).length).toBeGreaterThan(0);
  });

  it("renders an unreadable configuration as unknown and refuses to write over it", async () => {
    mockApi.verificationSettings.mockResolvedValue(
      stored({
        enabled: true,
        config_unavailable: true,
        config_error: "stored verification config could not be read — settings shown are not the stored state",
      }),
    );
    render(<VerificationSettingsForm />);
    // The run-state line says the state is unknown, and the alert repeats the
    // server's own reason — neither renders as a deliberate "off".
    expect(await screen.findByText(/so this state is unknown/)).toBeTruthy();
    const alert = screen.getByText(/settings shown are not the stored state/);
    expect(alert.getAttribute("role")).toBe("alert");
    expect((screen.getByLabelText("Verify cases against this tenant's devices") as HTMLInputElement).disabled).toBe(true);
    expect((screen.getByRole("button", { name: "Save" }) as HTMLButtonElement).disabled).toBe(true);
  });

  it("keeps the tenant opt-in and the platform capability apart", async () => {
    mockApi.verificationSettings.mockResolvedValue(stored({ feature: false, enabled: true }));
    render(<VerificationSettingsForm />);
    expect(await screen.findByText(/has not turned on active verification/)).toBeTruthy();
  });

  it("offers a retry, not an empty form, when the settings could not be read", async () => {
    mockApi.verificationSettings.mockRejectedValue(new Error("503 Service Unavailable"));
    render(<VerificationSettingsForm />);
    expect(await screen.findByRole("button", { name: "Read the settings again" })).toBeTruthy();
  });
});

describe("copy", () => {
  it("holds the NOC voice", () => {
    const here = dirname(fileURLToPath(import.meta.url));
    for (const f of ["VerificationSettingsCard.tsx", "../lib/verificationSettings.ts"]) {
      const src = readFileSync(join(here, f), "utf8");
      expect(scanCopy(src, join("tabs", f))).toEqual([]);
    }
  });
});

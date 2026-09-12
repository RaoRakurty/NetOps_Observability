// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// TwoFactorCard.test.tsx — self-service two-factor enrolment.
//
// WHAT IS ACTUALLY AT RISK HERE, and therefore what these tests assert:
//
//   1. THE CARD MUST NEVER SHOW A STATE THE SERVER DOES NOT HOLD. Every control
//      re-reads the status afterwards, so "on" on the screen means "on" in the
//      account. A card that showed a stale "on" after a failed turn-off would
//      leave an operator locked into a factor they think they removed.
//   2. THE SECRET IS TRANSIENT. It exists on screen for exactly one step, and is
//      gone from the DOM the moment activation succeeds.
//   3. THE QR IS DRAWN, NOT INJECTED. Real <svg>/<path> elements, and the source
//      may not contain dangerouslySetInnerHTML at all (CLAUDE.md §15, LLM02).
//   4. THE COPY IS HONEST. A federated account is told its provider owns the
//      factor and gets no controls; a status read that fails gets an operator
//      sentence, not the thrown envelope; and the card states that there are NO
//      recovery codes, because the platform issues none.
//   5. THE UI-WORDS SWEEP DID NOT COST A CLAIM (tracker 270). The teaching moved
//      to ai/skills/explain/auth.two-factor.md, auth.no-recovery-codes.md and
//      auth.provider-managed-mfa.md behind the (i), so every assertion below
//      pins the SHORT claim AND the "Ask Iris about …" button that carries the
//      rest. A state that quietly lost its (i) is a promise withdrawn.
//
// The route each control uses is asserted twice over: the card calls the typed
// helper, and the helper is checked against the path it posts to in
// services/api.ts — so a renamed route cannot pass by mocking.

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, cleanup, fireEvent, waitFor } from "@testing-library/react";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const mockApi = vi.hoisted(() => ({
  mfaStatus: vi.fn(),
  mfaSetup: vi.fn(),
  mfaActivate: vi.fn(),
  mfaDisable: vi.fn(),
}));

vi.mock("../services/api", () => ({ api: mockApi }));
vi.mock("./Icon", () => ({ default: () => <span /> }));

import TwoFactorCard from "./TwoFactorCard";

const HERE = dirname(fileURLToPath(import.meta.url));
const SECRET = "JBSWY3DPEHPK3PXP";
const URI =
  "otpauth://totp/Correlix:alice?secret=JBSWY3DPEHPK3PXP&issuer=Correlix&algorithm=SHA1&digits=6&period=30";

function status(over: Partial<{ enabled: boolean; pending: boolean; local: boolean }> = {}) {
  return { enabled: false, pending: false, local: true, ...over };
}

beforeEach(() => {
  vi.clearAllMocks();
  mockApi.mfaStatus.mockResolvedValue(status());
  mockApi.mfaSetup.mockResolvedValue({ secret: SECRET, uri: URI });
  mockApi.mfaActivate.mockResolvedValue({ enabled: true });
  mockApi.mfaDisable.mockResolvedValue({ enabled: false });
});

afterEach(cleanup);

/** Renders and waits for the status read to settle. */
async function open() {
  const view = render(<TwoFactorCard />);
  await waitFor(() => expect(mockApi.mfaStatus).toHaveBeenCalled());
  await waitFor(() => expect(screen.queryByText(/Reading two-factor state/i)).toBeNull());
  return view;
}

function typeCode(value: string) {
  const input = screen.getByLabelText(/Six-digit code/i);
  fireEvent.change(input, { target: { value } });
  return input;
}

// ── the states an operator can land in ───────────────────────────────────────

describe("TwoFactorCard — honest states", () => {
  it("reads the status once on open and says the factor is off", async () => {
    await open();
    expect(mockApi.mfaStatus).toHaveBeenCalledTimes(1);
    expect(screen.getByText(/two-factor authentication is off\. Sign-in asks for your password only\./i)).toBeTruthy();
    // The definition of a one-time code left the card; the (i) must carry it.
    expect(screen.getByRole("button", { name: "Ask Iris about Two-factor authentication" })).toBeTruthy();
    expect(screen.getByRole("button", { name: "Set up" })).toBeTruthy();
    expect(screen.queryByRole("button", { name: /turn off/i })).toBeNull();
  });

  it("a federated account is told its provider owns the factor, and gets no controls", async () => {
    mockApi.mfaStatus.mockResolvedValue(status({ local: false }));
    const { container } = await open();
    expect(screen.getByText(/managed by your identity provider, not here/i)).toBeTruthy();
    expect(screen.getByRole("button", { name: "Ask Iris about Managed by your identity provider" })).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Set up" })).toBeNull();
    expect(screen.queryByRole("button", { name: /turn off/i })).toBeNull();
    expect(container.querySelector("input")).toBeNull();
  });

  it("an unreadable status shows an operator sentence, never the thrown envelope", async () => {
    mockApi.mfaStatus.mockRejectedValue(
      new Error('500 Internal Server Error: {"error":"pq: dial tcp 10.0.0.5:5432: connection refused"}'),
    );
    const { container } = await open();
    const alert = screen.getByRole("alert");
    expect(alert.textContent).toBe("The service did not answer.");
    expect(container.textContent).not.toContain("10.0.0.5");
    expect(container.textContent).not.toContain("pq:");
    // The read is retryable rather than a dead end.
    fireEvent.click(screen.getByRole("button", { name: /try again/i }));
    await waitFor(() => expect(mockApi.mfaStatus).toHaveBeenCalledTimes(2));
  });

  it("a pending enrolment offers activation and a fresh start, without inventing a secret", async () => {
    mockApi.mfaStatus.mockResolvedValue(status({ pending: true }));
    const { container } = await open();
    expect(screen.getByText(/started and not finished/i)).toBeTruthy();
    expect(container.querySelector("svg")).toBeNull();   // no secret in hand, no code drawn
    expect(container.textContent).not.toContain(SECRET);

    fireEvent.click(screen.getByRole("button", { name: /start over/i }));
    await waitFor(() => expect(mockApi.mfaSetup).toHaveBeenCalledTimes(1));
    await waitFor(() => expect(screen.getByRole("img", { name: /enrolment code/i })).toBeTruthy());
  });

  it("an account with the factor on says so and asks for a code before removing it", async () => {
    mockApi.mfaStatus.mockResolvedValue(status({ enabled: true }));
    await open();
    expect(screen.getByText(/two-factor authentication is on\. Sign-in asks for a code\./i)).toBeTruthy();
    expect(screen.queryByLabelText(/six-digit code/i)).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "Turn off" }));
    expect(screen.getByLabelText(/six-digit code/i)).toBeTruthy();
    expect(screen.getByText(/needs a current code/i)).toBeTruthy();
  });

  it("states that there are no recovery codes and names the real recovery path", async () => {
    await open();
    // Shortened by the ui-words sweep, but the CONSEQUENCE is intact: no codes
    // exist, and losing the device costs an administrator reset.
    const note = screen.getByText(/no recovery codes/i);
    expect(note.textContent).toMatch(/an administrator resets two-factor/i);
    expect(note.textContent).toMatch(/if the device is lost/i);
    expect(screen.getByRole("button", { name: "Ask Iris about No recovery codes" })).toBeTruthy();
  });
});

// ── the routes each control uses ─────────────────────────────────────────────

describe("TwoFactorCard — each control calls its own route", () => {
  it("Set up posts the enrolment start and shows the code and the setup key", async () => {
    const { container } = await open();
    fireEvent.click(screen.getByRole("button", { name: "Set up" }));
    await waitFor(() => expect(mockApi.mfaSetup).toHaveBeenCalledTimes(1));
    expect(mockApi.mfaSetup).toHaveBeenCalledWith();

    const qr = await screen.findByRole("img", { name: /enrolment code/i });
    expect(qr.tagName.toLowerCase()).toBe("svg");
    expect(container.textContent).toContain(SECRET);
    expect(mockApi.mfaActivate).not.toHaveBeenCalled();
  });

  it("Turn on posts the typed code, then re-reads the status", async () => {
    await open();
    fireEvent.click(screen.getByRole("button", { name: "Set up" }));
    await screen.findByRole("img", { name: /enrolment code/i });

    typeCode("123456");
    mockApi.mfaStatus.mockResolvedValue(status({ enabled: true }));
    fireEvent.click(screen.getByRole("button", { name: /turn on two-factor/i }));

    await waitFor(() => expect(mockApi.mfaActivate).toHaveBeenCalledWith("123456"));
    await waitFor(() => expect(mockApi.mfaStatus).toHaveBeenCalledTimes(2));
    expect(await screen.findByText(/two-factor authentication is on\./i)).toBeTruthy();
  });

  it("Turn off posts the current code, then re-reads the status", async () => {
    mockApi.mfaStatus.mockResolvedValue(status({ enabled: true }));
    await open();
    fireEvent.click(screen.getByRole("button", { name: "Turn off" }));
    typeCode("654321");
    mockApi.mfaStatus.mockResolvedValue(status({ enabled: false }));
    fireEvent.click(screen.getByRole("button", { name: /turn off two-factor/i }));

    await waitFor(() => expect(mockApi.mfaDisable).toHaveBeenCalledWith("654321"));
    await waitFor(() => expect(mockApi.mfaStatus).toHaveBeenCalledTimes(2));
    expect(await screen.findByText(/two-factor authentication is off\./i)).toBeTruthy();
  });

  it("submits only a complete six-digit code", async () => {
    await open();
    fireEvent.click(screen.getByRole("button", { name: "Set up" }));
    await screen.findByRole("img", { name: /enrolment code/i });
    typeCode("12ab3");                                // letters are refused by the field
    expect((screen.getByLabelText(/six-digit code/i) as HTMLInputElement).value).toBe("123");
    expect((screen.getByRole("button", { name: /turn on two-factor/i }) as HTMLButtonElement).disabled).toBe(true);
    typeCode("123456");
    expect((screen.getByRole("button", { name: /turn on two-factor/i }) as HTMLButtonElement).disabled).toBe(false);
  });

  it("a refused code leaves the factor off and repeats the server's own reason", async () => {
    await open();
    fireEvent.click(screen.getByRole("button", { name: "Set up" }));
    await screen.findByRole("img", { name: /enrolment code/i });
    typeCode("000000");
    mockApi.mfaActivate.mockRejectedValue(
      new Error('400 Bad Request: {"error":"that code didn\'t match — check your authenticator and try again"}'),
    );
    fireEvent.click(screen.getByRole("button", { name: /turn on two-factor/i }));

    const alert = await screen.findByRole("alert");
    expect(alert.textContent).toMatch(/that code didn't match/i);
    expect(screen.getByRole("img", { name: /enrolment code/i })).toBeTruthy(); // still enrolling
  });

  it("the typed helpers post to the documented routes", () => {
    const src = readFileSync(join(HERE, "..", "services", "api.ts"), "utf-8");
    expect(src).toMatch(/mfaStatus:[^\n]*"\/api\/auth\/mfa\/status"/);
    expect(src).toMatch(/mfaSetup:[^\n]*"\/api\/auth\/mfa\/setup"[^\n]*method: "POST"/);
    expect(src).toMatch(/mfaActivate:[^\n]*"\/api\/auth\/mfa\/activate"[^\n]*method: "POST"/);
    expect(src).toMatch(/mfaDisable:[^\n]*"\/api\/auth\/mfa\/disable"[^\n]*method: "POST"/);
    // The code travels in the body, never in the URL.
    expect(src).toMatch(/mfaActivate:[^\n]*body: JSON\.stringify\(\{ code \}\)/);
    expect(src).toMatch(/mfaDisable:[^\n]*body: JSON\.stringify\(\{ code \}\)/);
  });
});

// ── the secret, and how the code is drawn ────────────────────────────────────

describe("TwoFactorCard — the secret is transient and the code is drawn, not injected", () => {
  it("the secret leaves the DOM as soon as the factor is on", async () => {
    const { container } = await open();
    fireEvent.click(screen.getByRole("button", { name: "Set up" }));
    await screen.findByRole("img", { name: /enrolment code/i });
    expect(container.textContent).toContain(SECRET);

    typeCode("123456");
    mockApi.mfaStatus.mockResolvedValue(status({ enabled: true }));
    fireEvent.click(screen.getByRole("button", { name: /turn on two-factor/i }));

    await screen.findByText(/two-factor authentication is on\./i);
    expect(container.textContent).not.toContain(SECRET);
    expect(container.innerHTML).not.toContain(SECRET);
    expect(container.querySelector("svg")).toBeNull();
  });

  it("the QR is real SVG elements with a title, not injected markup", async () => {
    const { container } = await open();
    fireEvent.click(screen.getByRole("button", { name: "Set up" }));
    const svg = await screen.findByRole("img", { name: /enrolment code/i });

    expect(svg.namespaceURI).toBe("http://www.w3.org/2000/svg");
    expect(svg.querySelector("title")?.textContent).toMatch(/enrolment code/i);
    const path = svg.querySelector("path");
    expect(path, "the modules are drawn as a path element").not.toBeNull();
    expect(path!.getAttribute("d") ?? "").toMatch(/^M\d+ \d+h\d+v1h-\d+z/);
    // Nothing in the symbol is markup the encoder produced.
    expect(path!.getAttribute("d")).not.toContain("<");
    // The URI is drawn, never linked or navigated to.
    expect(container.querySelector('a[href^="otpauth"]')).toBeNull();
    expect(container.innerHTML).not.toContain("otpauth://");
  });

  it("the component never injects HTML and never logs the secret", () => {
    const src = readFileSync(join(HERE, "TwoFactorCard.tsx"), "utf-8");
    expect(src).not.toMatch(/dangerouslySetInnerHTML|\.innerHTML/);
    expect(src).not.toMatch(/console\.\w+/);
  });
});

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// ErrorBoundary.test.tsx — the white-screen guard.
//
// What is pinned here is the contract an operator depends on when a route
// throws: they are TOLD which view failed, they can retry it, navigating away
// recovers on its own, and the report they can paste carries no stack and no
// credentials or addresses. A regression in any of those is either a blank
// console or a leak, so each has a test rather than a comment.

import { describe, it, expect, afterEach, beforeEach, vi } from "vitest";
import { render, screen, cleanup, fireEvent } from "@testing-library/react";
import ErrorBoundary, { redact, diagnosticText } from "./ErrorBoundary";

// React prints its own "The above error occurred in…" report for every caught
// error. Silencing it keeps the suite readable — and the spy doubles as proof
// that the boundary logs the stack to the console rather than to the screen.
let consoleSpy: ReturnType<typeof vi.spyOn>;
beforeEach(() => {
  consoleSpy = vi.spyOn(console, "error").mockImplementation(() => {});
});
afterEach(() => {
  consoleSpy.mockRestore();
  cleanup();
});

/** A child that throws on demand. `throws` is read at render time. */
function Boom({ throws, message }: { throws: boolean; message?: string }) {
  if (throws) throw new Error(message ?? "peers.map is not a function");
  return <div>live view</div>;
}

describe("ErrorBoundary — a throwing view degrades to a named panel", () => {
  it("catches a render exception and names the view that failed", () => {
    render(
      <ErrorBoundary label="Detection Rules">
        <Boom throws />
      </ErrorBoundary>,
    );
    expect(screen.getByRole("alert")).toBeTruthy();
    expect(screen.getByText("Detection Rules could not be displayed")).toBeTruthy();
    expect(screen.queryByText("live view")).toBeNull();
  });

  it("offers Try again, Reload this page and Copy report", () => {
    render(
      <ErrorBoundary label="Detection Rules">
        <Boom throws />
      </ErrorBoundary>,
    );
    expect(screen.getByRole("button", { name: "Try again" })).toBeTruthy();
    expect(screen.getByRole("button", { name: "Reload this page" })).toBeTruthy();
    expect(screen.getByRole("button", { name: "Copy report" })).toBeTruthy();
  });

  it("Try again clears the boundary and re-renders the view", () => {
    // The transient case the retry exists for: the same element renders again
    // and the second attempt succeeds (a read that had not landed the first
    // time). The condition lives OUTSIDE the element so the retry — which
    // re-renders the children the boundary already holds — can see it change.
    let failing = true;
    function Flaky() {
      if (failing) throw new Error("peers.map is not a function");
      return <div>live view</div>;
    }
    render(
      <ErrorBoundary label="Detection Rules">
        <Flaky />
      </ErrorBoundary>,
    );
    expect(screen.getByText("Detection Rules could not be displayed")).toBeTruthy();

    failing = false;
    fireEvent.click(screen.getByRole("button", { name: "Try again" }));
    expect(screen.getByText("live view")).toBeTruthy();
    expect(screen.queryByText("Detection Rules could not be displayed")).toBeNull();
  });

  it("recovers on navigation: a new route key clears a caught error", () => {
    const { rerender } = render(
      <ErrorBoundary label="Detection Rules" resetKey="security/rules">
        <Boom throws />
      </ErrorBoundary>,
    );
    expect(screen.getByText("Detection Rules could not be displayed")).toBeTruthy();

    // Navigating away — the shell hands the boundary the new route and the
    // healthy view for it. No operator action, no leftover fallback.
    rerender(
      <ErrorBoundary label="Devices" resetKey="infrastructure/devices">
        <Boom throws={false} />
      </ErrorBoundary>,
    );
    expect(screen.getByText("live view")).toBeTruthy();
    expect(screen.queryByRole("alert")).toBeNull();
  });

  it("sends the stack to the console and never to the screen", () => {
    render(
      <ErrorBoundary label="Detection Rules">
        <Boom throws message="peers.map is not a function" />
      </ErrorBoundary>,
    );
    const logged = consoleSpy.mock.calls.find((c) => c[0] === "[ui] view render error");
    expect(logged, "the boundary must log the failure").toBeTruthy();
    expect((logged?.[1] as { componentStack: string }).componentStack).toContain("Boom");

    const shown = screen.getByRole("alert").textContent ?? "";
    expect(shown).not.toContain("componentStack");
    expect(shown).not.toMatch(/\bat \w+ \(/);
  });

  it("copies the redacted report and confirms it", () => {
    const writeText = vi.fn(() => Promise.resolve());
    Object.defineProperty(navigator, "clipboard", { value: { writeText }, configurable: true });
    render(
      <ErrorBoundary label="Detection Rules" route="#/security/rules">
        <Boom throws message="peers.map is not a function" />
      </ErrorBoundary>,
    );
    fireEvent.click(screen.getByRole("button", { name: "Copy report" }));
    expect(writeText).toHaveBeenCalledTimes(1);
    const copied = String(writeText.mock.calls[0][0]);
    expect(copied).toContain("view: Detection Rules");
    expect(copied).toContain("route: #/security/rules");
    expect(screen.getByRole("button", { name: "Report copied" })).toBeTruthy();
  });

  it("renders a custom fallback when one is supplied (FrontPage panels)", () => {
    render(
      <ErrorBoundary label="This panel" fallback={() => <div>panel isolated</div>}>
        <Boom throws />
      </ErrorBoundary>,
    );
    expect(screen.getByText("panel isolated")).toBeTruthy();
    expect(screen.queryByText("This panel could not be displayed")).toBeNull();
  });

  it("passes healthy children straight through", () => {
    render(
      <ErrorBoundary label="Devices">
        <Boom throws={false} />
      </ErrorBoundary>,
    );
    expect(screen.getByText("live view")).toBeTruthy();
    expect(screen.queryByRole("alert")).toBeNull();
  });
});

describe("the report is safe to paste", () => {
  const err = new Error(
    'peers.map is not a function reading https://nms.corp.example/api?token=SGVsbG9Xb3JsZFNlY3JldEtleTEyMzQ1Ng from 10.42.7.19:9200 (api_key=sk-9f2b7c1d4e6a8b0c3d5e7f91)',
  );
  err.stack = "Error: peers.map is not a function\n    at Boom (/src/pages/security/SecurityRules.tsx:41:9)";
  const text = diagnosticText({ label: "Detection Rules", route: "#/security/rules", at: "2026-09-02T10:11:12.000Z", error: err });

  it("carries the four facts a support ticket needs", () => {
    expect(text).toContain("view: Detection Rules");
    expect(text).toContain("route: #/security/rules");
    expect(text).toContain("time: 2026-09-02T10:11:12.000Z");
    expect(text).toContain("error: Error");
  });

  it("carries no stack", () => {
    expect(text).not.toContain("at Boom");
    expect(text).not.toContain("SecurityRules.tsx");
    expect(text).not.toMatch(/\bat \w+ \(/);
  });

  it("strips a token, a key and an address", () => {
    expect(text).not.toContain("SGVsbG9Xb3JsZFNlY3JldEtleTEyMzQ1Ng");
    expect(text).not.toContain("sk-9f2b7c1d4e6a8b0c3d5e7f91");
    expect(text).not.toContain("10.42.7.19");
    expect(text).not.toContain("nms.corp.example");
    expect(text).toContain("[redacted]");
  });
});

describe("redact", () => {
  it.each([
    ["an IPv4 address", "dial 192.168.10.4 refused", "192.168.10.4"],
    ["an IPv4 host:port", "reading 10.0.0.9:9200", "10.0.0.9:9200"],
    ["an IPv6 address", "peer fe80::1c2d:3e4f:5a6b down", "fe80::1c2d:3e4f:5a6b"],
    ["a MAC address", "device 00:1b:44:11:3a:b7 unknown", "00:1b:44:11:3a:b7"],
    ["a JWT", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJvcHMifQ.c2lnbmF0dXJl expired", "eyJzdWIiOiJvcHMifQ"],
    ["a bearer header", "Authorization: Bearer abc123def456ghi789", "abc123def456ghi789"],
    ["a password assignment", 'password="hunter2-not-really"', "hunter2-not-really"],
    ["a URL", "GET https://vault.internal/v1/creds timed out", "vault.internal"],
    ["an e-mail address", "owner ops.lead@corp.example was notified", "ops.lead@corp.example"],
    ["a long opaque key", "signature 9f2b7c1d4e6a8b0c3d5e7f918273a4b5", "9f2b7c1d4e6a8b0c3d5e7f918273a4b5"],
  ])("removes %s", (_what, input, secret) => {
    const out = redact(input);
    expect(out).not.toContain(secret);
    expect(out).toContain("[redacted]");
  });

  it("keeps the sentence a person can act on", () => {
    expect(redact("peers.map is not a function")).toBe("peers.map is not a function");
  });

  it("bounds the report: a runaway message is truncated", () => {
    expect(redact("x ".repeat(5000)).length).toBeLessThanOrEqual(300);
  });

  it("survives a non-string", () => {
    expect(redact(undefined as unknown as string)).toBe("");
  });
});

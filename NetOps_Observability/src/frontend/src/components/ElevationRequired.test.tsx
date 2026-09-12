// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// ElevationRequired + the step-up refusal parser.
//
// The property under test is that a step-up refusal is NAMED: an operator who
// hits an elevated-only action mid-incident must be shown where to get the
// access, not a generic 403. And the parser must be total — every other 403 in
// the product goes through the same code path and must be untouched by it.

import { describe, it, expect, afterEach } from "vitest";
import { render, screen, cleanup, act } from "@testing-library/react";
import ElevationRequired from "./ElevationRequired";
import { countdown } from "./IconRail";
import { parseElevationRefusal, ELEVATION_REQUIRED_EVENT, type ElevationRefusal } from "../services/api";

afterEach(cleanup);

describe("parseElevationRefusal", () => {
  it("reads a step-up refusal and its providers", () => {
    const got = parseElevationRefusal(JSON.stringify({
      error: "elevated access is required — sign in through Break Glass",
      code: "ELEVATION_REQUIRED",
      elevation_providers: [{ id: "jit", name: "Break Glass" }],
    }));
    expect(got?.providers).toEqual([{ id: "jit", name: "Break Glass" }]);
    expect(got?.error).toContain("Break Glass");
  });

  it("leaves every other 403 alone", () => {
    expect(parseElevationRefusal(JSON.stringify({ error: "administration admin permission required" }))).toBeNull();
    expect(parseElevationRefusal("tenant suspended")).toBeNull();
    expect(parseElevationRefusal("")).toBeNull();
    expect(parseElevationRefusal("null")).toBeNull();
  });

  it("survives a refusal with no provider list", () => {
    const got = parseElevationRefusal(JSON.stringify({ code: "ELEVATION_REQUIRED" }));
    expect(got?.providers).toEqual([]);
    expect(got?.error).not.toBe("");
  });
});

describe("ElevationRequired", () => {
  const fire = (detail: ElevationRefusal) =>
    act(() => { window.dispatchEvent(new CustomEvent(ELEVATION_REQUIRED_EVENT, { detail })); });

  it("renders nothing until a refusal arrives", () => {
    const { container } = render(<ElevationRequired />);
    expect(container).toBeEmptyDOMElement();
  });

  it("names the provider and offers the button", () => {
    render(<ElevationRequired />);
    fire({ error: "elevated access is required — sign in through Break Glass", providers: [{ id: "jit", name: "Break Glass" }] });
    expect(screen.getByRole("alert")).toHaveTextContent("Break Glass");
    expect(screen.getByRole("button", { name: /Sign in through Break Glass/ })).toBeInTheDocument();
  });

  it("says what to do when no door is configured", () => {
    render(<ElevationRequired />);
    fire({ error: "elevated access is required for this action", providers: [] });
    expect(screen.getByText(/Ask an administrator/)).toBeInTheDocument();
  });
});

describe("countdown", () => {
  const now = new Date("2026-09-07T12:00:00Z");
  it("reads as time an operator can act on", () => {
    expect(countdown("2026-09-07T12:15:00Z", now)).toBe("15m left");
    expect(countdown("2026-09-07T14:30:00Z", now)).toBe("2h 30m left");
    expect(countdown("2026-09-07T12:00:30Z", now)).toBe("under a minute");
  });
  it("never claims time that is gone", () => {
    expect(countdown("2026-09-07T11:59:00Z", now)).toBe("ending");
    expect(countdown("2026-09-07T12:00:00Z", now)).toBe("ending");
  });
  it("renders nothing for an unusable timestamp", () => {
    expect(countdown("not a date", now)).toBe("");
  });
});

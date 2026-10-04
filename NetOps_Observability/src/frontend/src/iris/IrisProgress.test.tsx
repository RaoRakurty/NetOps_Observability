// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// IrisProgress.test.tsx — the operational trace: closed event names mapped to
// plain words, unknown names never echoed, a polite live region, bounded.

import { describe, it, expect, afterEach } from "vitest";
import { render, screen, cleanup } from "@testing-library/react";
import IrisProgress, { stepLabel, type ProgressStep } from "./IrisProgress";
import { HOSTILE } from "../test/irisFixtures";

afterEach(cleanup);

describe("IrisProgress", () => {
  it("maps the closed event names to plain words", () => {
    expect(stepLabel("resolved")).toBe("Understood the question");
    expect(stepLabel("querying")).toBe("Reading the data");
    expect(stepLabel("found")).toBe("Found results");
    expect(stepLabel("rca_loaded")).toBe("Loaded the root-cause analysis");
    expect(stepLabel("rendering")).toBe("Preparing the answer");
  });

  it("never echoes an unknown event name (incl. prototype names)", () => {
    expect(stepLabel("I think the root cause is…")).toBe("Working");
    expect(stepLabel("constructor")).toBe("Working");
    expect(stepLabel("__proto__")).toBe("Working");
  });

  it("lists steps with their state and announces the latest", () => {
    render(
      <IrisProgress
        steps={[
          { event: "resolved", state: "done" },
          { event: "querying", detail: "3 devices", state: "active" },
        ]}
      />,
    );
    const items = screen.getAllByRole("listitem");
    expect(items).toHaveLength(2);
    expect(items[0]).toHaveTextContent("Understood the question");
    expect(items[0]).toHaveTextContent("(done)");
    expect(items[1]).toHaveTextContent("Reading the data · 3 devices");
    const live = screen.getByRole("status");
    expect(live).toHaveAttribute("aria-live", "polite");
    expect(live).toHaveTextContent("Reading the data — in progress");
  });

  it("shows a failed step in words", () => {
    render(<IrisProgress steps={[{ event: "querying", state: "failed" }]} />);
    expect(screen.getByRole("status")).toHaveTextContent("Reading the data — failed");
  });

  it("treats a bogus state as in progress", () => {
    render(<IrisProgress steps={[{ event: "found", state: "constructor" as unknown as ProgressStep["state"] }]} />);
    expect(screen.getByRole("status")).toHaveTextContent("Found results — in progress");
  });

  it("copes with no or malformed steps", () => {
    render(<IrisProgress steps={[null, { event: 5 }, "x"] as unknown as ProgressStep[]} />);
    expect(screen.queryAllByRole("listitem")).toHaveLength(0);
    expect(screen.getByRole("status")).toHaveTextContent("");
  });

  it("bounds the number of steps", () => {
    const steps = Array.from({ length: 50 }, () => ({ event: "querying", state: "done" as const }));
    render(<IrisProgress steps={steps} />);
    expect(screen.getAllByRole("listitem")).toHaveLength(20);
  });

  it("renders a hostile detail as clipped text", () => {
    const { container } = render(<IrisProgress steps={[{ event: "found", detail: HOSTILE + "x".repeat(500) }]} />);
    expect(container.querySelector("script")).toBeNull();
    expect(container.textContent).toContain("<script>");
    expect(container.textContent!.length).toBeLessThan(300);
  });
});

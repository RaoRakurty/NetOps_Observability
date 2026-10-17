// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// RecommendationCards (N-I7): a suggestion, never an action.

import { describe, it, expect, afterEach } from "vitest";
import { render, screen, cleanup } from "@testing-library/react";
import RecommendationCards, { NO_ACTION_NOTICE } from "./RecommendationCards";
import type { AiRecommendation } from "../services/api";

afterEach(cleanup);

const card = (over: Partial<AiRecommendation> = {}): AiRecommendation => ({
  id: "rec-1", title: "Suggested next steps", steps: ["Check the carrier circuit status."],
  why: "Based on the incident's root-cause analysis.", basis: ["problem:p1"], origin: "rca_next_actions",
  notice: "No action has been executed.", ...over,
});

describe("RecommendationCards", () => {
  it("shows the steps, the basis link and the label — and nothing that acts", () => {
    const { container } = render(
      <RecommendationCards cards={[card()]} citations={[{ id: "problem:p1", kind: "finding", label: "WAN loss at dfw", href: "#/investigate/rca?id=p1" }]} />,
    );
    expect(screen.getByText("Check the carrier circuit status.")).toBeTruthy();
    expect(screen.getByText(NO_ACTION_NOTICE)).toBeTruthy();
    expect(screen.getByRole("link", { name: "WAN loss at dfw" }).getAttribute("href")).toBe("#/investigate/rca?id=p1");
    expect(container.querySelectorAll("button, form, input, [onclick]").length).toBe(0);
  });

  it("keeps the label even when the server's notice says otherwise", () => {
    render(<RecommendationCards cards={[card({ notice: "Action executed!" })]} citations={[]} />);
    expect(screen.getByText(NO_ACTION_NOTICE)).toBeTruthy();
    expect(screen.queryByText("Action executed!")).toBeNull();
  });

  it("renders an unsafe or unknown basis as text, never a link", () => {
    const { container } = render(
      <RecommendationCards
        cards={[card({ basis: ["problem:evil", "problem:missing"] })]}
        citations={[{ id: "problem:evil", kind: "finding", label: "evil", href: "javascript:alert(1)" }]}
      />,
    );
    expect(container.querySelectorAll("a").length).toBe(0);
    expect(screen.getByText("evil")).toBeTruthy();
    expect(screen.getByText("problem:missing")).toBeTruthy();
  });

  it("renders step text as text, never markup", () => {
    const { container } = render(<RecommendationCards cards={[card({ steps: ['<img src=x onerror="window.__rec=1">'] })]} citations={[]} />);
    expect(container.querySelector("img")).toBeNull();
    expect(screen.getByText('<img src=x onerror="window.__rec=1">')).toBeTruthy();
  });
});

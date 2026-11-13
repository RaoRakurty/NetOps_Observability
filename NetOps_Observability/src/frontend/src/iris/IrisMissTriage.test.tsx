// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

import { render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import IrisMissTriage from "./IrisMissTriage";
import { api } from "../services/api";

afterEach(() => vi.restoreAllMocks());

describe("IrisMissTriage", () => {
  it("lists the miss classes with counts and the caller's own examples as text", async () => {
    vi.spyOn(api, "irisTriage").mockResolvedValue({
      scope: "tenant", window: "the last 30 days",
      class_order: ["no_tool", "no_data", "wrong_route", "wrong_tool", "wording", "provider_error"],
      classes: [
        { class: "no_data", count: 3, examples: [{ question: "<img src=x onerror=alert(1)> where is polling" }, { question: "" }] },
        { class: "wording", count: 1, examples: [] },
      ],
    });
    render(<IrisMissTriage />);
    await waitFor(() => expect(screen.getByTestId("iris-miss-triage")).toBeTruthy());
    expect(screen.getByText("No data for it")).toBeTruthy();
    expect(screen.getByText(/3 questions/)).toBeTruthy();
    expect(screen.getByText(/1 question$/)).toBeTruthy();
    // Hostile text renders as text, never as markup.
    expect(screen.getByText(/onerror=alert/)).toBeTruthy();
    expect(document.querySelector("img")).toBeNull();
  });

  it("tells a non-admin it is admin-only", async () => {
    vi.spyOn(api, "irisTriage").mockRejectedValue(new Error("403 Forbidden: forbidden"));
    render(<IrisMissTriage />);
    await waitFor(() => expect(screen.getByText(/Only workspace admins/)).toBeTruthy());
  });

  it("says so when nothing was missed", async () => {
    vi.spyOn(api, "irisTriage").mockResolvedValue({ scope: "tenant", window: "w", class_order: [], classes: [] });
    render(<IrisMissTriage />);
    await waitFor(() => expect(screen.getByText(/answered every recent question/)).toBeTruthy());
  });
});

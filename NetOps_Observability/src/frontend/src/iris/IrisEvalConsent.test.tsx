// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import IrisEvalConsent from "./IrisEvalConsent";
import { api } from "../services/api";

vi.mock("../services/api", () => ({
  api: { irisEvalConsent: vi.fn(), setIrisEvalConsent: vi.fn() },
}));

const get = api.irisEvalConsent as unknown as ReturnType<typeof vi.fn>;
const set = api.setIrisEvalConsent as unknown as ReturnType<typeof vi.fn>;

describe("IrisEvalConsent", () => {
  beforeEach(() => {
    get.mockReset();
    set.mockReset();
  });

  it("is off by default and ticking it saves the person's own choice", async () => {
    get.mockResolvedValue({ consented: false });
    set.mockResolvedValue({ consented: true });
    render(<IrisEvalConsent />);
    const box = (await screen.findByRole("checkbox", { name: /use what i ask to test iris/i })) as HTMLInputElement;
    expect(box.checked).toBe(false);
    fireEvent.click(box);
    await waitFor(() => expect(set).toHaveBeenCalledWith(true));
    await waitFor(() => expect(box.checked).toBe(true));
  });

  it("unticking revokes", async () => {
    get.mockResolvedValue({ consented: true });
    set.mockResolvedValue({ consented: false });
    render(<IrisEvalConsent />);
    const box = (await screen.findByRole("checkbox", { name: /use what i ask to test iris/i })) as HTMLInputElement;
    expect(box.checked).toBe(true);
    fireEvent.click(box);
    await waitFor(() => expect(set).toHaveBeenCalledWith(false));
  });

  it("hides itself where there is no workspace or no store", async () => {
    get.mockRejectedValue(new Error('400 Bad Request: {"error":"sharing questions applies inside one workspace"}'));
    const { container } = render(<IrisEvalConsent />);
    await waitFor(() => expect(get).toHaveBeenCalled());
    expect(container.querySelector('[data-testid="iris-eval-consent"]')).toBeNull();
  });

  it("an empty answer reads as off, never as on", async () => {
    get.mockResolvedValue({});
    render(<IrisEvalConsent />);
    const box = (await screen.findByRole("checkbox", { name: /use what i ask to test iris/i })) as HTMLInputElement;
    expect(box.checked).toBe(false);
  });
});

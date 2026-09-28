// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// RecentQuestions.test.tsx — the caller's own recent questions (tracker 337
// N-C8): outcomes in plain words, question text as escaped text, the
// workspace view asked for explicitly (the server decides who may), and a
// refusal shown as an operator sentence.

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, cleanup, fireEvent, waitFor } from "@testing-library/react";

const irisQueries = vi.fn();
const correctIrisQuery = vi.fn();
const compileIrisQuery = vi.fn();
vi.mock("../services/api", () => ({
  api: {
    irisQueries: (...a: unknown[]) => irisQueries(...a),
    correctIrisQuery: (...a: unknown[]) => correctIrisQuery(...a),
    compileIrisQuery: (...a: unknown[]) => compileIrisQuery(...a),
  },
}));

import RecentQuestions from "./RecentQuestions";

const rec = (over = {}) => ({
  id: "11111111-2222-4333-8444-555555555555", principal: "alice", source: "router", at: "2026-09-27T10:00:00Z",
  question: "cpu on edge-a", outcome: "answered", validation_codes: [], entities: [], rows: 0, series: 1,
  duration_ms: 12, corrections: [], ...over,
});

beforeEach(() => {
  irisQueries.mockReset();
  correctIrisQuery.mockReset();
  compileIrisQuery.mockReset();
});
afterEach(() => cleanup());

describe("RecentQuestions", () => {
  it("lists the caller's own questions with plain-language outcomes", async () => {
    irisQueries.mockResolvedValue({ queries: [rec(), rec({ id: "22222222-2222-4333-8444-555555555555", question: "", outcome: "unparsed", source: "query_execute", corrections: [{ kind: "other" }] })], scope: "mine", retention_days: 30, kinds: [] });
    render(<RecentQuestions />);
    const list = await screen.findByTestId("iris-recent-list");
    expect(irisQueries).toHaveBeenCalledWith("mine", 10);
    expect(list).toHaveTextContent("cpu on edge-a — answered, Iris box");
    expect(list).toHaveTextContent("A query you ran — not understood");
    expect(list).toHaveTextContent("1 correction");
    expect(screen.getAllByText("That's not what I meant")).toHaveLength(2);
    expect(screen.getByText("Kept for 30 days.")).toBeInTheDocument();
  });

  it("renders a hostile question as text, never markup", async () => {
    irisQueries.mockResolvedValue({ queries: [rec({ question: '<img src=x onerror="alert(1)">' })], scope: "mine", retention_days: 30, kinds: [] });
    const { container } = render(<RecentQuestions />);
    await screen.findByTestId("iris-recent-list");
    expect(container.querySelector("img")).toBeNull();
    expect(container.textContent).toContain('<img src=x onerror="alert(1)">');
  });

  it("asks for the workspace view only when chosen, and shows who asked", async () => {
    irisQueries.mockResolvedValue({ queries: [], scope: "mine", retention_days: 30, kinds: [] });
    render(<RecentQuestions />);
    expect(await screen.findByText("No questions yet.")).toBeInTheDocument();
    irisQueries.mockResolvedValue({ queries: [rec({ principal: "bob" })], scope: "tenant", retention_days: 30, kinds: [] });
    fireEvent.click(screen.getByLabelText("Everyone in this workspace (admins)"));
    await waitFor(() => expect(irisQueries).toHaveBeenLastCalledWith("tenant", 10));
    expect(await screen.findByTestId("iris-recent-list")).toHaveTextContent("asked by bob");
    // Corrections are the asker's own: none offered on someone else's list.
    expect(screen.queryByText("That's not what I meant")).toBeNull();
  });

  it("shows a refusal as an operator sentence", async () => {
    irisQueries.mockResolvedValue({ queries: [], scope: "mine", retention_days: 30, kinds: [] });
    render(<RecentQuestions />);
    await screen.findByText("No questions yet.");
    irisQueries.mockRejectedValue(new Error('403 Forbidden: {"error":"only a workspace admin can see everyone\'s questions"}'));
    fireEvent.click(screen.getByLabelText("Everyone in this workspace (admins)"));
    const alert = await screen.findByRole("alert");
    expect(alert.textContent).not.toContain("403");
    expect(alert.textContent).not.toContain("{");
  });

  it("re-reads when asked to refresh", async () => {
    irisQueries.mockResolvedValue({ queries: [], scope: "mine", retention_days: 30, kinds: [] });
    const { rerender } = render(<RecentQuestions refreshKey={0} />);
    await waitFor(() => expect(irisQueries).toHaveBeenCalledTimes(1));
    rerender(<RecentQuestions refreshKey={1} />);
    await waitFor(() => expect(irisQueries).toHaveBeenCalledTimes(2));
  });
});

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// QueryExplain.test.tsx — "Explain this query" (tracker 337 N-C5): the
// server's plain-language reading shown as escaped text, the model disclosure
// first whenever the model wrote the query, a stale query flagged, a missing
// query explained, and a refusal shown as an operator sentence.

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, cleanup, fireEvent } from "@testing-library/react";

const explainIrisQuery = vi.fn();
vi.mock("../services/api", () => ({
  api: { explainIrisQuery: (...a: unknown[]) => explainIrisQuery(...a) },
}));

import QueryExplain from "./QueryExplain";

const ID = "11111111-2222-4333-8444-555555555555";
const base = {
  id: ID, asked_via: "router", outcome: "answered", question: "cpu on edge-a", query_type: "metric_series",
  compiled_by: "grammar", catalog_current: true, still_valid: true,
  explanation: {
    summary: "Shows cpu over time for device edge-a (dev-a) — the last hour.",
    parts: [
      { facet: "what", text: "Shows cpu over time." },
      { facet: "entities", text: "About device edge-a (dev-a)." },
      { facet: "window", text: "Time window: the last hour." },
    ],
  },
};

beforeEach(() => {
  explainIrisQuery.mockReset();
});
afterEach(() => cleanup());

describe("QueryExplain", () => {
  it("loads the explanation only when asked, once", async () => {
    explainIrisQuery.mockResolvedValue(base);
    render(<QueryExplain queryId={ID} />);
    expect(explainIrisQuery).not.toHaveBeenCalled();
    fireEvent.click(screen.getByText("Explain this query"));
    expect(await screen.findByText(base.explanation.summary)).toBeInTheDocument();
    expect(explainIrisQuery).toHaveBeenCalledWith(ID);
    expect(screen.getByText("About")).toBeInTheDocument();
    expect(screen.getByText("Time window: the last hour.")).toBeInTheDocument();
    expect(screen.queryByTestId("iris-explain-model")).toBeNull();
    fireEvent.click(screen.getByText("Hide explanation"));
    fireEvent.click(screen.getByText("Explain this query"));
    expect(explainIrisQuery).toHaveBeenCalledTimes(1);
  });

  it("discloses a model-written query first", async () => {
    explainIrisQuery.mockResolvedValue({ ...base, compiled_by: "model", source: "model", disclosure: "Interpreted by the AI model, not the built-in question grammar — check the query shown with this answer before relying on it." });
    render(<QueryExplain queryId={ID} />);
    fireEvent.click(screen.getByText("Explain this query"));
    const note = await screen.findByTestId("iris-explain-model");
    expect(note).toHaveTextContent("Interpreted by the AI model");
  });

  it("flags a query that no longer passes its checks", async () => {
    explainIrisQuery.mockResolvedValue({ ...base, still_valid: false });
    render(<QueryExplain queryId={ID} />);
    fireEvent.click(screen.getByText("Explain this query"));
    expect(await screen.findByTestId("iris-explain-stale")).toBeInTheDocument();
  });

  it("says why there is nothing to explain", async () => {
    explainIrisQuery.mockResolvedValue({ ...base, explanation: null, outcome: "unparsed", reason: "Iris did not understand this question, so no query was built." });
    render(<QueryExplain queryId={ID} />);
    fireEvent.click(screen.getByText("Explain this query"));
    expect(await screen.findByText("Iris did not understand this question, so no query was built.")).toBeInTheDocument();
  });

  it("renders server text as text, never markup", async () => {
    explainIrisQuery.mockResolvedValue({ ...base, explanation: { summary: '<img src=x onerror="alert(1)">', parts: [{ facet: "what", text: "<b>x</b>" }] } });
    const { container } = render(<QueryExplain queryId={ID} />);
    fireEvent.click(screen.getByText("Explain this query"));
    await screen.findByText('<img src=x onerror="alert(1)">');
    expect(container.querySelector("img")).toBeNull();
    expect(container.querySelector("b")).toBeNull();
  });

  it("shows a refusal as an operator sentence", async () => {
    explainIrisQuery.mockRejectedValue(new Error('404 Not Found: {"error":"not found"}'));
    render(<QueryExplain queryId={ID} />);
    fireEvent.click(screen.getByText("Explain this query"));
    const alert = await screen.findByRole("alert");
    expect(alert.textContent).not.toContain("{");
  });
});

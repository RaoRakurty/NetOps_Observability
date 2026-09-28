// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// QueryCorrection.test.tsx — "That's not what I meant" (tracker 337 N-C8):
// the correction names a closed kind; a rewording is attached only when the
// server compiled it to a VALID query; a failure is shown as an operator
// sentence, never a raw server body; and nothing is sent until asked.

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, cleanup, fireEvent, waitFor } from "@testing-library/react";

const compileIrisQuery = vi.fn();
const correctIrisQuery = vi.fn();
vi.mock("../services/api", () => ({
  api: {
    compileIrisQuery: (...a: unknown[]) => compileIrisQuery(...a),
    correctIrisQuery: (...a: unknown[]) => correctIrisQuery(...a),
  },
}));

import QueryCorrection, { KIND_LABEL } from "./QueryCorrection";

const ID = "11111111-2222-4333-8444-555555555555";

beforeEach(() => {
  compileIrisQuery.mockReset();
  correctIrisQuery.mockReset();
});
afterEach(() => cleanup());

const open = () => fireEvent.click(screen.getByText("That's not what I meant"));

describe("QueryCorrection", () => {
  it("sends nothing until the operator opens and sends it", () => {
    render(<QueryCorrection queryId={ID} />);
    expect(screen.queryByTestId("iris-correction")).toBeNull();
    open();
    expect(screen.getByTestId("iris-correction")).toBeInTheDocument();
    expect(correctIrisQuery).not.toHaveBeenCalled();
  });

  it("offers only the closed list of kinds", () => {
    render(<QueryCorrection queryId={ID} />);
    open();
    const opts = Array.from(screen.getByLabelText("Iris got the").querySelectorAll("option")).map((o) => o.getAttribute("value"));
    expect(opts).toEqual(Object.keys(KIND_LABEL));
  });

  it("sends the kind and note, then confirms without promising a change", async () => {
    correctIrisQuery.mockResolvedValue({});
    const onSaved = vi.fn();
    render(<QueryCorrection queryId={ID} onSaved={onSaved} />);
    open();
    fireEvent.change(screen.getByLabelText("Iris got the"), { target: { value: "wrong_window" } });
    fireEvent.change(screen.getByLabelText("Note (optional)"), { target: { value: "  I meant yesterday  " } });
    fireEvent.click(screen.getByText("Send"));
    await waitFor(() => expect(correctIrisQuery).toHaveBeenCalledWith(ID, { kind: "wrong_window", note: "I meant yesterday" }));
    expect(compileIrisQuery).not.toHaveBeenCalled();
    expect(await screen.findByTestId("iris-correction-saved")).toHaveTextContent("do not change on their own");
    expect(onSaved).toHaveBeenCalled();
  });

  it("attaches a rewording only when the server compiled it to a valid query", async () => {
    const ast = { v: 1, query_type: "metric_series", target: "device", metric: "mem_util_pct" };
    compileIrisQuery.mockResolvedValue({ ast, validation: { valid: true } });
    correctIrisQuery.mockResolvedValue({});
    render(<QueryCorrection queryId={ID} />);
    open();
    fireEvent.change(screen.getByLabelText("How would you ask it? (optional)"), { target: { value: "memory on edge-a" } });
    fireEvent.click(screen.getByText("Send"));
    await waitFor(() => expect(correctIrisQuery).toHaveBeenCalledWith(ID, { kind: "wrong_entity", ast }));
    expect(compileIrisQuery.mock.calls[0][0]).toBe("memory on edge-a");
  });

  it("refuses a rewording Iris cannot run, and sends nothing", async () => {
    compileIrisQuery.mockResolvedValue({ unparsed: true, not_understood: ["thingy"] });
    render(<QueryCorrection queryId={ID} />);
    open();
    fireEvent.change(screen.getByLabelText("How would you ask it? (optional)"), { target: { value: "the thingy" } });
    fireEvent.click(screen.getByText("Send"));
    expect(await screen.findByRole("alert")).toHaveTextContent("could not turn that wording into a query");
    expect(correctIrisQuery).not.toHaveBeenCalled();
  });

  it("asks for something when the kind is 'something else' and nothing is said", () => {
    render(<QueryCorrection queryId={ID} />);
    open();
    fireEvent.change(screen.getByLabelText("Iris got the"), { target: { value: "other" } });
    fireEvent.click(screen.getByText("Send"));
    expect(screen.getByRole("alert")).toHaveTextContent("Say what was wrong");
    expect(correctIrisQuery).not.toHaveBeenCalled();
  });

  it("shows a server failure as an operator sentence, not the raw body", async () => {
    correctIrisQuery.mockRejectedValue(new Error('500 Internal Server Error: {"error":"pq: relation iris_query_log does not exist"}'));
    render(<QueryCorrection queryId={ID} />);
    open();
    fireEvent.click(screen.getByText("Send"));
    const alert = await screen.findByRole("alert");
    expect(alert.textContent).not.toContain("iris_query_log");
    expect(alert.textContent).not.toContain("500");
  });
});

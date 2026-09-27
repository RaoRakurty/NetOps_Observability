// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// IrisVocabulary.test.tsx — the three steps, and the honesty rules they carry:
// a name is never guessed (an ambiguous match is offered as a choice), a
// question Iris did not fully understand is never runnable, and a result value
// is rendered as text, never markup.

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, cleanup, fireEvent, waitFor } from "@testing-library/react";

const irisAliases = vi.fn();
const putIrisAlias = vi.fn();
const deleteIrisAlias = vi.fn();
const resolveIrisEntity = vi.fn();
const compileIrisQuery = vi.fn();
const executeIrisQuery = vi.fn();
const startIrisConversation = vi.fn();
const askIrisConversation = vi.fn();
vi.mock("../services/api", () => ({
  api: {
    irisAliases: (...a: unknown[]) => irisAliases(...a),
    putIrisAlias: (...a: unknown[]) => putIrisAlias(...a),
    deleteIrisAlias: (...a: unknown[]) => deleteIrisAlias(...a),
    resolveIrisEntity: (...a: unknown[]) => resolveIrisEntity(...a),
    compileIrisQuery: (...a: unknown[]) => compileIrisQuery(...a),
    executeIrisQuery: (...a: unknown[]) => executeIrisQuery(...a),
    startIrisConversation: (...a: unknown[]) => startIrisConversation(...a),
    askIrisConversation: (...a: unknown[]) => askIrisConversation(...a),
  },
}));

import IrisVocabulary, { cell } from "./IrisVocabulary";

const ref = (id: string, over = {}) => ({
  input_text: "hq fw", entity_id: id, entity_type: "device", confidence: 0.9, resolution_method: "inventory_name", ...over,
});

beforeEach(() => {
  for (const f of [irisAliases, putIrisAlias, deleteIrisAlias, resolveIrisEntity, compileIrisQuery, executeIrisQuery,
    startIrisConversation, askIrisConversation]) f.mockReset();
  irisAliases.mockResolvedValue({ aliases: [{ entity_type: "device", entity_id: "device:fw-hq-01", alias: "HQ firewall" }], max: 2000 });
});
afterEach(() => cleanup());

const type = (label: string, value: string) => fireEvent.change(screen.getByLabelText(label), { target: { value } });

describe("1 · names your team uses", () => {
  it("lists the workspace's names and how many remain", async () => {
    render(<IrisVocabulary />);
    expect(await screen.findByTestId("iris-alias-list")).toHaveTextContent("HQ firewall → Device device:fw-hq-01");
    expect(screen.getByText("1 of 2000 used.")).toBeInTheDocument();
  });

  it("saves an explicit id without resolving it (the server checks visibility)", async () => {
    putIrisAlias.mockResolvedValue({});
    render(<IrisVocabulary />);
    type("Name your team uses", "core");
    type("What it refers to", "device:core-1");
    fireEvent.click(screen.getByText("Add"));
    await waitFor(() => expect(putIrisAlias).toHaveBeenCalledWith({ entity_type: "device", entity_id: "device:core-1", alias: "core" }));
    expect(resolveIrisEntity).not.toHaveBeenCalled();
  });

  it("saves a single confident match, but offers an ambiguous one as a choice", async () => {
    putIrisAlias.mockResolvedValue({});
    resolveIrisEntity.mockResolvedValueOnce({ refs: [ref("device:fw-1")], ambiguous: false });
    render(<IrisVocabulary />);
    type("Name your team uses", "edge");
    type("What it refers to", "fw");
    fireEvent.click(screen.getByText("Add"));
    await waitFor(() => expect(putIrisAlias).toHaveBeenCalledWith({ entity_type: "device", entity_id: "device:fw-1", alias: "edge" }));

    putIrisAlias.mockClear();
    resolveIrisEntity.mockResolvedValueOnce({ refs: [ref("device:fw-1"), ref("device:fw-2")], ambiguous: true });
    type("Name your team uses", "edge");
    type("What it refers to", "fw");
    fireEvent.click(screen.getByText("Add"));
    expect(await screen.findByTestId("iris-alias-candidates")).toHaveTextContent("device:fw-2");
    expect(putIrisAlias).not.toHaveBeenCalled();
    fireEvent.click(screen.getByText("device:fw-2"));
    await waitFor(() => expect(putIrisAlias).toHaveBeenCalledWith({ entity_type: "device", entity_id: "device:fw-2", alias: "edge" }));
  });

  it("a partial match that needs confirmation is never saved silently", async () => {
    resolveIrisEntity.mockResolvedValueOnce({ refs: [ref("device:fw-1", { needs_confirmation: true, resolution_method: "partial_name" })], ambiguous: false });
    render(<IrisVocabulary />);
    type("Name your team uses", "edge");
    type("What it refers to", "f");
    fireEvent.click(screen.getByText("Add"));
    expect(await screen.findByTestId("iris-alias-candidates")).toBeInTheDocument();
    expect(putIrisAlias).not.toHaveBeenCalled();
  });

  it("says plainly when nothing visible matches", async () => {
    resolveIrisEntity.mockResolvedValueOnce({ refs: [], ambiguous: false });
    render(<IrisVocabulary />);
    type("Name your team uses", "edge");
    type("What it refers to", "nope");
    fireEvent.click(screen.getByText("Add"));
    expect(await screen.findByRole("alert")).toHaveTextContent('No device called "nope" is visible to you');
  });

  it("removes a name", async () => {
    deleteIrisAlias.mockResolvedValue(undefined);
    render(<IrisVocabulary />);
    fireEvent.click(await screen.findByLabelText("Remove HQ firewall"));
    await waitFor(() => expect(deleteIrisAlias).toHaveBeenCalledWith("device", "HQ firewall"));
  });
});

describe("2 · check a name", () => {
  it("shows how the name resolved and how sure Iris is", async () => {
    resolveIrisEntity.mockResolvedValueOnce({ refs: [ref("device:fw-1", { resolution_method: "tenant_alias", confidence: 1 })], ambiguous: false });
    render(<IrisVocabulary />);
    type("Name to check", "hq fw");
    fireEvent.click(screen.getByText("Check"));
    expect(await screen.findByTestId("iris-check")).toHaveTextContent("your team's name, 100% sure");
  });

  it("an unknown name is reported as unknown", async () => {
    resolveIrisEntity.mockResolvedValueOnce({ refs: null, ambiguous: false });
    render(<IrisVocabulary />);
    type("Name to check", "zzz");
    fireEvent.click(screen.getByText("Check"));
    expect(await screen.findByTestId("iris-check")).toHaveTextContent("Iris does not recognise that name.");
  });
});

describe("3 · try a question", () => {
  it("a question Iris did not fully understand lists the words and is not runnable", async () => {
    compileIrisQuery.mockResolvedValueOnce({ unparsed: true, not_understood: ["purple"], intent: "metric_query", ast: { type: "metric" }, validation: { valid: true } });
    render(<IrisVocabulary />);
    type("Question", "purple latency");
    fireEvent.click(screen.getByText("Only show how Iris reads it"));
    expect(await screen.findByTestId("iris-understood")).toHaveTextContent("it could not place: purple");
    expect(screen.queryByText("Run it")).toBeNull();
  });

  it("an invalid query shows why and is not runnable", async () => {
    compileIrisQuery.mockResolvedValueOnce({ intent: "metric_query", ast: { type: "metric" },
      validation: { valid: false, errors: [{ path: "metric", code: "unknown_metric", message: "unknown metric", suggestions: ["latency"] }] } });
    render(<IrisVocabulary />);
    type("Question", "latncy");
    fireEvent.click(screen.getByText("Only show how Iris reads it"));
    expect(await screen.findByTestId("iris-validation-errors")).toHaveTextContent("unknown metric — did you mean latency?");
    expect(screen.queryByText("Run it")).toBeNull();
  });

  it("a valid query runs the exact validated query and shows the rows", async () => {
    const ast = { version: 1, type: "list" };
    compileIrisQuery.mockResolvedValueOnce({ intent: "list_changes", ast, validation: { valid: true } });
    executeIrisQuery.mockResolvedValueOnce({ result: { query_id: "q", query_type: "list", window: { from: "", to: "" }, truncated: true,
      rows: [{ id: "c1", actor: "<b>x</b>" }], provenance: { source: "change_ledger", executed_at: "", duration_ms: 7 } } });
    render(<IrisVocabulary />);
    type("Question", "what changed today");
    fireEvent.click(screen.getByText("Only show how Iris reads it"));
    fireEvent.click(await screen.findByText("Run it"));
    await waitFor(() => expect(executeIrisQuery).toHaveBeenCalledWith(ast));
    const res = await screen.findByTestId("iris-result");
    expect(res).toHaveTextContent("1 row (more exist — showing the first page) · from change_ledger in 7 ms");
    expect(res).toHaveTextContent("<b>x</b>"); // text, not markup
    expect(res.querySelector("b")).toBeNull();
    // Headers and cells carry the 14 px body size themselves: the global th/td
    // rule is 12 px, so inheriting from the table was not enough (found by the
    // N-E5 browser spec).
    for (const el of Array.from(res.querySelectorAll("th, td"))) {
      expect((el as HTMLElement).style.fontSize).toBe("14px");
    }
  });

  it("a declined request says so and offers nothing to run", async () => {
    compileIrisQuery.mockResolvedValueOnce({ decline: "Iris is read-only; it never changes devices." });
    render(<IrisVocabulary />);
    type("Question", "shut the interface");
    fireEvent.click(screen.getByText("Only show how Iris reads it"));
    expect(await screen.findByTestId("iris-understood")).toHaveTextContent("Iris will not do this: Iris is read-only");
    expect(screen.queryByText("Run it")).toBeNull();
  });
});

describe("3 · follow-ups in a conversation", () => {
  const answer = (q: string, over = {}) => ({
    conversation_id: "c1", intent: "query_metric", ast: { v: 1 }, validation: { valid: true },
    turn: { at: "", question: q, outcome: "answered", rows: 1 },
    result: { query_id: "q", query_type: "metric_series", window: { from: "", to: "" }, truncated: false,
      rows: [{ device: "edge-1", value: 12 }], provenance: { source: "victoriametrics", executed_at: "", duration_ms: 3 } },
    ...over,
  });

  it("starts ONE conversation and asks every follow-up in it — only the question is sent", async () => {
    startIrisConversation.mockResolvedValue({ id: "c1", created_at: "", updated_at: "", turns: [] });
    askIrisConversation.mockImplementation((_id: string, q: string) => Promise.resolve(answer(q)));
    render(<IrisVocabulary />);
    type("Question", "cpu on edge-1");
    fireEvent.click(screen.getByText("Ask"));
    expect(await screen.findByTestId("iris-result")).toHaveTextContent("1 row");
    type("Question", "memory on that device");
    fireEvent.click(screen.getByText("Ask"));
    await waitFor(() => expect(screen.getByTestId("iris-history")).toHaveTextContent("memory on that device — answered"));
    expect(startIrisConversation).toHaveBeenCalledTimes(1);
    expect(askIrisConversation.mock.calls.map((c) => c.slice(0, 2))).toEqual([["c1", "cpu on edge-1"], ["c1", "memory on that device"]]);
    expect(screen.queryByText("Run it")).toBeNull(); // an asked answer already ran
  });

  it("a conversation that has ended is replaced once, and the restart is said", async () => {
    startIrisConversation.mockResolvedValueOnce({ id: "old", turns: [] }).mockResolvedValueOnce({ id: "new", turns: [] });
    askIrisConversation.mockRejectedValueOnce(new Error("404 Not Found: {\"error\":\"not found\"}"))
      .mockImplementation((_id: string, q: string) => Promise.resolve(answer(q)));
    render(<IrisVocabulary />);
    type("Question", "cpu on edge-1");
    fireEvent.click(screen.getByText("Ask"));
    expect(await screen.findByRole("alert")).toHaveTextContent("That conversation had ended — started a new one.");
    expect(askIrisConversation.mock.calls.map((c) => c[0])).toEqual(["old", "new"]);
  });

  it("a reference with nothing to point at is shown as not understood", async () => {
    startIrisConversation.mockResolvedValue({ id: "c1", turns: [] });
    askIrisConversation.mockResolvedValue(answer("cpu on that device", {
      ast: undefined, validation: undefined, result: undefined, unparsed: true, not_understood: ["that device"],
      turn: { at: "", question: "cpu on that device", outcome: "unparsed", rows: 0 },
    }));
    render(<IrisVocabulary />);
    type("Question", "cpu on that device");
    fireEvent.click(screen.getByText("Ask"));
    expect(await screen.findByTestId("iris-understood")).toHaveTextContent("it could not place: that device");
    expect(screen.getByTestId("iris-history")).toHaveTextContent("cpu on that device — not understood");
    expect(screen.queryByTestId("iris-result")).toBeNull();
  });

  it("New conversation forgets the follow-up context", async () => {
    startIrisConversation.mockResolvedValueOnce({ id: "c1", turns: [] }).mockResolvedValueOnce({ id: "c2", turns: [] });
    askIrisConversation.mockImplementation((_id: string, q: string) => Promise.resolve(answer(q)));
    render(<IrisVocabulary />);
    type("Question", "cpu on edge-1");
    fireEvent.click(screen.getByText("Ask"));
    fireEvent.click(await screen.findByText("New conversation"));
    expect(screen.queryByTestId("iris-history")).toBeNull();
    type("Question", "memory on edge-1");
    fireEvent.click(screen.getByText("Ask"));
    await waitFor(() => expect(askIrisConversation.mock.calls.map((c) => c[0])).toEqual(["c1", "c2"]));
  });
});

describe("cell", () => {
  it("renders values as text", () => {
    expect(cell(null)).toBe("—");
    expect(cell(3)).toBe("3");
    expect(cell({ a: 1 })).toBe('{"a":1}');
  });
});

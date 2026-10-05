// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// StatementText.test.tsx — statement classes in the Iris answer (tracker 337
// N-B4): every sentence carries the server's class as a WORD, a sentence with
// no evidence of its own says so, the server's notes are listed, nothing is
// rendered as markup, fonts stay on the 14 / 16 px scale, and a missing or
// mismatched payload falls back to the plain text unchanged.

import { describe, it, expect, afterEach } from "vitest";
import { render, screen, cleanup } from "@testing-library/react";
import type { AiStatement } from "../services/api";
import StatementText, { classWord, statementTag, statementsMatch, CLASS_WORD } from "./StatementText";

afterEach(cleanup);

const REWORD = "Reworded by Correlix: a change that happened around an incident is temporally correlated, not established as cause unless Correlix's analysis establishes it.";

const statements: AiStatement[] = [
  { text: "The root cause is the optical loss on edge-1 [hypothesis:p1:0]. ", class: "CORRELIX_RCA", grounded: true, citations: ["hypothesis:p1:0"] },
  {
    text: "\"Configuration change on edge-1 at 10:02\" [hypothesis:p1:1] happened around this incident — temporally correlated, not established as cause (Correlix ranks it only as an unconfirmed candidate cause). ",
    class: "CORRELIX_RCA", grounded: true, citations: ["hypothesis:p1:1"], note: REWORD,
  },
  { text: "That pattern is typical of a dirty connector. ", class: "DERIVED", grounded: false, note: "No evidence cited — Iris's reading of the evidence, not an observation." },
  { text: "Ethernet1/1 went down [log:os:1]. ", class: "OBSERVED", grounded: true, citations: ["log:os:1"] },
  { text: "Next: reseat the optic.", class: "RECOMMENDATION", grounded: true },
];
const text = statements.map((s) => s.text).join("");

describe("StatementText", () => {
  it("tags every sentence with its class word and keeps the text intact", () => {
    render(<StatementText text={text} statements={statements} className="op-text" />);
    const root = screen.getByTestId("iris-statements");
    expect(root.className).toBe("op-text");
    const rows = screen.getAllByTestId("iris-stmt");
    expect(rows).toHaveLength(5);
    expect(rows.map((r) => r.getAttribute("data-class"))).toEqual(
      ["CORRELIX_RCA", "CORRELIX_RCA", "DERIVED", "OBSERVED", "RECOMMENDATION"]);
    const tags = screen.getAllByTestId("iris-stmt-class").map((t) => t.textContent);
    expect(tags).toEqual([
      "Correlix analysis", "Correlix analysis", "Derived · no evidence cited", "Observed", "Recommendation",
    ]);
    // The narrative itself still reads exactly as the server wrote it.
    const sentences = rows.map((r) => (r.firstChild as Text).textContent).join(" ");
    expect(sentences).toContain("temporally correlated, not established as cause");
    expect(rows[2].getAttribute("data-grounded")).toBe("no");
  });

  it("lists each distinct server note once, as plain text", () => {
    render(<StatementText text={text} statements={statements} />);
    const notes = screen.getByTestId("iris-stmt-notes");
    expect(notes.querySelectorAll("li")).toHaveLength(2);
    expect(notes.textContent).toContain("Reworded by Correlix");
    // The note also rides on the tag as a tooltip.
    expect(screen.getAllByTestId("iris-stmt-class")[1].getAttribute("title")).toBe(REWORD);
  });

  it("renders server strings as text, never markup", () => {
    const evil: AiStatement[] = [{ text: "<img src=x onerror=alert(1)> link down [log:1].", class: "OBSERVED", grounded: true }];
    const { container } = render(<StatementText text={evil[0].text} statements={evil} />);
    expect(container.querySelector("img")).toBeNull();
    expect(container.textContent).toContain("<img src=x onerror=alert(1)>");
  });

  it("keeps the 14 px scale for tags and notes", () => {
    render(<StatementText text={text} statements={statements} />);
    for (const tag of screen.getAllByTestId("iris-stmt-class")) expect(tag.style.fontSize).toBe("14px");
    expect(screen.getByTestId("iris-stmt-notes").style.fontSize).toBe("14px");
  });

  it("falls back to the plain text when statements are absent or do not spell it", () => {
    const { rerender, container } = render(<StatementText text="Plain answer." className="tsl-iris-text" />);
    expect(screen.queryByTestId("iris-statements")).toBeNull();
    expect(container.textContent).toBe("Plain answer.");
    rerender(<StatementText text="Something else entirely." statements={statements} />);
    expect(screen.queryByTestId("iris-statements")).toBeNull();
    expect(container.textContent).toBe("Something else entirely.");
  });

  it("names every class, and shows an unknown class verbatim", () => {
    expect(Object.keys(CLASS_WORD).sort()).toEqual(
      ["CORRELIX_RCA", "DERIVED", "DOCUMENTATION", "HISTORICAL", "OBSERVED", "RECOMMENDATION"]);
    expect(classWord("HISTORICAL")).toBe("Past investigation");
    expect(classWord("DOCUMENTATION")).toBe("Documentation");
    expect(classWord("FUTURE_CLASS")).toBe("FUTURE_CLASS");
    expect(statementTag({ text: "x", class: "HISTORICAL", grounded: false })).toBe("Past investigation · no evidence cited");
    expect(statementsMatch("ab", [{ text: "a", class: "OBSERVED", grounded: true }, { text: "b", class: "OBSERVED", grounded: true }])).toBe(true);
    expect(statementsMatch("ab", [])).toBe(false);
  });
});

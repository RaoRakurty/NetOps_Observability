// AskIris.test.tsx — the affordance that carries the words a screen gave up.
//
// docs/design/UI_WORDS_IRIS_EXPLAINS_2026-09-06.md. The contract is small and
// every clause of it is load-bearing:
//   · it names the thing it explains, so a screen reader hears "Ask Iris about
//     Confirmed RCA" and not "button";
//   · it sends the TOPIC ID, never the prose — the server owns the answer;
//   · it does not filter, navigate or submit the control it sits inside;
//   · it renders (and works) with no shell provider, because it is dropped into
//     cards that are unit tested standalone.

import { describe, it, expect, afterEach, vi } from "vitest";
import { render, screen, cleanup, fireEvent } from "@testing-library/react";
import { readFileSync, readdirSync, existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import AskIris, { IRIS_ASK_EVENT, irisAskQuestion, type IrisAskDetail } from "./AskIris";
import { ShellContext, type ShellState, TIME_RANGES } from "../context/shell";

afterEach(() => { cleanup(); vi.restoreAllMocks(); });

/** Captures every iris:ask raised during the test. */
function listen(): IrisAskDetail[] {
  const seen: IrisAskDetail[] = [];
  window.addEventListener(IRIS_ASK_EVENT, (e) => seen.push((e as CustomEvent<IrisAskDetail>).detail));
  return seen;
}

const shell = (over: Partial<ShellState>): ShellState => ({
  range: TIME_RANGES[1], setRange: () => {},
  query: "", setQuery: () => {},
  copilotOpen: false, setCopilotOpen: () => {},
  helpOpen: false, setHelpOpen: () => {}, helpPath: "", openHelp: () => {},
  navigate: () => {},
  ...over,
});

describe("AskIris", () => {
  it("is named after the words it explains", () => {
    render(<AskIris topic="kpi.confirmed-rca" label="Confirmed RCA" />);
    expect(screen.getByRole("button", { name: "Ask Iris about Confirmed RCA" })).toBeTruthy();
  });

  it("sends the topic id and a question an operator could have typed", () => {
    const seen = listen();
    render(<AskIris topic="kpi.confirmed-rca" label="Confirmed RCA" />);
    fireEvent.click(screen.getByRole("button", { name: /Ask Iris/ }));
    expect(seen).toEqual([{ topic: "kpi.confirmed-rca", question: irisAskQuestion("Confirmed RCA") }]);
    // The prose never travels: the server answers from its own authored file.
    expect(seen[0].question).not.toContain("mean:");
    expect(seen[0].topic).toBe("kpi.confirmed-rca");
  });

  // The button reads NO context on purpose: it is dropped into cards that are
  // unit tested with the shell module mocked, and a context read here would make
  // an explanation affordance the reason an unrelated page test fails. Opening
  // the drawer belongs to the drawer (components/OpsisDrawer.tsx).
  it("touches no shell state — it only raises the event", () => {
    const setCopilotOpen = vi.fn();
    render(
      <ShellContext.Provider value={shell({ setCopilotOpen })}>
        <AskIris topic="chip.noc-pressure" label="NOC pressure" />
      </ShellContext.Provider>,
    );
    fireEvent.click(screen.getByRole("button", { name: /Ask Iris/ }));
    expect(setCopilotOpen).not.toHaveBeenCalled();
  });

  it("asking the same topic twice raises the event twice", () => {
    const seen = listen();
    render(<AskIris topic="kpi.critical" label="Critical" />);
    const btn = screen.getByRole("button", { name: /Ask Iris/ });
    fireEvent.click(btn);
    fireEvent.click(btn);
    expect(seen).toHaveLength(2);
  });

  // The regression that would otherwise be found in production: a KPI tile IS a
  // filter button, and a queue row IS a click target. Explaining a number must
  // never also change what the operator is looking at.
  it("never triggers the control it sits inside", () => {
    const seen = listen();
    const onTile = vi.fn();
    // A div, not a <button>, only because a button inside a button is invalid
    // DOM. The real KPI tile keeps the `(i)` as a SIBLING of its filter button
    // for the same reason; what is under test here is the click never escaping.
    render(
      <div onClick={onTile}>
        83<AskIris topic="kpi.rca-blocked" label="Blocked" />
      </div>,
    );
    fireEvent.click(screen.getByRole("button", { name: /Ask Iris/ }));
    expect(onTile).not.toHaveBeenCalled();
    expect(seen).toHaveLength(1);
  });

  it("works with no shell provider (a page card under test is not the app)", () => {
    const seen = listen();
    render(<AskIris topic="kpi.untriaged" label="Untriaged" />);
    expect(() => fireEvent.click(screen.getByRole("button", { name: /Ask Iris/ }))).not.toThrow();
    expect(seen).toHaveLength(1);
  });

  it("draws a 16px icon and no words", () => {
    const { container } = render(<AskIris topic="kpi.untriaged" label="Untriaged" />);
    const btn = container.querySelector("button.ask-iris") as HTMLElement;
    expect(btn.textContent).toBe("");
    expect(btn.querySelector("svg")?.getAttribute("width")).toBe("16");
  });
});

// ── the cross-language contract ─────────────────────────────────────────────
//
// An `(i)` whose topic has no authored file is worse than no `(i)` at all: it
// promises an explanation and delivers a refusal. The backend refuses honestly
// (ai/explain.go), but the gap must never SHIP — so the shipped UI and the
// authored corpus are checked against each other here, in the one test that
// fails fast and names the missing file.

const SRC = dirname(dirname(fileURLToPath(import.meta.url)));   // src/frontend/src
const EXPLAIN = join(SRC, "..", "..", "backend", "ai", "skills", "explain");

/** Every topic id a shipped .tsx/.ts hands to AskIris. */
function referencedTopics(dir: string, out = new Set<string>()): Set<string> {
  for (const e of readdirSync(dir, { withFileTypes: true })) {
    const full = join(dir, e.name);
    if (e.isDirectory()) {
      if (e.name !== "node_modules") referencedTopics(full, out);
      continue;
    }
    if (!/\.tsx?$/.test(e.name) || e.name.includes(".test.")) continue;
    const src = readFileSync(full, "utf-8");
    // `topic="x"`, `topic: "x"`, and the expression forms `topic={cond ? "a" : "b"}`.
    for (const m of src.matchAll(/topic[=:]\s*(?:"([\w.-]+)"|\{([^}]*)\})/g)) {
      if (m[1]) { out.add(m[1]); continue; }
      for (const q of (m[2] ?? "").matchAll(/"([a-z][a-z0-9]*(?:[.-][a-z0-9]+)+)"/g)) out.add(q[1]);
    }
  }
  return out;
}

describe("AskIris topics are authored", () => {
  it("every topic the UI asks for has a file in ai/skills/explain", () => {
    expect(existsSync(EXPLAIN), `explain corpus not found at ${EXPLAIN}`).toBe(true);
    const authored = new Set(readdirSync(EXPLAIN).filter((f) => f.endsWith(".md")).map((f) => f.slice(0, -3)));
    const missing = [...referencedTopics(SRC)].filter((t) => !authored.has(t)).sort();
    expect(
      missing,
      "an (i) promises an explanation; write src/backend/ai/skills/explain/<topic>.md for:\n" + missing.join("\n"),
    ).toEqual([]);
  });

  it("finds topics to check (a broken walk must not pass silently)", () => {
    expect(referencedTopics(SRC).size).toBeGreaterThan(30);
  });
});

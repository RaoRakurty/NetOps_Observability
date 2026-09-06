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

  it("opens the assistant when a shell is present", () => {
    const setCopilotOpen = vi.fn();
    render(
      <ShellContext.Provider value={shell({ setCopilotOpen })}>
        <AskIris topic="chip.noc-pressure" label="NOC pressure" />
      </ShellContext.Provider>,
    );
    fireEvent.click(screen.getByRole("button", { name: /Ask Iris/ }));
    expect(setCopilotOpen).toHaveBeenCalledWith(true);
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

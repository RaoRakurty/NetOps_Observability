// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// HypothesisTrace.test.tsx — the lines of investigation in the investigation
// trace (tracker 337 N-B3): the engine's verdict labelled as the engine's,
// each hypothesis's state as a word with its transitions and evidence, nothing
// rendered as markup, fonts on the 14 / 16 px scale, a held set read back by
// id, a 404 as a plain sentence and every other failure through operatorError.

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, cleanup, fireEvent } from "@testing-library/react";
import type { AiHypothesisSet } from "../services/api";

const aiHypotheses = vi.fn();
vi.mock("../services/api", () => ({
  api: { aiHypotheses: (...a: unknown[]) => aiHypotheses(...a) },
}));

import HypothesisTrace, { engineHeading, stateWord, STATE_WORD } from "./HypothesisTrace";

const ID = "11111111-2222-4333-8444-555555555555";

function sampleSet(over: Partial<AiHypothesisSet> = {}): AiHypothesisSet {
  return {
    notice: "Lines of investigation, not causes: each one records what a check observed. Only the correlation engine names a root cause.",
    engine: {
      tier: "confirmed", statement: "P-7 — BGP peer down on edge-1; verdict confirmed", citation_id: "verdict:p7",
      note: "This is the correlation engine's verdict (Confirmed). Iris does not replace it.",
    },
    hypotheses: [
      {
        id: "bgp-session", statement: "A BGP session on the device is not Established", layer: "bgp", state: "SUPPORTED",
        evidence: ["state:bgp:dev:1"], engine_note: "Consistent with the correlation engine's verdict above, which alone names the cause.",
        transitions: [
          { to: "PROPOSED", round: 1, skill: "bgp-session-down", tool: "get_device_state", reason: "the bgp session down check can test this with Device state" },
          { from: "PROPOSED", to: "TESTING", round: 1, skill: "bgp-session-down", tool: "get_device_state", fact: "tool:get_device_state=ok", reason: "tested with Device state" },
          { from: "TESTING", to: "SUPPORTED", round: 1, skill: "bgp-session-down", tool: "get_device_state", fact: "state:bgp_peer=idle", reason: "the BGP session is idle" },
        ],
      },
      {
        id: "link-down", statement: "The interface in scope is down", layer: "physical", state: "INCONCLUSIVE",
        evidence: ["state:interfaces:dev:1"],
        engine_note: "The engine's verdict does not name this. The observation is shown as evidence; it does not replace or contradict the engine's verdict.",
        transitions: [
          { to: "PROPOSED", round: 2, skill: "interface-down", reason: "the interface down check can test this with Device state" },
          { from: "PROPOSED", to: "TESTING", round: 2, skill: "interface-down", reason: "tested with Device state" },
          { from: "TESTING", to: "INCONCLUSIVE", round: 2, skill: "interface-down", fact: "verdict:tier=confirmed",
            reason: "the interface is operationally down, but the correlation engine's verdict (Confirmed) does not name this — it is kept as evidence only" },
        ],
      },
      {
        id: "bgp-fault-signature", statement: "A known BGP fault signature matches the device's own output", layer: "bgp", state: "REJECTED",
        transitions: [{ from: "TESTING", to: "REJECTED", round: 1, reason: "the protocol diagnostic ran and no known signature matched" }],
      },
    ],
    ...over,
  };
}

beforeEach(() => { aiHypotheses.mockReset(); });
afterEach(() => cleanup());

/** Every inline font size inside el is on the 14 / 16 px scale. */
function fontsOnScale(el: HTMLElement): string[] {
  const off: string[] = [];
  el.querySelectorAll<HTMLElement>("[style]").forEach((n) => {
    const fs = n.style.fontSize;
    if (fs && fs !== "14px" && fs !== "16px") off.push(`${n.tagName}:${fs}`);
  });
  return off;
}

describe("stateWord / engineHeading", () => {
  it("names every state in words and keeps an unknown one verbatim", () => {
    expect(Object.keys(STATE_WORD)).toEqual(["PROPOSED", "TESTING", "SUPPORTED", "REJECTED", "INCONCLUSIVE"]);
    expect(stateWord("SUPPORTED")).toBe("Supported by evidence");
    expect(stateWord("REJECTED")).toBe("Ruled out by evidence");
    expect(stateWord("FUTURE_STATE")).toBe("FUTURE_STATE");
  });
  it("always names the engine as the source of a verdict", () => {
    expect(engineHeading({ tier: "suspected", note: "" })).toBe("Correlation engine verdict: Suspected");
    expect(engineHeading({ tier: "undetermined", note: "" })).toBe("Correlation engine: no cause identified");
    expect(engineHeading({ note: "" })).toBe("Correlation engine: no verdict in scope");
    expect(engineHeading(undefined)).toBe("Correlation engine: no verdict in scope");
  });
});

describe("HypothesisTrace", () => {
  it("renders the engine's verdict as the engine's, then each hypothesis with its state and path", () => {
    render(<HypothesisTrace set={sampleSet()} />);
    const root = screen.getByTestId("iris-hypotheses");
    const engine = screen.getByTestId("iris-hyp-engine");
    expect(engine).toHaveTextContent("Correlation engine verdict: Confirmed");
    expect(screen.getByTestId("iris-hyp-engine-statement")).toHaveTextContent("BGP peer down on edge-1");
    expect(root).toHaveTextContent("Only the correlation engine names a root cause.");

    const items = screen.getAllByTestId("iris-hyp");
    expect(items.map((i) => i.getAttribute("data-state"))).toEqual(["SUPPORTED", "INCONCLUSIVE", "REJECTED"]);
    expect(screen.getAllByTestId("iris-hyp-state").map((s) => s.textContent))
      .toEqual(["Supported by evidence", "Inconclusive", "Ruled out by evidence"]);
    // The capped hypothesis shows its observation AND why it is not a verdict.
    expect(items[1]).toHaveTextContent("does not replace or contradict the engine's verdict");

    // The path opens on demand: every transition with its round, method and reason.
    fireEvent.click(screen.getAllByText(/How this was checked/)[1]);
    const steps = screen.getAllByTestId("iris-hyp-steps")[1];
    expect(steps).toHaveTextContent("Proposed — round 2, interface down");
    expect(steps).toHaveTextContent("Inconclusive — round 2, interface down: the interface is operationally down");
    expect(screen.getAllByTestId("iris-hyp-evidence")[1]).toHaveTextContent("state:interfaces:dev:1");
  });

  it("never presents a hypothesis as the cause — no Iris-authored cause wording", () => {
    render(<HypothesisTrace set={sampleSet({ engine: { tier: "undetermined", note: "The correlation engine has not identified a cause for this incident (status: Undetermined). Iris does not name one." } })} />);
    const root = screen.getByTestId("iris-hypotheses");
    expect(screen.getByTestId("iris-hyp-engine")).toHaveTextContent("Correlation engine: no cause identified");
    expect(screen.queryByTestId("iris-hyp-engine-statement")).toBeNull();
    // Component-authored words never assert a cause.
    const authored = [root.querySelector("h4")?.textContent, ...Object.values(STATE_WORD)].join(" ");
    expect(authored).not.toMatch(/root cause|caused by|because of|the cause/i);
  });

  it("renders every string as text, never markup", () => {
    const evil = sampleSet();
    evil.hypotheses[0].statement = "<img src=x onerror=alert(1)>";
    evil.engine.statement = "<script>alert(1)</script>";
    const { container } = render(<HypothesisTrace set={evil} />);
    expect(container.querySelector("img")).toBeNull();
    expect(container.querySelector("script")).toBeNull();
    expect(screen.getAllByTestId("iris-hyp")[0]).toHaveTextContent("<img src=x onerror=alert(1)>");
  });

  it("keeps every font on the 14 / 16 px scale", () => {
    const { container } = render(<HypothesisTrace set={sampleSet()} />);
    screen.getAllByText(/How this was checked/).forEach((s) => fireEvent.click(s));
    expect(fontsOnScale(container)).toEqual([]);
    expect(container.querySelector("h4")?.style.fontSize).toBe("16px");
  });

  it("draws nothing without a set or an id", () => {
    const { container } = render(<HypothesisTrace />);
    expect(container.innerHTML).toBe("");
  });

  it("reads a held set back by id", async () => {
    aiHypotheses.mockResolvedValue(sampleSet({ id: ID }));
    render(<HypothesisTrace investigationId={ID} />);
    expect(await screen.findByTestId("iris-hypotheses")).toBeInTheDocument();
    expect(aiHypotheses).toHaveBeenCalledWith(ID);
  });

  it("says plainly when a held set is gone (404)", async () => {
    aiHypotheses.mockRejectedValue(new Error('404 Not Found: {"error":"not found"}'));
    render(<HypothesisTrace investigationId={ID} />);
    expect(await screen.findByTestId("iris-hypotheses-gone")).toHaveTextContent("no longer held");
    expect(screen.queryByRole("alert")).toBeNull();
  });

  it("routes any other failure through operatorError — no developer text on screen", async () => {
    aiHypotheses.mockRejectedValue(new Error('500 Internal Server Error: {"error":"dial tcp 10.0.0.5:5432: connect: connection refused"}'));
    render(<HypothesisTrace investigationId={ID} />);
    const alert = await screen.findByRole("alert");
    expect(alert.textContent).not.toMatch(/10\.0\.0\.5|dial tcp|\{/);
    expect(alert.style.fontSize).toBe("14px");
  });
});

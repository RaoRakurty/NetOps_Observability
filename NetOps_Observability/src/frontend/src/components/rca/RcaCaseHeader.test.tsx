// RcaCaseHeader.test.tsx — the RCA "six-question" case header, lifted out of
// RcaWorkspace so the Troubleshooting investigation surface can show the SAME
// verdict for the same object instead of growing a second vocabulary.
//
// This file pins the header's contract at its new home: what happened (title) ·
// how certain (pills) · the decision callout · when + which RCA id · the aside
// claims · the evidence summary · the feedback slot. RcaWorkspace.test.tsx
// continues to assert the same things through the workspace, which is the
// regression net for the extraction.

import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, cleanup, within } from "@testing-library/react";
import RcaCaseHeader, { Pill } from "./RcaCaseHeader";
import { buildRcaCase, type EvidenceSummary, type RcaCase } from "./rcaCase";
import { signal, timeline, corrObject } from "../../test/factories";

vi.mock("../../services/api", () => ({ api: {} }));

function baseCase(over: Partial<RcaCase> = {}): RcaCase {
  const tl = timeline({
    verdict_tier: "suspected",
    signals: [signal({ kind: "bgp_state_anomaly", modality_class: "control_plane", entity_id: "wan-r2:192.168.100.5" })],
  });
  return { ...buildRcaCase(tl, corrObject(), {}, "NetOps", []), ...over };
}

const summary: EvidenceSummary = {
  symptoms: 2, sources: 2, durationLabel: "22m, ongoing",
  verdictReason: "Two independent sources saw the same interruption.",
  observations: 41,
  rows: [
    { label: "BGP session interrupted", source: "Routing", since: "19:25", buckets: [0, 3, 1, 0], observations: 4, fidelity: "B2" },
    { label: "Interface down", source: "Device health", since: "19:26", buckets: [1, 0, 0, 0], observations: 1 },
  ],
};

beforeEach(() => cleanup());

describe("the six-question header", () => {
  it("renders the case title as the section heading", () => {
    const data = baseCase();
    render(<RcaCaseHeader data={data} />);
    expect(screen.getByRole("heading", { level: 2 })).toHaveTextContent(data.title);
  });

  it("renders every status pill with its tone", () => {
    const data = baseCase({ pills: [{ tone: "orange", text: "Suspected" }, { tone: "blue", text: "2 sources" }] });
    const { container } = render(<RcaCaseHeader data={data} />);
    data.pills.forEach((p) => expect(screen.getByText(p.text)).toBeInTheDocument());
    expect(container.querySelectorAll(".rw-pill")).toHaveLength(2);
    expect(container.querySelector(".rw-pill")?.className).toContain("orange");
  });

  it("renders the decision callout with its tone when the engine made one", () => {
    const data = baseCase({ decision: { tone: "red", text: "Escalate to the carrier." } });
    const { container } = render(<RcaCaseHeader data={data} />);
    expect(screen.getByText("Decision:")).toBeInTheDocument();
    expect(screen.getByText("Escalate to the carrier.")).toBeInTheDocument();
    expect(container.querySelector(".rw-callout")?.className).toContain("red");
  });

  it("renders NO decision callout when the engine decided nothing", () => {
    const { container } = render(<RcaCaseHeader data={baseCase({ decision: { tone: "", text: "" } })} />);
    expect(container.querySelector(".rw-callout")).toBeNull();
    expect(screen.queryByText("Decision:")).toBeNull();
  });

  it("states when it was detected and which RCA id it is", () => {
    const data = baseCase({ observedAt: "2026-06-16 19:25", rcaId: "P-ABC123" });
    render(<RcaCaseHeader data={data} />);
    expect(screen.getByText("2026-06-16 19:25")).toBeInTheDocument();
    expect(screen.getByText("P-ABC123")).toBeInTheDocument();
  });

  it("renders every aside claim, keeping the mono flag", () => {
    const data = baseCase({ aside: [{ k: "Affected", v: "wan-r2" }, { k: "Peer", v: "192.0.2.9", mono: true }] });
    const { container } = render(<RcaCaseHeader data={data} />);
    expect(container.querySelectorAll(".rw-metric")).toHaveLength(2);
    expect(screen.getByText("Affected")).toBeInTheDocument();
    expect(screen.getByText("192.0.2.9").className).toContain("mono");
    expect(screen.getByText("wan-r2").className).not.toContain("mono");
  });
});

describe("the evidence summary", () => {
  it("renders the verdict reason and one row per symptom", () => {
    render(<RcaCaseHeader data={baseCase({ evidenceSummary: summary })} />);
    const block = screen.getByLabelText("Evidence summary");
    expect(block).toHaveTextContent("Two independent sources saw the same interruption.");
    expect(within(block).getByText("BGP session interrupted")).toBeInTheDocument();
    expect(within(block).getByText("Interface down")).toBeInTheDocument();
    expect(block.querySelectorAll(".rw-evsum-row")).toHaveLength(2);
  });

  it("renders repetition as ink — one cell per bucket — and the onset", () => {
    render(<RcaCaseHeader data={baseCase({ evidenceSummary: summary })} />);
    const rows = screen.getByLabelText("Evidence summary").querySelectorAll(".rw-evsum-row");
    expect(rows[0].querySelectorAll(".rw-evsum-cell")).toHaveLength(4);
    expect(rows[0]).toHaveTextContent("since 19:25");
    expect(rows[0].getAttribute("title")).toContain("seen by Routing");
    expect(rows[0].getAttribute("title")).toContain("4 observations");
  });

  it("badges only the rows whose fidelity the engine named", () => {
    const { container } = render(<RcaCaseHeader data={baseCase({ evidenceSummary: summary })} />);
    // one row carries a fidelity tier, one does not — no placeholder for the second
    expect(container.querySelectorAll(".rw-evsum-row")[1].textContent).not.toContain("B2");
  });

  it("renders nothing when the engine produced no evidence summary", () => {
    const { container } = render(<RcaCaseHeader data={baseCase({ evidenceSummary: undefined })} />);
    expect(container.querySelector(".rw-evsum")).toBeNull();
    cleanup();
    const empty = render(<RcaCaseHeader data={baseCase({ evidenceSummary: { ...summary, rows: [] } })} />);
    expect(empty.container.querySelector(".rw-evsum")).toBeNull();
  });
});

describe("the feedback slot", () => {
  it("renders the host's feedback row under the aside", () => {
    const { container } = render(
      <RcaCaseHeader data={baseCase()} feedbackSlot={<div data-testid="fb">Was this right?</div>} />,
    );
    expect(screen.getByTestId("fb")).toBeInTheDocument();
    expect(container.querySelector(".rw-fbrow")).not.toBeNull();
  });

  it("renders no feedback row when the host offered none (the investigation surface)", () => {
    const { container } = render(<RcaCaseHeader data={baseCase()} />);
    expect(container.querySelector(".rw-fbrow")).toBeNull();
  });
});

describe("Pill", () => {
  it("is exported for the workspace and carries the tone class", () => {
    const { container } = render(<Pill p={{ tone: "green", text: "Recovered" }} />);
    expect(container.firstElementChild?.className).toBe("rw-pill green");
    expect(screen.getByText("Recovered")).toBeInTheDocument();
  });
});

describe("every value is escaped text (§15)", () => {
  it("a hostile title renders as characters, not as markup", () => {
    const hostile = '<img src=x onerror="alert(1)">';
    const { container } = render(<RcaCaseHeader data={baseCase({ title: hostile })} />);
    expect(screen.getByRole("heading", { level: 2 })).toHaveTextContent(hostile);
    expect(container.querySelector("img")).toBeNull();
    expect(container.innerHTML).toContain("&lt;img");
  });

  it("a hostile decision text renders as characters", () => {
    const { container } = render(<RcaCaseHeader data={baseCase({ decision: { tone: "", text: "<script>x</script>" } })} />);
    expect(screen.getByText("<script>x</script>")).toBeInTheDocument();
    expect(container.querySelector("script")).toBeNull();
  });
});

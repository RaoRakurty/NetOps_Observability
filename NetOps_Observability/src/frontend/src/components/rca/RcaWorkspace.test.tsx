import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent, within, cleanup } from "@testing-library/react";
import RcaWorkspace from "./RcaWorkspace";
import { buildRcaCase, EXAMPLE_CASE } from "./rcaCase";
import { signal, timeline, corrObject } from "../../test/factories";

// Mock the API so the assistant wiring is exercised without a real backend.
const copilotChat = vi.fn();
vi.mock("../../services/api", () => ({ api: { copilotChat: (...a: unknown[]) => copilotChat(...a) } }));

function suspectedCase() {
  const tl = timeline({
    verdict_tier: "suspected",
    signals: [signal({ kind: "bgp_state_anomaly", modality_class: "control_plane", entity_id: "wan-r2:192.168.100.5", attrs: '{"peer":"192.168.100.5"}' })],
  });
  return buildRcaCase(tl, corrObject(), {}, "NetOps", []);
}

function renderWS(data = suspectedCase(), view: "operator" | "debug" = "operator") {
  const onView = vi.fn();
  const onExportPdf = vi.fn();
  const utils = render(
    <RcaWorkspace data={data} view={view} onView={onView} onExportPdf={onExportPdf}
      topologySlot={<div data-testid="topo-slot">TOPOLOGY</div>}
      debugExtra={<div data-testid="replay">REPLAY</div>} />,
  );
  return { ...utils, onView, onExportPdf, data };
}

beforeEach(() => { cleanup(); copilotChat.mockReset(); });

describe("RcaWorkspace — operator view renders every widget from the data", () => {
  it("renders the case title, subtitle and all status pills", () => {
    const { data } = renderWS();
    expect(screen.getByRole("heading", { level: 2 })).toHaveTextContent(data.title);
    data.pills.forEach((p) => expect(screen.getByText(p.text)).toBeInTheDocument());
  });

  it("renders the executive summary and every why-line", () => {
    const { data } = renderWS();
    expect(screen.getByText(data.summary)).toBeInTheDocument();
    data.why.forEach((w) => expect(screen.getByText(new RegExp(w.label))).toBeInTheDocument());
  });

  it("renders every impact row value", () => {
    const { data } = renderWS();
    data.impact.forEach((r) => expect(screen.getAllByText(r.v).length).toBeGreaterThan(0));
  });

  it("uses the topology slot when provided", () => {
    renderWS();
    expect(screen.getByTestId("topo-slot")).toBeInTheDocument();
  });

  it("renders one evidence card per plane with its finding", () => {
    const { data } = renderWS();
    expect(screen.getByText("Network path & causal topology")).toBeInTheDocument();
    // plane names (e.g. "Device health") appear in both the matrix and the
    // timeline lane labels — assert presence, not uniqueness.
    data.evidence.forEach((e) => expect(screen.getAllByText(e.title).length).toBeGreaterThan(0));
  });

  it("renders all four confidence-ladder steps and captions", () => {
    const { data } = renderWS();
    data.ladder.forEach((s) => {
      expect(screen.getByText(s.label)).toBeInTheDocument();
      expect(screen.getByText(s.caption)).toBeInTheDocument();
    });
  });

  it("renders every timeline lane (including empty ones)", () => {
    const { data } = renderWS();
    expect(data.timeline.length).toBe(4);
    data.timeline.forEach((lane) => expect(screen.getAllByText(lane.label).length).toBeGreaterThan(0));
  });

  it("clicking a timeline marker shows its detail", () => {
    const { data } = renderWS();
    const marker = data.timeline.flatMap((l) => l.markers)[0];
    fireEvent.click(screen.getByRole("button", { name: marker.label }));
    expect(screen.getByText(new RegExp("Marker detail"))).toBeInTheDocument();
  });

  it("renders each hypothesis row and the ticket callout", () => {
    const { data } = renderWS();
    // the #1 hypothesis text can equal the case title — assert presence.
    data.hypotheses.forEach((h) => expect(screen.getAllByText(h.hypo).length).toBeGreaterThan(0));
    expect(screen.getByText(new RegExp(data.ticket.callout.strong))).toBeInTheDocument();
  });

  it("renders every next-action with its badge", () => {
    const { data } = renderWS();
    data.nextActions.forEach((a) => expect(screen.getByText(a.text)).toBeInTheDocument());
  });

  it("does not render the debug JSON model in operator view", () => {
    renderWS();
    expect(screen.queryByText("Correlation data model")).not.toBeInTheDocument();
  });
});

describe("RcaWorkspace — view toggle + export wiring", () => {
  it("Export PDF button invokes the callback", () => {
    const { onExportPdf } = renderWS();
    fireEvent.click(screen.getByRole("button", { name: /Export PDF/ }));
    expect(onExportPdf).toHaveBeenCalledOnce();
  });

  it("clicking Debug View requests the view change", () => {
    const { onView } = renderWS();
    fireEvent.click(screen.getByRole("tab", { name: "Debug View" }));
    expect(onView).toHaveBeenCalledWith("debug");
  });

  it("debug view shows the accounting table, JSON model and the replay slot", () => {
    renderWS(suspectedCase(), "debug");
    expect(screen.getByText("Correlation data model")).toBeInTheDocument();
    expect(screen.getByText("Promotion logic")).toBeInTheDocument();
    expect(screen.getByTestId("replay")).toBeInTheDocument();
  });
});

describe("RcaWorkspace — Ask RCA assistant (Correlix AI) wiring", () => {
  it("sends the question to copilotChat and shows the answer", async () => {
    copilotChat.mockResolvedValue({ provider: "test", text: "Because evidence is single-source." });
    renderWS();
    fireEvent.click(screen.getByRole("button", { name: "Ask" }));
    expect(copilotChat).toHaveBeenCalledOnce();
    expect(await screen.findByText(/Because evidence is single-source\./)).toBeInTheDocument();
    // grounding must carry RCA context, never secrets
    const sent = JSON.stringify(copilotChat.mock.calls[0]);
    expect(sent).toMatch(/RCA context/);
  });

  it("degrades to an honest 'not connected' state when the assistant errors", async () => {
    copilotChat.mockRejectedValue(new Error("feature disabled"));
    renderWS();
    fireEvent.click(screen.getByRole("button", { name: "Ask" }));
    expect(await screen.findByText(/Assistant not connected/)).toBeInTheDocument();
  });
});

describe("RcaWorkspace — synthetic EXAMPLE_CASE shows the watermark", () => {
  it("flags synthetic data", () => {
    renderWS(EXAMPLE_CASE);
    expect(screen.getByText(/Synthetic data/)).toBeInTheDocument();
  });
});

describe("RcaWorkspace — cloud section (#81 P3G 1c)", () => {
  it("is absent for a network-only object", () => {
    renderWS(suspectedCase());
    expect(screen.queryByText("Cloud application & resources")).not.toBeInTheDocument();
  });

  it("renders app, resources, changes and the corroboration seam when cloud evidence exists", () => {
    const tl = timeline({
      verdict_tier: "suspected",
      signals: [
        signal({ source: "cloud", kind: "cloud_health", modality_class: "device_telemetry", entity_type: "app", entity_id: "billing", attrs: '{"app":"billing","account":"123","region":"us-east-1"}', severity: "high" }),
        signal({ source: "cloud", kind: "database_metric", modality_class: "device_telemetry", entity_type: "cloud_resource", entity_id: "billing-db", metric_name: "connections_pct", value: 98, severity: "warn", is_trigger: false }),
      ],
    });
    renderWS(buildRcaCase(tl, corrObject({ verdict_tier: "suspected", signal_count: 2 }), {}, "AppOps", []));
    expect(screen.getByText("Cloud application & resources")).toBeInTheDocument();
    expect(screen.getByText("billing")).toBeInTheDocument();
    expect(screen.getByText("billing-db")).toBeInTheDocument();
    expect(screen.getByText("Single-plane · suspected")).toBeInTheDocument();
    expect(screen.getByText(/Cloud ↔ network seam/)).toBeInTheDocument();
  });
});

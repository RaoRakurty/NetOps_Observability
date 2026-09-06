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
      pathSlot={<div data-testid="path-slot">PATH</div>}
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

  it("renders ONE merged path section (owner P1: no duplicate topology section)", () => {
    renderWS();
    expect(screen.getByTestId("path-slot")).toBeInTheDocument();
    expect(screen.getByText("Network path & causality")).toBeInTheDocument();
    // the old duplicate section is gone
    expect(screen.queryByText("Network path & causal topology")).not.toBeInTheDocument();
    expect(screen.queryByText("Path causality")).not.toBeInTheDocument();
  });

  it("renders one evidence card per plane with its finding", () => {
    const { data } = renderWS();
    // plane names (e.g. "Device health") appear in both the matrix and the
    // timeline lane labels — assert presence, not uniqueness.
    data.evidence.forEach((e) => expect(screen.getAllByText(e.title).length).toBeGreaterThan(0));
  });

  it("renders all four confidence-ladder steps and captions", () => {
    const { data } = renderWS();
    data.ladder.forEach((s) => {
      expect(screen.getByText(s.label)).toBeInTheDocument();
      expect(screen.getByText(s.caption)).toBeInTheDocument();
      // ui-words sweep 5 (tracker 270): a ladder caption is a locator, never a
      // sentence — the budget is three words and what a step MEANS is
      // explain/rca.confidence-ladder.md behind the (i) on the section heading.
      expect(s.caption.trim().split(/\s+/).length).toBeLessThanOrEqual(3);
    });
    expect(screen.getByRole("button", { name: "Ask Iris about Confidence ladder" })).toBeInTheDocument();
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

describe("RcaWorkspace — event timeline (owner P1 2026-07-19)", () => {
  it("renders chronological events with real timestamps as an accessible collapsible list", () => {
    const { container } = renderWS();
    expect(screen.getByText("Event timeline")).toBeInTheDocument();
    // first symptom entry, derived from the signal's real timestamp
    expect(screen.getByText(/First symptom — /)).toBeInTheDocument();
    // native <details> (keyboard-operable collapse), open by default
    const details = container.querySelector("details.rw-events") as HTMLDetailsElement;
    expect(details).toBeTruthy();
    expect(details.open).toBe(true);
    // list semantics + machine-readable <time dateTime>
    const items = details.querySelectorAll("ol.rw-events-list > li");
    expect(items.length).toBeGreaterThan(0);
    const time = details.querySelector("time") as HTMLTimeElement;
    expect(time.getAttribute("dateTime")).toMatch(/^\d{4}-\d{2}-\d{2}T/);
  });

  it("renders no event panel when the case has no events", () => {
    const data = { ...suspectedCase(), events: [] };
    renderWS(data);
    expect(screen.queryByText("Event timeline")).not.toBeInTheDocument();
  });
});

describe("RcaWorkspace — view toggle + export wiring", () => {
  it("Export PDF button invokes the callback", () => {
    const { onExportPdf } = renderWS();
    fireEvent.click(screen.getByRole("button", { name: /Export PDF/ }));
    expect(onExportPdf).toHaveBeenCalledOnce();
  });

  it("clicking Evidence detail requests the view change", () => {
    const { onView } = renderWS();
    // a11y pass: the view switch is a toggle-button group (aria-pressed), not
    // an ARIA tablist (no tabpanel/roving-focus wiring exists here).
    fireEvent.click(screen.getByRole("button", { name: "Evidence detail" }));
    expect(onView).toHaveBeenCalledWith("debug");
  });

  it("debug view shows the accounting table, JSON model and the replay slot", () => {
    renderWS(suspectedCase(), "debug");
    expect(screen.getByText("Correlation data model")).toBeInTheDocument();
    expect(screen.getByText("Promotion logic")).toBeInTheDocument();
    expect(screen.getByTestId("replay")).toBeInTheDocument();
  });
});

describe("RcaWorkspace — Ask RCA assistant (Iris AI) wiring", () => {
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

// ── Security evidence rows + parser-rule fidelity (T2b class / A7) ───────────

const SEC_ATTRS = JSON.stringify({
  evidence_class: "security", evidence_subclass: "exposure", rule_id: "netrule.exposed_mgmt",
  parser_rev: "bus", fidelity: "doc_claimed", seam_id: "seam-7", seam_type: "DIA", internet_facing: true,
});

function securityCase(objOver: Record<string, unknown> = {}) {
  const tl = timeline({
    verdict_tier: "confirmed", top_hypothesis: "sig.ent.security.exposure-story",
    signals: [
      signal({ kind: "bgp_adjacency_change", modality_class: "control_plane", entity_id: "edge-r1:192.168.100.5",
        attrs: '{"peer":"192.168.100.5","fidelity":"live_validated"}' }),
      signal({ kind: "security_exposure", source: "security", modality_class: "security", observer_type: "platform",
        observer_id: "security:vuln", collection_path: "via_aggregator", entity_id: "edge-r1", metric_name: "",
        attrs: SEC_ATTRS, is_trigger: false, ts: "2026-06-16 19:25:20" }),
    ],
  });
  return buildRcaCase(tl, corrObject({ verdict_tier: "confirmed", signal_count: 2, ...objOver }), {}, "netops", []);
}

describe("RcaWorkspace — security evidence reads as its own source class", () => {
  it("renders the security row by subclass with its seam, exposure and provider chips", () => {
    renderWS(securityCase());
    expect(screen.getByText("Exposure")).toBeInTheDocument();
    expect(screen.getByText("Seam: ISP (seam-7)")).toBeInTheDocument();
    expect(screen.getByText("Internet-facing")).toBeInTheDocument();
    expect(screen.getByText("Observed by vuln")).toBeInTheDocument();
  });

  it('accounts security + network evidence as "2 independent sources"', () => {
    renderWS(securityCase());
    expect(screen.getByText("Confirmed — cross-checked by 2 independent sources (Routing & link events + Security evidence).")).toBeInTheDocument();
  });

  it("shows no security row at all for a network-only case", () => {
    renderWS(suspectedCase());
    expect(screen.queryByText("Exposure")).not.toBeInTheDocument();
    expect(screen.queryByText(/^Seam: /)).not.toBeInTheDocument();
  });
});

describe("RcaWorkspace — parser-rule fidelity badges", () => {
  it("renders one badge per evidence row, coloured by tier (same ladder as Telemetry Coverage)", () => {
    const tl = timeline({
      verdict_tier: "suspected",
      signals: [
        signal({ kind: "bgp_adjacency_change", modality_class: "control_plane", entity_id: "edge-r1", attrs: '{"fidelity":"live_validated"}' }),
        signal({ kind: "if_errors", modality_class: "device_telemetry", entity_id: "edge-r1", attrs: '{"fidelity":"lab_validated"}', is_trigger: false }),
        signal({ kind: "flow_volume_anomaly", modality_class: "passive_flow", entity_id: "edge-r1", attrs: '{"fidelity":"doc_claimed"}', is_trigger: false }),
        signal({ kind: "probe_loss", modality_class: "active_probe", entity_id: "probe-dallas", attrs: '{"fidelity":"code"}', is_trigger: false }),
      ],
    });
    renderWS(buildRcaCase(tl, corrObject({ signal_count: 4 }), {}, "netops", []));
    expect(screen.getAllByText("live validated")[0]).toHaveClass("badge", "tier-t1");
    expect(screen.getAllByText("lab validated")[0]).toHaveClass("badge", "tier-t3");
    expect(screen.getAllByText("doc claimed")[0]).toHaveClass("badge", "tier-t4");
    expect(screen.getAllByText("unverified")[0]).toHaveClass("badge", "tier-t5");
  });

  it("renders no badge when the evidence declared no fidelity", () => {
    renderWS(suspectedCase());
    ["live validated", "lab validated", "doc claimed", "unverified", "unrated"].forEach((t) =>
      expect(screen.queryByText(t)).not.toBeInTheDocument());
  });

  it("grades a row by its WEAKEST rule — one unproven rule caps the whole row", () => {
    const tl = timeline({
      verdict_tier: "suspected",
      signals: [
        signal({ kind: "bgp_adjacency_change", modality_class: "control_plane", entity_id: "edge-r1", attrs: '{"fidelity":"live_validated"}' }),
        signal({ kind: "bgp_state_anomaly", modality_class: "control_plane", entity_id: "edge-r1", attrs: '{"fidelity":"code"}', is_trigger: false }),
      ],
    });
    const { container } = renderWS(buildRcaCase(tl, corrObject({ signal_count: 2 }), {}, "netops", []));
    const routing = [...container.querySelectorAll<HTMLElement>(".rw-ecard")]
      .find((el) => el.querySelector(".rw-etitle")?.textContent === "Routing / link") as HTMLElement;
    expect(within(routing).getByText("unverified")).toBeInTheDocument();
    expect(within(routing).queryByText("live validated")).not.toBeInTheDocument();
  });
});

describe("RcaWorkspace — confidence ladder fidelity gap (A7)", () => {
  const gapObj = {
    verdict_tier: "suspected",
    hypotheses: JSON.stringify({
      ranking: { hypotheses: [{ id: "sig.ent.security.exposure-story", verdict: { fidelity_gap: ["netrule.exposed_mgmt"], fidelity_min: "doc_claimed" } }] },
    }),
  };

  it("states the honest reason and names the rules that held confirmation back", () => {
    renderWS(securityCase(gapObj));
    expect(screen.getByText("Confirmation held back — evidence from unvalidated parser rules: netrule.exposed_mgmt")).toBeInTheDocument();
  });

  it("renders nothing when the engine sent no gap", () => {
    renderWS(securityCase());
    expect(screen.queryByText(/Confirmation held back/)).not.toBeInTheDocument();
  });
});

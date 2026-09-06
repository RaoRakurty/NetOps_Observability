// Flows.appViews.test.tsx — the APP and SERVICE views of the flow plane, at the
// screen. flowsAppViews.test.ts pins the maths; this pins what an operator
// actually reads:
//
//   · each section asks its own endpoint with the window IN SECONDS;
//   · a 501 from the service catalog renders the SERVER'S REASON as a sentence,
//     never an empty table that reads as "no services";
//   · an unattributed service reads UNMEASURED, never "0 B" / "no traffic";
//   · the unknown bucket is a row with an explanation, not an omission;
//   · with the filter bar set, the window-only caveat is on screen — these
//     endpoints take `since` and nothing else;
//   · the per-row drill lands on Conversations for the same window.

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, cleanup, waitFor, fireEvent, within } from "@testing-library/react";

vi.mock("../components/EChart", () => ({ default: () => <div data-testid="chart" /> }));

const flowsApps = vi.fn();
const flowsServices = vi.fn();
const topTalkers = vi.fn();
const flowsTopN = vi.fn();
const flowsTimeseries = vi.fn();
const flowsByType = vi.fn();
const appIdResolveBatch = vi.fn();

vi.mock("../services/api", () => ({
  api: {
    flowsApps: (...a: unknown[]) => flowsApps(...a),
    flowsServices: (...a: unknown[]) => flowsServices(...a),
    topTalkers: (...a: unknown[]) => topTalkers(...a),
    flowsTopN: (...a: unknown[]) => flowsTopN(...a),
    flowsTimeseries: (...a: unknown[]) => flowsTimeseries(...a),
    flowsByType: (...a: unknown[]) => flowsByType(...a),
    appIdResolveBatch: (...a: unknown[]) => appIdResolveBatch(...a),
  },
}));

import Flows, { ApplicationsSection, ServicesSection } from "./Flows";
import { _resetAppNamesForTest } from "../services/appNames";

const q = { since: 3600, ftype: "", filters: {}, fkey: "", direction: "" } as never;
const noop = () => {};

const APPS = {
  apps: [
    { app: "AWS S3", src_app: "payroll", tier: "confirmed", bytes: 900, flows: 9, dests: 3 },
    { app: "unknown", src_app: "10.0.0.0/8 hosts", tier: "undetermined", bytes: 100, flows: 4, dests: 12 },
    // legacy row: no source column was recorded — NOT an unnamed app
    { app: "Salesforce", src_app: "", tier: "suspected", bytes: 50, flows: 2, dests: 1 },
  ],
  count: 3,
  coverage: { top_pairs: 200, window_seconds: 3600, catalog_prefixes: 1240 },
};

const SERVICES = {
  services: [
    { service_id: "s-pay", name: "Payroll", criticality: "high", attributed: true, bytes: 4096, flows: 12 },
    { service_id: "s-new", name: "New service", criticality: "medium", attributed: false, bytes: 0, flows: 0 },
  ],
  count: 2,
};

afterEach(cleanup);
beforeEach(() => {
  vi.useRealTimers();
  for (const m of [flowsApps, flowsServices, topTalkers, flowsTopN, flowsTimeseries, flowsByType, appIdResolveBatch]) m.mockReset();
  _resetAppNamesForTest();
  flowsApps.mockResolvedValue(APPS);
  flowsServices.mockResolvedValue(SERVICES);
  topTalkers.mockResolvedValue({ data: [] });
  flowsTopN.mockResolvedValue({ data: [] });
  flowsTimeseries.mockResolvedValue({ data: [] });
  flowsByType.mockResolvedValue({ data: [] });
  appIdResolveBatch.mockResolvedValue({});
});

describe("Applications section", () => {
  it("asks /api/flows/apps for the window in seconds, once per window", async () => {
    render(<ApplicationsSection q={q} filterKeys={[]} onDrill={noop} />);
    await waitFor(() => expect(flowsApps).toHaveBeenCalledTimes(1));
    expect(flowsApps).toHaveBeenCalledWith(3600);
    expect(flowsServices).not.toHaveBeenCalled();
  });

  it("renders the source→destination pair with the engine's attribution words", async () => {
    render(<ApplicationsSection q={q} filterKeys={[]} onDrill={noop} />);
    await waitFor(() => expect(screen.getByText("AWS S3")).toBeInTheDocument());
    expect(screen.getByText("payroll")).toBeInTheDocument();
    expect(screen.getByText("Confirmed")).toBeInTheDocument();
    expect(screen.getByText("Suspected · not confirmed")).toBeInTheDocument();
    expect(screen.getByText("Under review")).toBeInTheDocument();
  });

  it("shows the unknown bucket as its own row and explains what it means", async () => {
    render(<ApplicationsSection q={q} filterKeys={[]} onDrill={noop} />);
    await waitFor(() => expect(screen.getByText("Unknown")).toBeInTheDocument());
    // the row is a measurement: it carries its own volume and share
    const table = within(screen.getByLabelText("Applications by volume"));
    expect(table.getByText("100 B")).toBeInTheDocument();
    expect(table.getByText("9.5%")).toBeInTheDocument();
    // and the screen says what the bucket is, rather than leaving it bare
    expect(screen.getByText(/Traffic whose far end no naming source claimed/i)).toBeInTheDocument();
    expect(table.getByText("uncatalogued or internal")).toBeInTheDocument();
    // UI-words sweep 5 (tracker 270): the rest of the lesson is behind the (i)
    expect(screen.getByRole("button", { name: "Ask Iris about Unknown" })).toBeTruthy();
  });

  it("calls a legacy blank source NOT RESOLVED, never an unknown app", async () => {
    render(<ApplicationsSection q={q} filterKeys={[]} onDrill={noop} />);
    await waitFor(() => expect(screen.getByText("Source not resolved")).toBeInTheDocument());
    expect(screen.getByText(/only its far end is named/i)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Ask Iris about Source not resolved" })).toBeTruthy();
  });

  it("renders the coverage statement rather than hiding it", async () => {
    render(<ApplicationsSection q={q} filterKeys={[]} onDrill={noop} />);
    await waitFor(() => expect(screen.getByText(/busiest 200 source-to-destination pairs/i)).toBeInTheDocument());
    expect(screen.getByText(/not every flow/i)).toBeInTheDocument();
    expect(screen.getByText(/1,240 catalogued address ranges/i)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Ask Iris about Coverage" })).toBeTruthy();
  });

  it("says the filters do not narrow it when the filter bar is active", async () => {
    render(<ApplicationsSection q={q} filterKeys={["src", "device"]} onDrill={noop} />);
    await waitFor(() => expect(flowsApps).toHaveBeenCalled());
    const caveat = screen.getByText(/the filters above do not narrow these numbers/i);
    expect(caveat).toBeInTheDocument();
    // UI-words sweep 5 (tracker 270): the note is one short claim; WHICH fields
    // are ignored is the tooltip on the same element, not a second sentence.
    expect(caveat.getAttribute("title")).toMatch(/source and device/i);
    expect(caveat.getAttribute("title")).toMatch(/direction toggle/i);
  });

  it("states the window-only scope even with no filters set", async () => {
    render(<ApplicationsSection q={q} filterKeys={[]} onDrill={noop} />);
    await waitFor(() => expect(flowsApps).toHaveBeenCalled());
    expect(screen.getByText(/Applications answer over the selected time window only/i)).toBeInTheDocument();
  });

  it("owns its failure with an operator sentence, not a raw error", async () => {
    flowsApps.mockRejectedValue(new Error("502 Bad Gateway: clickhouse: dial tcp 10.0.0.9:9000: connect: connection refused"));
    render(<ApplicationsSection q={q} filterKeys={[]} onDrill={noop} />);
    await waitFor(() => expect(screen.getByText("The service did not answer.")).toBeInTheDocument());
    expect(screen.queryByText(/clickhouse/i)).not.toBeInTheDocument();
  });

  it("says nothing was named rather than showing a bare empty table", async () => {
    flowsApps.mockResolvedValue({ apps: [], count: 0, coverage: { top_pairs: 200, window_seconds: 3600, catalog_prefixes: 0 } });
    render(<ApplicationsSection q={q} filterKeys={[]} onDrill={noop} />);
    await waitFor(() => expect(screen.getByText("Nothing was named in this window.")).toBeInTheDocument());
  });
});

describe("Services section", () => {
  it("asks /api/flows/services for the window in seconds", async () => {
    render(<ServicesSection q={q} filterKeys={[]} onDrill={noop} />);
    await waitFor(() => expect(flowsServices).toHaveBeenCalledTimes(1));
    expect(flowsServices).toHaveBeenCalledWith(3600);
    expect(flowsApps).not.toHaveBeenCalled();
  });

  it("renders the 501 catalog reason as an operator sentence, not an empty list", async () => {
    flowsServices.mockRejectedValue(
      new Error('501 Not Implemented: {"error":"service catalog requires the PostgreSQL backend"}'),
    );
    render(<ServicesSection q={q} filterKeys={[]} onDrill={noop} />);
    await waitFor(() =>
      expect(screen.getByText("The service view is not available on this deployment.")).toBeInTheDocument(),
    );
    // the server's own reason is shown, verbatim in substance
    expect(screen.getByText(/service catalog requires the PostgreSQL/i)).toBeInTheDocument();
    // and no table pretending the catalog is empty
    expect(screen.queryByText("Services by volume")).not.toBeInTheDocument();
  });

  it("renders an unattributed service as UNMEASURED, never as zero traffic", async () => {
    render(<ServicesSection q={q} filterKeys={[]} onDrill={noop} />);
    await waitFor(() => expect(screen.getByText("New service")).toBeInTheDocument());

    // the measured row shows real volume …
    const table = within(screen.getByLabelText("Services by measured volume"));
    expect(table.getByText("4.0 KB")).toBeInTheDocument();
    expect(table.getByText("100.0%")).toBeInTheDocument();
    // … and the unattributed row shows neither a byte count nor a 0% share
    expect(table.getAllByText("Not measured").length).toBeGreaterThanOrEqual(3); // bytes, share, flows
    expect(table.queryByText("0 B")).not.toBeInTheDocument();
    expect(table.queryByText("0.0%")).not.toBeInTheDocument();
    expect(screen.getByText("no selector yet")).toBeInTheDocument();
    expect(screen.getByText(/No selector matches this service yet/i)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Ask Iris about Not measured" })).toBeTruthy();
  });

  it("keeps the measured service above the unmeasured group", async () => {
    render(<ServicesSection q={q} filterKeys={[]} onDrill={noop} />);
    await waitFor(() => expect(screen.getByText("Payroll")).toBeInTheDocument());
    const body = document.body.textContent ?? "";
    expect(body.indexOf("Payroll")).toBeLessThan(body.indexOf("New service"));
  });

  it("says the filters do not narrow it when the filter bar is active", async () => {
    render(<ServicesSection q={q} filterKeys={["dst"]} onDrill={noop} />);
    await waitFor(() => expect(flowsServices).toHaveBeenCalled());
    const caveat = screen.getByText(/Services: the filters above do not narrow these numbers/i);
    expect(caveat).toBeInTheDocument();
    expect(caveat.getAttribute("title")).toMatch(/destination/i);
  });

  it("owns a non-501 failure with its own operator sentence", async () => {
    flowsServices.mockRejectedValue(new Error("500 Internal Server Error: {}"));
    render(<ServicesSection q={q} filterKeys={[]} onDrill={noop} />);
    await waitFor(() => expect(screen.getByText("The service did not answer.")).toBeInTheDocument());
  });
});

describe("the drill from an app/service row", () => {
  it("switches the page to Conversations for the same window", async () => {
    render(<Flows sinceSeconds={3600} />);

    fireEvent.click(screen.getByRole("button", { name: "Applications" }));
    await waitFor(() => expect(flowsApps).toHaveBeenCalledWith(3600));
    await waitFor(() => expect(screen.getByText("AWS S3")).toBeInTheDocument());

    const table = screen.getByLabelText("Applications by volume");
    const drills = within(table).getAllByRole("button", { name: "Conversations for this window" });
    expect(drills.length).toBeGreaterThan(0);
    // the affordance is honest about what it does NOT do
    expect(drills[0].getAttribute("title")).toMatch(/not narrowed to/i);

    fireEvent.click(drills[0]);

    await waitFor(() =>
      expect(screen.getByText("Top conversations")).toBeInTheDocument(),
    );
    // the same window travelled with the switch
    await waitFor(() => expect(topTalkers).toHaveBeenCalled());
    expect(topTalkers.mock.calls[0][0]).toBe(3600);
  });

  it("offers the same drill from a service row", async () => {
    render(<Flows sinceSeconds={3600} />);

    fireEvent.click(screen.getByRole("button", { name: "Services" }));
    await waitFor(() => expect(screen.getByText("Payroll")).toBeInTheDocument());

    const table = screen.getByLabelText("Services by measured volume");
    fireEvent.click(within(table).getAllByRole("button", { name: "Conversations for this window" })[0]);

    await waitFor(() =>
      expect(screen.getByText("Top conversations")).toBeInTheDocument(),
    );
  });
});

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// talkingSections.test.tsx — the Who-is-talking views of Explore → Flows, at
// the screen. Carried over from the Flows page's tests (Flows.appnames,
// Flows.appViews, Flows.xss — removed with tabs/Flows.tsx on 2026-11-12); the
// rules they pinned still hold:
//
//   · visible endpoint IPs are resolved to application names ONCE per batch,
//     unresolved IPs render bare (no "unknown" spam);
//   · the app / service endpoints get the window in seconds and nothing else,
//     and the screen says the chip filters do not narrow them;
//   · the unknown bucket is a measured row with its explanation;
//   · an unattributed service reads UNMEASURED, never 0 B / 0 %;
//   · a 501 from the catalog renders the server's reason, not an empty table;
//   · H15a: every dynamic part of the bar tooltip ECharts inserts via
//     innerHTML is escaped — the row key AND the resolved app name.

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, cleanup, waitFor, within, fireEvent } from "@testing-library/react";

const captured: any[] = [];
vi.mock("../../components/EChart", () => ({
  default: (props: { option: unknown }) => {
    captured.push(props.option);
    return <div data-testid="chart" />;
  },
}));

const flowsApps = vi.fn();
const flowsServices = vi.fn();
const topTalkers = vi.fn();
const flowsTopN = vi.fn();
const flowsCoverage = vi.fn();
const appIdResolveBatch = vi.fn();

vi.mock("../../services/api", () => ({
  api: {
    flowsApps: (...a: unknown[]) => flowsApps(...a),
    flowsServices: (...a: unknown[]) => flowsServices(...a),
    topTalkers: (...a: unknown[]) => topTalkers(...a),
    flowsTopN: (...a: unknown[]) => flowsTopN(...a),
    flowsCoverage: (...a: unknown[]) => flowsCoverage(...a),
    appIdResolveBatch: (...a: unknown[]) => appIdResolveBatch(...a),
  },
}));

import { ApplicationsSection, ConversationsSection, ServicesSection, TopNPanel } from "./talkingSections";
import { _resetAppNamesForTest } from "../../services/appNames";
import { resetCoverageCache } from "../flowEmpty";

const q = { since: 3600, ftype: "", filters: {}, fkey: "", direction: "" };
const noop = () => {};

const APPS = {
  apps: [
    { app: "AWS S3", src_app: "payroll", tier: "confirmed", bytes: 900, flows: 9, dests: 3 },
    { app: "unknown", src_app: "10.0.0.0/8 hosts", tier: "undetermined", bytes: 100, flows: 4, dests: 12 },
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
  captured.length = 0;
  for (const m of [flowsApps, flowsServices, topTalkers, flowsTopN, flowsCoverage, appIdResolveBatch]) m.mockReset();
  _resetAppNamesForTest();
  resetCoverageCache();
  flowsApps.mockResolvedValue(APPS);
  flowsServices.mockResolvedValue(SERVICES);
  topTalkers.mockResolvedValue({ data: [] });
  flowsTopN.mockResolvedValue({ data: [] });
  flowsCoverage.mockResolvedValue({ data: [{ flows: 0 }] });
  appIdResolveBatch.mockResolvedValue({});
});

describe("Conversations — app-name enrichment", () => {
  it("batch-resolves visible IPs once and renders app names with their source", async () => {
    topTalkers.mockResolvedValue({
      data: [
        { src: "10.0.1.10", dst: "52.94.0.9", bytes_total: 3000, packets_total: 30, flows: 3 },
        { src: "192.0.2.7", dst: "8.8.8.8", bytes_total: 100, packets_total: 1, flows: 1 },
      ],
    });
    appIdResolveBatch.mockResolvedValue({
      "10.0.1.10": { app: "payroll", source: "cloud_tag", confidence: 0.95 },
      "52.94.0.9": { app: "AWS S3", source: "ip_catalog", confidence: 0.55 },
    });
    render(<ConversationsSection q={q} />);
    await waitFor(() => expect(screen.getByText("10.0.1.10")).toBeInTheDocument());
    await waitFor(() => expect(appIdResolveBatch).toHaveBeenCalledTimes(1));
    expect(appIdResolveBatch.mock.calls[0][0]).toEqual(expect.arrayContaining(["10.0.1.10", "52.94.0.9", "192.0.2.7", "8.8.8.8"]));
    await waitFor(() => expect(screen.getByText("payroll")).toBeInTheDocument());
    expect(screen.getByText("payroll")).toHaveAttribute("title", "identified by cloud_tag");
    expect(screen.getByText("8.8.8.8")).toBeInTheDocument();
    expect(screen.queryByText("unknown")).not.toBeInTheDocument();
    // Plain column words: From / To, or the two ends when both directions are folded.
    expect(screen.getByText("From")).toBeInTheDocument();
  });

  it("passes the window, source, filters and direction to the API", async () => {
    render(<ConversationsSection q={{ ...q, ftype: "sflow", filters: { device: "10.0.0.1", if: "3" }, fkey: "k", direction: "bi" }} limit={10} />);
    await waitFor(() => expect(topTalkers).toHaveBeenCalledWith(3600, 10, "sflow", { device: "10.0.0.1", if: "3" }, "bi"));
  });
});

describe("H15a — the Top-N bar tooltip escapes every dynamic interpolation", () => {
  const HOSTILE_KEY = `<img src=x onerror=alert(1)>`;
  const HOSTILE_APP = `<svg/onload=alert(2)>`;
  beforeEach(() => {
    flowsTopN.mockResolvedValue({
      data: [
        { k: HOSTILE_KEY, bytes_total: 4096, packets_total: 4, flows: 2 },
        { k: "10.0.1.10", bytes_total: 2048, packets_total: 2, flows: 1 },
      ],
    });
    appIdResolveBatch.mockResolvedValue({ "10.0.1.10": { app: HOSTILE_APP, source: "device_log", confidence: 0.9 } });
  });

  it("neutralizes a hostile row key in the real formatter", async () => {
    render(<TopNPanel title="Busiest sources" by="src_addr" q={q} />);
    await waitFor(() => expect(captured.length).toBeGreaterThan(0));
    const fmt = captured[captured.length - 1].tooltip.formatter as (p: unknown) => string;
    const out = fmt([{ name: HOSTILE_KEY, value: 4096, dataIndex: 0 }]);
    expect(out).not.toContain("<img");
    expect(out).toContain("&lt;img");
    expect(out).toContain("<br/>");
  });

  it("neutralizes a hostile resolved app name in the real formatter, without double escaping", async () => {
    render(<TopNPanel title="Busiest sources" by="src_addr" q={q} />);
    await waitFor(() => expect(appIdResolveBatch).toHaveBeenCalled());
    await waitFor(() => {
      const fmt = captured[captured.length - 1].tooltip.formatter as (p: unknown) => string;
      expect(fmt([{ name: "10.0.1.10", value: 2048, dataIndex: 1 }])).toContain("&lt;svg");
    });
    const fmt = captured[captured.length - 1].tooltip.formatter as (p: unknown) => string;
    const out = fmt([{ name: "10.0.1.10", value: 2048, dataIndex: 1 }]);
    expect(out).not.toContain("<svg");
    expect(out).not.toContain("&amp;lt;");
  });
});

describe("Applications", () => {
  it("asks for the window in seconds, once", async () => {
    render(<ApplicationsSection q={q} filterKeys={[]} onDrill={noop} />);
    await waitFor(() => expect(flowsApps).toHaveBeenCalledTimes(1));
    expect(flowsApps).toHaveBeenCalledWith(3600);
    expect(flowsServices).not.toHaveBeenCalled();
  });

  it("renders the pair with the engine's attribution words", async () => {
    render(<ApplicationsSection q={q} filterKeys={[]} onDrill={noop} />);
    await waitFor(() => expect(screen.getByText("AWS S3")).toBeInTheDocument());
    expect(screen.getByText("payroll")).toBeInTheDocument();
    expect(screen.getByText("Confirmed")).toBeInTheDocument();
    expect(screen.getByText("Suspected · not confirmed")).toBeInTheDocument();
    expect(screen.getByText("Under review")).toBeInTheDocument();
  });

  it("shows the unknown bucket as a measured row, and says what it is", async () => {
    render(<ApplicationsSection q={q} filterKeys={[]} onDrill={noop} />);
    await waitFor(() => expect(screen.getByText("Unknown")).toBeInTheDocument());
    const table = within(screen.getByLabelText("Applications by volume"));
    expect(table.getByText("100 B")).toBeInTheDocument();
    expect(table.getByText("9.5%")).toBeInTheDocument();
    expect(table.getByText("uncatalogued or internal")).toBeInTheDocument();
    expect(screen.getByText(/Traffic whose far end no naming source claimed/i)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Ask Iris about Unknown" })).toBeTruthy();
  });

  it("calls a blank source NOT RESOLVED, never an unknown app", async () => {
    render(<ApplicationsSection q={q} filterKeys={[]} onDrill={noop} />);
    await waitFor(() => expect(screen.getByText("Source not resolved")).toBeInTheDocument());
    expect(screen.getByText(/only its far end is named/i)).toBeInTheDocument();
  });

  it("states its coverage", async () => {
    render(<ApplicationsSection q={q} filterKeys={[]} onDrill={noop} />);
    await waitFor(() => expect(screen.getByText(/busiest 200 source-to-destination pairs/i)).toBeInTheDocument());
    expect(screen.getByRole("button", { name: "Ask Iris about Coverage" })).toBeTruthy();
  });

  it("says the chip filters do not narrow it, naming them in the tooltip", async () => {
    render(<ApplicationsSection q={q} filterKeys={["addr", "device"]} onDrill={noop} />);
    await waitFor(() => expect(flowsApps).toHaveBeenCalled());
    const caveat = screen.getByText(/the filters above do not narrow these numbers/i);
    expect(caveat.getAttribute("title")).toMatch(/device/i);
  });

  it("the Application chip narrows the list by name", async () => {
    render(<ApplicationsSection q={q} filterKeys={[]} appFilter="sales" onDrill={noop} />);
    await waitFor(() => expect(screen.getByText("Salesforce")).toBeInTheDocument());
    expect(screen.queryByText("AWS S3")).not.toBeInTheDocument();
  });

  it("owns its failure with an operator sentence, not a raw error", async () => {
    flowsApps.mockRejectedValue(new Error("502 Bad Gateway: clickhouse: dial tcp 10.0.0.9:9000: connect: connection refused"));
    render(<ApplicationsSection q={q} filterKeys={[]} onDrill={noop} />);
    await waitFor(() => expect(screen.getByText("The service did not answer.")).toBeInTheDocument());
    expect(screen.queryByText(/clickhouse/i)).not.toBeInTheDocument();
  });

  it("the row drill hands control back to the page", async () => {
    const drill = vi.fn();
    render(<ApplicationsSection q={q} filterKeys={[]} onDrill={drill} />);
    await waitFor(() => expect(screen.getByText("AWS S3")).toBeInTheDocument());
    const btn = within(screen.getByLabelText("Applications by volume")).getAllByRole("button", { name: "Conversations for this window" })[0];
    expect(btn.getAttribute("title")).toMatch(/not narrowed to/i);
    fireEvent.click(btn);
    expect(drill).toHaveBeenCalled();
  });
});

describe("Services", () => {
  it("renders the 501 catalog reason, not an empty list", async () => {
    flowsServices.mockRejectedValue(new Error('501 Not Implemented: {"error":"service catalog requires the PostgreSQL backend"}'));
    render(<ServicesSection q={q} filterKeys={[]} onDrill={noop} />);
    await waitFor(() => expect(screen.getByText("The service view is not available on this deployment.")).toBeInTheDocument());
    expect(screen.getByText(/service catalog requires the PostgreSQL/i)).toBeInTheDocument();
    expect(screen.queryByText("Services by volume")).not.toBeInTheDocument();
  });

  it("renders an unattributed service as UNMEASURED, never zero, below the measured ones", async () => {
    render(<ServicesSection q={q} filterKeys={[]} onDrill={noop} />);
    await waitFor(() => expect(screen.getByText("New service")).toBeInTheDocument());
    const table = within(screen.getByLabelText("Services by measured volume"));
    expect(table.getByText("4.0 KB")).toBeInTheDocument();
    expect(table.getByText("100.0%")).toBeInTheDocument();
    expect(table.getAllByText("Not measured").length).toBeGreaterThanOrEqual(3);
    expect(table.queryByText("0 B")).not.toBeInTheDocument();
    expect(screen.getByText("no selector yet")).toBeInTheDocument();
    const body = document.body.textContent ?? "";
    expect(body.indexOf("Payroll")).toBeLessThan(body.indexOf("New service"));
  });

  it("owns a non-501 failure with its own operator sentence", async () => {
    flowsServices.mockRejectedValue(new Error("500 Internal Server Error: {}"));
    render(<ServicesSection q={q} filterKeys={[]} onDrill={noop} />);
    await waitFor(() => expect(screen.getByText("The service did not answer.")).toBeInTheDocument());
  });
});

import { describe, it, expect, vi, afterEach } from "vitest";
import { render, screen, cleanup } from "@testing-library/react";
import ResourceMetricsPanel from "./ResourceMetricsPanel";
import type { CloudMetricSeriesResponse } from "../../services/api";

vi.mock("../../components/EChart", () => ({ default: () => <div data-testid="chart" /> }));

const seriesResp: CloudMetricSeriesResponse = {
  metric: "cloud_cpu_util", label: "CPU utilization", unit: "percent",
  window_minutes: 180, step_seconds: 60, start: 0, end: 10800,
  series: [{ resource_id: "i-1", resource_name: "web-1", points: [[100, 4.2]] }],
  catalog: [{ name: "cloud_cpu_util", label: "CPU utilization", unit: "percent" }],
};

const cloudMetricSeries = vi.fn(() => Promise.resolve(seriesResp));
vi.mock("../../services/api", () => ({
  api: { cloudMetricSeries: (...a: unknown[]) => cloudMetricSeries(...(a as [])) },
}));

afterEach(() => { cleanup(); cloudMetricSeries.mockClear(); });

describe("ResourceMetricsPanel", () => {
  it("renders a chart when the store has samples", async () => {
    render(<ResourceMetricsPanel targets={[{ id: "i-1", name: "web-1" }]} subject="web-1" />);
    expect(await screen.findByTestId("chart")).toBeInTheDocument();
    expect(cloudMetricSeries).toHaveBeenCalledWith(["i-1"], "cloud_cpu_util", 180);
  });

  it("shows the honest empty state when nothing is ingested", async () => {
    cloudMetricSeries.mockResolvedValueOnce({ ...seriesResp, series: [{ resource_id: "i-1", resource_name: "web-1", points: [] }] });
    render(<ResourceMetricsPanel targets={[{ id: "i-1", name: "web-1" }]} subject="web-1" />);
    expect(await screen.findByText(/No CPU utilization ingested for web-1/)).toBeInTheDocument();
    expect(screen.queryByTestId("chart")).toBeNull();
  });

  it("reports a store failure as an error, never an empty chart", async () => {
    cloudMetricSeries.mockRejectedValueOnce(new Error("502 Bad Gateway"));
    render(<ResourceMetricsPanel targets={[{ id: "i-1", name: "web-1" }]} subject="web-1" />);
    expect(await screen.findByText(/Metric store unreachable/)).toBeInTheDocument();
  });

  it("caps charted resources and says so", async () => {
    const targets = Array.from({ length: 8 }, (_, i) => ({ id: `i-${i}`, name: `r-${i}` }));
    render(<ResourceMetricsPanel targets={targets} subject="my-app" />);
    expect(await screen.findByText(/Charting the first 6 of 8 resources/)).toBeInTheDocument();
    expect(cloudMetricSeries.mock.calls[0][0]).toHaveLength(6);
  });

  it("is honest when no resources exist to chart", () => {
    render(<ResourceMetricsPanel targets={[]} subject="empty-app" />);
    expect(screen.getByText(/No cloud resources to chart/)).toBeInTheDocument();
    expect(cloudMetricSeries).not.toHaveBeenCalled();
  });
});

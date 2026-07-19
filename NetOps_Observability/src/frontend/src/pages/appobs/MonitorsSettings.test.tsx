import { describe, it, expect, vi, afterEach } from "vitest";
import { render, screen, cleanup, fireEvent, waitFor } from "@testing-library/react";
import MonitorsSettings from "./MonitorsSettings";
import type { CloudMonitorRow } from "../../services/api";

const row: CloudMonitorRow = {
  id: "m1", tenant_id: "t1", name: "High CPU", metric: "cloud_cpu_util",
  mode: "threshold", condition: "above", threshold: 90, enabled: true,
  last_state: "firing", last_reason: "cloud_cpu_util is 95 on i-1 (above 90)",
  last_eval_at: new Date().toISOString(),
};

const cloudMonitors = vi.fn(() => Promise.resolve({ monitors: [row], count: 1, max_monitors: 50 }));
const createCloudMonitor = vi.fn(() => Promise.resolve(row));
const updateCloudMonitor = vi.fn(() => Promise.resolve(row));
const deleteCloudMonitor = vi.fn(() => Promise.resolve({ deleted: "m1" }));
vi.mock("../../services/api", () => ({
  api: {
    cloudMonitors: () => cloudMonitors(),
    createCloudMonitor: (m: unknown) => createCloudMonitor(m as never),
    updateCloudMonitor: (id: string, m: unknown) => updateCloudMonitor(id as never, m as never),
    deleteCloudMonitor: (id: string) => deleteCloudMonitor(id as never),
  },
}));

afterEach(() => {
  cleanup();
  cloudMonitors.mockClear(); createCloudMonitor.mockClear();
  updateCloudMonitor.mockClear(); deleteCloudMonitor.mockClear();
});

describe("MonitorsSettings", () => {
  it("lists monitors with the evaluator's verdict verbatim", async () => {
    render(<MonitorsSettings />);
    expect(await screen.findByText("High CPU")).toBeInTheDocument();
    expect(screen.getByText("firing")).toBeInTheDocument();
    expect(screen.getByText(/cloud_cpu_util is 95 on i-1/)).toBeInTheDocument();
  });

  it("shows the honest empty state when none exist", async () => {
    cloudMonitors.mockResolvedValueOnce({ monitors: [], count: 0, max_monitors: 50 });
    render(<MonitorsSettings />);
    expect(await screen.findByText("No cloud monitors defined")).toBeInTheDocument();
  });

  it("creates a monitor from the form and closes it only on success", async () => {
    cloudMonitors.mockResolvedValueOnce({ monitors: [], count: 0, max_monitors: 50 });
    render(<MonitorsSettings />);
    fireEvent.click(await screen.findByText("New monitor"));
    fireEvent.change(screen.getByLabelText("Monitor name"), { target: { value: "Net spike" } });
    fireEvent.change(screen.getByLabelText("Metric"), { target: { value: "cloud_net_in_bytes" } });
    fireEvent.change(screen.getByLabelText("Threshold"), { target: { value: "1000000" } });
    fireEvent.click(screen.getByText("Create"));
    await waitFor(() => expect(createCloudMonitor).toHaveBeenCalledWith({
      name: "Net spike", metric: "cloud_net_in_bytes", mode: "threshold",
      condition: "above", threshold: 1000000, enabled: true,
    }));
  });

  it("refuses an invalid draft locally (no request)", async () => {
    cloudMonitors.mockResolvedValueOnce({ monitors: [], count: 0, max_monitors: 50 });
    render(<MonitorsSettings />);
    fireEvent.click(await screen.findByText("New monitor"));
    fireEvent.click(screen.getByText("Create"));
    expect(await screen.findByText(/give the monitor a name/)).toBeInTheDocument();
    expect(createCloudMonitor).not.toHaveBeenCalled();
  });

  it("toggles enabled via a full-definition PUT", async () => {
    render(<MonitorsSettings />);
    fireEvent.click(await screen.findByText("Disable"));
    await waitFor(() => expect(updateCloudMonitor).toHaveBeenCalledWith("m1", {
      name: "High CPU", metric: "cloud_cpu_util", mode: "threshold",
      condition: "above", threshold: 90, enabled: false,
    }));
  });

  it("surfaces a 403 as an honest permissions message", async () => {
    deleteCloudMonitor.mockRejectedValueOnce(new Error("403 Forbidden"));
    render(<MonitorsSettings />);
    fireEvent.click(await screen.findByText("Delete"));
    expect(await screen.findByText(/requires alerts write access/)).toBeInTheDocument();
  });
});

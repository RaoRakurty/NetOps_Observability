// DataProtection.test.tsx — #150: the Backup & DR page renders the snapshot
// policy as a live control surface and stays HONEST about every gap: a
// disabled policy is a loud warning (not a quiet checkbox), an unreadable
// policy shows its detail string, and a scheduled full backup with no run
// report says "never ran / not reporting" rather than rendering nothing.

import { describe, it, expect, vi, afterEach } from "vitest";
import { render, screen, cleanup, fireEvent, waitFor } from "@testing-library/react";

const mockApi = vi.hoisted(() => ({
  backupConfig: vi.fn(),
  setBackupConfig: vi.fn(),
  snapshotPolicy: vi.fn(),
  setSnapshotPolicy: vi.fn(),
}));
vi.mock("../services/api", () => ({ api: mockApi }));
vi.mock("../components/Icon", () => ({ default: () => <span /> }));

import DataProtection from "./DataProtection";

afterEach(() => { cleanup(); vi.clearAllMocks(); });

const baseStatus = {
  remote_configured: false, schedule_enabled: false, os_snapshot_repo_ok: true,
  os_last_snapshot_age_hours: 20, os_snapshot_detail: "newest successful snapshot 20h ago",
  on_host_only_warning: true,
};
const baseCfg = { remote_url: "", schedule_enabled: false };
const basePolicy = {
  enabled: true, schedule_cron: "30 1 * * *", retention_max_count: 14, retention_max_age_days: 0,
  last_run: { status: "SUCCESS", time: "2026-08-07T01:33:52Z", duration_seconds: 179 },
  next_run: "2026-08-08T01:30:00Z",
};

describe("DataProtection snapshot policy (#150)", () => {
  it("renders policy state: schedule, retention, last and next run", async () => {
    mockApi.backupConfig.mockResolvedValue({ config: baseCfg, status: baseStatus });
    mockApi.snapshotPolicy.mockResolvedValue(basePolicy);
    render(<DataProtection />);

    expect(await screen.findByDisplayValue("30 1 * * *")).toBeTruthy();
    expect(screen.getByDisplayValue("14")).toBeTruthy();
    expect(screen.getByText(/SUCCESS · 2026-08-07T01:33:52Z · 179s/)).toBeTruthy();
    expect(screen.getByText("2026-08-08T01:30:00Z")).toBeTruthy();
  });

  it("a DISABLED policy is a loud warning, not a quiet checkbox", async () => {
    mockApi.backupConfig.mockResolvedValue({ config: baseCfg, status: baseStatus });
    mockApi.snapshotPolicy.mockResolvedValue({ ...basePolicy, enabled: false });
    render(<DataProtection />);

    expect(await screen.findByText(/Snapshots are DISABLED/)).toBeTruthy();
  });

  it("an unreadable policy surfaces its detail string (honest, never blank)", async () => {
    mockApi.backupConfig.mockResolvedValue({ config: baseCfg, status: baseStatus });
    mockApi.snapshotPolicy.mockResolvedValue({
      enabled: false, schedule_cron: "", retention_max_count: 0,
      detail: "snapshot policy unreadable: opensearch 500 Internal Server Error",
    });
    render(<DataProtection />);

    expect(await screen.findByText(/snapshot policy unreadable/)).toBeTruthy();
  });

  it("toggling Enabled PUTs {enabled} and re-renders from the reply", async () => {
    mockApi.backupConfig.mockResolvedValue({ config: baseCfg, status: baseStatus });
    mockApi.snapshotPolicy.mockResolvedValue(basePolicy);
    mockApi.setSnapshotPolicy.mockResolvedValue({ ...basePolicy, enabled: false });
    render(<DataProtection />);

    const toggle = (await screen.findByLabelText(/Enabled/)) as HTMLInputElement;
    fireEvent.click(toggle);
    await waitFor(() => expect(mockApi.setSnapshotPolicy).toHaveBeenCalledWith({ enabled: false }));
    expect(await screen.findByText(/Snapshots are DISABLED/)).toBeTruthy();
  });

  it("max-age retention: renders the day count, PUTs changes, and clearing sends 0", async () => {
    mockApi.backupConfig.mockResolvedValue({ config: baseCfg, status: baseStatus });
    mockApi.snapshotPolicy.mockResolvedValue({ ...basePolicy, retention_max_age_days: 30 });
    mockApi.setSnapshotPolicy.mockResolvedValue({ ...basePolicy, retention_max_age_days: 60 });
    render(<DataProtection />);

    const ageInput = (await screen.findByDisplayValue("30")) as HTMLInputElement;
    fireEvent.change(ageInput, { target: { value: "60" } });
    fireEvent.blur(ageInput);
    await waitFor(() => expect(mockApi.setSnapshotPolicy).toHaveBeenCalledWith({ retention_max_age_days: 60 }));

    // Emptying the field clears the age condition (0 = count-only retention).
    fireEvent.change(ageInput, { target: { value: "" } });
    fireEvent.blur(ageInput);
    await waitFor(() => expect(mockApi.setSnapshotPolicy).toHaveBeenCalledWith({ retention_max_age_days: 0 }));
  });

  it("max-age 0 renders as the empty 'no age limit' field, not a literal 0", async () => {
    mockApi.backupConfig.mockResolvedValue({ config: baseCfg, status: baseStatus });
    mockApi.snapshotPolicy.mockResolvedValue(basePolicy);
    render(<DataProtection />);

    const ageInput = (await screen.findByPlaceholderText("no age limit")) as HTMLInputElement;
    expect(ageInput.value).toBe("");
    // Blurring the untouched empty field must NOT fire a no-op PUT.
    fireEvent.blur(ageInput);
    expect(mockApi.setSnapshotPolicy).not.toHaveBeenCalled();
  });

  it("a scheduled full backup with NO run report says so instead of rendering nothing", async () => {
    mockApi.backupConfig.mockResolvedValue({
      config: { ...baseCfg, schedule_enabled: true },
      status: { ...baseStatus, schedule_enabled: true },
    });
    mockApi.snapshotPolicy.mockResolvedValue(basePolicy);
    render(<DataProtection />);

    expect(await screen.findByText(/no run report — never ran, or the host cron is not reporting/)).toBeTruthy();
  });

  it("renders the full-backup last run when the report exists", async () => {
    mockApi.backupConfig.mockResolvedValue({
      config: baseCfg,
      status: {
        ...baseStatus,
        full_backup: { status: "success", ended: "2026-08-07T02:31:00Z", size_bytes: 1610612736, duration_seconds: 74, failures: 0 },
      },
    });
    mockApi.snapshotPolicy.mockResolvedValue(basePolicy);
    render(<DataProtection />);

    expect(await screen.findByText(/success · 2026-08-07T02:31:00Z · 1.5 GiB · 74s/)).toBeTruthy();
  });
});

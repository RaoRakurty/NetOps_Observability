// DataProtection.test.tsx — the backup & recovery console.
//
// WHAT THESE TESTS ARE FOR. A backup screen is the one screen an operator reads
// exactly once, under pressure, and then acts on. Three failure modes matter
// more than everything else, so most of this file is about them:
//
//   1. A NUMBER NOBODY MEASURED MUST NOT LOOK LIKE A MEASUREMENT. Every panel is
//      fed a payload with holes in it, and each test asserts the screen says
//      "not measured — <reason>" rather than 0, a dash, or a green tick.
//   2. "NEVER" MUST NOT LOOK LIKE "NOT MEASURED". A restore point nobody has
//      probed is a gap we measured, not silence; the screen says so in its own
//      words ("Never verified", "Never succeeded").
//   3. A DESTRUCTIVE ACTION MUST BE HARD TO DO BY ACCIDENT. The in-place restore
//      and the delete are both type-to-confirm on the restore point's own name;
//      the tests prove the gate holds and that the safe path is the default.
//
// Everything else — admin gating, async progress, panel independence, the
// honest states and the copy guards — follows the same shape: build the state,
// assert the exact sentence an operator reads.

import { describe, it, expect, vi, afterEach, beforeEach } from "vitest";
import { render, screen, cleanup, fireEvent, waitFor, within } from "@testing-library/react";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { scanCopy } from "../copyVoice.test";
import { scanForEngineVocabulary } from "../components/rca/vocabulary.test";
import type {
  BackupCoverageView, BackupOperation, EngineCoverage, OperationListView,
  SnapshotListView, SnapshotRepositoryView, SnapshotPolicy, SnapshotView,
  StorageMeasuredReport, StorageReading,
} from "../services/api";

const mockApi = vi.hoisted(() => ({
  backupCoverage: vi.fn(),
  snapshotList: vi.fn(),
  snapshotPolicy: vi.fn(),
  setSnapshotPolicy: vi.fn(),
  backupConfig: vi.fn(),
  setBackupConfig: vi.fn(),
  backupOperations: vi.fn(),
  storageMeasured: vi.fn(),
  backupOperation: vi.fn(),
  createSnapshot: vi.fn(),
  deleteSnapshot: vi.fn(),
  restoreSnapshot: vi.fn(),
  verifySnapshot: vi.fn(),
}));
const mockUseAuth = vi.hoisted(() => vi.fn());

vi.mock("../services/api", () => ({ api: mockApi }));
vi.mock("../hooks/useAuth", () => ({ useAuth: mockUseAuth }));
vi.mock("../components/Icon", () => ({ default: () => <span /> }));

import DataProtection from "./DataProtection";

// ── fixtures (the wire shapes from system_backup_contract.go) ────────────────

function engine(over: Partial<EngineCoverage> = {}): EngineCoverage {
  return {
    id: "opensearch", name: "Search snapshots",
    covered: "yes", covered_reason: "the daily policy produced a successful copy 10h ago",
    schedule: { enabled: true, cron: "30 1 * * *", governed_by_gui: true, detail: "" },
    last_attempt: { at: "2026-09-04T01:33:00Z", result: "success" },
    last_success_at: "2026-09-04T01:33:00Z",
    last_verified: { at: "2026-09-01T04:00:00Z", result: "pass" },
    size_bytes: 1610612736, size_detail: "",
    retention: { max_count: 14, max_age_days: 30, detail: "" },
    target: { kind: "offsite", location: "rsync://nas/correlix/", immutable: true, immutable_detail: "", encrypted: true, encrypted_detail: "" },
    rpo_hours: 10.5, rpo_detail: "",
    ...over,
  };
}

function coverage(over: Partial<BackupCoverageView> = {}): BackupCoverageView {
  return { generated_at: "2026-09-04T12:00:00Z", engines: [engine()], external: [], ...over };
}

function repo(over: Partial<SnapshotRepositoryView> = {}): SnapshotRepositoryView {
  return { name: "netops-fs", registered: true, verified: true, verified_detail: "", ...over };
}

function snapshot(over: Partial<SnapshotView> = {}): SnapshotView {
  return {
    name: "netops-daily-20260904", state: "SUCCESS",
    indices: ["netops-syslog-2026.09.04", "netops-traps-2026.09.04"], index_count: 2,
    started_at: "2026-09-04T01:30:00Z", ended_at: "2026-09-04T01:33:00Z", duration_seconds: 180,
    shards: { total: 6, successful: 6, failed: 0 }, failures: [], failures_trimmed: 0,
    size_bytes: null, size_detail: "not measured on this read — pass ?sizes=1",
    restorable_verified: true, restorable_verified_at: "2026-09-01T04:00:00Z", restorable_detail: "",
    ...over,
  };
}

function list(over: Partial<SnapshotListView> = {}): SnapshotListView {
  const snaps = over.snapshots ?? [snapshot()];
  return { repository: repo(), snapshots: snaps, total: snaps.length, ...over };
}

const POLICY: SnapshotPolicy = {
  enabled: true, schedule_cron: "30 1 * * *", retention_max_count: 14, retention_max_age_days: 0,
  last_run: { status: "SUCCESS", time: "2026-09-04T01:33:00Z", duration_seconds: 180 },
  next_run: "2026-09-05T01:30:00Z",
  managed_by: "gui",
};

function op(over: Partial<BackupOperation> = {}): BackupOperation {
  return {
    id: "op-00112233445566aa", kind: "snapshot_create", state: "running", actor: "root",
    started_at: "2026-09-04T11:59:00Z", ended_at: null, target: {},
    ...over,
  };
}

const OPS: OperationListView = {
  capacity: 50,
  operations: [
    op({ id: "op-a1", kind: "snapshot_create", state: "succeeded", ended_at: "2026-09-04T01:33:00Z", target: { snapshot: "netops-daily-20260904" } }),
    op({
      id: "op-a2", kind: "snapshot_verify", state: "succeeded", ended_at: "2026-09-01T04:02:00Z",
      target: { snapshot: "netops-daily-20260901" },
      verify: {
        snapshot: "netops-daily-20260901", index: "netops-traps", temp_index: "probe-1",
        source_docs: 1200, restored_docs: 1200, match: true, temp_deleted: true, duration_seconds: 42,
      },
    }),
  ],
};

function reading(over: Partial<StorageReading> = {}): StorageReading {
  return {
    store: "opensearch", scope: "__platform__",
    bytes_on_disk: 3221225472,
    detail: "read back from the search tier's own index stats",
    source: "_cat/indices?bytes=b store.size",
    sampled_at: "2026-09-04T11:59:30Z",
    ...over,
  };
}

function storage(over: Partial<StorageMeasuredReport> = {}): StorageMeasuredReport {
  return {
    scope: "__platform__", cross_tenant: true,
    generated_at: "2026-09-04T11:59:30Z",
    readings: [reading()],
    total_measured_bytes: 3221225472,
    unmeasured_stores: [],
    measurement_note: "Every number here was MEASURED: read back from the store that owns the bytes.",
    ...over,
  };
}

function setup(over: {
  coverage?: BackupCoverageView | Error;
  list?: SnapshotListView | Error;
  policy?: SnapshotPolicy;
  ops?: OperationListView;
  storage?: StorageMeasuredReport | Error;
  platformAdmin?: boolean;
} = {}) {
  const resolve = <T,>(v: T | Error) => (v instanceof Error ? Promise.reject(v) : Promise.resolve(v));
  mockApi.backupCoverage.mockReturnValue(resolve(over.coverage ?? coverage()));
  mockApi.snapshotList.mockReturnValue(resolve(over.list ?? list()));
  mockApi.snapshotPolicy.mockResolvedValue(over.policy ?? POLICY);
  mockApi.backupConfig.mockResolvedValue({
    config: { remote_url: "rsync://nas/correlix/", schedule_enabled: true, schedule_cron: "30 2 * * *" },
    status: {},
  });
  mockApi.backupOperations.mockResolvedValue(over.ops ?? OPS);
  mockApi.storageMeasured.mockReturnValue(resolve(over.storage ?? storage()));
  mockUseAuth.mockReturnValue({
    user: { username: "root", platform_admin: over.platformAdmin ?? true },
    loading: false,
  });
}

beforeEach(() => { vi.setSystemTime(new Date("2026-09-04T12:00:00Z")); });
afterEach(() => { cleanup(); vi.clearAllMocks(); vi.useRealTimers(); });

// ── 1 · protection health header ────────────────────────────────────────────

describe("protection health header", () => {
  it("states the verdict WITH the condition that decided it, not a bare colour", async () => {
    setup();
    render(<DataProtection />);
    expect(await screen.findByText("Protected")).toBeTruthy();
    expect(screen.getByText(/at least one restore has been proved/)).toBeTruthy();
  });

  it("an uncovered engine makes the platform unprotected, and the header names it", async () => {
    setup({
      coverage: coverage({
        engines: [engine(), engine({ id: "postgres", covered: "no", covered_reason: "no bundle has ever been written" })],
      }),
    });
    render(<DataProtection />);
    expect(await screen.findByText("Unprotected")).toBeTruthy();
    expect(screen.getByText("Application state is not covered — no bundle has ever been written")).toBeTruthy();
  });

  it("copies with no proved restore read as At risk, never as Protected", async () => {
    setup({ coverage: coverage({ engines: [engine({ last_verified: null })] }) });
    render(<DataProtection />);
    expect(await screen.findByText("At risk")).toBeTruthy();
    expect(screen.getByText(/a copy nobody knows is good/i)).toBeTruthy();
  });

  it("sources the header numbers it has: proved age, next run, repository", async () => {
    setup();
    render(<DataProtection />);
    // 2026-09-01T04:00 → 2026-09-04T12:00 is 3d 08h.
    expect((await screen.findAllByText("3d 08h ago")).length).toBeGreaterThan(0);
    expect(screen.getByText("in 13h 30m")).toBeTruthy();
    expect(screen.getByText("Registered and verified")).toBeTruthy();
    expect(screen.getByText(/netops-fs · 1 restore points/)).toBeTruthy();
  });

  it("names the one header number the platform does not publish, instead of inventing it", async () => {
    setup();
    render(<DataProtection />);
    expect(await screen.findByText(/not measured — the platform does not report the repository volume's capacity/))
      .toBeTruthy();
    expect(screen.queryByText("0% free")).toBeNull();
  });

  it("a disabled policy has no next run, and says why rather than showing a blank", async () => {
    setup({ policy: { ...POLICY, enabled: false } });
    render(<DataProtection />);
    expect((await screen.findAllByText("not measured — the recovery-point policy is disabled")).length)
      .toBeGreaterThan(0);
  });

  it("reports the achieved recovery point per engine and refuses to assume an objective", async () => {
    setup({
      coverage: coverage({
        engines: [
          engine({ id: "opensearch", rpo_hours: 10.5 }),
          engine({ id: "clickhouse", rpo_hours: null, rpo_detail: "no successful copy exists" }),
        ],
      }),
    });
    render(<DataProtection />);
    expect(await screen.findByText("last good copy 10h 30m old · objective not set")).toBeTruthy();
    expect(screen.getAllByText("not measured — no successful copy exists").length).toBeGreaterThan(0);
  });

  it("once the platform publishes an objective the header judges against it", async () => {
    setup({
      coverage: coverage({ engines: [engine({ rpo_hours: 48, rpo_target_hours: 24 })] }),
    });
    render(<DataProtection />);
    // "scheduled" is load-bearing (S4): the header must say WHICH objective it
    // judged against, because a schedule-derived cadence is evidence and a
    // declared policy is intent.
    expect(await screen.findByText("Objective missed · 2d 00h against a 1d 00h scheduled objective")).toBeTruthy();
  });

  it("labels a DECLARED objective as declared when no schedule is in force", async () => {
    setup({
      coverage: coverage({ engines: [engine({ rpo_hours: 48, rpo_objective_hours: 24 })] }),
    });
    render(<DataProtection />);
    expect(await screen.findByText("Objective missed · 2d 00h against a 1d 00h declared objective")).toBeTruthy();
  });
});

// ── 2 · coverage matrix ─────────────────────────────────────────────────────

describe("coverage matrix", () => {
  it("renders one row per engine under the operator's name for the data", async () => {
    setup({
      coverage: coverage({
        engines: [engine({ id: "victoriametrics" }), engine({ id: "clickhouse" }), engine({ id: "secrets_tls" })],
      }),
    });
    render(<DataProtection />);
    const table = await screen.findByRole("table", { name: "Protection coverage by engine" });
    expect(within(table).getByText("Metrics history")).toBeTruthy();
    expect(within(table).getByText("Flows & correlation history")).toBeTruthy();
    expect(within(table).getByText("Secrets & TLS material")).toBeTruthy();
  });

  it("carries the reason for EVERY verdict, including a covered one", async () => {
    setup();
    render(<DataProtection />);
    const table = await screen.findByRole("table", { name: "Protection coverage by engine" });
    expect(within(table).getAllByText("Covered").length).toBeGreaterThan(0);
    expect(within(table).getByText("the daily policy produced a successful copy 10h ago")).toBeTruthy();
  });

  it("a not-applicable row says WHY instead of showing a blank or a gap", async () => {
    setup({
      coverage: coverage({
        engines: [engine({
          id: "device_configs", covered: "not_applicable",
          covered_reason: "configuration backup is off (FEATURE_CONFIG_BACKUP is not enabled)",
        })],
      }),
    });
    render(<DataProtection />);
    expect(await screen.findByText("Not protected here")).toBeTruthy();
    expect(screen.getByText(/configuration backup is off/)).toBeTruthy();
  });

  it("an unmeasured cell states the reason rather than an empty or zero cell", async () => {
    setup({
      coverage: coverage({
        engines: [engine({
          id: "postgres",
          size_bytes: null, size_detail: "the bundle has not been written yet",
          last_verified: null, detail: "no restorability probe covers this engine",
        })],
      }),
    });
    render(<DataProtection />);
    expect(await screen.findByText("not measured — the bundle has not been written yet")).toBeTruthy();
    expect(screen.getAllByText("not measured — no restorability probe covers this engine").length).toBeGreaterThan(0);
    expect(screen.queryByText("0 B")).toBeNull();
  });

  it("'never succeeded' is its own state — a measured gap, not silence", async () => {
    setup({ coverage: coverage({ engines: [engine({ last_success_at: undefined })] }) });
    render(<DataProtection />);
    expect(await screen.findByText("Never succeeded")).toBeTruthy();
  });

  it("carries the immutability and encryption badges, each with its own reason", async () => {
    setup({
      coverage: coverage({
        engines: [engine({
          target: {
            kind: "local", immutable: false, immutable_detail: "a filesystem repository cannot be made immutable",
            encrypted: null, encrypted_detail: "the platform cannot see whether the volume is encrypted",
          },
        })],
      }),
    });
    render(<DataProtection />);
    expect(await screen.findByText("Mutable")).toBeTruthy();
    expect(screen.getByText("not measured — the platform cannot see whether the volume is encrypted")).toBeTruthy();
  });

  it("names an externally-owned job as external rather than claiming to govern it", async () => {
    setup({
      coverage: coverage({
        engines: [engine({
          id: "system_bundle",
          schedule: { enabled: true, cron: "30 2 * * *", governed_by_gui: false, detail: "a host cron runs scripts/backup.sh" },
        })],
      }),
    });
    render(<DataProtection />);
    // The 2026-09-06 word sweep moved "not governed here" into
    // ai/skills/explain/backup.external-job.md: the row still names the job as
    // External and still carries the source's own detail, with the `(i)` beside it.
    expect(await screen.findByText(/External — a host cron runs scripts\/backup.sh/)).toBeTruthy();
    expect(screen.getByRole("button", { name: /Ask Iris about External/i })).toBeTruthy();
  });

  it("says so when the platform lists no engines at all", async () => {
    setup({ coverage: coverage({ engines: [] }) });
    render(<DataProtection />);
    expect(await screen.findByText("The platform listed no engines to protect.")).toBeTruthy();
  });

  it("surfaces a partial coverage read instead of presenting it as complete", async () => {
    setup({ coverage: coverage({ detail: "the flow store did not answer within the read budget" }) });
    render(<DataProtection />);
    expect(await screen.findByText("The coverage table is incomplete.")).toBeTruthy();
    expect(screen.getByText("the flow store did not answer within the read budget")).toBeTruthy();
  });
});

// ── 2b · bytes on disk (measured) ───────────────────────────────────────────

describe("bytes on disk (measured)", () => {
  it("renders one row per store under the data's name, with the query behind it", async () => {
    setup({
      storage: storage({
        readings: [
          reading({ store: "clickhouse", scope: "acme", bytes_on_disk: 1073741824, source: "system.parts bytes_on_disk" }),
          reading({ store: "victoriametrics", scope: "__platform__", bytes_on_disk: 536870912, source: "vm_data_size_bytes" }),
        ],
        total_measured_bytes: 1610612736,
      }),
    });
    render(<DataProtection />);
    const table = await screen.findByRole("table", { name: "Bytes on disk by store" });
    expect(within(table).getByText("Flows & correlation history")).toBeTruthy();
    expect(within(table).getByText("Metrics history")).toBeTruthy();
    expect(within(table).getByText("acme")).toBeTruthy();
    expect(within(table).getByText("Platform")).toBeTruthy();
    expect(within(table).getByText("1.0 GiB")).toBeTruthy();
    expect(within(table).getByText("system.parts bytes_on_disk")).toBeTruthy();
  });

  it("a store nobody could weigh states the reason and never renders 0 B", async () => {
    setup({
      storage: storage({
        readings: [reading({
          store: "kafka", bytes_on_disk: null, source: "",
          detail: "not measured — the event bus does not expose its log directory to this service",
        })],
        total_measured_bytes: 0,
        unmeasured_stores: ["kafka"],
        measurement_note: "PARTIAL. `total_measured_bytes` is a LOWER BOUND.",
      }),
    });
    render(<DataProtection />);
    const table = await screen.findByRole("table", { name: "Bytes on disk by store" });
    expect(within(table).getByText(
      "not measured — the event bus does not expose its log directory to this service",
    )).toBeTruthy();
    expect(within(table).queryByText("0 B")).toBeNull();
    // Nothing was read, so there is no query to name — and it says that.
    expect(within(table).getByText("not measured — nothing was read, so there is no query to name")).toBeTruthy();
  });

  it("zero bytes IS a measurement and renders as 0 B", async () => {
    setup({
      storage: storage({
        readings: [reading({ store: "filestore", bytes_on_disk: 0, detail: "a walk of the platform's own data directory", source: "statfs" })],
        total_measured_bytes: 0,
      }),
    });
    render(<DataProtection />);
    const table = await screen.findByRole("table", { name: "Bytes on disk by store" });
    expect(within(table).getByText("0 B")).toBeTruthy();
    expect(within(table).getByText("Files kept on the platform host")).toBeTruthy();
  });

  it("calls the total a lower bound while a store contributes nothing, and prints the note verbatim", async () => {
    setup({
      storage: storage({
        readings: [reading(), reading({ store: "kafka", bytes_on_disk: null, source: "", detail: "not measured — the log directory is not visible here" })],
        unmeasured_stores: ["kafka"],
        measurement_note: "PARTIAL. `total_measured_bytes` is a LOWER BOUND: it sums only the stores that could be measured.",
      }),
    });
    render(<DataProtection />);
    expect(await screen.findByText("measured total (lower bound)")).toBeTruthy();
    expect(screen.getByText("PARTIAL. `total_measured_bytes` is a LOWER BOUND: it sums only the stores that could be measured.")).toBeTruthy();
    // Named twice on purpose: once as the store that contributes nothing to the
    // header total, once as the row carrying its own reason.
    expect(screen.getAllByText("Events queued on the bus")).toHaveLength(2);
  });

  it("a complete read calls the total what it is, with every store weighed", async () => {
    setup();
    render(<DataProtection />);
    expect(await screen.findByText("measured total")).toBeTruthy();
    expect(screen.getByText("Every store was weighed")).toBeTruthy();
    expect(screen.queryByText("measured total (lower bound)")).toBeNull();
  });

  it("shows when each reading was taken, so a stale number reads as stale", async () => {
    setup({ storage: storage({ readings: [reading({ sampled_at: "2026-09-04T09:00:00Z" })] }) });
    render(<DataProtection />);
    const table = await screen.findByRole("table", { name: "Bytes on disk by store" });
    expect(within(table).getByText("3h 00m ago")).toBeTruthy();
  });

  it("puts the breakdown behind a disclosure, with the measured ratio only where it exists", async () => {
    setup({
      storage: storage({
        readings: [reading({
          components: [
            { name: "netops-syslog-acme-2026.09.04", bytes_on_disk: 2147483648, rows: 1200000, uncompressed_bytes: null },
            { name: "netops-flows-acme", bytes_on_disk: 1000, rows: 10, uncompressed_bytes: 4900 },
          ],
        })],
      }),
    });
    render(<DataProtection />);
    expect(await screen.findByText("Where the bytes are · 2 largest")).toBeTruthy();
    expect(screen.getByText("netops-syslog-acme-2026.09.04")).toBeTruthy();
    // Only the component whose store reports an uncompressed size carries a ratio.
    expect(screen.getAllByText(/× \(measured\)/)).toHaveLength(1);
    expect(screen.getByText("4.9× (measured)")).toBeTruthy();
  });

  it("a dead read shows the panel error and never a byte count", async () => {
    setup({ storage: new Error("500 Internal Server Error: {}") });
    render(<DataProtection />);
    expect(await screen.findByText("Protected")).toBeTruthy();
    expect(screen.queryByRole("table", { name: "Bytes on disk by store" })).toBeNull();
    expect(screen.queryByText("measured total")).toBeNull();
    expect(screen.queryByText("0 B")).toBeNull();
  });
});

// ── 3 · restore points ──────────────────────────────────────────────────────

describe("restore points", () => {
  it("renders state, duration, index count and the restorability badge", async () => {
    setup();
    render(<DataProtection />);
    expect(await screen.findByText("netops-daily-20260904")).toBeTruthy();
    expect(screen.getAllByText("Success").length).toBeGreaterThan(0);
    expect(screen.getByText("3m 00s")).toBeTruthy();
    expect(screen.getByText(/Verified · 3d 08h ago/)).toBeTruthy();
  });

  it("size is opt-in: the row says why it is absent until sizes are measured", async () => {
    setup();
    render(<DataProtection />);
    expect(await screen.findByText("not measured — not measured on this read — pass ?sizes=1")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Measure sizes" }));
    await waitFor(() => expect(mockApi.snapshotList).toHaveBeenCalledWith({ sizes: true }));
  });

  it("an unprobed copy reads 'Never verified' — a gap, not a shrug and not a pass", async () => {
    setup({
      list: list({ snapshots: [snapshot({ restorable_verified: null, restorable_detail: "no probe has ever run" })] }),
    });
    render(<DataProtection />);
    expect(await screen.findByText("Never verified")).toBeTruthy();
  });

  it("shows shard failures with the engine's own reason text", async () => {
    setup({
      list: list({
        snapshots: [snapshot({
          state: "PARTIAL",
          shards: { total: 6, successful: 4, failed: 2 },
          failures: [{ index: "netops-syslog", shard: 3, reason: "NoSuchFileException: indices/0/3/__abc" }],
          failures_trimmed: 1,
        })],
      }),
    });
    render(<DataProtection />);
    expect(await screen.findByText(/2 of 6 shards failed · netops-syslog\[3\] NoSuchFileException/)).toBeTruthy();
    expect(screen.getByText(/1 more not listed/)).toBeTruthy();
  });

  it("renders with zero, one and five hundred restore points without changing shape", async () => {
    for (const n of [0, 1, 500]) {
      cleanup();
      const snaps = Array.from({ length: n }, (_, i) =>
        snapshot({ name: `netops-daily-${String(i).padStart(4, "0")}`, started_at: `2026-09-0${(i % 4) + 1}T01:30:00Z` }));
      setup({ list: list({ snapshots: snaps }) });
      render(<DataProtection />);
      if (n === 0) {
        expect(await screen.findByText("No restore point exists yet.")).toBeTruthy();
      } else {
        const grid = await screen.findByRole("grid", { name: "Restore points" });
        expect(Number(grid.getAttribute("aria-rowcount"))).toBe(n);
      }
    }
  });

  it("takes a restore point on demand and shows the accepted operation, then its progress", async () => {
    setup();
    mockApi.createSnapshot.mockResolvedValue(op({ progress: "" }));
    mockApi.backupOperation.mockResolvedValue(op({ progress: "Copying 2 of 5 indices." }));
    render(<DataProtection />);
    fireEvent.click(await screen.findByRole("button", { name: "Take restore point now" }));
    await waitFor(() => expect(mockApi.createSnapshot).toHaveBeenCalled());
    expect(await screen.findByText("Copying 2 of 5 indices.")).toBeTruthy();
    expect(screen.getByRole("progressbar", { name: "Operation progress" })).toBeTruthy();
  });

  it("shows what was recorded once a long operation settles, and re-reads the page", async () => {
    setup();
    mockApi.createSnapshot.mockResolvedValue(op({ progress: "" }));
    mockApi.backupOperation.mockResolvedValue(op({
      state: "succeeded", ended_at: "2026-09-04T12:00:30Z",
      target: { snapshot: "netops-daily-20260904b" }, progress: "Restore point created.",
    }));
    render(<DataProtection />);
    fireEvent.click(await screen.findByRole("button", { name: "Take restore point now" }));
    expect(await screen.findByText(/Recorded · root · snapshot_create/)).toBeTruthy();
    // Settling triggers a re-read of the posture, the list and the trail.
    await waitFor(() => expect(mockApi.backupCoverage).toHaveBeenCalledTimes(2));
  });

  it("renders a failed operation's error rather than a silent stop", async () => {
    setup();
    mockApi.createSnapshot.mockResolvedValue(op({ progress: "" }));
    mockApi.backupOperation.mockResolvedValue(op({
      state: "failed", ended_at: "2026-09-04T12:00:05Z", error: "repository netops-fs is read-only",
    }));
    render(<DataProtection />);
    fireEvent.click(await screen.findByRole("button", { name: "Take restore point now" }));
    expect(await screen.findByText("repository netops-fs is read-only")).toBeTruthy();
  });

  it("reports a refused action as an operator sentence", async () => {
    setup();
    mockApi.createSnapshot.mockRejectedValue(new Error("429 Too Many Requests: {}"));
    render(<DataProtection />);
    fireEvent.click(await screen.findByRole("button", { name: "Take restore point now" }));
    expect(await screen.findByText("The action did not complete.")).toBeTruthy();
    expect(screen.getByText("Too many requests just now — try again shortly.")).toBeTruthy();
  });

  it("verifies one copy on demand, by name", async () => {
    setup();
    mockApi.verifySnapshot.mockResolvedValue(op({ kind: "snapshot_verify", state: "running" }));
    mockApi.backupOperation.mockResolvedValue(op({ kind: "snapshot_verify", state: "running", progress: "Comparing document counts." }));
    render(<DataProtection />);
    fireEvent.click((await screen.findAllByRole("button", { name: "Verify now" }))[0]);
    await waitFor(() => expect(mockApi.verifySnapshot).toHaveBeenCalledWith("netops-daily-20260904"));
    expect(await screen.findByText("Comparing document counts.")).toBeTruthy();
  });
});

// ── 3a · restore wizard ─────────────────────────────────────────────────────

async function openRestore() {
  fireEvent.click((await screen.findAllByRole("button", { name: "Restore…" }))[0]);
  return screen.findByRole("dialog", { name: /Restore from netops-daily-20260904/ });
}

describe("restore wizard", () => {
  it("defaults to the SAFE path: restored alongside under a new name", async () => {
    setup();
    mockApi.restoreSnapshot.mockResolvedValue(op({ kind: "snapshot_restore", state: "succeeded", ended_at: "2026-09-04T12:01:00Z" }));
    render(<DataProtection />);
    const dlg = await openRestore();
    fireEvent.click(within(dlg).getByRole("button", { name: "Next" }));       // scope → destination
    expect(within(dlg).getByText(/netops-syslog-2026.09.04 → restored-netops-syslog-2026.09.04/)).toBeTruthy();
    fireEvent.click(within(dlg).getByRole("button", { name: "Next" }));       // destination → review
    fireEvent.click(within(dlg).getByRole("button", { name: "Start restore" }));

    await waitFor(() => expect(mockApi.restoreSnapshot).toHaveBeenCalledWith({
      snapshot: "netops-daily-20260904", indices: [], mode: "renamed", rename_prefix: "restored-",
    }));
  });

  it("refuses to advance when the prefix would put the data back on the live names", async () => {
    setup();
    render(<DataProtection />);
    const dlg = await openRestore();
    fireEvent.click(within(dlg).getByRole("button", { name: "Next" }));
    fireEvent.change(within(dlg).getByLabelText("Name prefix for the restored indices") as HTMLInputElement, {
      target: { value: "" },
    });
    expect(within(dlg).getByText(/That is an overwrite, not a rename/)).toBeTruthy();
    expect((within(dlg).getByRole("button", { name: "Next" }) as HTMLButtonElement).disabled).toBe(true);
  });

  it("the in-place path is its own labelled step and needs the name typed exactly", async () => {
    setup();
    mockApi.restoreSnapshot.mockResolvedValue(op({ kind: "snapshot_restore", state: "running" }));
    mockApi.backupOperation.mockResolvedValue(op({ kind: "snapshot_restore", state: "running" }));
    render(<DataProtection />);
    const dlg = await openRestore();
    fireEvent.click(within(dlg).getByRole("button", { name: "Next" }));
    fireEvent.click(within(dlg).getByLabelText(/Restore in place, overwriting the live data/));
    fireEvent.click(within(dlg).getByRole("button", { name: "Next" }));

    expect(within(dlg).getByText("An in-place restore closes and overwrites the live indices.")).toBeTruthy();
    expect((within(dlg).getByRole("button", { name: "Next" }) as HTMLButtonElement).disabled).toBe(true);

    const confirm = within(dlg).getByLabelText(/Type netops-daily-20260904 to authorise the in-place restore/) as HTMLInputElement;
    fireEvent.change(confirm, { target: { value: "netops-daily-2026090" } });   // one character short
    expect((within(dlg).getByRole("button", { name: "Next" }) as HTMLButtonElement).disabled).toBe(true);
    fireEvent.change(confirm, { target: { value: "netops-daily-20260904" } });
    fireEvent.click(within(dlg).getByRole("button", { name: "Next" }));
    fireEvent.click(within(dlg).getByRole("button", { name: "Start restore" }));

    await waitFor(() => expect(mockApi.restoreSnapshot).toHaveBeenCalledWith({
      snapshot: "netops-daily-20260904", indices: [], mode: "in_place", confirm: "netops-daily-20260904",
    }));
  });

  it("restores only the indices the operator picked", async () => {
    setup();
    mockApi.restoreSnapshot.mockResolvedValue(op({ kind: "snapshot_restore", state: "succeeded", ended_at: "2026-09-04T12:01:00Z" }));
    render(<DataProtection />);
    const dlg = await openRestore();
    fireEvent.click(within(dlg).getByLabelText(/Whole restore point/));         // uncheck → pick indices
    fireEvent.click(within(dlg).getByLabelText("netops-traps-2026.09.04"));     // drop the second
    fireEvent.click(within(dlg).getByRole("button", { name: "Next" }));
    fireEvent.click(within(dlg).getByRole("button", { name: "Next" }));
    fireEvent.click(within(dlg).getByRole("button", { name: "Start restore" }));

    await waitFor(() => expect(mockApi.restoreSnapshot).toHaveBeenCalledWith(
      expect.objectContaining({ indices: ["netops-syslog-2026.09.04"] })));
  });
});

// ── 3b · delete ─────────────────────────────────────────────────────────────

describe("deleting a restore point", () => {
  it("spells out the consequence and stays disabled until the name is typed exactly", async () => {
    setup();
    mockApi.deleteSnapshot.mockResolvedValue(op({ kind: "snapshot_delete", state: "succeeded", ended_at: "2026-09-04T12:00:10Z" }));
    render(<DataProtection />);
    fireEvent.click((await screen.findAllByRole("button", { name: "Delete…" }))[0]);
    const dlg = await screen.findByRole("dialog", { name: /Delete netops-daily-20260904/ });
    expect(within(dlg).getByText("Deleting a restore point cannot be undone.")).toBeTruthy();

    expect((within(dlg).getByRole("button", { name: "Delete restore point" }) as HTMLButtonElement).disabled).toBe(true);
    const field = within(dlg).getByLabelText(/Type netops-daily-20260904 to confirm deletion/) as HTMLInputElement;
    fireEvent.change(field, { target: { value: "netops-daily-2026090" } });
    expect((within(dlg).getByRole("button", { name: "Delete restore point" }) as HTMLButtonElement).disabled).toBe(true);
    fireEvent.change(field, { target: { value: "netops-daily-20260904" } });
    fireEvent.click(within(dlg).getByRole("button", { name: "Delete restore point" }));

    await waitFor(() => expect(mockApi.deleteSnapshot)
      .toHaveBeenCalledWith("netops-daily-20260904", "netops-daily-20260904"));
  });
});

// ── admin gating ────────────────────────────────────────────────────────────

describe("platform-admin gating", () => {
  it("hides every mutating control from a tenant admin and says why", async () => {
    setup({ platformAdmin: false });
    render(<DataProtection />);
    expect(await screen.findByText("This posture is read-only for you.")).toBeTruthy();
    expect(screen.getByRole("button", { name: /Ask Iris about This posture is read-only for you/i })).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Take restore point now" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Restore…" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Delete…" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Run restore drill" })).toBeNull();
    expect(screen.getByText("Changing the policy requires a platform administrator.")).toBeTruthy();
    // The posture itself stays readable — gating hides controls, not evidence.
    expect(screen.getByText("Protected")).toBeTruthy();
  });

  it("gives the platform administrator the full control set", async () => {
    setup({ platformAdmin: true });
    render(<DataProtection />);
    expect(await screen.findByRole("button", { name: "Take restore point now" })).toBeTruthy();
    expect(screen.getByRole("button", { name: "Run restore drill" })).toBeTruthy();
    expect(screen.queryByText("This posture is read-only for you.")).toBeNull();
  });
});

// ── 4 · policies ────────────────────────────────────────────────────────────

describe("policies", () => {
  it("a disabled recovery-point policy states the consequence, not just the state", async () => {
    setup({ policy: { ...POLICY, enabled: false } });
    render(<DataProtection />);
    expect(await screen.findByText("The recovery-point policy is disabled.")).toBeTruthy();
    expect(screen.getByText(/No new restore points will be created/)).toBeTruthy();
  });

  it("a disabled policy names who turned it off, when and why", async () => {
    setup({
      policy: {
        ...POLICY, enabled: false,
        disabled_reason: "the repository volume is being replaced",
        disabled_at: "2026-09-03T09:12:00Z", disabled_by: "root",
      },
    });
    render(<DataProtection />);
    expect(await screen.findByText(/Turned off by root on 2026-09-03T09:12:00Z: the repository volume is being replaced/))
      .toBeTruthy();
  });

  it("an off policy with NO recorded reason says that may not have been deliberate", async () => {
    setup({ policy: { ...POLICY, enabled: false } });
    render(<DataProtection />);
    expect(await screen.findByText(/recorded no reason for it being off, so this may not have been deliberate/))
      .toBeTruthy();
  });

  it("turning the policy off asks for a reason first and sends it with the write", async () => {
    setup();
    mockApi.setSnapshotPolicy.mockResolvedValue({ ...POLICY, enabled: false });
    render(<DataProtection />);
    fireEvent.click(await screen.findByLabelText("Enabled"));
    expect(screen.getByText("Turning this off stops new restore points being created.")).toBeTruthy();
    // Nothing is written until a reason is given.
    expect(mockApi.setSnapshotPolicy).not.toHaveBeenCalled();
    const off = screen.getByRole("button", { name: "Turn it off" }) as HTMLButtonElement;
    expect(off.disabled).toBe(true);
    fireEvent.change(screen.getByLabelText("Reason for turning the recovery-point policy off"), {
      target: { value: "the repository volume is being replaced" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Turn it off" }));
    await waitFor(() => expect(mockApi.setSnapshotPolicy).toHaveBeenCalledWith({
      enabled: false, reason: "the repository volume is being replaced",
    }));
  });

  it("'Keep it on' backs out without writing anything", async () => {
    setup();
    render(<DataProtection />);
    fireEvent.click(await screen.findByLabelText("Enabled"));
    fireEvent.click(screen.getByRole("button", { name: "Keep it on" }));
    expect(screen.queryByText("Turning this off stops new restore points being created.")).toBeNull();
    expect(mockApi.setSnapshotPolicy).not.toHaveBeenCalled();
  });

  it("warns when something other than this page owns the enabled flag", async () => {
    setup({ policy: { ...POLICY, managed_by: "bootstrap" } });
    render(<DataProtection />);
    expect(await screen.findByText("This switch is not authoritative.")).toBeTruthy();
    expect(screen.getByText(/owned by bootstrap/)).toBeTruthy();
  });

  it("edits the window and retention through the policy route", async () => {
    setup();
    mockApi.setSnapshotPolicy.mockResolvedValue({ ...POLICY, retention_max_count: 30 });
    render(<DataProtection />);
    const retention = await screen.findByLabelText("Retention, keep newest count") as HTMLInputElement;
    fireEvent.change(retention, { target: { value: "30" } });
    fireEvent.blur(retention);
    await waitFor(() => expect(mockApi.setSnapshotPolicy).toHaveBeenCalledWith({ retention_max_count: 30 }));
  });

  it("surfaces the policy's own detail string when it could not be read in full", async () => {
    setup({
      policy: {
        enabled: false, schedule_cron: "", retention_max_count: 0, retention_max_age_days: 0,
        detail: "the policy document could not be read",
      },
    });
    render(<DataProtection />);
    expect(await screen.findByText("The policy could not be read in full.")).toBeTruthy();
    expect(screen.getByText("the policy document could not be read")).toBeTruthy();
  });

  it("keeps the bundle destination form and warns when there is no off-host copy", async () => {
    setup();
    mockApi.backupConfig.mockResolvedValue({ config: { remote_url: "", schedule_enabled: false }, status: {} });
    render(<DataProtection />);
    expect(await screen.findByText("The bundle has no off-host destination.")).toBeTruthy();
    fireEvent.change(screen.getByLabelText("Off-host destination") as HTMLInputElement, {
      target: { value: "rsync://nas/correlix/" },
    });
    mockApi.setBackupConfig.mockResolvedValue({
      config: { remote_url: "rsync://nas/correlix/", schedule_enabled: false }, status: {},
    });
    fireEvent.click(screen.getByRole("button", { name: "Save bundle policy" }));
    await waitFor(() => expect(mockApi.setBackupConfig)
      .toHaveBeenCalledWith(expect.objectContaining({ remote_url: "rsync://nas/correlix/" })));
  });

  it("lists a host-owned mechanism as external, with its source", async () => {
    setup({
      coverage: coverage({
        external: [{
          name: "Nightly rsync to the NAS", source: "host crontab", schedule: "0 3 * * *",
          detail: "It was installed by hand and this page does not control it.",
        }],
      }),
    });
    render(<DataProtection />);
    expect(await screen.findByText("Nightly rsync to the NAS is external, not governed here.")).toBeTruthy();
    expect(screen.getByText(/Source: host crontab · 0 3 \* \* \*/)).toBeTruthy();
  });
});

// ── 5 · activity and drills ─────────────────────────────────────────────────

describe("activity and drills", () => {
  it("renders the operations trail and splits the drill history out of it", async () => {
    setup();
    render(<DataProtection />);
    expect(await screen.findByText(/Take restore point · netops-daily-20260904/)).toBeTruthy();
    expect(screen.getByText("documents matched")).toBeTruthy();
    expect(screen.getByText("1200 of 1200 documents matched on netops-traps")).toBeTruthy();
  });

  it("says plainly when no restore has ever been proved", async () => {
    setup({ ops: { capacity: 50, operations: [] } });
    render(<DataProtection />);
    expect(await screen.findByText("No restore has ever been proved.")).toBeTruthy();
    // What a drill DOES is ai/skills/explain/backup.proven-restore.md now; the
    // screen keeps the verdict and the action.
    expect(screen.getByText(/Run a restore drill/)).toBeTruthy();
    expect(screen.getByRole("button", { name: /Ask Iris about No restore has ever been proved/i })).toBeTruthy();
  });

  it("the restore drill probes the newest good copy — no snapshot named", async () => {
    setup();
    mockApi.verifySnapshot.mockResolvedValue(op({ kind: "snapshot_verify", state: "running" }));
    mockApi.backupOperation.mockResolvedValue(op({ kind: "snapshot_verify", state: "running", progress: "Restoring the smallest index." }));
    render(<DataProtection />);
    fireEvent.click(await screen.findByRole("button", { name: "Run restore drill" }));
    await waitFor(() => expect(mockApi.verifySnapshot).toHaveBeenCalledWith());
    expect(await screen.findByText("Restoring the smallest index.")).toBeTruthy();
  });

  it("a drill whose counts did not match reads as a failure, not a run", async () => {
    setup({
      ops: {
        capacity: 50,
        operations: [op({
          id: "op-b1", kind: "snapshot_verify", state: "succeeded", ended_at: "2026-09-04T04:02:00Z",
          target: { snapshot: "netops-daily-20260903" },
          verify: {
            snapshot: "netops-daily-20260903", index: "netops-flows", temp_index: "probe-2",
            source_docs: 1200, restored_docs: 1198, match: false, temp_deleted: true, duration_seconds: 40,
          },
        })],
      },
    });
    render(<DataProtection />);
    expect(await screen.findByText("documents did not match")).toBeTruthy();
    expect(screen.getByText(/1198 documents restored against 1200 in netops-flows/)).toBeTruthy();
  });

  it("says what the bounded trail cannot show", async () => {
    setup();
    render(<DataProtection />);
    expect(await screen.findByText("Newest 50 operations")).toBeTruthy();
  });

  it("caps the trail and offers the rest behind one control", async () => {
    const many = Array.from({ length: 20 }, (_, i) =>
      op({ id: `op-c${i}`, state: "succeeded", ended_at: "2026-09-04T01:00:00Z", target: { snapshot: `netops-daily-${i}` } }));
    setup({ ops: { capacity: 50, operations: many } });
    render(<DataProtection />);
    expect(await screen.findByRole("button", { name: "Show all 20 entries" })).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Show all 20 entries" }));
    expect(screen.getByRole("button", { name: "Show fewer entries" })).toBeTruthy();
  });
});

// ── 6 · honest states ───────────────────────────────────────────────────────

describe("honest states, each with its own remedy and the procedure link", () => {
  it.each([
    [{ registered: false }, "The snapshot repository is not registered.", /opensearch-init/],
    [{ verified: false }, "The repository failed verification.", /2026-08-27/],
    [{ verified: null }, "The repository has not been verified on this read.", /Registration is not restorability/],
  ])("repository %o", async (over, headline, remedy) => {
    setup({ list: list({ repository: repo(over as Partial<SnapshotRepositoryView>) }) });
    render(<DataProtection />);
    expect(await screen.findByText(headline)).toBeTruthy();
    expect(screen.getByText(remedy)).toBeTruthy();
    const link = screen.getAllByRole("link", { name: /Back up and restore procedure/ })[0] as HTMLAnchorElement;
    expect(link.getAttribute("href")).toBe("/docs/deploy/back-up-and-restore");
  });

  it("no restore point yet — nothing to restore from, and the next action", async () => {
    setup({ list: list({ snapshots: [] }) });
    render(<DataProtection />);
    expect(await screen.findByText("No restore point exists yet.")).toBeTruthy();
    expect(screen.getByText(/Take one now, then run a restore drill/)).toBeTruthy();
  });

  it("the list itself could not be read — the panel says so, verbatim", async () => {
    setup({
      list: list({ snapshots: [], detail: "the search tier answered 503 while listing the repository" }),
    });
    render(<DataProtection />);
    expect(await screen.findByText("The restore points could not be listed.")).toBeTruthy();
    expect(screen.getByText("the search tier answered 503 while listing the repository")).toBeTruthy();
  });

  it("an unreachable repository makes the posture unprotected and names the read failure", async () => {
    setup({ list: new Error("500 Internal Server Error: {}") });
    render(<DataProtection />);
    expect(await screen.findByText("Unprotected")).toBeTruthy();
    expect(screen.getByText("The snapshot repository cannot be read.")).toBeTruthy();
  });

  it("each panel fails independently: a dead trail leaves the posture readable", async () => {
    setup();
    mockApi.backupOperations.mockRejectedValue(new Error("500 Internal Server Error: {}"));
    render(<DataProtection />);
    expect(await screen.findByText("Protected")).toBeTruthy();
    expect(screen.getByText("The service did not answer.")).toBeTruthy();
  });

  it("a dead coverage read never leaves a blank verdict", async () => {
    setup({ coverage: new Error("500 Internal Server Error: {}") });
    render(<DataProtection />);
    expect((await screen.findAllByText("The service did not answer.")).length).toBeGreaterThan(0);
    expect(screen.queryByText("Protected")).toBeNull();
  });
});

// ── 7 · accessibility + copy guards ─────────────────────────────────────────

describe("accessibility", () => {
  it("every part of the console is a named landmark", async () => {
    setup();
    render(<DataProtection />);
    for (const name of [
      "Protection health", "Coverage", "Bytes on disk",
      "Restore points", "Policies", "Activity and drills",
    ]) {
      expect(await screen.findByRole("region", { name })).toBeTruthy();
    }
  });

  it("the wizard is a dialog with an accessible name, and Escape cancels it", async () => {
    setup();
    render(<DataProtection />);
    const dlg = await openRestore();
    expect(dlg.getAttribute("aria-modal")).toBe("true");
    fireEvent.keyDown(window, { key: "Escape" });
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    expect(mockApi.restoreSnapshot).not.toHaveBeenCalled();
  });

  it("every control the operator types into carries a label", async () => {
    setup();
    render(<DataProtection />);
    // The bundle form is the last panel to settle, so wait on it first.
    expect(await screen.findByLabelText("Push command")).toBeTruthy();
    expect(screen.getByLabelText("Filter restore points")).toBeTruthy();
    expect(screen.getByLabelText("Recovery-point window, cron in UTC")).toBeTruthy();
    expect(screen.getByLabelText("Retention, maximum age in days")).toBeTruthy();
    expect(screen.getByLabelText("Bundle schedule, cron")).toBeTruthy();
  });
});

describe("copy guards on this page's own sources", () => {
  const here = dirname(fileURLToPath(import.meta.url));
  const files = ["DataProtection.tsx", "dataProtection.model.ts"];

  it("shows no denied developer-speak", () => {
    const hits = files.flatMap((f) => scanCopy(readFileSync(join(here, f), "utf-8"), `pages/${f}`));
    expect(hits, hits.join("\n")).toEqual([]);
  });

  it("never puts the engine word on screen", () => {
    const hits = files.flatMap((f) => scanForEngineVocabulary(readFileSync(join(here, f), "utf-8"), `pages/${f}`));
    expect(hits, hits.join("\n")).toEqual([]);
  });

  it("names the DATA, not the storage product, in every engine label", () => {
    const src = readFileSync(join(here, "dataProtection.model.ts"), "utf-8");
    const labels = [...src.matchAll(/^\s+\w+:\s"([^"]+)",$/gm)].map((m) => m[1]);
    expect(labels.length).toBeGreaterThan(6);
    for (const l of labels) expect(l).not.toMatch(/ClickHouse|VictoriaMetrics|Lucene/i);
  });
});

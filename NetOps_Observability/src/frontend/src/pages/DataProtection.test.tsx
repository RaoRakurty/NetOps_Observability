// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// DataProtection.test.tsx — the backup & recovery console.
//
// WHAT THESE TESTS ARE FOR. A backup screen is the one screen an operator reads
// exactly once, under pressure, and then acts on. Since the 2026-09-08 rebuild
// it reads as ONE question with an answer — "can this appliance be recovered,
// and how much would be lost?" — so the first thing these tests hold down is
// that the answer is honest:
//
//   1. NEVER GREEN FROM NOTHING. Every path that lacks a fact answers Unknown,
//      and "Recoverable: Yes" is reachable only through a restore somebody
//      actually proved. There is an explicit test per state, including the one
//      where the coverage read failed.
//   2. A NUMBER NOBODY MEASURED MUST NOT LOOK LIKE A MEASUREMENT. Every panel is
//      fed a payload with holes in it, and each test asserts the screen says
//      "not measured — <reason>" rather than 0, a dash, or a green tick.
//   3. "NEVER" MUST NOT LOOK LIKE "NOT MEASURED". A copy nobody has probed is a
//      gap we measured, not silence; the screen says so in its own words
//      ("Never proved", "Not copied yet").
//   4. A DESTRUCTIVE ACTION MUST BE HARD TO DO BY ACCIDENT. The in-place restore
//      and the delete are both type-to-confirm on the copy's own name, and both
//      keep their consequence text in full. Those assertions are UNCHANGED by
//      the rebuild, on purpose.
//   5. THE SHAPE IS THE PRODUCT. Three sections in one order (Protect, Recover,
//      Storage), with the evidence the answer demoted behind disclosures that
//      are CLOSED until asked for. A regression that promotes the seventy-row
//      footprint table back to the first screen fails here.

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

// ── fixtures (the wire shapes from internal/dataprotect/contract.go) ─────────

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
      started_at: "2026-09-01T04:00:00Z",
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
  bundle?: { config: Record<string, unknown>; status: Record<string, unknown> } | Error;
  platformAdmin?: boolean;
} = {}) {
  const resolve = <T,>(v: T | Error) => (v instanceof Error ? Promise.reject(v) : Promise.resolve(v));
  mockApi.backupCoverage.mockReturnValue(resolve(over.coverage ?? coverage()));
  mockApi.snapshotList.mockReturnValue(resolve(over.list ?? list()));
  mockApi.snapshotPolicy.mockResolvedValue(over.policy ?? POLICY);
  mockApi.backupConfig.mockReturnValue(resolve(over.bundle ?? {
    config: { remote_url: "rsync://nas/correlix/", schedule_enabled: true, schedule_cron: "30 2 * * *" },
    status: {},
  }));
  mockApi.backupOperations.mockResolvedValue(over.ops ?? OPS);
  mockApi.storageMeasured.mockReturnValue(resolve(over.storage ?? storage()));
  mockUseAuth.mockReturnValue({
    user: { username: "root", platform_admin: over.platformAdmin ?? true },
    loading: false,
  });
}

/**
 * Opens one disclosure. The evidence sections start CLOSED — that is the point
 * of the rebuild — so a test that reads them has to ask for them, exactly as an
 * operator does.
 */
function expand(summary: string | RegExp): HTMLDetailsElement {
  const el = screen.getByText(summary, { selector: "summary" });
  const details = el.closest("details") as HTMLDetailsElement;
  details.open = true;
  fireEvent(details, new Event("toggle", { bubbles: false }));
  return details;
}

/**
 * The answer card once its data has landed. The loading placeholder carries the
 * same landmark name on purpose (no layout shift), so a test must wait for a
 * value that only the settled card renders.
 */
async function answerCard(): Promise<HTMLElement> {
  await screen.findByText("Recoverable");
  return screen.getByRole("region", { name: "Recovery" });
}

beforeEach(() => { vi.setSystemTime(new Date("2026-09-04T12:00:00Z")); });
afterEach(() => { cleanup(); vi.clearAllMocks(); vi.useRealTimers(); });

// ── 1 · the answer ──────────────────────────────────────────────────────────

describe("the answer card", () => {
  it("asks the page's question in plain words, at the top", async () => {
    setup();
    render(<DataProtection />);
    expect(await screen.findByText("Can this appliance be recovered, and how much would be lost?")).toBeTruthy();
  });

  it("answers Yes only for a covered platform with a proved restore, and says why", async () => {
    setup();
    render(<DataProtection />);
    const card = await answerCard();
    expect(within(card).getByText("Yes")).toBeTruthy();
    expect(within(card).getByText(/at least one restore has been proved/)).toBeTruthy();
  });

  it("answers Not yet — never Yes — when a store is not copied, and names it", async () => {
    setup({
      coverage: coverage({
        engines: [engine(), engine({ id: "postgres", covered: "no", covered_reason: "no bundle has ever been written" })],
      }),
    });
    render(<DataProtection />);
    const card = await answerCard();
    expect(within(card).getByText("Not yet")).toBeTruthy();
    expect(within(card).queryByText("Yes")).toBeNull();
    expect(within(card).getByText("Application state is not covered — no bundle has ever been written")).toBeTruthy();
  });

  it("answers Not yet when copies exist but no restore was ever proved", async () => {
    setup({ coverage: coverage({ engines: [engine({ last_verified: null })] }), ops: { capacity: 50, operations: [] } });
    render(<DataProtection />);
    const card = await answerCard();
    expect(within(card).getByText("Not yet")).toBeTruthy();
    expect(within(card).getByText(/a copy nobody knows is good/i)).toBeTruthy();
  });

  it("answers Unknown — never green from nothing — when the facts could not be read", async () => {
    setup({ coverage: new Error("503 Service Unavailable: {}") });
    render(<DataProtection />);
    const card = await screen.findByRole("region", { name: "Recovery" });
    // The question still stands; the answer is the failure, not a blank verdict.
    expect(within(card).getByText("Can this appliance be recovered, and how much would be lost?")).toBeTruthy();
    expect(within(card).getByRole("alert")).toBeTruthy();
    expect(within(card).queryByText("Yes")).toBeNull();
  });

  it("answers Unknown when the platform lists nothing it protects", async () => {
    setup({ coverage: coverage({ engines: [] }) });
    render(<DataProtection />);
    const card = await answerCard();
    expect(within(card).getByText("Unknown")).toBeTruthy();
    expect(within(card).getByText(/reported no engine it is responsible for protecting/)).toBeTruthy();
  });

  it("gives the three facts: last good copy, what would be lost, the last drill", async () => {
    setup();
    render(<DataProtection />);
    const card = await answerCard();
    expect(within(card).getByText("Last good copy")).toBeTruthy();
    expect(within(card).getByText("10h 27m ago")).toBeTruthy();      // 2026-09-04T01:33 → 12:00
    expect(within(card).getByText("Would lose")).toBeTruthy();
    expect(within(card).getByText("up to 10h 30m")).toBeTruthy();    // from rpo_hours, not the target
    expect(within(card).getByText("Last drill")).toBeTruthy();
    expect(within(card).getByText("Drill passed")).toBeTruthy();
    expect(within(card).getByText("3d 08h ago")).toBeTruthy();
  });

  it("calls the loss window a FLOOR when a store reported no age at all", async () => {
    setup({
      coverage: coverage({
        engines: [engine(), engine({ id: "secrets_tls", rpo_hours: null, rpo_detail: "no envelope has been written" })],
      }),
    });
    render(<DataProtection />);
    const card = await answerCard();
    expect(within(card).getByText("at least 10h 30m")).toBeTruthy();
  });

  it("says Never for a drill that has not happened, rather than showing nothing", async () => {
    setup({ coverage: coverage({ engines: [engine({ last_verified: null })] }) });
    render(<DataProtection />);
    const card = await answerCard();
    expect(within(card).getByText("Never")).toBeTruthy();
  });

  it("renders an absent last-good-copy as its REASON, never as a zero or a dash", async () => {
    setup({ coverage: coverage({ engines: [engine({ last_success_at: "", rpo_hours: null, rpo_detail: "" })] }) });
    render(<DataProtection />);
    const card = await answerCard();
    expect(within(card).getByText("not measured — no store has ever reported a successful copy")).toBeTruthy();
    expect(within(card).getByText("not measured — no store reported the age of its last good copy")).toBeTruthy();
    expect(within(card).queryByText("0s ago")).toBeNull();
    expect(within(card).queryByText("up to 0s")).toBeNull();
  });
});

describe("the one action", () => {
  it("offers a drill on a healthy platform, and runs it against the newest good copy", async () => {
    setup();
    mockApi.verifySnapshot.mockResolvedValue(op({ kind: "snapshot_verify", state: "succeeded", ended_at: "2026-09-04T12:00:30Z" }));
    render(<DataProtection />);
    const card = await answerCard();
    fireEvent.click(within(card).getByRole("button", { name: "Run a drill" }));
    await waitFor(() => expect(mockApi.verifySnapshot).toHaveBeenCalledWith());
  });

  it("offers a backup when nothing has ever been copied", async () => {
    setup({ coverage: coverage({ engines: [engine({ last_success_at: "", last_verified: null })] }) });
    mockApi.createSnapshot.mockResolvedValue(op({ state: "succeeded", ended_at: "2026-09-04T12:00:10Z" }));
    render(<DataProtection />);
    const card = await answerCard();
    fireEvent.click(within(card).getByRole("button", { name: "Run a backup" }));
    await waitFor(() => expect(mockApi.createSnapshot).toHaveBeenCalled());
  });

  it("names the failing store, and opens the evidence rather than pretending to repair it", async () => {
    setup({
      coverage: coverage({
        engines: [engine(), engine({ id: "postgres", covered: "no", covered_reason: "no bundle has ever been written" })],
      }),
    });
    render(<DataProtection />);
    const card = await answerCard();
    const btn = within(card).getByRole("button", { name: "Fix Application state" });
    fireEvent.click(btn);
    await waitFor(() =>
      expect((screen.getByText("Per-store details", { selector: "summary" })
        .closest("details") as HTMLDetailsElement).open).toBe(true));
    expect(mockApi.createSnapshot).not.toHaveBeenCalled();
    expect(mockApi.verifySnapshot).not.toHaveBeenCalled();
  });

  it("offers a re-read, not a verdict, when the copy store could not be read", async () => {
    setup({ coverage: new Error("500 Internal Server Error: {}") });
    render(<DataProtection />);
    expect(await screen.findByRole("button", { name: "Read it again" })).toBeTruthy();
  });
});

// ── 2 · protect ─────────────────────────────────────────────────────────────

describe("Protect", () => {
  it("is a short table: store, copied, last copy, kept for", async () => {
    setup();
    render(<DataProtection />);
    const table = await screen.findByRole("table", { name: "What is copied" });
    const heads = within(table).getAllByRole("columnheader").map((h) => h.textContent);
    expect(heads).toEqual(["Store", "Copied", "Last copy", "Kept for"]);
    expect(within(table).getByText("Log & event search")).toBeTruthy();
    // "Copied" is both the column and the verdict; the cell is the second one.
    expect(within(table).getAllByText("Copied").length).toBe(2);
    expect(within(table).getByText("10h 27m ago")).toBeTruthy();
    expect(within(table).getByText("14 copies · 30 days")).toBeTruthy();
  });

  it("says 'Not copied yet' — a measured gap — rather than leaving the cell blank", async () => {
    setup({ coverage: coverage({ engines: [engine({ last_success_at: "" })] }) });
    render(<DataProtection />);
    const table = await screen.findByRole("table", { name: "What is copied" });
    expect(within(table).getByText("Not copied yet")).toBeTruthy();
  });

  it("says WHY a store is not protected here, instead of showing a gap", async () => {
    setup({
      coverage: coverage({
        engines: [engine({
          id: "kafka", name: "Event bus", covered: "not_applicable",
          covered_reason: "the bus is a transport, not a store of record",
        })],
      }),
    });
    render(<DataProtection />);
    const table = await screen.findByRole("table", { name: "What is copied" });
    expect(within(table).getByText("Not protected here")).toBeTruthy();
    expect(within(table).getByText("the bus is a transport, not a store of record")).toBeTruthy();
  });

  it("renders an absent retention as the server's REASON, never as 'no retention'", async () => {
    setup({
      coverage: coverage({
        engines: [engine({ retention: { max_count: null, max_age_days: null, detail: "it dies with the bundle artifact" } })],
      }),
    });
    render(<DataProtection />);
    // The short table states the absence compactly and carries the server's
    // sentence on hover; the paragraph itself moved into the per-store matrix.
    const table = await screen.findByRole("table", { name: "What is copied" });
    const cell = within(table).getByText("Not measured");
    expect(cell.getAttribute("title")).toBe("not measured — it dies with the bundle artifact");
    expect(within(table).queryByText("0 copies")).toBeNull();
    expand("Per-store details");
    expect(within(screen.getByRole("table", { name: "Protection coverage by store" }))
      .getByText("not measured — it dies with the bundle artifact")).toBeTruthy();
  });

  it("puts the schedule and the retention on screen as sentences, each with Edit", async () => {
    setup();
    render(<DataProtection />);
    expect((await screen.findAllByText("Daily at 01:30 UTC")).length).toBeGreaterThan(0);
    expect(screen.getByText("Keep 14 copies")).toBeTruthy();
    expect(screen.getByText(/next in 13h 30m/)).toBeTruthy();
    expect(screen.getAllByRole("button", { name: "Edit" }).length).toBe(3);
  });

  it("prints a cron it cannot read verbatim rather than guessing at a sentence", async () => {
    setup({ policy: { ...POLICY, schedule_cron: "*/15 2-4 * * 1-5" } });
    render(<DataProtection />);
    expect(await screen.findByText("*/15 2-4 * * 1-5")).toBeTruthy();
  });

  it("says the schedule is off, rather than showing its stale expression", async () => {
    setup({ policy: { ...POLICY, enabled: false } });
    render(<DataProtection />);
    expect(await screen.findByText("Off")).toBeTruthy();
    expect(screen.getByText("not measured — the schedule is off")).toBeTruthy();
  });

  it("states whether a copy exists anywhere but this host, and what it costs", async () => {
    setup({ bundle: { config: { remote_url: "", schedule_enabled: false }, status: {} } });
    render(<DataProtection />);
    expect(await screen.findByText("Off-host copy")).toBeTruthy();
    expect(screen.getByText("Not set")).toBeTruthy();
    expect(screen.getByText("One disk failure would lose both copies.")).toBeTruthy();
  });

  it("names the configured off-host destination when there is one", async () => {
    setup();
    render(<DataProtection />);
    expect(await screen.findByText("Set")).toBeTruthy();
    expect(screen.getAllByText("rsync://nas/correlix/").length).toBeGreaterThan(0);
  });

  it("opens the schedule editor in a dialog, not inline on the page", async () => {
    setup();
    render(<DataProtection />);
    expect((await screen.findAllByText("Daily at 01:30 UTC")).length).toBeGreaterThan(0);
    expect(screen.queryByRole("dialog")).toBeNull();
    fireEvent.click(screen.getAllByRole("button", { name: "Edit" })[0]);
    const dlg = await screen.findByRole("dialog", { name: /Schedule and retention/ });
    expect(within(dlg).getByLabelText("Copy window, cron in UTC")).toBeTruthy();
  });

  it("opens the off-host editor in its own dialog", async () => {
    setup();
    render(<DataProtection />);
    expect(await screen.findByText("Off-host copy")).toBeTruthy();
    fireEvent.click(screen.getAllByRole("button", { name: "Edit" })[2]);
    const dlg = await screen.findByRole("dialog", { name: /Off-host copy/ });
    expect(within(dlg).getByLabelText("Push command")).toBeTruthy();
  });
});

describe("Protect — the evidence, one disclosure down", () => {
  it("keeps the nine-column matrix, closed until asked for", async () => {
    setup();
    render(<DataProtection />);
    const sum = await screen.findByText("Per-store details", { selector: "summary" });
    expect((sum.closest("details") as HTMLDetailsElement).open).toBe(false);
    expand("Per-store details");
    const table = screen.getByRole("table", { name: "Protection coverage by store" });
    const heads = within(table).getAllByRole("columnheader").map((h) => h.textContent);
    expect(heads).toEqual([
      "Store", "Copied", "Schedule", "Last attempt", "Last success",
      "Last proved", "Size", "Kept for", "Where it lands",
    ]);
  });

  it("carries the reason for EVERY verdict, including a copied one", async () => {
    setup();
    render(<DataProtection />);
    await screen.findByText("Per-store details", { selector: "summary" });
    expand("Per-store details");
    const table = screen.getByRole("table", { name: "Protection coverage by store" });
    expect(within(table).getByText("the daily policy produced a successful copy 10h ago")).toBeTruthy();
  });

  it("keeps the immutability and encryption badges, each with its own reason", async () => {
    setup({
      coverage: coverage({
        engines: [engine({
          target: {
            kind: "local", location: "data/opensearch-snapshots",
            immutable: false, immutable_detail: "a filesystem repository on the same host",
            encrypted: null, encrypted_detail: "the platform cannot see the volume's encryption state",
          },
        })],
      }),
    });
    render(<DataProtection />);
    await screen.findByText("Per-store details", { selector: "summary" });
    expand("Per-store details");
    expect(screen.getByText("Mutable")).toBeTruthy();
    expect(screen.getByText("not measured — the platform cannot see the volume's encryption state")).toBeTruthy();
  });

  it("keeps the recovery-point objectives, and still refuses to assume one", async () => {
    setup({ coverage: coverage({ engines: [engine({ rpo_target_hours: null, rpo_objective_hours: null })] }) });
    render(<DataProtection />);
    await screen.findByText("Per-store details", { selector: "summary" });
    expand("Per-store details");
    expect(screen.getByText(/last good copy 10h 30m old · objective not set/)).toBeTruthy();
  });

  it("judges against a SCHEDULED objective when the platform publishes one", async () => {
    setup({ coverage: coverage({ engines: [engine({ rpo_hours: 10.5, rpo_target_hours: 24 })] }) });
    render(<DataProtection />);
    await screen.findByText("Per-store details", { selector: "summary" });
    expand("Per-store details");
    expect(screen.getByText(/Objective met · 10h 30m against a 1d 00h scheduled objective/)).toBeTruthy();
  });

  it("keeps the host jobs this page does not govern, named as external", async () => {
    setup({
      coverage: coverage({
        external: [{
          name: "nightly rsync to the NAS", source: "host crontab", schedule: "0 3 * * *",
          detail: "external to the product — this page does not govern it",
        }],
      }),
    });
    render(<DataProtection />);
    await screen.findByText("Per-store details", { selector: "summary" });
    expand("Per-store details");
    expect(screen.getByText("nightly rsync to the NAS")).toBeTruthy();
    expect(screen.getByText("host crontab · 0 3 * * *")).toBeTruthy();
  });

  it("names the copy store's state as an outcome, and reports its free space", async () => {
    setup({ list: list({ repository: repo({ disk_free_bytes: 1073741824, disk_total_bytes: 4294967296 }) }) });
    render(<DataProtection />);
    await screen.findByText("Per-store details", { selector: "summary" });
    expand("Per-store details");
    expect(screen.getByText("Ready")).toBeTruthy();
    expect(screen.getByText("1.0 GiB free of 4.0 GiB (25%)")).toBeTruthy();
  });

  it("says the volume was not weighed rather than printing a 0% free", async () => {
    setup({ list: list({ repository: repo({ disk_detail: "the api container does not mount that path" }) }) });
    render(<DataProtection />);
    await screen.findByText("Per-store details", { selector: "summary" });
    expand("Per-store details");
    expect(screen.getAllByText("not measured — the api container does not mount that path").length).toBeGreaterThan(0);
    expect(screen.queryByText(/0% free/)).toBeNull();
    expect(screen.queryByText("0 B free of 0 B (0%)")).toBeNull();
  });

  it("says so when the platform lists nothing to protect at all", async () => {
    setup({ coverage: coverage({ engines: [] }) });
    render(<DataProtection />);
    expect(await screen.findByText("Nothing was listed to protect.")).toBeTruthy();
  });
});

// ── 3 · recover ─────────────────────────────────────────────────────────────

describe("Recover", () => {
  it("leads with the drill history, in plain outcomes", async () => {
    setup();
    render(<DataProtection />);
    const sec = await screen.findByRole("region", { name: "Recover" });
    expect(within(sec).getAllByText("Drill passed").length).toBeGreaterThan(0);
    expect(within(sec).getByText("netops-daily-20260901")).toBeTruthy();
  });

  it("a drill whose counts did not match reads as a failure, not as a run", async () => {
    setup({
      ops: {
        capacity: 50,
        operations: [op({
          id: "op-b1", kind: "snapshot_verify", state: "succeeded", ended_at: "2026-09-04T02:00:00Z",
          target: { snapshot: "netops-daily-20260904" },
          verify: {
            snapshot: "netops-daily-20260904", index: "netops-traps", temp_index: "probe-2",
            source_docs: 1200, restored_docs: 900, match: false, temp_deleted: true, duration_seconds: 30,
          },
        })],
      },
    });
    render(<DataProtection />);
    const sec = await screen.findByRole("region", { name: "Recover" });
    expect(within(sec).getByText("Drill failed")).toBeTruthy();
    expect(within(sec).queryByText("Drill passed")).toBeNull();
  });

  it("says plainly when no restore has ever been proved, with the next action", async () => {
    setup({ coverage: coverage({ engines: [engine({ last_verified: null })] }), ops: { capacity: 50, operations: [] } });
    render(<DataProtection />);
    const sec = await screen.findByRole("region", { name: "Recover" });
    expect(within(sec).getByText("No restore has ever been proved.")).toBeTruthy();
    expect(within(sec).getByText(/Run a drill; its result is recorded here/)).toBeTruthy();
  });

  it("never contradicts the card: an empty drill list points at the proof it has", async () => {
    // The coverage table reports a PASSED restore (the host bundle drill) while
    // this page's own operations ring is empty. Saying "never proved" here would
    // contradict the answer card two inches above it.
    setup({ ops: { capacity: 50, operations: [] } });
    render(<DataProtection />);
    const sec = await screen.findByRole("region", { name: "Recover" });
    expect(within(sec).getByText("No drill has run from here.")).toBeTruthy();
    expect(within(sec).getByText(/The last proof came from Log & event search, 3d 08h ago\./)).toBeTruthy();
    expect(within(sec).queryByText("No restore has ever been proved.")).toBeNull();
  });

  it("runs a drill against the newest good copy — no copy named", async () => {
    setup();
    mockApi.verifySnapshot.mockResolvedValue(op({ kind: "snapshot_verify", state: "succeeded", ended_at: "2026-09-04T12:00:40Z" }));
    render(<DataProtection />);
    const sec = await screen.findByRole("region", { name: "Recover" });
    // The section header's own control, not the answer card's.
    fireEvent.click(within(within(sec).getAllByRole("button", { name: "Run a drill" })[0].closest(".dp-sec-hd") as HTMLElement)
      .getByRole("button", { name: "Run a drill" }));
    await waitFor(() => expect(mockApi.verifySnapshot).toHaveBeenCalledWith());
  });

  it("keeps the copies behind a disclosure, closed until asked for", async () => {
    setup();
    render(<DataProtection />);
    const sum = await screen.findByText(/^Restore from a copy · 1$/, { selector: "summary" });
    expect((sum.closest("details") as HTMLDetailsElement).open).toBe(false);
  });

  it("renders each copy's state, duration, index count and drill verdict", async () => {
    setup();
    render(<DataProtection />);
    await screen.findByText(/^Restore from a copy · 1$/, { selector: "summary" });
    expand(/^Restore from a copy · 1$/);
    expect(screen.getByText("netops-daily-20260904")).toBeTruthy();
    expect(screen.getAllByText("Success").length).toBeGreaterThan(0);
    expect(screen.getByText("3m 00s")).toBeTruthy();
    expect(screen.getByText(/Drill passed · 3d 08h ago/)).toBeTruthy();
  });

  it("a copy nobody probed reads 'Never proved' — a gap, not a shrug and not a pass", async () => {
    setup({
      list: list({ snapshots: [snapshot({ restorable_verified: null, restorable_detail: "no probe has ever run" })] }),
    });
    render(<DataProtection />);
    await screen.findByText(/^Restore from a copy · 1$/, { selector: "summary" });
    expand(/^Restore from a copy · 1$/);
    expect(screen.getByText("Never proved")).toBeTruthy();
  });

  it("size stays opt-in, and says why it is absent until it is measured", async () => {
    setup();
    render(<DataProtection />);
    await screen.findByText(/^Restore from a copy · 1$/, { selector: "summary" });
    expand(/^Restore from a copy · 1$/);
    expect(screen.getByText("not measured — not measured on this read — pass ?sizes=1")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Measure sizes" }));
    await waitFor(() => expect(mockApi.snapshotList).toHaveBeenCalledWith({ sizes: true }));
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
    await screen.findByText(/^Restore from a copy · 1$/, { selector: "summary" });
    expand(/^Restore from a copy · 1$/);
    expect(screen.getByText(/2 of 6 shards failed · netops-syslog\[3\] NoSuchFileException/)).toBeTruthy();
    expect(screen.getByText(/1 more not listed/)).toBeTruthy();
  });

  it("renders with zero, one and five hundred copies without changing shape", async () => {
    for (const n of [0, 1, 500]) {
      cleanup();
      const snaps = Array.from({ length: n }, (_, i) =>
        snapshot({ name: `netops-daily-${String(i).padStart(4, "0")}`, started_at: `2026-09-0${(i % 4) + 1}T01:30:00Z` }));
      setup({ list: list({ snapshots: snaps }) });
      render(<DataProtection />);
      await screen.findByText(new RegExp(`^Restore from a copy · ${n}$`), { selector: "summary" });
      expand(new RegExp(`^Restore from a copy · ${n}$`));
      if (n === 0) {
        expect(screen.getByText("No copy exists yet.")).toBeTruthy();
      } else {
        const grid = screen.getByRole("grid", { name: "Copies" });
        expect(Number(grid.getAttribute("aria-rowcount"))).toBe(n);
      }
    }
  });

  it("keeps the audit trail behind its own disclosure, with what it cannot show", async () => {
    setup();
    render(<DataProtection />);
    const sum = await screen.findByText(/^Activity · 2$/, { selector: "summary" });
    expect((sum.closest("details") as HTMLDetailsElement).open).toBe(false);
    expand(/^Activity · 2$/);
    expect(screen.getByText(/^Take restore point · netops-daily-20260904$/)).toBeTruthy();
    expect(screen.getByText("The platform keeps the newest 50 entries.")).toBeTruthy();
  });
});

describe("running an action", () => {
  it("shows the accepted operation and then its progress", async () => {
    setup();
    mockApi.createSnapshot.mockResolvedValue(op({ progress: "" }));
    mockApi.backupOperation.mockResolvedValue(op({ progress: "Copying 2 of 5 indices." }));
    render(<DataProtection />);
    fireEvent.click(await screen.findByRole("button", { name: "Back up now" }));
    await waitFor(() => expect(mockApi.createSnapshot).toHaveBeenCalled());
    expect(await screen.findByText("Copying 2 of 5 indices.")).toBeTruthy();
    expect(screen.getByRole("progressbar", { name: "Operation progress" })).toBeTruthy();
  });

  it("shows what was recorded once it settles, and re-reads the page", async () => {
    setup();
    mockApi.createSnapshot.mockResolvedValue(op({ progress: "" }));
    mockApi.backupOperation.mockResolvedValue(op({
      state: "succeeded", ended_at: "2026-09-04T12:00:30Z",
      target: { snapshot: "netops-daily-20260904b" }, progress: "Restore point created.",
    }));
    render(<DataProtection />);
    fireEvent.click(await screen.findByRole("button", { name: "Back up now" }));
    expect(await screen.findByText(/Recorded · root · snapshot_create/)).toBeTruthy();
    await waitFor(() => expect(mockApi.backupCoverage).toHaveBeenCalledTimes(2));
  });

  it("renders a failed operation's error rather than a silent stop", async () => {
    setup();
    mockApi.createSnapshot.mockResolvedValue(op({ progress: "" }));
    mockApi.backupOperation.mockResolvedValue(op({
      state: "failed", ended_at: "2026-09-04T12:00:05Z", error: "repository netops-fs is read-only",
    }));
    render(<DataProtection />);
    fireEvent.click(await screen.findByRole("button", { name: "Back up now" }));
    expect(await screen.findByText("repository netops-fs is read-only")).toBeTruthy();
  });

  it("reports a refused action as an operator sentence", async () => {
    setup();
    mockApi.createSnapshot.mockRejectedValue(new Error("429 Too Many Requests: {}"));
    render(<DataProtection />);
    fireEvent.click(await screen.findByRole("button", { name: "Back up now" }));
    expect(await screen.findByText("The action did not complete.")).toBeTruthy();
    expect(screen.getByText("Too many requests just now — try again shortly.")).toBeTruthy();
  });

  it("drills one copy on demand, by name", async () => {
    setup();
    mockApi.verifySnapshot.mockResolvedValue(op({ kind: "snapshot_verify", state: "running" }));
    mockApi.backupOperation.mockResolvedValue(op({ kind: "snapshot_verify", state: "running", progress: "Comparing document counts." }));
    render(<DataProtection />);
    await screen.findByText(/^Restore from a copy · 1$/, { selector: "summary" });
    expand(/^Restore from a copy · 1$/);
    const grid = screen.getByRole("grid", { name: "Copies" });
    fireEvent.click(within(grid).getByRole("button", { name: "Run a drill" }));
    await waitFor(() => expect(mockApi.verifySnapshot).toHaveBeenCalledWith("netops-daily-20260904"));
    expect(await screen.findByText("Comparing document counts.")).toBeTruthy();
  });
});

// ── 3a · restore wizard (destructive paths — unchanged by the rebuild) ───────

async function openRestore() {
  await screen.findByText(/^Restore from a copy · 1$/, { selector: "summary" });
  expand(/^Restore from a copy · 1$/);
  fireEvent.click(screen.getAllByRole("button", { name: "Restore…" })[0]);
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
    fireEvent.click(within(dlg).getByLabelText(/Whole copy/));                  // uncheck → pick indices
    fireEvent.click(within(dlg).getByLabelText("netops-traps-2026.09.04"));     // drop the second
    fireEvent.click(within(dlg).getByRole("button", { name: "Next" }));
    fireEvent.click(within(dlg).getByRole("button", { name: "Next" }));
    fireEvent.click(within(dlg).getByRole("button", { name: "Start restore" }));

    await waitFor(() => expect(mockApi.restoreSnapshot).toHaveBeenCalledWith(
      expect.objectContaining({ indices: ["netops-syslog-2026.09.04"] })));
  });
});

// ── 3b · delete ─────────────────────────────────────────────────────────────

describe("deleting a copy", () => {
  it("spells out the consequence and stays disabled until the name is typed exactly", async () => {
    setup();
    mockApi.deleteSnapshot.mockResolvedValue(op({ kind: "snapshot_delete", state: "succeeded", ended_at: "2026-09-04T12:00:10Z" }));
    render(<DataProtection />);
    await screen.findByText(/^Restore from a copy · 1$/, { selector: "summary" });
    expand(/^Restore from a copy · 1$/);
    fireEvent.click(screen.getAllByRole("button", { name: "Delete…" })[0]);
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

// ── 4 · storage ─────────────────────────────────────────────────────────────

describe("Storage", () => {
  it("summarises the footprint and keeps the per-store table CLOSED", async () => {
    setup();
    render(<DataProtection />);
    const sec = await screen.findByRole("region", { name: "Storage" });
    expect(within(sec).getByText("measured total")).toBeTruthy();
    expect(within(sec).getAllByText("3.0 GiB").length).toBeGreaterThan(0);
    const sum = within(sec).getByText(/^Bytes by store · 1$/, { selector: "summary" });
    expect((sum.closest("details") as HTMLDetailsElement).open).toBe(false);
  });

  it("calls the total a LOWER BOUND while a store contributes nothing", async () => {
    setup({
      storage: storage({
        unmeasured_stores: ["kafka"],
        measurement_note: "PARTIAL. `total_measured_bytes` is a LOWER BOUND.",
      }),
    });
    render(<DataProtection />);
    const sec = await screen.findByRole("region", { name: "Storage" });
    expect(within(sec).getByText("measured total (lower bound)")).toBeTruthy();
    expect(within(sec).getByText("Events queued on the bus")).toBeTruthy();
  });

  it("says every store was weighed when the read is complete", async () => {
    setup();
    render(<DataProtection />);
    const sec = await screen.findByRole("region", { name: "Storage" });
    expect(within(sec).getByText("Every store weighed")).toBeTruthy();
  });

  it("renders one row per store under the data's name, with the query behind it", async () => {
    setup();
    render(<DataProtection />);
    await screen.findByText(/^Bytes by store · 1$/, { selector: "summary" });
    expand(/^Bytes by store · 1$/);
    const table = screen.getByRole("table", { name: "Bytes on disk by store" });
    expect(within(table).getByText("Log & event search")).toBeTruthy();
    expect(within(table).getByText("_cat/indices?bytes=b store.size")).toBeTruthy();
  });

  it("a store nobody could weigh states the reason and never renders 0 B", async () => {
    setup({
      storage: storage({
        readings: [reading({
          store: "kafka", bytes_on_disk: null, source: "",
          detail: "not measured — the api ships no client for the bus",
        })],
        total_measured_bytes: 0, unmeasured_stores: ["kafka"],
      }),
    });
    render(<DataProtection />);
    await screen.findByText(/^Bytes by store · 1$/, { selector: "summary" });
    expand(/^Bytes by store · 1$/);
    const table = screen.getByRole("table", { name: "Bytes on disk by store" });
    expect(within(table).getByText("not measured — the api ships no client for the bus")).toBeTruthy();
    expect(within(table).queryByText("0 B")).toBeNull();
  });

  it("a real ZERO is a measurement and renders as 0 B", async () => {
    setup({ storage: storage({ readings: [reading({ bytes_on_disk: 0 })], total_measured_bytes: 0 }) });
    render(<DataProtection />);
    await screen.findByText(/^Bytes by store · 1$/, { selector: "summary" });
    expand(/^Bytes by store · 1$/);
    expect(screen.getAllByText("0 B").length).toBeGreaterThan(0);
  });

  it("puts the breakdown behind its own disclosure, with the ratio only where measured", async () => {
    setup({
      storage: storage({
        readings: [reading({
          components: [
            { name: "netops-syslog-2026.09.04", bytes_on_disk: 1073741824, rows: 4200000, uncompressed_bytes: 5368709120 },
            { name: "netops-traps-2026.09.04", bytes_on_disk: 536870912, rows: null, uncompressed_bytes: null },
          ],
        })],
      }),
    });
    render(<DataProtection />);
    await screen.findByText(/^Bytes by store · 1$/, { selector: "summary" });
    expand(/^Bytes by store · 1$/);
    expand(/Where the bytes are/);
    expect(screen.getByText("5.0× (measured)")).toBeTruthy();
    expect(screen.queryByText("1.0× (measured)")).toBeNull();
  });

  it("a dead read shows the panel error and never a byte count", async () => {
    setup({ storage: new Error("502 Bad Gateway: {}") });
    render(<DataProtection />);
    const sec = await screen.findByRole("region", { name: "Storage" });
    expect(within(sec).getByRole("alert")).toBeTruthy();
    expect(within(sec).queryAllByText("3.0 GiB")).toEqual([]);
  });
});

// ── gating, panels and landmarks ────────────────────────────────────────────

describe("platform-admin gating", () => {
  it("hides every mutating control from a tenant admin and says why", async () => {
    setup({ platformAdmin: false });
    render(<DataProtection />);
    expect(await screen.findByText("This page is read-only for you.")).toBeTruthy();
    expect(screen.getByRole("button", { name: /Ask Iris about This page is read-only for you/i })).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Back up now" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Run a drill" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Restore…" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Delete…" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Edit" })).toBeNull();
    // The answer itself stays readable — gating hides controls, not evidence.
    const card = await answerCard();
    expect(within(card).getByText("Yes")).toBeTruthy();
  });

  it("gives the platform administrator the full control set", async () => {
    setup({ platformAdmin: true });
    render(<DataProtection />);
    expect(await screen.findByRole("button", { name: "Back up now" })).toBeTruthy();
    expect(screen.getAllByRole("button", { name: "Run a drill" }).length).toBeGreaterThan(0);
    expect(screen.queryByText("This page is read-only for you.")).toBeNull();
  });
});

describe("the schedule editor", () => {
  async function openSchedule() {
    render(<DataProtection />);
    await screen.findByText("Off-host copy");
    fireEvent.click(screen.getAllByRole("button", { name: "Edit" })[0]);
    return screen.findByRole("dialog", { name: /Schedule and retention/ });
  }

  it("an off schedule states the consequence, not just the state", async () => {
    setup({ policy: { ...POLICY, enabled: false } });
    const dlg = await openSchedule();
    expect(within(dlg).getByText("The schedule is off.")).toBeTruthy();
    expect(within(dlg).getByText(/No new copies will be made/)).toBeTruthy();
  });

  it("names who turned it off, when and why", async () => {
    setup({
      policy: {
        ...POLICY, enabled: false,
        disabled_reason: "the copy volume is being replaced",
        disabled_at: "2026-09-03T09:12:00Z", disabled_by: "root",
      },
    });
    const dlg = await openSchedule();
    expect(within(dlg).getByText(/Turned off by root on 2026-09-03T09:12:00Z: the copy volume is being replaced/))
      .toBeTruthy();
  });

  it("an off schedule with NO recorded reason says it may not have been deliberate", async () => {
    setup({ policy: { ...POLICY, enabled: false } });
    const dlg = await openSchedule();
    expect(within(dlg).getByText(/may not have been deliberate/)).toBeTruthy();
  });

  it("turning it off asks for a reason FIRST and sends it with the write", async () => {
    setup();
    mockApi.setSnapshotPolicy.mockResolvedValue({});
    const dlg = await openSchedule();
    fireEvent.click(within(dlg).getByLabelText(/Copies run on this schedule/));
    expect(within(dlg).getByText("Turning this off stops new copies being made.")).toBeTruthy();
    expect(mockApi.setSnapshotPolicy).not.toHaveBeenCalled();

    fireEvent.change(within(dlg).getByLabelText("Reason for turning the schedule off"), {
      target: { value: "the copy volume is being replaced" },
    });
    fireEvent.click(within(dlg).getByRole("button", { name: "Turn it off" }));
    await waitFor(() => expect(mockApi.setSnapshotPolicy).toHaveBeenCalledWith({
      enabled: false, reason: "the copy volume is being replaced",
    }));
  });

  it("'Keep it on' backs out without writing anything", async () => {
    setup();
    const dlg = await openSchedule();
    fireEvent.click(within(dlg).getByLabelText(/Copies run on this schedule/));
    fireEvent.click(within(dlg).getByRole("button", { name: "Keep it on" }));
    expect(within(dlg).queryByText("Turning this off stops new copies being made.")).toBeNull();
    expect(mockApi.setSnapshotPolicy).not.toHaveBeenCalled();
  });

  it("warns when something other than this page owns the on/off state", async () => {
    setup({ policy: { ...POLICY, managed_by: "policy-file", managed_by_detail: "the bootstrap wrote it" } });
    const dlg = await openSchedule();
    expect(within(dlg).getByText("This switch is not authoritative.")).toBeTruthy();
    expect(within(dlg).getByText(/owned by policy-file/)).toBeTruthy();
    expect(within(dlg).getByText(/the bootstrap wrote it/)).toBeTruthy();
  });

  it("edits the window and the retention through the same route", async () => {
    setup();
    mockApi.setSnapshotPolicy.mockResolvedValue({});
    const dlg = await openSchedule();
    fireEvent.blur(within(dlg).getByLabelText("Copy window, cron in UTC"), { target: { value: "0 3 * * *" } });
    await waitFor(() => expect(mockApi.setSnapshotPolicy).toHaveBeenCalledWith({ schedule_cron: "0 3 * * *" }));
    fireEvent.blur(within(dlg).getByLabelText("Retention, keep newest count"), { target: { value: "21" } });
    await waitFor(() => expect(mockApi.setSnapshotPolicy).toHaveBeenCalledWith({ retention_max_count: 21 }));
  });
});

describe("the off-host editor", () => {
  async function openOffHost(bundle?: { config: Record<string, unknown>; status: Record<string, unknown> }) {
    setup(bundle ? { bundle } : {});
    render(<DataProtection />);
    await screen.findByText("Off-host copy");
    fireEvent.click(screen.getAllByRole("button", { name: "Edit" })[2]);
    return screen.findByRole("dialog", { name: /Off-host copy/ });
  }

  it("warns when there is no off-host copy at all", async () => {
    const dlg = await openOffHost({ config: { remote_url: "", schedule_enabled: false }, status: {} });
    expect(within(dlg).getByText("There is no off-host copy.")).toBeTruthy();
  });

  it("states which retention number is actually in force", async () => {
    const dlg = await openOffHost({
      config: { remote_url: "rsync://nas/", schedule_enabled: true, retain_count: null }, status: {},
    });
    expect(within(dlg).getByText("Not set. The host keeps 7.")).toBeTruthy();
  });

  it("never renders a deliberate 0 as unset, and says what it costs", async () => {
    const dlg = await openOffHost({
      config: { remote_url: "rsync://nas/", schedule_enabled: true, retain_count: 0 }, status: {},
    });
    expect(within(dlg).getByText("Pruning off. Every copy kept.")).toBeTruthy();
  });

  it("says that clearing a stored retention is not a change", async () => {
    const dlg = await openOffHost({
      config: { remote_url: "rsync://nas/", schedule_enabled: true, retain_count: 21 }, status: {},
    });
    const field = within(dlg).getByLabelText("Off-host copies kept") as HTMLInputElement;
    fireEvent.change(field, { target: { value: "" } });
    expect(within(dlg).getByText("Clearing is not a change. Saving keeps 21.")).toBeTruthy();
  });

  it("refuses a retention the server would reject rather than sending it", async () => {
    const dlg = await openOffHost({
      config: { remote_url: "rsync://nas/", schedule_enabled: true, retain_count: 7 }, status: {},
    });
    const field = within(dlg).getByLabelText("Off-host copies kept") as HTMLInputElement;
    fireEvent.change(field, { target: { value: "999" } });
    expect(within(dlg).getByText("The host keeps the 7 newest copies.")).toBeTruthy();
  });
});

describe("honest states, each with its own remedy and the procedure link", () => {
  it("a copy store that is not set up names the bootstrap that creates it", async () => {
    setup({ list: list({ repository: repo({ registered: false }) }), policy: { ...POLICY, repository: repo({ registered: false }) } });
    render(<DataProtection />);
    expect(await screen.findByText("The copy store is not set up.")).toBeTruthy();
    expect(screen.getByRole("link", { name: /Back up and restore procedure/ })).toBeTruthy();
  });

  it("an unreachable copy store makes the answer Not yet and names the read failure", async () => {
    setup({ list: new Error("504 Gateway Timeout: {}") });
    render(<DataProtection />);
    const card = await answerCard();
    expect(within(card).getByText("Not yet")).toBeTruthy();
    expect(screen.getByText("The copy store cannot be read.")).toBeTruthy();
  });

  it("each panel fails independently: a dead trail leaves the answer readable", async () => {
    setup();
    mockApi.backupOperations.mockRejectedValue(new Error("500 Internal Server Error: {}"));
    render(<DataProtection />);
    const card = await answerCard();
    expect(within(card).getByText("Yes")).toBeTruthy();
    expand(/^Activity · 0$/);
    expect(within(screen.getByRole("region", { name: "Recover" })).getByRole("alert")).toBeTruthy();
  });
});

describe("accessibility and shape", () => {
  it("the page is four named landmarks, in the order the answer needs them", async () => {
    setup();
    render(<DataProtection />);
    await screen.findByRole("region", { name: "Recovery" });
    const ids = screen.getAllByRole("region").map((r) => r.getAttribute("data-section"));
    expect(ids).toEqual(["answer", "protect", "recover", "storage"]);
  });

  it("every evidence disclosure starts CLOSED — the answer is the first screen", async () => {
    setup();
    render(<DataProtection />);
    await screen.findByText("Per-store details", { selector: "summary" });
    const open = screen.getAllByText(/./, { selector: "summary" })
      .map((s) => s.closest("details") as HTMLDetailsElement)
      .filter((d) => d.open);
    expect(open).toEqual([]);
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
    await screen.findByText(/^Restore from a copy · 1$/, { selector: "summary" });
    expand(/^Restore from a copy · 1$/);
    expect(screen.getByLabelText("Filter copies")).toBeTruthy();
    fireEvent.click(screen.getAllByRole("button", { name: "Edit" })[0]);
    expect(await screen.findByLabelText("Copy window, cron in UTC")).toBeTruthy();
    expect(screen.getByLabelText("Retention, maximum age in days")).toBeTruthy();
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

  it("names the DATA, not the storage product, in every store label", () => {
    const src = readFileSync(join(here, "dataProtection.model.ts"), "utf-8");
    const labels = [...src.matchAll(/^\s+\w+:\s"([^"]+)",$/gm)].map((m) => m[1]);
    expect(labels.length).toBeGreaterThan(6);
    for (const l of labels) expect(l).not.toMatch(/ClickHouse|VictoriaMetrics|Lucene/i);
  });

  it("keeps engine nouns out of the headings and the chips", () => {
    const src = readFileSync(join(here, "DataProtection.tsx"), "utf-8");
    // Section headings and the answer card's own words. The engine vocabulary
    // that remains lives in the disclosures, the wizard and the explain corpus.
    for (const heading of ["Protect", "Recover", "Storage"]) {
      expect(src).toContain(`title="${heading}"`);
    }
    for (const banned of ["snapshot repository", "restorability", "applier", "the ring"]) {
      const inHeadings = new RegExp(`title="[^"]*${banned}`, "i");
      expect(src, banned).not.toMatch(inHeadings);
    }
  });
});

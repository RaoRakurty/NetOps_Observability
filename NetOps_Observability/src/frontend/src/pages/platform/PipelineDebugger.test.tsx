// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// PipelineDebugger.test.tsx — the guarantees this screen must not lose.
//
// The list is short on purpose, and every item is something an operator would
// be misled by if it broke:
//   1. it is a platform-operator tool, and a tenant admin is told so instead of
//      being handed platform plumbing;
//   2. an api that does not carry the debugger says so once, plainly, instead
//      of rendering an empty table that reads like a dead pipeline;
//   3. the three verdicts are three DIFFERENT things on screen, and a hop this
//      screen cannot see is never drawn as a miss;
//   4. the delay between hops is measured between hops that were SEEN;
//   5. a saved run opens, its module files read, and its archive downloads
//      through the api (never a bare link, which would arrive unauthenticated);
//   6. the log-level panel states what is raised, when it returns, and refuses
//      to offer a switch that does not exist;
//   7. the text armed on the parser filter is never shown back in full.

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, cleanup, fireEvent, waitFor, within } from "@testing-library/react";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { scanCopy } from "../../copyVoice.test";
import { scanForEngineVocabulary } from "../../components/rca/vocabulary.test";

const mockApi = vi.hoisted(() => ({
  devices: vi.fn(),
  listTenants: vi.fn(),
}));
const mockDebug = vi.hoisted(() => ({
  parseMarker: vi.fn(),
  startTrace: vi.fn(),
  traceStatus: vi.fn(),
  stageEvidence: vi.fn(),
  levelStatus: vi.fn(),
  setLevel: vi.fn(),
  armParseMarker: vi.fn(),
  disarmParseMarker: vi.fn(),
  sessions: vi.fn(),
  session: vi.fn(),
  sessionModule: vi.fn(),
  downloadSessionBundle: vi.fn(),
}));
const mockUseAuth = vi.hoisted(() => vi.fn());

vi.mock("../../services/api", () => ({
  api: mockApi,
  getToken: () => "test-token",
  getActiveScope: () => "",
}));
vi.mock("../../services/api.debug", async () => {
  const actual = await vi.importActual<typeof import("../../services/api.debug")>("../../services/api.debug");
  return { ...actual, debugApi: mockDebug, default: mockDebug };
});
vi.mock("../../hooks/useAuth", () => ({ useAuth: mockUseAuth }));
vi.mock("../../components/Icon", () => ({ default: () => <span /> }));

import PipelineDebugger from "./PipelineDebugger";

const STARTED = "2026-09-05T10:00:00.000Z";

/**
 * The defaults live in beforeEach so a test can override ONE of them in its own
 * body and still get the rest — setup() only decides who is looking and renders.
 */
function setup(over: { platformAdmin?: boolean } = {}) {
  if (over.platformAdmin === false) {
    mockUseAuth.mockReturnValue({ user: { username: "tenant-admin", platform_admin: false }, loading: false });
  }
  return render(<PipelineDebugger />);
}

/** Wait until the device list has arrived, so the picker holds real devices. */
async function pickDevice(name: string) {
  await screen.findByRole("option", { name });
  fireEvent.change(screen.getByLabelText("Device"), { target: { value: name } });
}

/** A finished follow carrying one of each verdict. */
const doneStatus = {
  marker: "01j9abcdefghjkmnpqrstvwxyz",
  kind: "syslog" as const,
  device: "spine1",
  tenant: "acme",
  started: STARTED,
  deadline: "2026-09-05T10:01:00.000Z",
  done: true,
  stages: [
    { stage: "kafka", verdict: "seen" as const, t_first_seen: "2026-09-05T10:00:01.000Z", query: "peek netops.syslog", detail: { offset: 41 } },
    { stage: "opensearch", verdict: "seen" as const, t_first_seen: "2026-09-05T10:00:01.250Z", query: "search netops-syslog-*" },
    { stage: "victoria", verdict: "not_observable" as const, reason: "a syslog record produces no series", query: "export" },
    { stage: "clickhouse", verdict: "not_seen" as const, reason: "no row carries this marker", query: "select" },
    { stage: "correlation", verdict: "not_seen" as const, reason: "no evidence row", query: "select" },
    { stage: "api", verdict: "seen" as const, t_first_seen: "2026-09-05T10:00:02.000Z", query: "retained lines" },
  ],
};

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

beforeEach(() => {
  mockUseAuth.mockReturnValue({ user: { username: "root", platform_admin: true }, loading: false });
  mockApi.devices.mockResolvedValue([
    { id: "d1", name: "spine1", address: "10.0.0.1", source: "netbox", last_seen: STARTED },
    { id: "d2", name: "leaf1", address: "10.0.0.2", source: "netbox", last_seen: STARTED },
  ]);
  mockApi.listTenants.mockResolvedValue([{ id: "acme", name: "Acme", slug: "acme" }]);
  mockDebug.parseMarker.mockResolvedValue({ armed: false, reason: "off — an injected record carries its own marker" });
  mockDebug.sessions.mockResolvedValue({ root: "/data/debug", sessions: [] });
  mockDebug.levelStatus.mockResolvedValue({
    modules: [
      { module: "api", level: "info", switchable: true, source: "live" },
      { module: "correlation", switchable: true, source: "unknown" },
      { module: "vector", switchable: false, source: "unknown", reason: "not runtime-switchable: it reads its level at start" },
      { module: "router", switchable: false, source: "unknown", reason: "not runtime-switchable: it reads its level at start" },
      { module: "ingress", switchable: false, source: "unknown", reason: "its level is applied at start" },
    ],
    max_window_seconds: 1800,
    default_window_seconds: 300,
  });
  mockDebug.startTrace.mockResolvedValue({
    marker: doneStatus.marker,
    kind: "syslog",
    device: "spine1",
    tenant: "acme",
    injected: true,
    ttl_seconds: 60,
    started: STARTED,
    synthetic: true,
    status_url: "/api/debug/trace/" + doneStatus.marker,
    session_id: "20260905T1000Z-trace-" + doneStatus.marker,
  });
  mockDebug.traceStatus.mockResolvedValue(doneStatus);
});

// ── 1. the gate ─────────────────────────────────────────────────────────────

describe("who may use it", () => {
  it("tells a tenant administrator this is a platform operator tool and asks the api for nothing", async () => {
    setup({ platformAdmin: false });
    expect(await screen.findByText(/platform operator tool/i)).toBeTruthy();
    expect(mockDebug.parseMarker).not.toHaveBeenCalled();
    expect(mockDebug.sessions).not.toHaveBeenCalled();
    expect(mockApi.devices).not.toHaveBeenCalled();
  });
});

// ── 2. an api that does not carry the debugger ──────────────────────────────

describe("an older api", () => {
  it("says so once, plainly, instead of rendering an empty pipeline", async () => {
    mockDebug.parseMarker.mockRejectedValue(new Error("404 Not Found: 404 page not found"));
    setup();
    expect(await screen.findByText(/does not carry the pipeline debugger/i)).toBeTruthy();
    expect(screen.queryByLabelText(/Hops crossed/i)).toBeNull();
  });

  it("keeps the rest of the screen when only the saved runs are missing", async () => {
    mockDebug.sessions.mockRejectedValue(new Error("404 Not Found: 404 page not found"));
    setup();
    expect(await screen.findByText(/does not keep saved runs yet/i)).toBeTruthy();
    // The trace form is still there — one missing route does not blank the page.
    expect(screen.getByLabelText("Telemetry")).toBeTruthy();
  });
});

// ── 3 + 4. the run and its table ────────────────────────────────────────────

describe("following one record", () => {
  it("sends the run the operator described, then draws every hop with its own verdict", async () => {
    setup();
    await pickDevice("spine1");
    fireEvent.change(screen.getByLabelText("Tenant"), { target: { value: "acme" } });
    fireEvent.change(screen.getByLabelText("Wait (seconds)"), { target: { value: "45" } });
    fireEvent.click(screen.getByRole("button", { name: /send one record and follow it/i }));

    await waitFor(() => expect(mockDebug.startTrace).toHaveBeenCalled());
    expect(mockDebug.startTrace.mock.calls[0][0]).toMatchObject({
      kind: "syslog",
      device: "spine1",
      tenant: "acme",
      ttl_seconds: 45,
      passive: false,
      // The screen has no host-side collector, so the api must keep the run.
      persist: true,
    });

    const table = await screen.findByLabelText("Hops crossed");
    // Every hop of the pipeline is a row — including the ones this screen
    // cannot see, which must not simply be missing.
    expect(within(table).getAllByRole("row").length).toBe(11); // 10 hops + the header

    const row = (stage: string) => table.querySelector(`tr[data-stage="${stage}"]`) as HTMLElement;
    // The first hop's verdict arrives with the first status read.
    await waitFor(() => expect(within(row("kafka")).getByText("Seen")).toBeTruthy());
    expect(within(row("clickhouse")).getByText("Not seen")).toBeTruthy();
    expect(within(row("victoria")).getByText("Not observable")).toBeTruthy();
    // A hop collected on the host is NOT a miss.
    expect(within(row("ingress")).getByText("Not observable")).toBeTruthy();
    expect(within(row("ingress")).getByText(/correlix-debug trace/i)).toBeTruthy();
    // The delay is measured between hops that were seen.
    expect(within(row("opensearch")).getByText("250 ms")).toBeTruthy();
    // …and is absent, not zero, where there is no earlier seen hop.
    expect(within(row("kafka")).getByText("—")).toBeTruthy();
  });

  it("opens a hop onto the evidence the api holds for it", async () => {
    mockDebug.stageEvidence.mockResolvedValue({
      stage: "kafka",
      verdict: "seen",
      query: "peek netops.syslog for the marker",
      detail: { topic: "netops.syslog", offset: 41 },
    });
    setup();
    await pickDevice("spine1");
    fireEvent.click(screen.getByRole("button", { name: /send one record and follow it/i }));
    const table = await screen.findByLabelText("Hops crossed");
    const row = table.querySelector('tr[data-stage="kafka"]') as HTMLElement;
    fireEvent.click(within(row).getByRole("button", { name: /read this hop/i }));

    await waitFor(() => expect(mockDebug.stageEvidence).toHaveBeenCalledWith("kafka", expect.objectContaining({ marker: doneStatus.marker })));
    expect(await within(row).findByText(/peek netops.syslog for the marker/)).toBeTruthy();
  });

  it("never sends anything for gNMI and says why", async () => {
    setup();
    await pickDevice("spine1");
    fireEvent.change(screen.getByLabelText("Telemetry"), { target: { value: "gnmi" } });
    expect(screen.getByText(/starts on the device, so nothing is sent/i)).toBeTruthy();
    expect(screen.getByLabelText("Look back (minutes)")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: /follow real traffic/i }));
    await waitFor(() => expect(mockDebug.startTrace).toHaveBeenCalled());
    expect(mockDebug.startTrace.mock.calls[0][0]).toMatchObject({ kind: "gnmi", passive: true, since_seconds: 600 });
  });

  it("shows the same run as a command line", async () => {
    setup();
    await pickDevice("leaf1");
    expect(screen.getByText(/correlix-debug trace --kind syslog --device leaf1/)).toBeTruthy();
  });
});

// ── 5. saved runs ───────────────────────────────────────────────────────────

describe("saved runs", () => {
  const summary = {
    id: "20260905T1000Z-trace-01j9abcdefghjkmnpqrstvwxyz",
    verb: "trace",
    marker: doneStatus.marker,
    kind: "syslog" as const,
    device: "spine1",
    tenant: "acme",
    started: STARTED,
    seen: 3,
    not_seen: 2,
    not_observable: 5,
    reached_api: true,
    bytes: 4096,
  };

  it("lists them, opens one, and reads a module file as text", async () => {
    mockDebug.sessions.mockResolvedValue({ root: "/data/debug", sessions: [summary] });
    mockDebug.session.mockResolvedValue({
      session: summary,
      modules: [{ module: "kafka", file: "kafka.log", bytes: 512 }],
      timeline: { marker: doneStatus.marker, kind: "syslog", started: STARTED, entries: doneStatus.stages },
      summary_text: "CORRELIX PIPELINE DEBUG — TRACE SUMMARY",
    });
    mockDebug.sessionModule.mockResolvedValue({
      session: summary.id,
      module: "kafka",
      file: "kafka.log",
      bytes: 512,
      lines: ['{"module":"kafka","msg":"marker seen at offset 41"}'],
    });
    setup();
    fireEvent.click(await screen.findByRole("button", { name: /^Open$/ }));
    const table = await screen.findByLabelText("Saved-run hops");
    const row = table.querySelector('tr[data-stage="kafka"]') as HTMLElement;
    fireEvent.click(within(row).getByRole("button", { name: /read this hop/i }));
    await waitFor(() => expect(mockDebug.sessionModule).toHaveBeenCalledWith(summary.id, "kafka"));
    expect(await within(row).findByText(/marker seen at offset 41/)).toBeTruthy();
  });

  it("downloads the archive through the api and states what arrived", async () => {
    mockDebug.sessions.mockResolvedValue({ root: "/data/debug", sessions: [summary] });
    mockDebug.downloadSessionBundle.mockResolvedValue({
      filename: `correlix-debug-${summary.id}.tar.gz`,
      sha256: "abcdef0123456789abcdef",
      bytes: 2048,
    });
    setup();
    fireEvent.click(await screen.findByRole("button", { name: /^Download$/ }));
    await waitFor(() => expect(mockDebug.downloadSessionBundle).toHaveBeenCalledWith(summary.id));
    expect(await screen.findByText(/SHA-256 abcdef0123456789/)).toBeTruthy();
  });

  it("states who wrote the run, with what, and what was redacted out of it", async () => {
    mockDebug.sessions.mockResolvedValue({ root: "/data/debug", sessions: [summary] });
    mockDebug.session.mockResolvedValue({
      session: summary,
      modules: [{ module: "kafka", file: "kafka.log", bytes: 512 }],
      manifest: {
        verb: "trace",
        started: STARTED,
        finished: "2026-09-05T10:00:31.000Z",
        actor: "platform-owner",
        tool: "correlix-debug 1.4.0",
        api_base: "http://api:8080",
        redaction: "secrets, communities and keys removed",
        flags: { kind: "syslog", ttl: "30s" },
        warnings: ["the routing lane was not watched: no live subscription"],
      },
    });
    setup();
    fireEvent.click(await screen.findByRole("button", { name: /^Open$/ }));
    expect(await screen.findByText("platform-owner")).toBeTruthy();
    expect(screen.getByText("correlix-debug 1.4.0")).toBeTruthy();
    expect(screen.getByText(/secrets, communities and keys removed/)).toBeTruthy();
    expect(screen.getByText("kind=syslog ttl=30s")).toBeTruthy();
    // A warning is stated, not folded into the tally.
    expect(screen.getByText(/no live subscription/)).toBeTruthy();
  });

  it("a run whose manifest could not be read says so, never renders as clean", async () => {
    const partial = { ...summary, incomplete: "manifest.json could not be read: unexpected EOF" };
    mockDebug.sessions.mockResolvedValue({ root: "/data/debug", sessions: [partial] });
    mockDebug.session.mockResolvedValue({
      session: partial,
      modules: [],
      reason: "manifest.json could not be read: unexpected EOF",
    });
    setup();
    fireEvent.click(await screen.findByRole("button", { name: /^Open$/ }));
    // Once as the provenance value, once as the warning — never absent.
    expect((await screen.findAllByText(/manifest.json could not be read/)).length).toBeGreaterThan(0);
  });

  it("says nothing has been saved rather than showing an empty list", async () => {
    mockDebug.sessions.mockResolvedValue({ root: "/data/debug", sessions: [], reason: "no run has been saved yet" });
    setup();
    expect(await screen.findByText(/Nothing has been saved here yet/i)).toBeTruthy();
    expect(screen.getByText(/no run has been saved yet/i)).toBeTruthy();
  });
});

// ── 6. log levels ───────────────────────────────────────────────────────────

describe("log detail", () => {
  it("raises the chosen modules for a bounded window and reports a refusal honestly", async () => {
    mockDebug.setLevel.mockResolvedValue({ module: "api", applied: true, level: "debug", revert_at: "2026-09-05T10:05:00Z" });
    setup();
    const window = await screen.findByLabelText("Detail window (minutes)");
    fireEvent.change(window, { target: { value: "99" } });
    // The form cannot ask past the cap the api enforces.
    expect((window as HTMLInputElement).value).toBe("30");
    fireEvent.click(screen.getByRole("button", { name: /raise to full detail/i }));
    await waitFor(() => expect(mockDebug.setLevel).toHaveBeenCalledWith({ module: "api", level: "debug", for_seconds: 1800 }));
    expect(await screen.findByText(/returns to its shipped level/i)).toBeTruthy();
  });

  it("does not offer a switch that does not exist, and says why", async () => {
    setup();
    const vector = await screen.findByLabelText("Include vector");
    expect((vector as HTMLInputElement).disabled).toBe(true);
    expect(screen.getAllByText(/not runtime-switchable/i).length).toBeGreaterThan(0);
  });

  it("says when a raised module returns to normal", async () => {
    mockDebug.levelStatus.mockResolvedValue({
      modules: [
        {
          module: "api",
          level: "debug",
          revert_at: new Date(Date.now() + 240_000).toISOString(),
          switchable: true,
          source: "live",
        },
      ],
      max_window_seconds: 1800,
      default_window_seconds: 300,
    });
    setup();
    expect(await screen.findByText(/Returns to normal in 2[34]\ds/)).toBeTruthy();
  });
});

// ── 7. the parser filter ────────────────────────────────────────────────────

describe("the parser decision trail", () => {
  it("never shows the armed text back in full", async () => {
    const secret = "customer-hostname-fragment-1234";
    mockDebug.parseMarker.mockResolvedValue({ armed: true, marker: secret, until: "2026-09-05T10:05:00Z" });
    setup();
    expect(await screen.findByText(/Armed on cust…/)).toBeTruthy();
    expect(screen.queryByText(new RegExp(secret))).toBeNull();
    expect(screen.getByText(/31 characters/)).toBeTruthy();
  });

  it("arms and turns off through the api", async () => {
    mockDebug.armParseMarker.mockResolvedValue({ armed: true, marker: "abc", until: "2026-09-05T10:05:00Z" });
    mockDebug.disarmParseMarker.mockResolvedValue({ armed: false });
    setup();
    fireEvent.change(await screen.findByLabelText("Text to match"), { target: { value: "bgp neighbor" } });
    fireEvent.click(screen.getByRole("button", { name: /^Arm$/ }));
    await waitFor(() => expect(mockDebug.armParseMarker).toHaveBeenCalledWith({ marker: "bgp neighbor", for_seconds: 300 }));
    fireEvent.click(screen.getByRole("button", { name: /turn off/i }));
    await waitFor(() => expect(mockDebug.disarmParseMarker).toHaveBeenCalled());
  });
});

// ── the shared copy guards, on this page's own sources ──────────────────────

describe("copy guards on this page's own sources", () => {
  const here = dirname(fileURLToPath(import.meta.url));
  const files = ["PipelineDebugger.tsx", "pipelineDebugger.model.ts"];

  it("shows no denied developer-speak", () => {
    const hits = files.flatMap((f) => scanCopy(readFileSync(join(here, f), "utf-8"), `pages/platform/${f}`));
    expect(hits, hits.join("\n")).toEqual([]);
  });

  it("never puts the engine word on screen", () => {
    const hits = files.flatMap((f) => scanForEngineVocabulary(readFileSync(join(here, f), "utf-8"), `pages/platform/${f}`));
    expect(hits, hits.join("\n")).toEqual([]);
  });

  it("holds the api client to the same copy rules", () => {
    const client = readFileSync(join(here, "../../services/api.debug.ts"), "utf-8");
    const hits = scanCopy(client, "services/api.debug.ts");
    expect(hits, hits.join("\n")).toEqual([]);
  });
});

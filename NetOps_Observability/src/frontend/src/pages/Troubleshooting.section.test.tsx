// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Troubleshooting.section.test.tsx — the page has ONE FACE.
//
// Owner, 2026-09-07 (verbatim): "Whenever I refresh troubleshooting page there
// is a stale page which shows correlation heartbeat touch path, vector sink,
// vector opensearch, shared filesystem in investigation panel. It looks like
// stale page." The cause was a second section — the June collection-pipeline
// board — that a bookmarked `?section=pipeline` reopened on every refresh.
//
// What is pinned here:
//  · there is NO section switch and no second surface: the page renders the
//    investigation and nothing else, and the legacy board's collector counts
//    are gone from it (they live on Platform → Stack Health now);
//  · every retired deep link — `?section=pipeline` (the board) and
//    `?section=protocol` (the manual bench retired on 2026-09-05,
//    docs/design/TAC_ESCALATION_2026-09-05.md §5) — lands on the investigation;
//  · the parameter is STRIPPED from the address on load, so the refresh the
//    owner reported cannot bring anything back;
//  · `?case=` still opens the investigation on that case, and the retired
//    `?symptom=` parameter lands on the picker rather than on a blank.
//
// Everything below is the real component tree — the investigation page, its
// lanes, IRIS, the escalation panel — against a mocked api, so "the page mounts
// a stub" cannot pass here.

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, cleanup, fireEvent, act, waitFor } from "@testing-library/react";
import { corrObject, signal, timeline } from "../test/factories";

// Every api function the page tree reaches: the investigation page, its seven
// lanes, IRIS and the TAC escalation panel.
const mocks = vi.hoisted(() => ({
  flowsByType: vi.fn(), searchLogs: vi.fn(), devices: vi.fn(), permissions: vi.fn(),
  tacState: vi.fn(), tacClassify: vi.fn(),
  correlations: vi.fn(), listIncidents: vi.fn(), createIncident: vi.fn(),
  seams: vi.fn(), getSeamOwners: vi.fn(),
  correlationDetail: vi.fn(), correlationTimeline: vi.fn(),
  correlationTickets: vi.fn(), correlationTicketCreate: vi.fn(), downloadRcaReport: vi.fn(),
  pathsHealth: vi.fn(), eventsFeed: vi.fn(), metricNames: vi.fn(), metricsQuery: vi.fn(),
  probePaths: vi.fn(), topTalkers: vi.fn(), aiAsk: vi.fn(),
}));
const errs = vi.hoisted(() => {
  class FakeNotPromoted extends Error {
    constructor(public reason: string) { super(reason); this.name = "RcaNotPromotedError"; }
  }
  return { FakeNotPromoted };
});
vi.mock("../services/api", () => ({ api: { ...mocks }, RcaNotPromotedError: errs.FakeNotPromoted }));

import Troubleshooting, { sectionFromHash } from "./Troubleshooting";

const CASE_ID = "corr-abc1234567890";
const openCase = () => corrObject({
  correlation_id: CASE_ID,
  top_hypothesis: "upstream_link_fault",
  hypotheses: JSON.stringify({ ranking: { hypotheses: [{ id: "upstream_link_fault", verdict: { owner: "isp", first_steps: [] } }] } }),
  affected: JSON.stringify({ devices: ["wan-r2"] }),
});

/** Render, letting the page's async loaders settle inside act(). */
async function show(hash: string) {
  location.hash = hash;
  const utils = render(<Troubleshooting rangeMinutes={60} />);
  await act(async () => { await Promise.resolve(); });
  return utils;
}

beforeEach(() => {
  Object.values(mocks).forEach((m) => m.mockReset());
  mocks.flowsByType.mockResolvedValue({ data: [] });
  mocks.searchLogs.mockResolvedValue({ hits: { total: { value: 0 } } });
  mocks.devices.mockResolvedValue([]);
  mocks.permissions.mockResolvedValue({ role: "operator", permissions: { infrastructure: 2 } });
  mocks.tacState.mockResolvedValue({
    incident_id: CASE_ID, incident_ref: "INC-2026-0007", title: "",
    can_collect: false, collect_note: "Live collection is not wired on this deployment.",
    catalog_version: "correlix-tac-classes-2026-09-05", connectors: [], devices: ["wan-r2"],
    state: null, state_note: "This incident has not been escalated in this api process.",
  });
  mocks.correlations.mockResolvedValue({ data: [openCase()] });
  mocks.listIncidents.mockResolvedValue([]);
  mocks.seams.mockResolvedValue([]);
  mocks.getSeamOwners.mockResolvedValue({ seam_owners: {} });
  mocks.correlationDetail.mockResolvedValue({ object: openCase(), edges: [] });
  mocks.correlationTimeline.mockResolvedValue(timeline({
    correlation_id: CASE_ID,
    signals: [signal({ kind: "bgp_state_anomaly", entity_id: "wan-r2" })],
  }));
  mocks.correlationTickets.mockResolvedValue({ status: { state: "none" }, audit: [] });
  mocks.pathsHealth.mockResolvedValue({ paths: [], count: 0 });
  mocks.eventsFeed.mockResolvedValue({ items: [] });
  mocks.metricNames.mockResolvedValue({ status: "success", data: [] });
  mocks.metricsQuery.mockResolvedValue({ status: "success", data: { resultType: "vector", result: [] } });
  mocks.probePaths.mockResolvedValue([]);
  mocks.topTalkers.mockResolvedValue({ data: [] });
  mocks.aiAsk.mockResolvedValue({ mode: "grounded", intent: "x", modules: [], text: "", citations: [], disclaimers: [] });
  location.hash = "#/investigate/troubleshooting";
});
afterEach(() => cleanup());

// ── the deep-link parser ─────────────────────────────────────────────────────

describe("sectionFromHash", () => {
  it.each([
    "#/investigate/troubleshooting",
    "#/investigate/troubleshooting?section=investigate",
    "#/investigate/troubleshooting?section=protocol",
    "#/investigate/troubleshooting?section=pipeline",
    "#/investigate/troubleshooting?section=nonsense",
    "#/investigate/troubleshooting?symptom=dns",
    "#/investigate/troubleshooting?case=corr-1",
    "",
  ] as const)("%p → the investigation", (hash) => {
    expect(sectionFromHash(hash)).toBe("investigate");
  });

  it("reads the live location hash when given none", () => {
    location.hash = "#/investigate/troubleshooting?section=pipeline";
    expect(sectionFromHash()).toBe("investigate");
  });
});

// ── one face ─────────────────────────────────────────────────────────────────

describe("the page has one face", () => {
  it("renders the investigation, with no section switch", async () => {
    await show("#/investigate/troubleshooting");
    expect(screen.getByRole("heading", { name: /What's wrong\?/, level: 2 })).toBeInTheDocument();
    expect(screen.queryByRole("group", { name: "Troubleshooting section" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Collection pipeline" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Investigation" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Protocol diagnostics" })).toBeNull();
  });

  // The board is DELETED, not hidden: nothing it rendered is reachable here,
  // and the legacy-board (i) went with it.
  it("carries nothing from the retired collection-pipeline board", async () => {
    await show("#/investigate/troubleshooting?section=pipeline");
    expect(screen.queryByText("Monitored devices")).toBeNull();
    expect(screen.queryByText(/Legacy board/)).toBeNull();
    expect(screen.queryByRole("button", { name: "Ask Iris about Collection pipeline board" })).toBeNull();
    expect(screen.queryByLabelText("Fleet counts")).toBeNull();
    expect(screen.queryByLabelText("Collectors")).toBeNull();
  });

  it("mounts the REAL investigation surface, not a stub", async () => {
    await show("#/investigate/troubleshooting");
    expect(screen.getByRole("heading", { name: /What's wrong\?/, level: 2 })).toBeInTheDocument();
    await waitFor(() => expect(mocks.correlations).toHaveBeenCalled());
  });
});

// ── deep links, and the address the refresh will read ────────────────────────

describe("retired deep links", () => {
  it.each([
    "#/investigate/troubleshooting?section=pipeline",
    "#/investigate/troubleshooting?section=protocol",
    "#/investigate/troubleshooting?section=nonsense",
  ] as const)("%p lands on the investigation", async (hash) => {
    await show(hash);
    expect(screen.getByRole("heading", { name: /What's wrong\?/, level: 2 })).toBeInTheDocument();
  });

  // THE OWNER'S BUG. Landing on the investigation is not enough while the
  // parameter survives in the address: the next refresh reads it again.
  it("strips the retired parameter from the address on load", async () => {
    await show("#/investigate/troubleshooting?section=pipeline");
    expect(location.hash).toBe("#/investigate/troubleshooting");
  });

  it("keeps the case while stripping the section", async () => {
    await show(`#/investigate/troubleshooting?section=pipeline&case=${CASE_ID}`);
    expect(location.hash).toBe(`#/investigate/troubleshooting?case=${CASE_ID}`);
    await waitFor(() => expect(mocks.correlationDetail).toHaveBeenCalledWith(CASE_ID));
  });

  it("leaves a clean address alone", async () => {
    await show("#/investigate/troubleshooting?case=corr-1");
    expect(location.hash).toBe("#/investigate/troubleshooting?case=corr-1");
  });

  // `?symptom=` was the old describe-only mode. It is gone: a described problem
  // is a real record now, so an old symptom link simply opens the picker.
  it("lands a retired symptom link on the picker, not on a blank", async () => {
    await show("#/investigate/troubleshooting?symptom=bgp_upstream");
    expect(screen.getByRole("heading", { name: /What's wrong\?/, level: 2 })).toBeInTheDocument();
    expect(screen.queryByTestId("ts-answer-block")).toBeNull();
  });

  it("opens the investigation on the linked correlation case", async () => {
    await show(`#/investigate/troubleshooting?case=${CASE_ID}`);
    await waitFor(() => expect(mocks.correlationDetail).toHaveBeenCalledWith(CASE_ID));
    // the plain answer leads; the engine's RCA header is inside the ONE
    // evidence disclosure, which is closed until it is asked for
    expect(screen.getByTestId("ts-answer")).toBeInTheDocument();
    expect(document.getElementById("ts-ev-body")).toHaveAttribute("hidden");
    await act(async () => { fireEvent.click(screen.getByRole("button", { name: "Show the evidence" })); });
    expect(document.getElementById("ts-ev-body")).not.toHaveAttribute("hidden");
    expect(await screen.findByTestId("ts-rca-header")).toBeInTheDocument();
  });

  it("ignores a case token that is not an opaque id", async () => {
    await show("#/investigate/troubleshooting?case=%3Cscript%3E");
    expect(mocks.correlationDetail).not.toHaveBeenCalled();
    expect(screen.queryByTestId("ts-answer-block")).toBeNull();
  });
});

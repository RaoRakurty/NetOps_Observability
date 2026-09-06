// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Troubleshooting.section.test.tsx — the TWO-section Troubleshooting page.
//
// What is pinned here:
//  · the section switch is a toggle-button group (aria-pressed) and defaults to
//    INVESTIGATION — the symptom-first operator surface is the page's reason to
//    exist (Project 4 §A); the June collection-pipeline board is now the legacy
//    second section, reachable for one release
//  · the RETIRED "Protocol diagnostics" section is gone: no button offers it and
//    an old deep link to it lands on the investigation surface, not on a blank
//    page (docs/design/TAC_ESCALATION_2026-09-05.md §5 — the manual bench is
//    replaced by the escalation flow, and its knowledge moved to Iris)
//  · each surviving section is reachable as a deep link
//    (#/investigate/troubleshooting?section=…), and an unrecognized link falls
//    back to the investigation surface rather than a blank page
//  · a case deep link lands the investigation on that case, and the retired
//    `?symptom=` parameter lands on the picker rather than on a blank
//  · picking a section mounts the REAL component (route registration, not a
//    stub): the investigation surface and the legacy board
//
// The metric board's chart primitives are stubbed: they are charted elsewhere
// and their ECharts dependency has nothing to do with the registration this
// file asserts. Everything below the switch — the investigation page, its
// lanes, IRIS, the escalation panel — is the real component against a mocked
// api, so "the switch mounts a stub" cannot pass here.

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, cleanup, fireEvent, act, waitFor, within } from "@testing-library/react";
import { corrObject, signal, timeline } from "../test/factories";

vi.mock("../components/board/panels", () => ({
  Group: ({ title, children }: { title: string; children?: unknown }) => (
    <section aria-label={title}>{children as never}</section>
  ),
  Panel: ({ title, children }: { title: string; children?: unknown }) => (
    <section aria-label={title}>{children as never}</section>
  ),
  MetricLine: ({ title }: { title: string }) => <div>{title}</div>,
  MetricTop: ({ title }: { title: string }) => <div>{title}</div>,
  MetricStat: ({ label }: { label: string }) => <div>{label}</div>,
  fmtNum: (n: number) => String(n),
}));
vi.mock("../components/ui", () => ({
  StatStrip: ({ children }: { children?: unknown }) => <div>{children as never}</div>,
  Stat: ({ label }: { label: string }) => <div>{label}</div>,
  StatTone: undefined,
}));

// Every api function the page tree reaches: the legacy board, the investigation
// page, its seven lanes, IRIS and the TAC escalation panel.
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

/** Render, letting every section's async loader settle inside act(). */
async function show(hash: string) {
  location.hash = hash;
  const utils = render(<Troubleshooting rangeMinutes={60} />);
  await act(async () => { await Promise.resolve(); });
  return utils;
}

const pressed = () =>
  screen.getByRole("group", { name: "Troubleshooting section" })
    .querySelector('button[aria-pressed="true"]')?.textContent;

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
    ["#/investigate/troubleshooting", "investigate"],
    ["#/investigate/troubleshooting?section=investigate", "investigate"],
    ["#/investigate/troubleshooting?section=protocol", "investigate"],
    ["#/investigate/troubleshooting?section=pipeline", "pipeline"],
    ["#/investigate/troubleshooting?section=nonsense", "investigate"],
    ["#/investigate/troubleshooting?symptom=dns", "investigate"],   // retired param

    ["#/investigate/troubleshooting?case=corr-1", "investigate"],
    ["", "investigate"],
  ] as const)("%p → %s", (hash, section) => {
    expect(sectionFromHash(hash)).toBe(section);
  });

  it("reads the live location hash when given none", () => {
    location.hash = "#/investigate/troubleshooting?section=pipeline";
    expect(sectionFromHash()).toBe("pipeline");
  });
});

// ── the switch ───────────────────────────────────────────────────────────────

describe("the section switch", () => {
  it("defaults to the INVESTIGATION surface", async () => {
    await show("#/investigate/troubleshooting");
    expect(pressed()).toBe("Investigation");
    expect(screen.getByRole("heading", { name: /What's wrong\?/, level: 2 })).toBeInTheDocument();
    expect(screen.queryByText("Monitored devices")).toBeNull();
    expect(screen.queryByRole("group", { name: "Protocol" })).toBeNull();
  });

  it("offers exactly the two surviving sections as toggle buttons", async () => {
    await show("#/investigate/troubleshooting");
    const group = screen.getByRole("group", { name: "Troubleshooting section" });
    expect(within(group).getAllByRole("button").map((b) => b.textContent))
      .toEqual(["Investigation", "Collection pipeline"]);
    expect(group.querySelectorAll('button[aria-pressed="true"]')).toHaveLength(1);
  });

  // The manual bench is gone, not hidden: nothing offers it and nothing mounts
  // it. Its knowledge lives on Iris → Knowledge, its work on the escalation.
  it("no longer offers the retired protocol-diagnostics bench", async () => {
    await show("#/investigate/troubleshooting");
    expect(screen.queryByRole("button", { name: "Protocol diagnostics" })).toBeNull();
    expect(screen.queryByLabelText("Protocol diagnostics")).toBeNull();
    expect(screen.queryByRole("group", { name: "Protocol" })).toBeNull();
  });

  it("mounts the legacy collection-pipeline board when picked, and labels it legacy", async () => {
    await show("#/investigate/troubleshooting");
    await act(async () => { fireEvent.click(screen.getByRole("button", { name: "Collection pipeline" })); });
    expect(screen.getByText("Monitored devices")).toBeInTheDocument();
    // The board still says what it is (sweep 5, tracker 270) — only the words
    // that TAUGHT why it exists moved behind the (i).
    expect(screen.getByText(/Legacy board/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Ask Iris about Collection pipeline board" })).toBeInTheDocument();
    expect(screen.queryByText(/answers one question/i)).toBeNull();
    expect(screen.queryByRole("heading", { name: /What's wrong\?/ })).toBeNull();
  });

  it("switches back to the investigation surface", async () => {
    await show("#/investigate/troubleshooting?section=pipeline");
    await act(async () => { fireEvent.click(screen.getByRole("button", { name: "Investigation" })); });
    expect(pressed()).toBe("Investigation");
    expect(screen.getByRole("heading", { name: /What's wrong\?/, level: 2 })).toBeInTheDocument();
  });

  it("shows only ONE section at a time — never stacked", async () => {
    await show("#/investigate/troubleshooting?section=pipeline");
    expect(screen.getByText("Monitored devices")).toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: /What's wrong\?/ })).toBeNull();
  });
});

// ── deep links ───────────────────────────────────────────────────────────────

describe("deep links", () => {
  it("lands a retired protocol-diagnostics link on the investigation surface", async () => {
    await show("#/investigate/troubleshooting?section=protocol");
    expect(pressed()).toBe("Investigation");
    expect(screen.getByRole("heading", { name: /What's wrong\?/, level: 2 })).toBeInTheDocument();
  });

  it("opens on the legacy pipeline board", async () => {
    await show("#/investigate/troubleshooting?section=pipeline");
    expect(pressed()).toBe("Collection pipeline");
    expect(screen.getByText("Monitored devices")).toBeInTheDocument();
  });

  // `?symptom=` was the old describe-only mode. It is gone: a described problem
  // is a real record now, so an old symptom link simply opens the picker.
  it("lands a retired symptom link on the picker, not on a blank", async () => {
    await show("#/investigate/troubleshooting?section=investigate&symptom=bgp_upstream");
    expect(pressed()).toBe("Investigation");
    expect(screen.getByRole("heading", { name: /What's wrong\?/, level: 2 })).toBeInTheDocument();
    expect(screen.queryByTestId("ts-answer-block")).toBeNull();
  });

  it("opens the investigation on the linked correlation case", async () => {
    await show(`#/investigate/troubleshooting?case=${CASE_ID}`);
    expect(pressed()).toBe("Investigation");
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

  it("falls back to the investigation surface on an unrecognized section", async () => {
    await show("#/investigate/troubleshooting?section=nonsense");
    expect(pressed()).toBe("Investigation");
    expect(screen.getByRole("heading", { name: /What's wrong\?/, level: 2 })).toBeInTheDocument();
  });
});

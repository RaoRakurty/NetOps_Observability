// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Administration → RCA Tickets: one numbered flow — destinations → rules →
// vendor case routing (optional) → deliveries. The steps are the pages they
// were; this tests the flow: what counts as done, what stays visible while
// locked, and that the page itself writes nothing.
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, cleanup, waitFor } from "@testing-library/react";
import type { ItsmConfig, IncidentPolicy, TacConnectorInfo } from "../../services/api";

const apiMock = vi.hoisted(() => ({
  itsmConfig: vi.fn(),
  tacConnectors: vi.fn(),
  ticketsOutbox: vi.fn(),
  incidentPolicies: vi.fn(),
}));
vi.mock("../../services/api", () => ({ api: apiMock }));
vi.mock("../../components/AskIris", () => ({ default: () => null }));
// The steps' own pages are covered by their own tests; here, markers.
vi.mock("../../tabs/admin", () => ({ IncidentPoliciesAdmin: () => <div data-testid="rules-body" /> }));
vi.mock("./TicketDelivery", () => ({ default: ({ part }: { part: string }) => <div data-testid={`delivery-${part}`} /> }));

import RcaTickets, { destinationsOf, policyConflict, usableConnector } from "./RcaTickets";

const cfg = (o: Partial<ItsmConfig> = {}): ItsmConfig =>
  ({
    servicenow: { enabled: false, configured: false, instance_url: "", user: "" },
    jira: { enabled: false, configured: false, base_url: "", email: "" },
    ...o,
  }) as unknown as ItsmConfig;
const pol = (o: Partial<IncidentPolicy>): IncidentPolicy => ({ id: "p", name: "p", enabled: true, ...o }) as IncidentPolicy;
const conn = (o: Partial<TacConnectorInfo>): TacConnectorInfo => ({ id: "c", display: "Cisco", configured: false, ...o }) as TacConnectorInfo;

beforeEach(() => {
  for (const f of Object.values(apiMock)) f.mockReset();
  apiMock.itsmConfig.mockResolvedValue(cfg());
  apiMock.tacConnectors.mockResolvedValue({ connectors: [] });
  apiMock.ticketsOutbox.mockResolvedValue({ outbox: [], total: 0 });
  apiMock.incidentPolicies.mockResolvedValue({ policies: [], ticketing_running: true });
});
afterEach(() => cleanup());

const stepOf = (id: string) => document.querySelector(`[data-step="${id}"]`) as HTMLElement;

describe("RCA Tickets flow", () => {
  it("a fresh tenant sees step 1 only; the rest name what to finish first", async () => {
    render(<RcaTickets />);
    await waitFor(() => expect(apiMock.incidentPolicies).toHaveBeenCalled());
    expect(await screen.findByText("Set up in Integrations")).toBeTruthy();
    expect(screen.queryByTestId("rules-body")).toBeNull();
    expect(screen.queryByTestId("delivery-deliveries")).toBeNull();
    expect(stepOf("rules").textContent).toMatch(/Finish step 1 first/);
    // Vendor case routing serves TAC escalation without auto-ticketing: never locked.
    expect(screen.getByTestId("delivery-cases")).toBeTruthy();
  });

  it("a connected destination opens the rules; ticketing running with no conflict opens case routing and deliveries", async () => {
    apiMock.itsmConfig.mockResolvedValue(cfg({ pagerduty: { enabled: true, has_routing_key: true } }));
    render(<RcaTickets />);
    expect(await screen.findByTestId("rules-body")).toBeTruthy();
    expect(await screen.findByTestId("delivery-cases")).toBeTruthy();
    expect(screen.getByTestId("delivery-deliveries")).toBeTruthy();
    expect(screen.getByTestId("dest-pagerduty").textContent).toMatch(/Connected/);
  });

  it("existing rules stay visible while step 1 is unmet (their step has data)", async () => {
    apiMock.incidentPolicies.mockResolvedValue({ policies: [pol({})], ticketing_running: true });
    render(<RcaTickets />);
    expect(await screen.findByTestId("rules-body")).toBeTruthy();
  });

  it("a failing outbox is never hidden behind the earlier steps", async () => {
    apiMock.ticketsOutbox.mockResolvedValue({ outbox: [{ id: "x" }], total: 3 });
    render(<RcaTickets />);
    expect(await screen.findByTestId("delivery-deliveries")).toBeTruthy();
    expect(stepOf("deliveries").textContent).toMatch(/3 in the outbox/);
  });

  it("says ticketing is off, and keeps the later steps locked, when the worker does not run", async () => {
    apiMock.itsmConfig.mockResolvedValue(cfg({ slack: { enabled: true, has_webhook: true } }));
    apiMock.incidentPolicies.mockResolvedValue({ policies: [pol({})], ticketing_running: false });
    render(<RcaTickets />);
    await waitFor(() => expect(stepOf("rules").textContent).toMatch(/Ticketing is off/));
    expect(screen.queryByTestId("delivery-deliveries")).toBeNull();
    expect(screen.getByTestId("delivery-cases")).toBeTruthy();
  });

  it("two enabled policies for one system hold ticketing — the flow says so", async () => {
    apiMock.itsmConfig.mockResolvedValue(cfg({ slack: { enabled: true, has_webhook: true } }));
    apiMock.incidentPolicies.mockResolvedValue({ policies: [pol({ id: "a" }), pol({ id: "b" })], ticketing_running: true });
    render(<RcaTickets />);
    await waitFor(() => expect(stepOf("rules").textContent).toMatch(/Held/));
  });

  it("helpers", () => {
    const d = destinationsOf(cfg({ pagerduty: { enabled: true, has_routing_key: false }, slack: { enabled: false, has_webhook: true } }));
    expect(d.map((x) => [x.id, x.on])).toEqual([["servicenow", false], ["jira", false], ["pagerduty", false], ["slack", false]]);
    expect(policyConflict([pol({ id: "a" }), pol({ id: "b", external_system: "jira" })])).toBe(false);
    expect(policyConflict([pol({ id: "a" }), pol({ id: "b" })])).toBe(true);
    expect(policyConflict([pol({ id: "a" }), pol({ id: "b", enabled: false })])).toBe(false);
    expect(usableConnector(conn({ configured: true }))).toBe(true);
    expect(usableConnector(conn({ configured: false }))).toBe(false);
    expect(usableConnector(conn({ portal_only: true, configured: true }))).toBe(true);
    expect(usableConnector(conn({ configured: true, unavailable: true }))).toBe(false);
  });
});

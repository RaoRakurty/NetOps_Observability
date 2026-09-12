// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// CloudLogs.test.tsx — the unified Cloud Logs view: a lane per cloud log family,
// each wired to a real tenant-scoped source (Inventory + Change to the cloud
// surfaces, the raw families to the tagged /api/logs/search?signal=cloud index).
// Honesty-first: an empty lane reads "No log entries in this window", never fabricated rows.

import { describe, it, expect, vi, afterEach, beforeEach } from "vitest";
import { render, screen, cleanup, fireEvent, within, waitFor } from "@testing-library/react";

const searchLogs = vi.fn();
const cloudResources = vi.fn();
const cloudChanges = vi.fn();

vi.mock("../services/api", () => ({
  api: {
    searchLogs: (...a: unknown[]) => searchLogs(...a),
    cloudResources: (...a: unknown[]) => cloudResources(...a),
    cloudChanges: (...a: unknown[]) => cloudChanges(...a),
  },
}));

import CloudLogs from "./CloudLogs";

afterEach(cleanup);

beforeEach(() => {
  searchLogs.mockReset();
  cloudResources.mockReset();
  cloudChanges.mockReset();
  cloudResources.mockResolvedValue({
    resources: [{
      tenant_id: "acme", cloud_provider: "aws", account_id: "123456789012", region: "us-east-1",
      resource_id: "app/billing-alb/0a1b", resource_type: "AWS::ElasticLoadBalancingV2::LoadBalancer",
      resource_name: "billing-alb", discovered_at: "2026-07-15T00:00:00Z", last_seen_at: "2026-07-15T01:00:00Z",
      source: "discovered", confidence: "confirmed",
    }],
    count: 1,
  });
  cloudChanges.mockResolvedValue({ changes: [], count: 0, window_hours: 24 });
  searchLogs.mockResolvedValue({ hits: { total: { value: 1 }, hits: [{
    _index: "netops-cloudlogs-acme-2026.07.15", _id: "h1",
    _source: {
      timestamp: "2026-07-15T00:00:00Z", cloud_family: "waf", cloud_provider: "aws",
      account: "123456789012", resource_id: "edge-acl", message: "BLOCK rate-limit /login",
    },
  }] } });
});

describe("Cloud Logs unified view", () => {
  it("renders a lane per cloud log family with customer-facing labels", async () => {
    render(<CloudLogs />);
    for (const label of ["Inventory", "Flow", "Load Balancer", "Web Application Firewall", "DNS", "Change", "Host"]) {
      expect(screen.getByRole("tab", { name: label })).toBeTruthy();
    }
    // Opens on Inventory, wired to the real cloud inventory surface.
    await waitFor(() => expect(cloudResources).toHaveBeenCalled());
    expect(await screen.findByText("billing-alb")).toBeTruthy();
  });

  it("WAF lane queries the tagged cloud index with cloud_family:waf and renders a raw row", async () => {
    render(<CloudLogs />);
    fireEvent.click(screen.getByRole("tab", { name: "Web Application Firewall" }));
    await waitFor(() => expect(searchLogs).toHaveBeenCalled());
    const opts = searchLogs.mock.calls[searchLogs.mock.calls.length - 1][0];
    expect(opts.signal).toBe("cloud");
    expect(opts.query).toContain("cloud_family:waf");
    expect(await screen.findByText(/BLOCK rate-limit/)).toBeTruthy();
  });

  it("provider filter narrows the log-lane query", async () => {
    render(<CloudLogs />);
    fireEvent.click(screen.getByRole("tab", { name: "DNS" }));
    await waitFor(() => expect(searchLogs).toHaveBeenCalled());
    fireEvent.change(screen.getByLabelText("Provider"), { target: { value: "aws" } });
    await waitFor(() => {
      const last = searchLogs.mock.calls[searchLogs.mock.calls.length - 1][0];
      expect(last.query).toContain("cloud_family:dns");
      expect(last.query).toContain("cloud_provider:aws");
    });
  });

  it("shows an honest empty state, never fabricated rows", async () => {
    searchLogs.mockResolvedValue({ hits: { total: { value: 0 }, hits: [] } });
    render(<CloudLogs />);
    fireEvent.click(screen.getByRole("tab", { name: "Flow" }));
    expect(await screen.findByText("No log entries in this window.")).toBeTruthy();
  });
});

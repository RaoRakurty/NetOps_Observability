import { afterEach, describe, expect, it, vi, beforeEach } from "vitest";
import { render, screen, cleanup, fireEvent } from "@testing-library/react";
import ResourceDetail from "./ResourceDetail";
import type { CloudResourceDetailResponse } from "../services/api";

// The permanent resource page (Wave 6 #20): identity header, honest empty
// states per tab, and the no-leak 404 view.

vi.mock("./appobs/ResourceMetricsPanel", () => ({
  default: ({ subject }: { subject: string }) => <div data-testid="metrics-panel">{subject}</div>,
}));

const cloudResource = vi.fn();
const topTalkers = vi.fn();
const eventsFeed = vi.fn();

vi.mock("../services/api", () => ({
  api: {
    cloudResource: (...a: unknown[]) => cloudResource(...a),
    topTalkers: (...a: unknown[]) => topTalkers(...a),
    eventsFeed: (...a: unknown[]) => eventsFeed(...a),
  },
}));

const detail = (over: Partial<CloudResourceDetailResponse["resource"]> = {}): CloudResourceDetailResponse => ({
  resource: {
    tenant_id: "acme",
    cloud_provider: "aws",
    account_id: "111122223333",
    region: "us-east-1",
    resource_id: "i-0abc123",
    resource_type: "ec2_instance",
    resource_name: "checkout-web-1",
    private_ips: ["10.50.1.10"],
    tags: { app: "checkout" },
    discovered_at: "2026-07-01T00:00:00Z",
    last_seen_at: "2026-07-19T00:00:00Z",
    source: "cloud_tag",
    confidence: "confirmed",
    app_id: "checkout",
    app_name: "Checkout",
    owner: "payments",
    env: "prod",
    ...over,
  },
  console_url: "https://console.aws.amazon.com/ec2",
});

beforeEach(() => {
  cloudResource.mockReset();
  topTalkers.mockReset();
  eventsFeed.mockReset();
});
afterEach(cleanup);

describe("ResourceDetail", () => {
  it("renders the identity header from the canonical id", async () => {
    cloudResource.mockResolvedValue(detail());
    render(<ResourceDetail kind="cloud" id="i-0abc123" />);
    expect(await screen.findByRole("heading", { name: "checkout-web-1" })).toBeInTheDocument();
    expect(cloudResource).toHaveBeenCalledWith("i-0abc123");
    // identity line: id · account · region (matched loosely — the line is one
    // element but ancestors share the text, so assert at-least-one match)
    expect(screen.getAllByText(/i-0abc123 · 111122223333 · us-east-1/).length).toBeGreaterThan(0);
    // console deep-link present because the backend resolved one
    expect(screen.getAllByText(/Open in provider console/).length).toBeGreaterThan(0);
    // overview kv shows the class
    expect(screen.getByText("Class")).toBeInTheDocument();
  });

  it("shows the honest not-found view on 404 without leaking existence", async () => {
    cloudResource.mockRejectedValue(new Error("404 Not Found: resource not found"));
    render(<ResourceDetail kind="cloud" id="i-of-another-tenant" />);
    expect(await screen.findByText("Resource not found")).toBeInTheDocument();
    expect(screen.getByText(/don't have access/)).toBeInTheDocument();
  });

  it("treats an unknown kind as not found (never a guess)", async () => {
    render(<ResourceDetail kind="martian" id="x" />);
    expect(await screen.findByText("Resource not found")).toBeInTheDocument();
    expect(cloudResource).not.toHaveBeenCalled();
  });

  it("distinguishes backend failure from absence", async () => {
    cloudResource.mockRejectedValue(new Error("502 Bad Gateway: upstream"));
    render(<ResourceDetail kind="cloud" id="i-0abc123" />);
    expect(await screen.findByText("Couldn't load this resource")).toBeInTheDocument();
  });

  it("metrics tab reuses the Service View metrics panel", async () => {
    cloudResource.mockResolvedValue(detail());
    render(<ResourceDetail kind="cloud" id="i-0abc123" />);
    await screen.findByRole("heading", { name: "checkout-web-1" });
    fireEvent.click(screen.getByRole("button", { name: "Metrics" }));
    expect(screen.getByTestId("metrics-panel")).toHaveTextContent("checkout-web-1");
  });

  it("events tab shows an honest empty state when nothing references the resource", async () => {
    cloudResource.mockResolvedValue(detail());
    eventsFeed.mockResolvedValue({ items: [], next_cursor: "", facets: {} });
    render(<ResourceDetail kind="cloud" id="i-0abc123" />);
    await screen.findByRole("heading", { name: "checkout-web-1" });
    fireEvent.click(screen.getByRole("button", { name: "Events" }));
    expect(await screen.findByText("No recent events")).toBeInTheDocument();
    expect(eventsFeed).toHaveBeenCalledWith({ q: "checkout-web-1", from: "168h", limit: "50" });
  });

  it("flows tab is honest when the inventory carries no IP addresses", async () => {
    cloudResource.mockResolvedValue(detail({ private_ips: [], public_ips: [] }));
    render(<ResourceDetail kind="cloud" id="i-0abc123" />);
    await screen.findByRole("heading", { name: "checkout-web-1" });
    fireEvent.click(screen.getByRole("button", { name: "Flows" }));
    expect(await screen.findByText("No IP addresses recorded")).toBeInTheDocument();
    expect(topTalkers).not.toHaveBeenCalled();
  });

  it("flows tab folds outbound + inbound conversations for the primary IP", async () => {
    cloudResource.mockResolvedValue(detail());
    topTalkers
      .mockResolvedValueOnce({ data: [{ src: "10.50.1.10", dst: "10.9.9.9", bytes_total: "1000", flows: "3" }] })
      .mockResolvedValueOnce({ data: [{ src: "10.8.8.8", dst: "10.50.1.10", bytes_total: "2000", flows: "5" }] });
    render(<ResourceDetail kind="cloud" id="i-0abc123" />);
    await screen.findByRole("heading", { name: "checkout-web-1" });
    fireEvent.click(screen.getByRole("button", { name: "Flows" }));
    expect(await screen.findByText("10.9.9.9")).toBeInTheDocument();
    expect(screen.getByText("10.8.8.8")).toBeInTheDocument();
    // biggest conversation first regardless of direction
    const rows = screen.getAllByRole("row").slice(1);
    expect(rows[0]).toHaveTextContent("10.8.8.8");
    expect(topTalkers).toHaveBeenCalledWith(86400, 15, "", { src: "10.50.1.10" });
    expect(topTalkers).toHaveBeenCalledWith(86400, 15, "", { dst: "10.50.1.10" });
  });

  it("service tab shows attribution when confident, honest emptiness when not", async () => {
    cloudResource.mockResolvedValue(detail());
    render(<ResourceDetail kind="cloud" id="i-0abc123" />);
    await screen.findByRole("heading", { name: "checkout-web-1" });
    fireEvent.click(screen.getByRole("button", { name: "Service" }));
    expect(screen.getAllByText("Checkout").length).toBeGreaterThan(0);
    expect(screen.getAllByText(/cloud_tag · confirmed/).length).toBeGreaterThan(0);
    cleanup();

    cloudResource.mockResolvedValue(detail({ app_id: "", app_name: "", confidence: "unknown" }));
    render(<ResourceDetail kind="cloud" id="i-0abc123" />);
    await screen.findByRole("heading", { name: "checkout-web-1" });
    fireEvent.click(screen.getByRole("button", { name: "Service" }));
    expect(await screen.findByText("Not attributed to a service")).toBeInTheDocument();
  });
});

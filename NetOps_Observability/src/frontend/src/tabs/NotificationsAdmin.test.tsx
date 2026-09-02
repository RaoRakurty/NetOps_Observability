// NotificationsAdmin audience contract. The seven delivery channels (SMTP,
// Twilio SMS, ntfy push, Slack, PagerDuty, Teams, SNS) are PLATFORM-global plumbing —
// every config endpoint behind their tiles is platform-gated, so a tenant
// admin clicking one gets only 403'd loads and dead forms. The tiles must not
// render for a non-platform principal. Contact points, by contrast, ARE
// tenant-scoped and stay visible to everyone.
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, cleanup, waitFor } from "@testing-library/react";

const mockUseAuth = vi.fn();
vi.mock("../hooks/useAuth", () => ({ useAuth: (...a: unknown[]) => mockUseAuth(...a) }));

import { NotificationsAdmin } from "./admin";
import { api } from "../services/api";

const CHANNEL_TILES = ["Configure Email", "Configure SMS & Push", "Configure Slack", "Configure PagerDuty", "Configure Microsoft Teams", "Configure Amazon SNS"];

beforeEach(() => {
  localStorage.clear();
  vi.spyOn(api, "smtpConfig").mockResolvedValue({ enabled: false, host: "", port: 587, from: "", to: "", user: "", pass_set: false, security: "starttls", min_severity: "critical" } as never);
  vi.spyOn(api, "twilioConfig").mockResolvedValue({ enabled: false, account_sid: "", token_set: false, from: "", to: "", min_severity: "critical" } as never);
  vi.spyOn(api, "ntfyConfig").mockResolvedValue({ enabled: false, server: "", topic: "", token_set: false, min_severity: "critical" } as never);
  vi.spyOn(api, "slackConfig").mockResolvedValue({ enabled: false, webhook_set: false, min_severity: "critical" } as never);
  vi.spyOn(api, "pagerDutyConfig").mockResolvedValue({ enabled: false, routing_set: false, min_severity: "critical" } as never);
  vi.spyOn(api, "notifyTeams").mockResolvedValue({ enabled: false, webhook_set: false, min_severity: "warning" } as never);
  vi.spyOn(api, "notifySNS").mockResolvedValue({ enabled: false, topic_arn: "", region: "", phone_numbers: "", min_severity: "critical", scope: "all", credentials_set: false } as never);
  vi.spyOn(api, "integrations").mockResolvedValue({ integrations: [], inbound_enabled: false } as never);
  vi.spyOn(api, "contactPoints").mockResolvedValue([]);
});
afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

describe("NotificationsAdmin", () => {
  it("shows the channel tiles to the platform owner", async () => {
    mockUseAuth.mockReturnValue({ user: { username: "root", platform_admin: true }, loading: false });
    render(<NotificationsAdmin />);
    for (const label of CHANNEL_TILES) {
      expect(await screen.findByLabelText(label)).toBeTruthy();
    }
    expect(screen.getByRole("heading", { name: "Contact points" })).toBeTruthy();
  });

  it("hides the platform-gated channel tiles from a tenant admin — contact points stay", async () => {
    mockUseAuth.mockReturnValue({ user: { username: "t-admin", platform_admin: false }, loading: false });
    render(<NotificationsAdmin />);
    // Tenant-scoped surface is present…
    expect(await screen.findByRole("heading", { name: "Contact points" })).toBeTruthy();
    // …but none of the dead platform tiles are.
    for (const label of CHANNEL_TILES) {
      expect(screen.queryByLabelText(label)).toBeNull();
    }
    // And the platform-gated channel config endpoints were never called.
    expect(api.smtpConfig).not.toHaveBeenCalled();
    expect(api.pagerDutyConfig).not.toHaveBeenCalled();
    expect(api.notifyTeams).not.toHaveBeenCalled();
    expect(api.notifySNS).not.toHaveBeenCalled();
  });

  it("renders no channel tiles while auth is still resolving (no flash either way)", async () => {
    mockUseAuth.mockReturnValue({ user: null, loading: true });
    render(<NotificationsAdmin />);
    await waitFor(() => expect(screen.getByRole("heading", { name: "Contact points" })).toBeTruthy());
    for (const label of CHANNEL_TILES) {
      expect(screen.queryByLabelText(label)).toBeNull();
    }
  });
});

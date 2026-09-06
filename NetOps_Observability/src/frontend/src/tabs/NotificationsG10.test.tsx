// G10 — Microsoft Teams + Amazon SNS channel cards in the Notifications admin.
//
// Both are platform-GLOBAL plumbing behind requirePlatformAdmin, so they get
// the same treatment as the Slack/PagerDuty cards: rendered only for the
// resolved platform principal, secrets write-only, and every server validator
// mirrored inline so a rejection names the field instead of arriving as a 400.
// These tests pin the three things a refactor is most likely to break silently:
// the masked-secret contract, the PUT body (a webhook must never be re-sent —
// or dropped — by accident), and the inline validation.
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, cleanup, fireEvent, waitFor } from "@testing-library/react";

const mockUseAuth = vi.fn();
vi.mock("../hooks/useAuth", () => ({ useAuth: (...a: unknown[]) => mockUseAuth(...a) }));

import { NotificationsAdmin } from "./admin";
import { api } from "../services/api";

const ARN = "arn:aws:sns:us-east-1:123456789012:netops-alerts";
const MASK = "•••••• (unchanged)";
const TEAMS_TILE = "Configure Microsoft Teams";
const SNS_TILE = "Configure Amazon SNS";

type TeamsShape = { enabled: boolean; webhook_set: boolean; min_severity: string };
type SnsShape = {
  enabled: boolean; topic_arn: string; region: string; phone_numbers: string;
  min_severity: string; scope: string; credentials_set: boolean;
};

const teamsCfg = (o: Partial<TeamsShape> = {}): TeamsShape =>
  ({ enabled: true, webhook_set: true, min_severity: "warning", ...o });
const snsCfg = (o: Partial<SnsShape> = {}): SnsShape =>
  ({ enabled: true, topic_arn: ARN, region: "us-east-1", phone_numbers: "", min_severity: "critical", scope: "all", credentials_set: true, ...o });

/** Stub every config load the page fires so only the channel under test varies. */
function stubApi(teams: TeamsShape, sns: SnsShape) {
  vi.spyOn(api, "smtpConfig").mockResolvedValue({ enabled: false, host: "", port: 587, from: "", to: "", user: "", pass_set: false, security: "starttls", min_severity: "critical" } as never);
  vi.spyOn(api, "twilioConfig").mockResolvedValue({ enabled: false, account_sid: "", token_set: false, from: "", to: "", min_severity: "critical" } as never);
  vi.spyOn(api, "ntfyConfig").mockResolvedValue({ enabled: false, server: "", topic: "", token_set: false, min_severity: "critical" } as never);
  vi.spyOn(api, "slackConfig").mockResolvedValue({ enabled: false, webhook_set: false, min_severity: "critical" } as never);
  vi.spyOn(api, "pagerDutyConfig").mockResolvedValue({ enabled: false, routing_set: false, min_severity: "critical" } as never);
  vi.spyOn(api, "integrations").mockResolvedValue({ integrations: [], inbound_enabled: false } as never);
  vi.spyOn(api, "contactPoints").mockResolvedValue([]);
  vi.spyOn(api, "notifyTeams").mockResolvedValue(teams as never);
  vi.spyOn(api, "notifySNS").mockResolvedValue(sns as never);
  vi.spyOn(api, "notifyTeamsUpdate").mockResolvedValue(teams as never);
  vi.spyOn(api, "notifySNSUpdate").mockResolvedValue(sns as never);
  vi.spyOn(api, "notifyTeamsTest").mockResolvedValue({ status: "sent" } as never);
  vi.spyOn(api, "notifySNSTest").mockResolvedValue({ status: "sent" } as never);
}

/** Render as the platform owner and open one channel's setup modal. */
async function openCard(tile: string, teams = teamsCfg(), sns = snsCfg()) {
  mockUseAuth.mockReturnValue({ user: { username: "root", platform_admin: true }, loading: false });
  stubApi(teams, sns);
  render(<NotificationsAdmin />);
  fireEvent.click(await screen.findByLabelText(tile));
  return screen.findByRole("dialog");
}

beforeEach(() => localStorage.clear());
afterEach(() => { cleanup(); vi.restoreAllMocks(); });

describe("Teams channel card", () => {
  it("renders the stored webhook as a masked replace affordance, never the value", async () => {
    await openCard(TEAMS_TILE);
    const field = await screen.findByPlaceholderText(MASK);
    expect((field as HTMLInputElement).type).toBe("password");
    expect((field as HTMLInputElement).value).toBe("");
    expect(screen.getByText(/A webhook is stored/i)).toBeTruthy();
    expect(screen.getByText(/Webhook URL \(stored\)/)).toBeTruthy();
  });

  it("shows an unmasked empty field with the example URL when nothing is stored", async () => {
    await openCard(TEAMS_TILE, teamsCfg({ enabled: false, webhook_set: false }));
    expect(await screen.findByPlaceholderText(/webhook\.office\.com/)).toBeTruthy();
    expect(screen.queryByPlaceholderText(MASK)).toBeNull();
  });

  it("omits webhook_url from the PUT when the field is untouched", async () => {
    await openCard(TEAMS_TILE);
    fireEvent.click(await screen.findByRole("button", { name: "Save" }));
    await waitFor(() => expect(api.notifyTeamsUpdate).toHaveBeenCalled());
    expect(api.notifyTeamsUpdate).toHaveBeenCalledWith({ enabled: true, min_severity: "warning" });
    const body = vi.mocked(api.notifyTeamsUpdate).mock.calls[0][0];
    expect("webhook_url" in body).toBe(false);
  });

  it("includes webhook_url in the PUT when the operator types a replacement, then clears it", async () => {
    await openCard(TEAMS_TILE);
    const next = "https://acme.webhook.office.com/webhookb2/replaced";
    fireEvent.change(await screen.findByPlaceholderText(MASK), { target: { value: next } });
    fireEvent.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(api.notifyTeamsUpdate).toHaveBeenCalledWith({ enabled: true, min_severity: "warning", webhook_url: next }));
    // The typed secret is dropped from component state once accepted.
    await waitFor(() => expect((screen.getByPlaceholderText(MASK) as HTMLInputElement).value).toBe(""));
  });

  it("rejects a plaintext webhook inline and never PUTs it", async () => {
    await openCard(TEAMS_TILE);
    fireEvent.change(await screen.findByPlaceholderText(MASK), { target: { value: "http://acme.webhook.office.com/hook" } });
    const err = await screen.findByRole("alert");
    expect(err.textContent).toMatch(/must use https/);
    fireEvent.click(screen.getByRole("button", { name: "Save" }));
    await screen.findByText("Fix the highlighted fields first.");
    expect(api.notifyTeamsUpdate).not.toHaveBeenCalled();
  });

  it("refuses to enable a channel with no webhook anywhere", async () => {
    await openCard(TEAMS_TILE, teamsCfg({ enabled: false, webhook_set: false }));
    fireEvent.click(await screen.findByLabelText("Enable Teams delivery", { selector: "input" }));
    expect((await screen.findByRole("alert")).textContent).toMatch(/before enabling Teams/);
  });

  it("renders the test-send result", async () => {
    await openCard(TEAMS_TILE);
    fireEvent.click(await screen.findByRole("button", { name: "Send test" }));
    expect(await screen.findByText(/Test sent/)).toBeTruthy();
  });

  it("renders a test-send failure reason", async () => {
    await openCard(TEAMS_TILE);
    vi.mocked(api.notifyTeamsTest).mockRejectedValueOnce(new Error("configure a webhook url first"));
    fireEvent.click(await screen.findByRole("button", { name: "Send test" }));
    expect(await screen.findByText("Test failed: configure a webhook url first")).toBeTruthy();
  });
});

describe("SNS channel card", () => {
  it("reports environment credentials read-only — no credential field exists", async () => {
    const dlg = await openCard(SNS_TILE);
    expect(await screen.findByText("Credentials detected")).toBeTruthy();
    // The CLAIM is unchanged — the credentials are not ours to hold. The
    // sentence that explained where they do come from moved to
    // ai/skills/explain/notify.sns-credentials.md, so the (i) is asserted with it.
    expect(screen.getByText(/AWS credentials come from the environment/)).toBeTruthy();
    expect(screen.getByRole("button", { name: /Ask Iris about AWS credentials/ })).toBeTruthy();
    expect(dlg.querySelectorAll('input[type="password"]').length).toBe(0);
    expect((screen.getByPlaceholderText(/arn:aws:sns/) as HTMLInputElement).value).toBe(ARN);
  });

  it("warns when the deployment has no AWS credentials", async () => {
    await openCard(SNS_TILE, teamsCfg(), snsCfg({ credentials_set: false }));
    expect(await screen.findByText("Credentials not set")).toBeTruthy();
  });

  it("PUTs the whole config and never echoes credentials_set back", async () => {
    await openCard(SNS_TILE);
    fireEvent.click(await screen.findByRole("button", { name: "Save" }));
    await waitFor(() => expect(api.notifySNSUpdate).toHaveBeenCalled());
    const body = vi.mocked(api.notifySNSUpdate).mock.calls[0][0];
    expect(body).toEqual({ enabled: true, topic_arn: ARN, region: "us-east-1", phone_numbers: "", min_severity: "critical", scope: "all" });
    expect("credentials_set" in body).toBe(false);
  });

  it("rejects a malformed topic ARN inline and never PUTs it", async () => {
    await openCard(SNS_TILE);
    fireEvent.change(await screen.findByPlaceholderText(/arn:aws:sns/), { target: { value: "arn:aws:sqs:us-east-1:123456789012:t" } });
    expect((await screen.findByRole("alert")).textContent).toMatch(/service must be "sns"/);
    fireEvent.click(screen.getByRole("button", { name: "Save" }));
    await screen.findByText("Fix the highlighted fields first.");
    expect(api.notifySNSUpdate).not.toHaveBeenCalled();
  });

  it("reports a region that disagrees with the topic ARN", async () => {
    await openCard(SNS_TILE);
    fireEvent.change(await screen.findByPlaceholderText("us-east-1"), { target: { value: "eu-west-1" } });
    expect((await screen.findByRole("alert")).textContent).toMatch(/does not match the topic ARN's region/);
  });

  it("reports a non-E.164 phone number", async () => {
    await openCard(SNS_TILE);
    fireEvent.change(await screen.findByPlaceholderText(/\+14155550123/), { target: { value: "555-0123" } });
    expect((await screen.findByRole("alert")).textContent).toMatch(/E.164/);
  });

  it("renders the test-send result and a failure reason", async () => {
    await openCard(SNS_TILE);
    fireEvent.click(await screen.findByRole("button", { name: "Send test" }));
    expect(await screen.findByText(/Test sent/)).toBeTruthy();
    vi.mocked(api.notifySNSTest).mockRejectedValueOnce(new Error("AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY must be set in the deployment environment"));
    fireEvent.click(screen.getByRole("button", { name: "Send test" }));
    expect(await screen.findByText(/Test failed: AWS_ACCESS_KEY_ID/)).toBeTruthy();
  });
});

describe("platform-owner gate (403 treatment)", () => {
  it("hides both tiles from a tenant admin and never calls their platform-gated endpoints", async () => {
    mockUseAuth.mockReturnValue({ user: { username: "t-admin", platform_admin: false }, loading: false });
    stubApi(teamsCfg(), snsCfg());
    render(<NotificationsAdmin />);
    await screen.findByRole("heading", { name: "Contact points" });
    expect(screen.queryByLabelText(TEAMS_TILE)).toBeNull();
    expect(screen.queryByLabelText(SNS_TILE)).toBeNull();
    expect(api.notifyTeams).not.toHaveBeenCalled();
    expect(api.notifySNS).not.toHaveBeenCalled();
  });

  it("renders neither tile while auth is still resolving", async () => {
    mockUseAuth.mockReturnValue({ user: null, loading: true });
    stubApi(teamsCfg(), snsCfg());
    render(<NotificationsAdmin />);
    await screen.findByRole("heading", { name: "Contact points" });
    expect(screen.queryByLabelText(TEAMS_TILE)).toBeNull();
    expect(screen.queryByLabelText(SNS_TILE)).toBeNull();
  });
});

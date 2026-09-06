// DeviceConfigPanel.test.tsx — the device Configuration panel.
//
// What is pinned here:
//  · the four state badges plus the honest "Never captured" edge
//  · the versions table (sha, time, size, status, golden star, drift, churn)
//  · Back up now: 202 → live-region job notice, 429 → "already running",
//    403 → inline no-permission line (the SERVER is the authority)
//  · the feature-off card on 404/501 — a product state, not an error
//  · XSS regression: hostile device config text and hostile diff lines reach
//    the DOM as ESCAPED TEXT — no <script> element, no HTML sink
//  · set golden asks for confirmation and only then sends the sha

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, cleanup, fireEvent, waitFor } from "@testing-library/react";
import type { ConfigStatus, ConfigText, ConfigVersion, Device } from "../../services/api";

const configStatus = vi.fn();
const configVersions = vi.fn();
const configVersion = vi.fn();
const configDiff = vi.fn();
const configBackup = vi.fn();
const configSetGolden = vi.fn();
const permissions = vi.fn();

vi.mock("../../services/api", () => ({
  api: {
    configStatus: (...a: unknown[]) => configStatus(...a),
    configVersions: (...a: unknown[]) => configVersions(...a),
    configVersion: (...a: unknown[]) => configVersion(...a),
    configDiff: (...a: unknown[]) => configDiff(...a),
    configBackup: (...a: unknown[]) => configBackup(...a),
    configSetGolden: (...a: unknown[]) => configSetGolden(...a),
    permissions: (...a: unknown[]) => permissions(...a),
  },
}));

import DeviceConfigPanel from "./DeviceConfigPanel";

const DEVICE = {
  id: "leaf1", name: "leaf1", address: "10.0.0.1", source: "static",
  last_seen: "2026-09-01T10:00:00Z",
} as Device;

const GOLDEN_SHA = "aaaaaaaaaaaabbbbbbbb";
const HEAD_SHA = "ccccccccccccdddddddd";

const VERSIONS: ConfigVersion[] = [
  { sha: HEAD_SHA, captured_at: "2026-09-01T12:00:00Z", size_bytes: 4096, status: "ok", golden: false, drift: "drifted", added: 3, removed: 1 },
  { sha: GOLDEN_SHA, captured_at: "2026-08-30T12:00:00Z", size_bytes: 4000, status: "ok", golden: true, drift: "in_sync" },
];

const STATUS: ConfigStatus = {
  device_id: "leaf1", state: "drifted", last_capture_at: "2026-09-01T12:00:00Z",
  last_sha: HEAD_SHA, golden_sha: GOLDEN_SHA,
};

function ok(status: Partial<ConfigStatus> = {}, versions: ConfigVersion[] = VERSIONS, golden: string | null = GOLDEN_SHA, infra = 2) {
  configStatus.mockResolvedValue({ ...STATUS, ...status });
  configVersions.mockResolvedValue({ device_id: "leaf1", items: versions, golden_sha: golden, next_cursor: null });
  permissions.mockResolvedValue({ role: "operator", permissions: { infrastructure: infra } });
}

beforeEach(() => {
  for (const m of [configStatus, configVersions, configVersion, configDiff, configBackup, configSetGolden, permissions]) m.mockReset();
});
afterEach(cleanup);

describe("state badge — four states plus the honest unknown", () => {
  // The row drift chips reuse the same words, so the device-level badge is
  // always read from the summary strip specifically.
  const summaryBadge = (c: HTMLElement) => c.querySelector(".cfg-summary .badge")?.textContent;

  it("renders the drifted state with the last capture time and the golden marker", async () => {
    ok();
    const { container } = render(<DeviceConfigPanel device={DEVICE} />);
    await waitFor(() => expect(summaryBadge(container)).toBe("Drifted"));
    expect(screen.getByText(/Last capture/)).toBeTruthy();
    expect(screen.getByText(/Golden baseline/)).toBeTruthy();
    // The summary carries the golden marker; the same sha also appears in its row.
    expect(container.querySelector(".cfg-summary")?.textContent).toContain(GOLDEN_SHA.slice(0, 12));
  });

  it("renders 'In sync' when the head capture matches golden", async () => {
    ok({ state: "in_sync" });
    const { container } = render(<DeviceConfigPanel device={DEVICE} />);
    await waitFor(() => expect(summaryBadge(container)).toBe("In sync"));
  });

  it("renders 'Changed' when the capture differs from the one before it", async () => {
    ok({ state: "changed" });
    const { container } = render(<DeviceConfigPanel device={DEVICE} />);
    await waitFor(() => expect(summaryBadge(container)).toBe("Changed"));
  });

  it("is honestly 'Never captured' when nothing was ever collected", async () => {
    ok({ state: "unknown", last_capture_at: undefined, golden_sha: null }, [], null);
    render(<DeviceConfigPanel device={DEVICE} />);
    expect(await screen.findByText("Never captured")).toBeTruthy();
    expect(screen.getByText(/No golden baseline set/)).toBeTruthy();
    expect(screen.getByText(/An empty history means nothing was collected/)).toBeTruthy();
  });

  it("surfaces a failed capture as a failure, with the reason", async () => {
    ok({ state: "failed", last_error: "ssh auth failed" });
    render(<DeviceConfigPanel device={DEVICE} />);
    expect(await screen.findByText("Capture failed")).toBeTruthy();
    expect(screen.getByText(/ssh auth failed/)).toBeTruthy();
  });
});

describe("versions table", () => {
  it("lists every capture with sha, time, size, status, drift, churn and the golden star", async () => {
    ok();
    render(<DeviceConfigPanel device={DEVICE} />);
    const table = await screen.findByRole("table", { name: /Configuration versions for leaf1/ });
    const rows = table.querySelectorAll("tbody tr");
    expect(rows.length).toBe(2);
    expect(rows[0].textContent).toContain(HEAD_SHA.slice(0, 12));
    expect(rows[0].textContent).toContain("4.0 KB");
    expect(rows[0].textContent).toContain("+3");
    expect(rows[0].textContent).toContain("ok");
    expect(screen.getAllByLabelText("Golden baseline").length).toBe(1);
    expect(rows[1].textContent).toContain("★");
  });

  it("offers view / diff-previous / diff-golden per row and no golden diff for golden itself", async () => {
    ok();
    render(<DeviceConfigPanel device={DEVICE} />);
    expect(await screen.findByRole("button", { name: `View version ${HEAD_SHA.slice(0, 12)}` })).toBeTruthy();
    expect(screen.getByRole("button", { name: /Compare version .* with the previous version/ })).toBeTruthy();
    expect(screen.getAllByRole("button", { name: /with the golden baseline/ }).length).toBe(1);
  });

  it("marks a failed capture in its row rather than hiding it", async () => {
    ok({}, [{ sha: "ffffffffffff1111", captured_at: "2026-09-01T12:00:00Z", size_bytes: 0, status: "failed", error: "timeout", golden: false, drift: "unknown" }], null);
    render(<DeviceConfigPanel device={DEVICE} />);
    expect(await screen.findByText("failed")).toBeTruthy();
    expect(screen.getAllByText("Unknown").length).toBeGreaterThan(0);
  });
});

describe("Back up now", () => {
  it("announces the queued job in a live region on 202", async () => {
    ok();
    configBackup.mockResolvedValue({ job_id: "job-42", status: "queued" });
    render(<DeviceConfigPanel device={DEVICE} />);
    fireEvent.click(await screen.findByRole("button", { name: /Back up/ }));
    const live = await screen.findByText(/Backup queued — job job-42/);
    expect(live.getAttribute("aria-live")).toBe("polite");
    expect(configBackup).toHaveBeenCalledWith("leaf1");
  });

  it("says a backup is already running on 429 instead of throwing an error", async () => {
    ok();
    configBackup.mockRejectedValue(new Error('429 Too Many Requests: {"error":"backup in progress"}'));
    render(<DeviceConfigPanel device={DEVICE} />);
    fireEvent.click(await screen.findByRole("button", { name: /Back up/ }));
    expect(await screen.findByText(/A backup is already running for this device/)).toBeTruthy();
  });

  it("renders the inline no-permission line when the SERVER answers 403", async () => {
    ok(); // client-side gate says writer — the server is still the authority
    configBackup.mockRejectedValue(new Error("403 Forbidden: infrastructure:write required"));
    render(<DeviceConfigPanel device={DEVICE} />);
    fireEvent.click(await screen.findByRole("button", { name: /Back up/ }));
    expect(await screen.findByText(/You do not have permission to do that/)).toBeTruthy();
  });

  it("disables the button and explains why without infrastructure:write", async () => {
    ok({}, VERSIONS, GOLDEN_SHA, 1);
    render(<DeviceConfigPanel device={DEVICE} />);
    await waitFor(() => expect((screen.getByRole("button", { name: /Back up/ }) as HTMLButtonElement).disabled).toBe(true));
    expect(screen.getByText(/You do not have permission to do that/)).toBeTruthy();
    expect(screen.queryByRole("button", { name: /Set version .* as the golden baseline/ })).toBeNull();
  });
});

describe("viewing a version and a diff — untrusted device text is escaped", () => {
  const HOSTILE = `hostname leaf1\n<script>alert('pwn')</script>\n<img src=x onerror=alert(2)>`;

  it("renders the captured configuration as escaped text, never as markup", async () => {
    ok();
    const doc: ConfigText = {
      device_id: "leaf1", sha: HEAD_SHA, captured_at: "2026-09-01T12:00:00Z",
      size_bytes: 120, golden: false, text: HOSTILE,
    };
    configVersion.mockResolvedValue(doc);
    const { container } = render(<DeviceConfigPanel device={DEVICE} />);
    fireEvent.click(await screen.findByRole("button", { name: `View version ${HEAD_SHA.slice(0, 12)}` }));
    const pre = await screen.findByLabelText(`Configuration ${HEAD_SHA.slice(0, 12)}`);
    // The bytes are all there…
    expect(pre.textContent).toContain("<script>alert('pwn')</script>");
    // …but NOTHING was parsed as markup: no script/img element entered the DOM.
    expect(container.querySelector("script")).toBeNull();
    expect(container.querySelector("img")).toBeNull();
    expect(container.innerHTML).toContain("&lt;script&gt;");
    expect(container.innerHTML).not.toContain("<script>");
  });

  it("renders a unified diff with per-line +/- classes and escapes hostile lines", async () => {
    ok();
    configDiff.mockResolvedValue({
      device_id: "leaf1", from: GOLDEN_SHA, to: HEAD_SHA, added: 1, removed: 1, truncated: false,
      unified: `--- golden\n+++ current\n@@ -1,2 +1,2 @@\n-banner motd ok\n+banner motd <script>alert('pwn')</script>\n`,
    });
    const { container } = render(<DeviceConfigPanel device={DEVICE} />);
    fireEvent.click(await screen.findByRole("button", { name: /Compare version .* with the golden baseline/ }));
    await screen.findByText(/banner motd <script>alert\('pwn'\)<\/script>/);
    expect(container.querySelectorAll(".cfg-diff-add").length).toBe(1);
    expect(container.querySelectorAll(".cfg-diff-del").length).toBe(1);
    expect(container.querySelectorAll(".cfg-diff-hunk").length).toBe(1);
    expect(container.querySelector("script")).toBeNull();
    expect(container.innerHTML).not.toContain("<script>");
    expect(configDiff).toHaveBeenCalledWith("leaf1", GOLDEN_SHA, HEAD_SHA);
  });

  it("diffs a version against the one before it", async () => {
    ok();
    configDiff.mockResolvedValue({ device_id: "leaf1", from: GOLDEN_SHA, to: HEAD_SHA, added: 0, removed: 0, unified: "", truncated: false });
    render(<DeviceConfigPanel device={DEVICE} />);
    fireEvent.click(await screen.findByRole("button", { name: /Compare version .* with the previous version/ }));
    await waitFor(() => expect(configDiff).toHaveBeenCalledWith("leaf1", GOLDEN_SHA, HEAD_SHA));
    expect(await screen.findByText(/The two versions are identical/)).toBeTruthy();
  });

  it("says so when the server truncated the diff", async () => {
    ok();
    configDiff.mockResolvedValue({
      device_id: "leaf1", from: GOLDEN_SHA, to: HEAD_SHA, added: 900, removed: 900,
      unified: "+one line\n", truncated: true,
    });
    render(<DeviceConfigPanel device={DEVICE} />);
    fireEvent.click(await screen.findByRole("button", { name: /Compare version .* with the golden baseline/ }));
    expect(await screen.findByText(/Truncated by the server/)).toBeTruthy();
  });
});

describe("set golden", () => {
  it("asks for confirmation first and only then sends the sha", async () => {
    ok();
    configSetGolden.mockResolvedValue({ device_id: "leaf1", golden_sha: HEAD_SHA });
    render(<DeviceConfigPanel device={DEVICE} />);
    const short = HEAD_SHA.slice(0, 12);
    fireEvent.click(await screen.findByRole("button", { name: `Set version ${short} as the golden baseline` }));
    // Nothing is sent on the first click — the confirm step must be crossed.
    expect(configSetGolden).not.toHaveBeenCalled();
    expect(screen.getByText(new RegExp(`Promoting ${short}`))).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: `Confirm version ${short} as the golden baseline` }));
    await waitFor(() => expect(configSetGolden).toHaveBeenCalledWith("leaf1", HEAD_SHA));
    expect(await screen.findByText(new RegExp(`Golden baseline set to ${short}`))).toBeTruthy();
  });

  it("can be cancelled without sending anything", async () => {
    ok();
    render(<DeviceConfigPanel device={DEVICE} />);
    const short = HEAD_SHA.slice(0, 12);
    fireEvent.click(await screen.findByRole("button", { name: `Set version ${short} as the golden baseline` }));
    fireEvent.click(screen.getByRole("button", { name: `Cancel setting version ${short} as the golden baseline` }));
    expect(configSetGolden).not.toHaveBeenCalled();
    expect(screen.getByRole("button", { name: `Set version ${short} as the golden baseline` })).toBeTruthy();
  });

  it("shows the no-permission line when the server refuses the promotion", async () => {
    ok();
    configSetGolden.mockRejectedValue(new Error("403 Forbidden: infrastructure:write required"));
    render(<DeviceConfigPanel device={DEVICE} />);
    const short = HEAD_SHA.slice(0, 12);
    fireEvent.click(await screen.findByRole("button", { name: `Set version ${short} as the golden baseline` }));
    fireEvent.click(screen.getByRole("button", { name: `Confirm version ${short} as the golden baseline` }));
    expect(await screen.findByText(/You do not have permission to do that/)).toBeTruthy();
  });
});

describe("feature flag off", () => {
  it("renders the calm 'not enabled' card on 404, not an error", async () => {
    configStatus.mockRejectedValue(new Error("404 Not Found: "));
    configVersions.mockRejectedValue(new Error("404 Not Found: "));
    permissions.mockResolvedValue({ role: "operator", permissions: { infrastructure: 2 } });
    render(<DeviceConfigPanel device={DEVICE} />);
    expect(await screen.findByText(/Config backup is not enabled on this deployment/)).toBeTruthy();
    expect(screen.queryByRole("alert")).toBeNull();
    expect(screen.queryByRole("button", { name: /Back up/ })).toBeNull();
  });

  it("renders the same card on 501", async () => {
    configStatus.mockRejectedValue(new Error("501 Not Implemented: feature disabled"));
    configVersions.mockRejectedValue(new Error("501 Not Implemented: feature disabled"));
    permissions.mockResolvedValue({ role: "operator", permissions: { infrastructure: 2 } });
    render(<DeviceConfigPanel device={DEVICE} />);
    expect(await screen.findByText(/Config backup is not enabled on this deployment/)).toBeTruthy();
  });

  it("still reports a real server failure as an error", async () => {
    configStatus.mockRejectedValue(new Error("500 Internal Server Error: boom"));
    configVersions.mockRejectedValue(new Error("500 Internal Server Error: boom"));
    permissions.mockResolvedValue({ role: "operator", permissions: { infrastructure: 2 } });
    render(<DeviceConfigPanel device={DEVICE} />);
    expect(await screen.findByRole("alert")).toBeTruthy();
  });
});

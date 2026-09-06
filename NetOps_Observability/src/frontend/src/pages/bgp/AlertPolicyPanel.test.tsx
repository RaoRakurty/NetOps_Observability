// AlertPolicyPanel.test.tsx — the render states of the BGP alert policy editor.
//
// Each case locks in an honesty contract, not a layout:
//   * an empty ASN set SAYS what it costs — a learned baseline, or a leak check
//     that does not run. An operator must not read silence as safety.
//   * the panel re-renders from the STORED policy, because the server dedupes,
//     drops AS0, sorts and canonicalizes every prefix key on save.
//   * a refusal keeps the typed policy on screen and says what was wrong.
//   * with alerting off the policy is still editable, and the panel says the
//     stored intent is not being evaluated — never that everything is fine.

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, cleanup, fireEvent, waitFor } from "@testing-library/react";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { scanCopy } from "../../copyVoice.test";
import type { BgpAlertConfigResp } from "../../services/api";

const bgpAlertConfig = vi.fn();
const setBgpAlertConfig = vi.fn();
vi.mock("../../services/api", () => ({
  api: {
    bgpAlertConfig: (...a: unknown[]) => bgpAlertConfig(...a),
    setBgpAlertConfig: (...a: unknown[]) => setBgpAlertConfig(...a),
  },
}));

import AlertPolicyPanel from "./AlertPolicyPanel";

const DEFAULTS = { min_visibility: 0.5, min_vantages: 2, max_prefixes: 200, max_asns_per_set: 32 };
const resp = (over: Partial<BgpAlertConfigResp> = {}): BgpAlertConfigResp => ({
  config: { default: {} },
  defaults: DEFAULTS,
  ...over,
});

beforeEach(() => {
  bgpAlertConfig.mockReset();
  setBgpAlertConfig.mockReset();
  bgpAlertConfig.mockResolvedValue(resp());
});
afterEach(cleanup);

describe("AlertPolicyPanel", () => {
  it("reads the tenant's stored policy", async () => {
    render(<AlertPolicyPanel />);
    await waitFor(() => expect(bgpAlertConfig).toHaveBeenCalledTimes(1));
  });

  it("renders the policy in force, with who set it", async () => {
    bgpAlertConfig.mockResolvedValue(resp({
      config: { default: { expected_origins: ["AS64500"], upstreams: ["AS3356"], min_visibility: 0.7 } },
      updated_by: "nora",
      updated_at: "2026-09-04T10:00:00Z",
    }));
    render(<AlertPolicyPanel />);
    await waitFor(() =>
      expect((screen.getByLabelText("Default expected origin AS") as HTMLInputElement).value).toBe("AS64500"));
    expect((screen.getByLabelText("Default upstream AS") as HTMLInputElement).value).toBe("AS3356");
    expect(screen.getByText(/Last set by nora/)).toBeTruthy();
  });

  it("says what an empty origin set and an empty upstream set cost", async () => {
    render(<AlertPolicyPanel />);
    expect(await screen.findByText(/guessed from the first observation/)).toBeTruthy();
    expect(screen.getByText(/unexpected-transit check does not run/)).toBeTruthy();
  });

  it("stops saying it once the operator declares a set", async () => {
    render(<AlertPolicyPanel />);
    const origins = await screen.findByLabelText("Default expected origin AS");
    fireEvent.change(origins, { target: { value: "AS64500" } });
    await waitFor(() => expect(screen.queryByText(/guessed from the first observation/)).toBeNull());
  });

  it("PUTs exactly the declared policy and no tenant field", async () => {
    setBgpAlertConfig.mockResolvedValue({ ok: true, config: { default: { expected_origins: ["AS64500"] } } });
    render(<AlertPolicyPanel />);
    fireEvent.change(await screen.findByLabelText("Default expected origin AS"), { target: { value: "AS64500" } });
    fireEvent.change(screen.getByLabelText("Default minimum vantage points"), { target: { value: "3" } });
    fireEvent.click(screen.getByRole("button", { name: "Save rules" }));
    await waitFor(() => expect(setBgpAlertConfig).toHaveBeenCalledTimes(1));
    const body = setBgpAlertConfig.mock.calls[0][0];
    expect(body).toEqual({ default: { expected_origins: ["AS64500"], min_vantages: 3 } });
    expect(JSON.stringify(body)).not.toMatch(/tenant/i);
  });

  it("re-renders from the STORED policy the server answered with, not from what was typed", async () => {
    // The operator types a duplicate and a non-canonical prefix; the server
    // dedupes, sorts and canonicalizes. The screen must show the server's.
    setBgpAlertConfig.mockResolvedValue({
      ok: true,
      config: {
        default: { expected_origins: ["64500", "64501"] },
        prefixes: { "193.0.0.0/21": { min_vantages: 4 } },
      },
    });
    render(<AlertPolicyPanel />);
    fireEvent.change(await screen.findByLabelText("Default expected origin AS"),
      { target: { value: "AS64501, AS64500, AS64500" } });
    fireEvent.click(screen.getByRole("button", { name: "Save rules" }));
    await screen.findByText("Saved.");
    expect((screen.getByLabelText("Default expected origin AS") as HTMLInputElement).value).toBe("64500, 64501");
    expect((screen.getByLabelText("Prefix 1") as HTMLInputElement).value).toBe("193.0.0.0/21");
  });

  it("keeps the typed policy and shows the platform's own reason when the save is refused", async () => {
    setBgpAlertConfig.mockRejectedValue(new Error('400 Bad Request: {"error":"at most 32 ASNs per set"}'));
    render(<AlertPolicyPanel />);
    fireEvent.change(await screen.findByLabelText("Default upstream AS"), { target: { value: "AS3356" } });
    fireEvent.click(screen.getByRole("button", { name: "Save rules" }));
    expect(await screen.findByText(/at most 32 ASNs per set/i)).toBeTruthy();
    expect((screen.getByLabelText("Default upstream AS") as HTMLInputElement).value).toBe("AS3356");
  });

  it("refuses a 33rd AS number before the round trip", async () => {
    render(<AlertPolicyPanel />);
    const many = Array.from({ length: 33 }, (_, i) => `AS${i + 1}`).join(",");
    fireEvent.change(await screen.findByLabelText("Default expected origin AS"), { target: { value: many } });
    fireEvent.click(screen.getByRole("button", { name: "Save rules" }));
    expect(await screen.findByText(/At most 32 AS numbers per set/)).toBeTruthy();
    expect(setBgpAlertConfig).not.toHaveBeenCalled();
  });

  it("refuses a policy key that is not a prefix before the round trip", async () => {
    render(<AlertPolicyPanel />);
    fireEvent.click(await screen.findByRole("button", { name: "Add a rule for one prefix" }));
    fireEvent.change(screen.getByLabelText("Prefix 1"), { target: { value: "AS64500" } });
    fireEvent.click(screen.getByRole("button", { name: "Save rules" }));
    expect(await screen.findByText(/AS64500 is not a prefix/)).toBeTruthy();
    expect(setBgpAlertConfig).not.toHaveBeenCalled();
  });

  it("adds and removes a per-prefix policy, and counts them against the server's cap", async () => {
    render(<AlertPolicyPanel />);
    fireEvent.click(await screen.findByRole("button", { name: "Add a rule for one prefix" }));
    expect(screen.getByText(/1 of 200/)).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: /Remove the policy for prefix 1/ }));
    expect(screen.getByText(/0 of 200/)).toBeTruthy();
  });

  it("says a stored policy is not being evaluated while alerting is off", async () => {
    render(<AlertPolicyPanel status={{ enabled: false, note: "BGP alerting is off. Set FEATURE_BGP_ALERTS=true." }} />);
    expect(await screen.findByText(/BGP alerting is off/)).toBeTruthy();
    expect(screen.getByText(/stored either way/)).toBeTruthy();
    // ...and the editor is still usable: the intent is worth recording now.
    expect((screen.getByLabelText("Default expected origin AS") as HTMLInputElement).disabled).toBe(false);
  });

  it("renders an operator sentence when the policy could not be read", async () => {
    bgpAlertConfig.mockRejectedValue(new Error("500 Internal Server Error: clickhouse: dial tcp 10.0.0.5:9000"));
    render(<AlertPolicyPanel />);
    const alert = await screen.findByRole("alert");
    expect(alert.textContent).toMatch(/could not be read|did not answer/);
    expect(alert.textContent).not.toMatch(/dial tcp/);
  });

  it("does not offer a save until something changes", async () => {
    render(<AlertPolicyPanel />);
    await waitFor(() =>
      expect((screen.getByRole("button", { name: "Save rules" }) as HTMLButtonElement).disabled).toBe(true));
    fireEvent.change(screen.getByLabelText("Default minimum visibility"), { target: { value: "0.6" } });
    expect((screen.getByRole("button", { name: "Save rules" }) as HTMLButtonElement).disabled).toBe(false);
  });
});

describe("copy", () => {
  it("holds the NOC voice", () => {
    const here = dirname(fileURLToPath(import.meta.url));
    for (const f of ["AlertPolicyPanel.tsx", "bgpAlerts.model.ts"]) {
      expect(scanCopy(readFileSync(join(here, f), "utf8"), join("pages/bgp", f))).toEqual([]);
    }
  });
});

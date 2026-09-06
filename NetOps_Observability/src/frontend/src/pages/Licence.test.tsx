// Licence.test.tsx — the platform Licence page.
//
// WHAT THESE TESTS ARE FOR. A licence screen is read by two people: an operator
// working out why something will not admit one more device, and a customer
// checking they got what they paid for. Four failure modes matter more than the
// rest, and most of this file is about them:
//
//   1. A CEILING NOBODY COUNTED MUST NOT LOOK LIKE A MEASUREMENT. The page is
//      fed a payload with holes in it and asserts it says
//      "not measured — <reason>" — never a 0, never an empty bar.
//   2. AN UNLIMITED CEILING HAS NO BAR. A fill drawn against "no limit" is a
//      number nobody measured, and -1 must never reach the screen.
//   3. A LIMIT NOTHING GATES ON MUST NOT LOOK LIKE ONE THAT BITES. The five
//      carried-but-un-enforced ceilings say so, in place, next to their number.
//   4. A REFUSAL IS REPEATED WORD FOR WORD. Whoever is holding a licence we
//      will not accept needs the platform's exact reason, not "that request was
//      not accepted".
//
// Everything else — the degraded state and its overage list, admin gating, the
// public-key download, the landmarks and the copy guards — follows the same
// shape: build the state, assert the exact sentence an operator reads.
//
// FIFTH, since the 2026-09-05 read split: THE TENANT PROJECTION SHOWS A TENANT
// ONLY WHAT IS THEIRS. The same page renders two payloads — the provider view
// and a tenant's own — and the branch is the SERVER's `scope`, never the SPA's
// idea of who is looking. A tenant must see their tier, their features, their
// own usage and who to ask; they must not see the customer, the licence id, the
// support terms, the file path or the signing keys, and the page must not draw
// a "not measured" placeholder where those would have been.

import { describe, it, expect, vi, afterEach, beforeEach } from "vitest";
import { render, screen, cleanup, fireEvent, waitFor } from "@testing-library/react";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { scanCopy } from "../copyVoice.test";
import { scanForEngineVocabulary } from "../components/rca/vocabulary.test";
import type {
  LicenceCeiling, LicenceFeature, LicenceKey, LicenceOverage, LicenceState,
  LicenceUsageView, LicenceView, MeterValue,
} from "../services/api";

const mockApi = vi.hoisted(() => ({
  getLicence: vi.fn(),
  putLicence: vi.fn(),
  deleteLicence: vi.fn(),
  // The Usage section is a SECOND contract (internal/metering) on the same
  // page, so it is a second mock. A page that called it and got `undefined`
  // would throw before any of the licence assertions below ran.
  licenceUsage: vi.fn(),
  downloadLicenceUsageReport: vi.fn(),
}));
const mockUseAuth = vi.hoisted(() => vi.fn());

vi.mock("../services/api", () => ({ api: mockApi }));
vi.mock("../hooks/useAuth", () => ({ useAuth: mockUseAuth }));
vi.mock("../components/Icon", () => ({ default: () => <span /> }));

import Licence from "./Licence";

// ── fixtures (the wire shapes from internal/licence/api.go) ─────────────────

const COMMUNITY_CEILINGS = {
  devices: 25, tenants: 1, orgs: 1, retention_days: 7,
  watched_prefixes: 5, skills: 0, provider_tokens_per_day: 0,
};

function ceiling(over: Partial<LicenceCeiling> = {}): LicenceCeiling {
  return {
    name: "devices", label: "monitored devices", unit: "monitored_devices",
    limit: 25, current: 12, enforced: true, over: false, ...over,
  };
}

/** The seven-row table the server always sends, enforced pair first. */
function ceilings(): LicenceCeiling[] {
  return [
    ceiling({ name: "devices", label: "monitored devices", unit: "monitored_devices", limit: 25, current: 12 }),
    ceiling({ name: "watched_prefixes", label: "watched prefixes", limit: 5, current: 2 }),
    ceiling({ name: "tenants", label: "tenants", limit: 1, current: 1, enforced: false }),
    ceiling({
      name: "orgs", label: "organisations", limit: 1, current: null,
      current_reason: "the platform does not count organisations", enforced: false,
    }),
    ceiling({ name: "retention_days", label: "retention days", limit: 7, current: null, current_reason: "retention is not counted as a usage", enforced: false }),
    ceiling({ name: "skills", label: "Iris skills", limit: 0, current: null, current_reason: "skills are not counted yet", enforced: false }),
    ceiling({
      name: "provider_tokens_per_day", label: "provider tokens per day", limit: 0,
      current: null, current_reason: "provider spend is not counted on this platform", enforced: false,
    }),
  ];
}

function feature(over: Partial<LicenceFeature> = {}): LicenceFeature {
  return { name: "saml", label: "SAML single sign-on", entitled: false, included_in: "enterprise", ...over };
}

const KEY: LicenceKey = {
  id: "k-lab-1", role: "current", base64: "Q+PMj3/TNIjbRvopQwXLM5tJfgjzPTsoHIWwiM0apR8=",
  note: "lab key, issues trial licences only",
};

function state(over: Partial<LicenceState> = {}): LicenceState {
  return {
    source: "community", tier: "community", ceilings: COMMUNITY_CEILINGS,
    phase: "valid", in_grace: false, degraded: false, ...over,
  };
}

const VERIFY_HINT =
  "Verify a licence offline with: correlix-licence verify <file> — " +
  "or with the published public key: correlix-licence verify <file> --pubkey <key>";

const EXPIRY_NOTE =
  "Expiry semantics are an owner decision that is still open. Nothing is ever deleted, and no licence " +
  "state can affect tenant isolation, data separation, permissions or sign-in.";

/** internal/licence.ManagedByProviderDetail. */
const MANAGED_BY_DETAIL =
  "There is one licence file per installation and it covers every tenant on it, so installing or replacing " +
  "it is the provider's action. Everything shown here is what that single file puts in force for you.";

/** internal/licence.TenantScopeNote. */
const SCOPE_NOTE =
  "The ceilings are the whole installation's and are shared with every tenant on it. The usage beside them " +
  "counts only your tenant, so it is not the platform's total.";

function view(over: Partial<LicenceView> = {}): LicenceView {
  return {
    scope: "platform",
    managed_by: "provider",
    managed_by_detail: MANAGED_BY_DETAIL,
    state: state(),
    ceilings: ceilings(),
    features: [
      feature({ name: "security_findings", label: "security findings", included_in: "team" }),
      feature({ name: "saml", label: "SAML single sign-on", included_in: "enterprise" }),
    ],
    overages: [],
    keys: [KEY],
    path: "/data/licence/licence.json",
    verify_hint: VERIFY_HINT,
    expiry_semantics: EXPIRY_NOTE,
    days_to_expiry: null,
    grace_days_left: null,
    ...over,
  };
}

/** An installed Team licence, in force. */
function teamView(over: Partial<LicenceView> = {}): LicenceView {
  return view({
    state: state({
      source: "file", tier: "team", licensed_tier: "team",
      customer: "Acme Networks", licence_id: "lic-2026-0007",
      issued_at: "2026-01-01T00:00:00Z", expires_at: "2027-01-01T00:00:00Z",
      grace_days: 30, key_id: "k-lab-1",
      features: ["security_findings"],
      support: { level: "business hours", contact: "support@correlix.example" },
      ceilings: { ...COMMUNITY_CEILINGS, devices: 250, watched_prefixes: 100, tenants: 5 },
    }),
    ceilings: [
      ceiling({ name: "devices", label: "devices", limit: 250, current: 118 }),
      ceiling({ name: "watched_prefixes", label: "watched prefixes", limit: 100, current: 40 }),
      ...ceilings().slice(2),
    ],
    features: [
      feature({ name: "security_findings", label: "security findings", entitled: true, included_in: "team" }),
      feature({ name: "saml", label: "SAML single sign-on", entitled: false, included_in: "enterprise" }),
    ],
    days_to_expiry: 119,
    ...over,
  });
}

/**
 * The TENANT PROJECTION, exactly as internal/licence.tenantView builds it: the
 * same licence with this tenant's own usage, and with the provider's commercial
 * identity, file path and key material ABSENT — not blanked, absent. The
 * fixture omits those keys for the same reason the server does.
 */
function tenantProjection(over: Partial<LicenceView> = {}): LicenceView {
  return {
    scope: "tenant",
    tenant: "acme",
    managed_by: "provider",
    managed_by_detail: MANAGED_BY_DETAIL,
    scope_note: SCOPE_NOTE,
    state: state({
      source: "file", tier: "team", licensed_tier: "team",
      expires_at: "2027-01-01T00:00:00Z", grace_days: 30,
      features: ["security_findings"],
      ceilings: { ...COMMUNITY_CEILINGS, devices: 250, watched_prefixes: 100, tenants: 5 },
    }),
    ceilings: [
      ceiling({ name: "devices", label: "devices", limit: 250, current: 7 }),
      ceiling({ name: "watched_prefixes", label: "watched prefixes", limit: 100, current: 1 }),
      ...ceilings().slice(2),
    ],
    features: [
      feature({ name: "security_findings", label: "security findings", entitled: true, included_in: "team" }),
      feature({ name: "saml", label: "SAML single sign-on", entitled: false, included_in: "enterprise" }),
    ],
    overages: [],
    expiry_semantics: EXPIRY_NOTE,
    days_to_expiry: 119,
    ...over,
  };
}

const OVERAGE: LicenceOverage = {
  ceiling: "devices", label: "monitored devices", current: 30, limit: 25, over: 5, lifted_by: "team",
  message:
    "5 of 30 monitored devices are over the Community ceiling of 25 — they are still here and nothing has been deleted, " +
    "but 5 are not covered by the licence; the Team tier covers them",
};

// ── usage fixtures (the wire shapes from internal/metering) ─────────────────

function meterValue(over: Partial<MeterValue> & { meter: string }): MeterValue {
  return {
    value: 0, unit: "monitored_devices", source: "configuration", samples: 1, ...over,
  };
}

function usageView(over: Partial<LicenceUsageView> = {}): LicenceUsageView {
  return {
    scope: "platform",
    from: "2026-08-06", to: "2026-09-04",
    meter_definitions: [
      {
        name: "monitored_devices_unique", label: "Monitored devices (unique)",
        unit: "monitored_devices", kind: "entitlement", aggregation: "unique", scope: "any",
        doc: "Distinct devices with at least one collector enabled at any point in the day.",
      },
      {
        name: "monitored_devices_peak", label: "Monitored devices (peak)",
        unit: "monitored_devices", kind: "entitlement", aggregation: "peak", scope: "any",
        doc: "The highest number of monitored devices seen in a single sample that day.",
      },
      {
        name: "trace_accepted_spans", label: "Trace spans accepted",
        unit: "records", kind: "diagnostic", aggregation: "sum", scope: "installation",
        doc: "Trace spans that reached the trace store after processing.",
      },
    ],
    days: [
      {
        day: "2026-09-03", tenant_id: "", samples: 24, updated_at: "2026-09-03T23:00:00Z",
        meters: { monitored_devices_peak: meterValue({ meter: "monitored_devices_peak", value: 10 }) },
      },
      {
        day: "2026-09-04", tenant_id: "", samples: 12, updated_at: "2026-09-04T11:00:00Z",
        meters: { monitored_devices_peak: meterValue({ meter: "monitored_devices_peak", value: 12 }) },
      },
    ],
    totals: {
      from: "2026-08-06", to: "2026-09-04", days: 2,
      meters: [
        meterValue({ meter: "monitored_devices_unique", value: 14, samples: 36 }),
        meterValue({ meter: "monitored_devices_peak", value: 12, samples: 36 }),
        meterValue({
          meter: "trace_accepted_spans", value: null, unit: "records",
          source: "not_measured", samples: 0,
          reason: "no distributed-tracing pipeline is configured on this installation",
        }),
      ],
    },
    tenants: [
      { tenant_id: "", label: "the installation", days: 2, meters: [meterValue({ meter: "monitored_devices_unique", value: 14 })] },
      { tenant_id: "acme", label: "acme", days: 2, meters: [meterValue({ meter: "monitored_devices_unique", value: 9 })] },
    ],
    licence: { tier: "community", device_ceiling: 25 },
    last_snapshot: "2026-09-04T11:00:00Z",
    snapshot_note: "Usage is sampled hourly and rolled up by UTC day.",
    notes: ["Monitored devices are counted from configuration."],
    key: {
      id: "6a2c68c9ec2ac72e", base64: "TtEqRdOD3XkjHKGEACqOCa9r/kylZFkgWjMuGtjr9GQ=",
      created_at: "2026-09-05T00:00:00Z",
      note: "Generated by this installation and never sent anywhere.",
    },
    report_hint: "Verify a downloaded usage report offline with: correlix-licence usage-verify <file>",
    ...over,
  };
}

function setup(over: { view?: LicenceView | Error; usage?: LicenceUsageView | Error; platformAdmin?: boolean } = {}) {
  const v = over.view ?? view();
  mockApi.getLicence.mockReturnValue(v instanceof Error ? Promise.reject(v) : Promise.resolve(v));
  const u = over.usage ?? usageView();
  mockApi.licenceUsage.mockReturnValue(u instanceof Error ? Promise.reject(u) : Promise.resolve(u));
  mockApi.downloadLicenceUsageReport.mockResolvedValue("correlix-usage-2026-08-06_2026-09-04.json");
  mockUseAuth.mockReturnValue({
    user: { username: "root", platform_admin: over.platformAdmin ?? true },
    loading: false,
  });
}

beforeEach(() => { vi.setSystemTime(new Date("2026-09-04T12:00:00Z")); });
afterEach(() => { cleanup(); vi.clearAllMocks(); vi.useRealTimers(); });

// ── 1 · the licence headline ────────────────────────────────────────────────

describe("the licence headline", () => {
  it("Community reads as the free tier, not as a fault", async () => {
    setup();
    render(<Licence />);
    // "Community" is the headline state, the state chip and the tier in force,
    // so it is deliberately on the page three times.
    expect((await screen.findAllByText("Community")).length).toBe(3);
    expect(screen.getByText(/free tier, not a fault state/)).toBeTruthy();
  });

  it("with no licence, every licence fact says WHY it is absent rather than showing a blank", async () => {
    setup();
    render(<Licence />);
    expect(await screen.findByText("not measured — no licence names a customer on this platform")).toBeTruthy();
    expect(screen.getByText("not measured — no licence is installed")).toBeTruthy();
    expect(screen.getByText("not measured — no licence is installed, so no grace period applies")).toBeTruthy();
    expect(screen.getByText("No expiry — Community ceilings do not lapse")).toBeTruthy();
  });

  it("an installed Team licence names the customer, the licence and the expiry", async () => {
    setup({ view: teamView() });
    render(<Licence />);
    expect(await screen.findByText("Team licence")).toBeTruthy();
    expect(screen.getByText("Acme Networks")).toBeTruthy();
    expect(screen.getByText("lic-2026-0007")).toBeTruthy();
    expect(screen.getByText("expires in 119 days")).toBeTruthy();
    expect(screen.getByText("30 days, set by the issuer")).toBeTruthy();
    expect(screen.getByText("business hours")).toBeTruthy();
  });

  it("a licence the platform REFUSED is the loudest thing on the page", async () => {
    setup({
      view: view({
        state: state({ load_error: "signature does not verify against any trusted key" }),
      }),
    });
    render(<Licence />);
    expect(await screen.findByText("Installed licence refused")).toBeTruthy();
    expect(screen.getByText("A licence is installed, and the platform will not use it.")).toBeTruthy();
    // The reason is the headline's own sentence AND the remedy's first clause.
    expect(screen.getAllByText(/signature does not verify against any trusted key/).length).toBe(2);
  });

  it("a degraded licence says which ceilings are in force and lists every overage", async () => {
    setup({
      view: view({
        state: state({
          source: "file", tier: "community", licensed_tier: "team",
          customer: "Acme Networks", licence_id: "lic-2026-0007",
          expires_at: "2026-06-01T00:00:00Z", phase: "post_grace", degraded: true, grace_days: 30,
          reason: "expired on 2026-06-01 and its 30-day grace period has passed",
        }),
        overages: [OVERAGE],
        days_to_expiry: -95,
      }),
    });
    render(<Licence />);
    expect(await screen.findByText("Past grace — running at Community ceilings")).toBeTruthy();
    // …and the state chip says what stopped and what did not.
    expect(screen.getByText("Past grace")).toBeTruthy();
    expect(screen.getByText("expired on 2026-06-01 and its 30-day grace period has passed")).toBeTruthy();
    expect(screen.getByText("expired 95 days ago — past its grace period")).toBeTruthy();
    // The overage list, verbatim, with the reassurance ahead of it.
    expect(screen.getByText(/nothing has been removed/)).toBeTruthy();
    expect(screen.getByText(OVERAGE.message)).toBeTruthy();
    expect(screen.getByText("5 over")).toBeTruthy();
    // The tier the file names is kept beside the tier in force — the customer
    // was not always Community and the page must not pretend they were.
    expect(screen.getByText("the licence names Team")).toBeTruthy();
  });

  it("inside grace, the page warns without claiming the licence has stopped working", async () => {
    setup({
      view: view({
        state: state({
          source: "file", tier: "team", licensed_tier: "team", customer: "Acme Networks",
          licence_id: "lic-2026-0007", expires_at: "2026-09-01T00:00:00Z",
          phase: "in_grace", in_grace: true, grace_days: 30,
          grace_ends_at: "2026-10-01T00:00:00Z", reason: "expired 3 days ago",
        }),
        days_to_expiry: -3,
        grace_days_left: 27,
      }),
    });
    render(<Licence />);
    expect(await screen.findByText("In grace")).toBeTruthy();
    // The chip carries the RUNWAY, from the server's own count — this page and
    // the metric can never disagree by a timezone.
    expect(screen.getByText("In grace · 27 days left")).toBeTruthy();
    expect(screen.getByText("expired 3 days ago — inside a 30-day grace period")).toBeTruthy();
  });
});

// ── 2 · current usage ───────────────────────────────────────────────────────

describe("current usage", () => {
  it("counts what it counts, against the licensed limit", async () => {
    setup();
    render(<Licence />);
    expect(await screen.findByText("12 of 25")).toBeTruthy();
    expect(screen.getByText("2 of 5")).toBeTruthy();
    expect(screen.getByText("Licensed limit 25.")).toBeTruthy();
  });

  it("says monitored devices, never just devices", async () => {
    // The C4 unit. A bar labelled "devices" against an inventory of 500 would
    // read as a limit on inventory rows, which is the misreading this label
    // exists to stop.
    setup();
    render(<Licence />);
    // findAll, not find: the Usage section below states the same unit beside its
    // own numbers, and that agreement is the point rather than a collision.
    expect((await screen.findAllByText("monitored devices")).length).toBeGreaterThan(0);
  });

  it("qualifies a MEASURED number when the ceiling is holding devices back", async () => {
    // "25 of 25" beside a network of forty is true and useless on its own.
    const note = "10 more device(s) are in the inventory and would be monitored, but the ceiling is full — " +
      "they are still discovered, still visible and nothing has been deleted; " +
      "raise the licence or turn monitoring off elsewhere to start collecting from them";
    const rows = ceilings();
    rows[0] = ceiling({ current: 25, note });
    setup({ view: view({ ceilings: rows }) });
    render(<Licence />);
    expect(await screen.findByText(note)).toBeTruthy();
  });

  it("a ceiling nobody counts shows the reason, never a zero", async () => {
    setup();
    render(<Licence />);
    expect(await screen.findByText("not measured — the platform does not count organisations")).toBeTruthy();
    expect(screen.getByText("not measured — provider spend is not counted on this platform")).toBeTruthy();
    expect(screen.queryByText("0 of 1")).toBeNull();
    expect(screen.queryByText("0 of 0")).toBeNull();
  });

  it("draws NO bar for a ceiling nobody counted", async () => {
    setup();
    const { container } = render(<Licence />);
    await screen.findByText("12 of 25");
    const rows = container.querySelectorAll(".lic-usage-row");
    expect(rows.length).toBe(7);
    // Two enforced rows are counted; the other five are not, so exactly two
    // fills exist. A fill on an uncounted row would be an invented number.
    expect(container.querySelectorAll(".lic-bar-fill").length).toBe(2);
    // The track is still on every row, so nothing shifts between reads.
    expect(container.querySelectorAll(".lic-bar").length).toBe(7);
    // The un-enforced "tenants" row IS counted (1 of 1) and still gets no fill:
    // a full bar on a limit nothing gates on would read as a live gate.
    const tenants = [...container.querySelectorAll(".lic-usage-row")]
      .find((r) => r.textContent?.includes("tenants")) as HTMLElement;
    expect(tenants.textContent).toContain("1 of 1");
    expect(tenants.querySelector(".lic-bar-fill")).toBeNull();
  });

  it("an unlimited ceiling shows the count in use and no bar — never -1", async () => {
    setup({
      view: view({
        ceilings: [ceiling({ name: "devices", label: "devices", limit: -1, current: 900 })],
      }),
    });
    const { container } = render(<Licence />);
    expect(await screen.findByText("900 in use · no limit")).toBeTruthy();
    expect(screen.getByText("This licence sets no limit here.")).toBeTruthy();
    expect(container.querySelectorAll(".lic-bar-fill").length).toBe(0);
    const usage = container.querySelector('[data-section="usage"]') as HTMLElement;
    expect(usage.textContent).not.toContain("-1");
  });

  it("a limit nothing gates on says so, in place, beside its number", async () => {
    setup();
    render(<Licence />);
    expect((await screen.findAllByText("carried, not enforced")).length).toBe(5);
    expect(screen.getAllByText(/nothing in the product gates on it today/).length).toBe(5);
  });

  it("over an enforced ceiling is marked on the row itself", async () => {
    setup({
      view: view({
        ceilings: [ceiling({ current: 30, limit: 25, over: true })],
        overages: [OVERAGE],
      }),
    });
    render(<Licence />);
    // The band pill replaced the old flat "over the ceiling" wording on
    // 2026-09-05 with the 80 / 90 / 100 % ramp.
    expect(await screen.findByText("over the allowance")).toBeTruthy();
    expect(screen.getByText("30 of 25")).toBeTruthy();
    // A HARD ceiling must not be described as a limit that does not block.
    expect(screen.getByText(/hard limit/)).toBeTruthy();
  });

  it("puts what actually gates at the top of the list", async () => {
    setup();
    const { container } = render(<Licence />);
    await screen.findByText("12 of 25");
    const names = [...container.querySelectorAll(".lic-usage-name")].map((n) => n.textContent);
    expect(names.slice(0, 2)).toEqual(["monitored devices", "watched prefixes"]);
  });

  it("names the tier that would lift a ceiling", async () => {
    setup({
      view: view({ ceilings: [ceiling({ lifted_by: "team" })] }),
    });
    const { container } = render(<Licence />);
    await screen.findByText("12 of 25");
    const usage = container.querySelector('[data-section="usage"]') as HTMLElement;
    expect(usage.textContent).toContain("Included in Team");
  });
});

// ── 3 · features ────────────────────────────────────────────────────────────

describe("features", () => {
  it("says which capabilities this licence grants and which tier has the rest", async () => {
    setup({ view: teamView() });
    render(<Licence />);
    expect(await screen.findByText("security findings")).toBeTruthy();
    expect(screen.getByText("Included")).toBeTruthy();
    expect(screen.getByText("SAML single sign-on")).toBeTruthy();
    expect(screen.getByText("Included in Enterprise")).toBeTruthy();
  });

  it("on Community nothing is claimed as included", async () => {
    setup();
    render(<Licence />);
    await screen.findByText("security findings");
    expect(screen.queryByText("Included")).toBeNull();
    expect(screen.getByText("Included in Team")).toBeTruthy();
  });
});

// ── 4 · installing ──────────────────────────────────────────────────────────

describe("installing a licence", () => {
  it("sends the pasted document byte for byte, and reports what landed", async () => {
    setup();
    mockApi.putLicence.mockResolvedValue(teamView());
    render(<Licence />);
    const box = await screen.findByLabelText("Licence document");
    fireEvent.change(box, { target: { value: '  {"licence_id":"lic-2026-0007"}  ' } });
    fireEvent.click(screen.getByRole("button", { name: "Install licence" }));
    await waitFor(() => expect(mockApi.putLicence).toHaveBeenCalledWith('{"licence_id":"lic-2026-0007"}'));
    expect(await screen.findByText("Installed lic-2026-0007 — Team.")).toBeTruthy();
    // The whole page now describes the licence that was just installed.
    expect(screen.getByText("Acme Networks")).toBeTruthy();
  });

  it("shows the platform's refusal WORD FOR WORD", async () => {
    setup();
    mockApi.putLicence.mockRejectedValue(
      new Error('400 Bad Request: {"error":"licence expired on 2026-01-01 and its 30-day grace period has passed"}'),
    );
    render(<Licence />);
    fireEvent.change(await screen.findByLabelText("Licence document"), { target: { value: "{}" } });
    fireEvent.click(screen.getByRole("button", { name: "Install licence" }));
    expect(await screen.findByText("licence expired on 2026-01-01 and its 30-day grace period has passed")).toBeTruthy();
    expect(screen.getByText("The platform refused that licence.")).toBeTruthy();
    expect(screen.getByText(/Nothing in force was touched/)).toBeTruthy();
    // Not softened into the generic sentence the rest of the product uses.
    expect(screen.queryByText("That request was not accepted.")).toBeNull();
  });

  it("a refusal with no explanation says that, rather than inventing one", async () => {
    setup();
    mockApi.putLicence.mockRejectedValue(new Error("400 Bad Request: "));
    render(<Licence />);
    fireEvent.change(await screen.findByLabelText("Licence document"), { target: { value: "{}" } });
    fireEvent.click(screen.getByRole("button", { name: "Install licence" }));
    expect(await screen.findByText("The platform did not say why it refused that document.")).toBeTruthy();
  });

  it("will not send an empty document", async () => {
    setup();
    render(<Licence />);
    await screen.findByLabelText("Licence document");
    expect((screen.getByRole("button", { name: "Install licence" }) as HTMLButtonElement).disabled).toBe(true);
    expect(mockApi.putLicence).not.toHaveBeenCalled();
  });

  it("removing a licence is type-to-confirm on the licence's own id", async () => {
    setup({ view: teamView() });
    mockApi.deleteLicence.mockResolvedValue(view());
    render(<Licence />);
    fireEvent.click(await screen.findByRole("button", { name: "Remove licence…" }));
    expect(screen.getByText("Removing the licence drops the platform to the Community ceilings.")).toBeTruthy();
    const go = screen.getByRole("button", { name: "Remove licence" }) as HTMLButtonElement;
    expect(go.disabled).toBe(true);
    fireEvent.change(screen.getByLabelText("Type lic-2026-0007 to confirm removing the licence"), {
      target: { value: "lic-2026-0007" },
    });
    expect((screen.getByRole("button", { name: "Remove licence" }) as HTMLButtonElement).disabled).toBe(false);
    fireEvent.click(screen.getByRole("button", { name: "Remove licence" }));
    await waitFor(() => expect(mockApi.deleteLicence).toHaveBeenCalled());
    expect(await screen.findByText("The licence was removed. The Community ceilings are now the ones in force.")).toBeTruthy();
  });

  it("says what removal does NOT do, before it is confirmed", async () => {
    setup({ view: teamView() });
    render(<Licence />);
    fireEvent.click(await screen.findByRole("button", { name: "Remove licence…" }));
    expect(screen.getByText(/No data is deleted and nothing stops collecting/)).toBeTruthy();
  });

  it("names the place a licence can be dropped by hand", async () => {
    setup();
    render(<Licence />);
    expect(await screen.findByText("/data/licence/licence.json")).toBeTruthy();
  });

  it("offers no remove control when there is nothing installed", async () => {
    setup();
    render(<Licence />);
    await screen.findByLabelText("Licence document");
    expect(screen.queryByRole("button", { name: "Remove licence…" })).toBeNull();
  });
});

// ── 5 · verification ────────────────────────────────────────────────────────

describe("verification", () => {
  it("shows the offline recipe verbatim", async () => {
    setup();
    render(<Licence />);
    expect(await screen.findByText(VERIFY_HINT)).toBeTruthy();
  });

  it("hands over the public key as a file that still says what it is", async () => {
    const saved: { name: string; body: string }[] = [];
    const created: string[] = [];
    vi.stubGlobal("URL", {
      createObjectURL: (b: Blob) => { created.push(String(b.type)); return "blob:key"; },
      revokeObjectURL: () => {},
    });
    // The anchor's click must not navigate happy-dom; capture the intent instead.
    const realCreate = document.createElement.bind(document);
    vi.spyOn(document, "createElement").mockImplementation((tag: string) => {
      const el = realCreate(tag);
      if (tag === "a") Object.defineProperty(el, "click", { value: () => saved.push({ name: (el as HTMLAnchorElement).download, body: "" }) });
      return el;
    });
    setup();
    render(<Licence />);
    fireEvent.click(await screen.findByRole("button", { name: /Download public key/ }));
    expect(saved.map((s) => s.name)).toEqual(["correlix-licence-k-lab-1.pub"]);
    expect(created).toEqual(["text/plain"]);
    expect(await screen.findByText("Saved correlix-licence-k-lab-1.pub.")).toBeTruthy();
    vi.unstubAllGlobals();
  });

  it("shows the key itself and what its role is FOR", async () => {
    setup();
    render(<Licence />);
    expect(await screen.findByText(KEY.base64)).toBeTruthy();
    expect(screen.getByText("Signs new licences")).toBeTruthy();
    expect(screen.getByText("lab key, issues trial licences only")).toBeTruthy();
  });

  it("a build trusting no key says no licence can be installed at all", async () => {
    setup({ view: view({ keys: [] }) });
    render(<Licence />);
    expect(await screen.findByText("This build trusts no signing key.")).toBeTruthy();
    expect(screen.getByText(/Report it with the platform version/)).toBeTruthy();
  });

  it("carries the standing note that expiry policy is still open", async () => {
    setup();
    render(<Licence />);
    expect(await screen.findByText(EXPIRY_NOTE)).toBeTruthy();
    expect(screen.getByText("What expiry does, and what it never does")).toBeTruthy();
  });
});

// ── 6 · gating and failure ──────────────────────────────────────────────────

describe("the tenant projection", () => {
  it("a tenant admin sees the licence read-only and is told who may change it", async () => {
    setup({ view: tenantProjection(), platformAdmin: false });
    render(<Licence />);
    // Said twice on purpose: once beside the licence itself, and again where
    // the install controls would have been.
    expect(await screen.findByText("Team licence")).toBeTruthy();
    await waitFor(() => expect(screen.getAllByText("You are seeing this licence read-only.").length).toBe(2));
    expect(screen.getAllByText(MANAGED_BY_DETAIL).length).toBe(2);
    expect(screen.getByText("Managed by")).toBeTruthy();
    expect(screen.getByText("provider")).toBeTruthy();
  });

  it("is shown no control that would be refused", async () => {
    setup({ view: tenantProjection(), platformAdmin: false });
    render(<Licence />);
    await screen.findByText("Team licence");
    expect(screen.queryByLabelText("Licence document")).toBeNull();
    expect(screen.queryByLabelText("Licence file to install")).toBeNull();
    expect(screen.queryByRole("button", { name: "Install licence" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Remove licence…" })).toBeNull();
  });

  it("shows the tenant's OWN usage, and says so, rather than the platform total", async () => {
    setup({ view: tenantProjection(), platformAdmin: false });
    render(<Licence />);
    expect(await screen.findByText("7 of 250")).toBeTruthy();
    expect(screen.getByText("1 of 100")).toBeTruthy();
    expect(screen.getByText(SCOPE_NOTE)).toBeTruthy();
    expect(screen.getByText("These numbers count your tenant only.")).toBeTruthy();
  });

  it("shows the tier and the features in force, which is what the tenant came for", async () => {
    setup({ view: tenantProjection(), platformAdmin: false });
    render(<Licence />);
    expect(await screen.findByText("Team licence")).toBeTruthy();
    // "Team" is the tier pill AND the tier that lifts several ceilings.
    expect(screen.getAllByText("Team").length).toBeGreaterThan(0);
    expect(screen.getByText("expires in 119 days")).toBeTruthy();
    expect(screen.getByText("30 days, set by the issuer")).toBeTruthy();
    expect(screen.getByText("security findings")).toBeTruthy();
  });

  it("omits the provider's commercial identity instead of drawing a hole where it was", async () => {
    setup({ view: tenantProjection(), platformAdmin: false });
    const { container } = render(<Licence />);
    await screen.findByText("Team licence");
    // Absent, not "not measured": the platform knows the customer perfectly
    // well, it is simply not this reader's business. Assert the fact grid
    // itself, so a section heading called "Licence" cannot mask the check.
    expect([...container.querySelectorAll(".lic-facts dt")].map((d) => d.textContent))
      .toEqual(["Tier in force", "Expiry", "Grace period", "Managed by"]);
    expect(screen.queryByText(/no licence names a customer/)).toBeNull();
    expect(screen.queryByText(/no licence is installed/)).toBeNull();
    // No key material, no offline recipe, no host path.
    expect(screen.queryByText(VERIFY_HINT)).toBeNull();
    expect(screen.queryByText(KEY.base64)).toBeNull();
    expect(screen.queryByRole("button", { name: /Download public key/ })).toBeNull();
    expect(screen.queryByRole("region", { name: "Verification" })).toBeNull();
  });

  it("still carries the standing note about what expiry can never do", async () => {
    setup({ view: tenantProjection(), platformAdmin: false });
    render(<Licence />);
    expect(await screen.findByText(EXPIRY_NOTE)).toBeTruthy();
    expect(screen.getByRole("region", { name: "Expiry" })).toBeTruthy();
  });

  it("a REFUSED licence still reaches the tenant, without the forensics", async () => {
    const refusal =
      "the licence installed on this platform was refused, so the Community ceilings are the ones in force — " +
      "ask your provider";
    setup({
      view: tenantProjection({ state: state({ load_error: refusal }) }),
      platformAdmin: false,
    });
    render(<Licence />);
    expect(await screen.findByText("Installed licence refused")).toBeTruthy();
    expect(screen.getAllByText(new RegExp(refusal)).length).toBeGreaterThan(0);
  });

  it("the platform owner narrowed into a tenant is told how to get the controls back", async () => {
    setup({ view: tenantProjection(), platformAdmin: true });
    render(<Licence />);
    await screen.findByText("Team licence");
    expect(screen.getByText(/return to the Global view to install or replace it/)).toBeTruthy();
  });
});

describe("the provider view", () => {
  it("keeps the whole licence, the keys and the controls", async () => {
    setup({ view: teamView() });
    render(<Licence />);
    expect(await screen.findByText("Team licence")).toBeTruthy();
    expect(screen.getByText("Acme Networks")).toBeTruthy();
    expect(screen.getByText("118 of 250")).toBeTruthy();
    expect(screen.getByText(VERIFY_HINT)).toBeTruthy();
    expect(screen.getByLabelText("Licence document")).toBeTruthy();
    // The platform bar is the installation's, so it carries no tenant note.
    expect(screen.queryByText("These numbers count your tenant only.")).toBeNull();
  });
});

describe("a read that failed", () => {
  it("every section says it cannot describe the licence, and none pretends otherwise", async () => {
    setup({ view: new Error("500 Internal Server Error: {}") });
    render(<Licence />);
    const errs = await screen.findAllByText("The service did not answer.");
    expect(errs.length).toBe(5);
    expect(screen.queryAllByText("Community")).toEqual([]);
    expect(screen.getAllByText(/Nothing in this part of the page is a statement about the licence/).length).toBe(5);
  });

  it("offers a re-read from the failed panel itself", async () => {
    setup({ view: new Error("500 Internal Server Error: {}") });
    render(<Licence />);
    const again = (await screen.findAllByRole("button", { name: "Read it again" }))[0];
    mockApi.getLicence.mockResolvedValue(view());
    fireEvent.click(again);
    expect((await screen.findAllByText("Community")).length).toBe(3);
  });
});

// ── 7 · accessibility + copy guards ─────────────────────────────────────────

describe("accessibility", () => {
  it("every part of the page is a named landmark", async () => {
    setup();
    render(<Licence />);
    for (const name of ["Licence", "Current usage", "Features", "Install a licence", "Verification"]) {
      expect(await screen.findByRole("region", { name })).toBeTruthy();
    }
  });

  it("each section carries a stable id a link or a test can aim at", async () => {
    setup();
    const { container } = render(<Licence />);
    await screen.findAllByText("Community");
    expect([...container.querySelectorAll("[data-section]")].map((s) => s.getAttribute("data-section")))
      .toEqual(["licence", "usage", "metering", "features", "install", "verification"]);
  });

  it("the tenant projection keeps the same landmarks, with Expiry where Verification was", async () => {
    setup({ view: tenantProjection(), platformAdmin: false });
    const { container } = render(<Licence />);
    await screen.findByText("Team licence");
    expect([...container.querySelectorAll("[data-section]")].map((s) => s.getAttribute("data-section")))
      .toEqual(["licence", "usage", "metering", "features", "install", "expiry"]);
    for (const name of ["Licence", "Current usage", "Features", "Changing this licence", "Expiry"]) {
      expect(screen.getByRole("region", { name })).toBeTruthy();
    }
  });

  it("every control the operator types into carries a label", async () => {
    setup({ view: teamView() });
    render(<Licence />);
    expect(await screen.findByLabelText("Licence document")).toBeTruthy();
    expect(screen.getByLabelText("Licence file to install")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Remove licence…" }));
    expect(screen.getByLabelText("Type lic-2026-0007 to confirm removing the licence")).toBeTruthy();
  });
});

describe("copy guards on this page's own sources", () => {
  const here = dirname(fileURLToPath(import.meta.url));
  const files = ["Licence.tsx", "licence.model.ts"];

  it("shows no denied developer-speak", () => {
    const hits = files.flatMap((f) => scanCopy(readFileSync(join(here, f), "utf-8"), `pages/${f}`));
    expect(hits, hits.join("\n")).toEqual([]);
  });

  it("never puts the engine word on screen", () => {
    const hits = files.flatMap((f) => scanForEngineVocabulary(readFileSync(join(here, f), "utf-8"), `pages/${f}`));
    expect(hits, hits.join("\n")).toEqual([]);
  });

  it("never renders the -1 sentinel or a machine token as copy", () => {
    const src = files.map((f) => readFileSync(join(here, f), "utf-8")).join("\n");
    for (const token of ["licence_ceiling", "licence_feature", "not_applicable"]) {
      expect(src).not.toContain(`>${token}<`);
    }
  });
});

// ── soft overage, the state chip and the over-ceiling device list ───────────
//
// These are the 2026-09-05 owner decisions rendered: a paid allowance that does
// not block, an evaluation licence that says how long is left, and the devices
// beyond the allowance — LISTED, with the page saying in the server's own words
// that none of them was disabled.

describe("soft overage on a paid tier", () => {
  const softCeiling = ceiling({
    name: "devices", label: "monitored devices", unit: "monitored_devices",
    limit: 250, current: 262, over: true, soft: true, enforced: true,
  });
  const softOverage = {
    ceiling: "devices", label: "monitored devices", unit: "monitored_devices",
    current: 262, limit: 250, over: 12, soft: true,
    since: "2026-09-01T00:00:00Z",
    message: "12 monitored devices above your Team allowance of 250 (262 in use). " +
      "Monitoring continues — nothing has been blocked, disabled or deleted; the overage is recorded for true-up",
  };

  it("says the allowance does not block, and never that anything stopped", async () => {
    setup({ view: teamView({ ceilings: [softCeiling], overages: [softOverage] }) });
    render(<Licence />);
    // The row says it on the bar, where the operator is looking.
    expect(await screen.findByText("soft — recorded, not blocked")).toBeTruthy();
    expect(screen.getByText("over the allowance")).toBeTruthy();
    expect(screen.getByText("262 of 250")).toBeTruthy();
    expect(screen.getByText(/does not block/)).toBeTruthy();
    // And the banner is a billing sentence, not a fault. The phrase appears
    // twice on purpose — once in the summary and once in the server's own
    // per-ceiling message — so both are asserted rather than one of them.
    expect(screen.getAllByText(/nothing has been blocked, disabled or deleted/).length).toBe(2);
    expect(screen.getByText(softOverage.message)).toBeTruthy();
    expect(screen.getByText("12 above")).toBeTruthy();
  });

  it("states when the overage began, and invents no deadline", async () => {
    setup({ view: teamView({ ceilings: [softCeiling], overages: [softOverage] }) });
    render(<Licence />);
    expect(await screen.findByText(/Recorded since 2026-09-01/)).toBeTruthy();
    // How long an overage may run is an order-form term. The page must not
    // contain a countdown of its own.
    expect(screen.queryByText(/days remaining/)).toBeNull();
    expect(screen.queryByText(/will be disabled/)).toBeNull();
  });

  it("lists WHICH devices are beyond the allowance, and that they are still monitored", async () => {
    setup({
      view: teamView({
        ceilings: [softCeiling],
        overages: [softOverage],
        over_ceiling_devices: [
          { device_id: "leaf-260", name: "leaf-260", reason: "monitored and beyond the licensed allowance of 250 monitored devices — still being collected from; nothing has been disabled, hidden or deleted" },
        ],
        over_ceiling_note: "These are the monitored devices beyond the licensed allowance. Correlix does not choose which devices a licence covers.",
      }),
    });
    render(<Licence />);
    expect(await screen.findByText("1 monitored device(s) beyond the allowance")).toBeTruthy();
    expect(screen.getByText("leaf-260")).toBeTruthy();
    expect(screen.getByText("still monitored")).toBeTruthy();
    expect(screen.getByText(/Correlix does not choose which devices a licence covers/)).toBeTruthy();
  });
});

describe("an evaluation licence", () => {
  it("names itself a trial and counts the days left", async () => {
    setup({
      view: teamView({
        state: state({
          source: "file", tier: "team", licensed_tier: "team", customer: "Acme Networks",
          expires_at: "2026-10-01T00:00:00Z", phase: "valid", trial: true, grace_days: 7,
        }),
        days_to_expiry: 12,
      }),
    });
    render(<Licence />);
    expect(await screen.findByText("Team evaluation licence")).toBeTruthy();
    expect(screen.getByText("Evaluation licence · 12 days left")).toBeTruthy();
  });
});

// ── the Usage section (metering, tracker 258) ───────────────────────────────
//
// A second contract on the same page, and the same governing rule: a meter with
// no counter is "not measured — <reason>", NEVER a zero. These tests are mostly
// about that, plus the two things a customer actually does here — read what
// their fleet cost them, and download a document they can check without us.

describe("recorded usage", () => {
  it("shows the monitored-device line in the tiering plan's own words", async () => {
    setup();
    render(<Licence />);
    // "Monitoring: N / 25 …" against the ceiling, and the sentence that stops a
    // customer believing a discovery sweep spent their allowance.
    expect(await screen.findByText(/Monitoring: 12 \/ 25 Community monitored devices\./)).toBeTruthy();
    expect(screen.getByText(/Discovery does not consume your monitoring allowance\./)).toBeTruthy();
  });

  it("never renders an unmeasured meter as a zero", async () => {
    setup();
    render(<Licence />);
    expect(await screen.findByText(
      "not measured — no distributed-tracing pipeline is configured on this installation",
    )).toBeTruthy();
  });

  it("separates the meters that bound an entitlement from the ones that cost nothing", async () => {
    setup();
    render(<Licence />);
    expect(await screen.findByText("Entitlement meters")).toBeTruthy();
    expect(screen.getByText("Diagnostic meters")).toBeTruthy();
    // The CLAIM — a diagnostic meter costs nothing — is unchanged. The sentence
    // that explained why moved to ai/skills/explain/licence.diagnostic-meters.md,
    // so the (i) that reaches it is pinned beside the claim.
    expect(screen.getByText(/Nothing here is charged for\./)).toBeTruthy();
    expect(screen.getByRole("button", { name: /Ask Iris about diagnostic meters/ })).toBeTruthy();
  });

  it("shows the per-tenant breakdown to the platform owner, and names the installation row", async () => {
    setup();
    render(<Licence />);
    expect(await screen.findByText("By tenant")).toBeTruthy();
    expect(screen.getByText("the installation")).toBeTruthy();
    expect(screen.getByText("acme")).toBeTruthy();
  });

  it("shows a tenant only their own numbers, with no breakdown of anyone else's", async () => {
    setup({
      view: tenantProjection(),
      platformAdmin: false,
      usage: usageView({
        scope: "tenant", tenant: "acme", tenants: undefined,
        scope_note: "These are your tenant's numbers only.",
      }),
    });
    render(<Licence />);
    await screen.findByText("Team licence");
    expect(screen.queryByText("By tenant")).toBeNull();
    expect(screen.queryByText("the installation")).toBeNull();
  });

  it("offers the signed report, naming the key it will carry and what that key is not", async () => {
    setup();
    render(<Licence />);
    expect(await screen.findByRole("button", { name: /Download signed usage report/ })).toBeTruthy();
    expect(screen.getByText("6a2c68c9ec2ac72e")).toBeTruthy();
    expect(screen.getByText(/never sent anywhere/)).toBeTruthy();
    expect(screen.getByText(/correlix-licence usage-verify/)).toBeTruthy();
  });

  it("asks the platform for the period the picker is on", async () => {
    setup();
    render(<Licence />);
    await screen.findByText("Entitlement meters");
    expect(mockApi.licenceUsage).toHaveBeenCalledWith({ from: "2026-08-06", to: "2026-09-04" });

    fireEvent.change(screen.getByLabelText("Period"), { target: { value: "7d" } });
    await waitFor(() =>
      expect(mockApi.licenceUsage).toHaveBeenCalledWith({ from: "2026-08-29", to: "2026-09-04" }));

    fireEvent.click(screen.getByRole("button", { name: /Download signed usage report/ }));
    await waitFor(() =>
      expect(mockApi.downloadLicenceUsageReport).toHaveBeenCalledWith({ from: "2026-08-29", to: "2026-09-04" }));
  });

  it("says a refused download was refused, in the platform's words", async () => {
    setup();
    mockApi.downloadLicenceUsageReport.mockRejectedValue(
      new Error("The usage report could not be produced: 503 no signing key"),
    );
    render(<Licence />);
    fireEvent.click(await screen.findByRole("button", { name: /Download signed usage report/ }));
    expect(await screen.findByText("The usage report was not produced.")).toBeTruthy();
    expect(screen.getByText(/no signing key/)).toBeTruthy();
  });

  it("says the history could not be read, rather than drawing an empty period", async () => {
    setup({
      usage: usageView({
        store_error: "the usage history could not be read, so the period below is not the full picture",
      }),
    });
    render(<Licence />);
    expect(await screen.findByText("The recorded usage could not be read.")).toBeTruthy();
  });

  it("says nothing has been recorded yet, which is not the same as nothing in use", async () => {
    setup({
      usage: usageView({
        last_snapshot: null,
        days: [],
        totals: { from: "2026-08-06", to: "2026-09-04", days: 0, meters: [] },
        tenants: [],
      }),
    });
    render(<Licence />);
    expect(await screen.findByText("Nothing recorded yet.")).toBeTruthy();
    expect(screen.getByText(/which is not the same as nothing being in use/)).toBeTruthy();
  });

  it("keeps the Usage section up when the licence read fails, and the other way round", async () => {
    setup({ view: new Error("500 Internal Server Error: {}") });
    render(<Licence />);
    // The licence sections say they cannot describe the licence…
    expect((await screen.findAllByText("The service did not answer.")).length).toBe(5);
    // …and the usage section still reports what was actually used.
    expect(screen.getByText("Entitlement meters")).toBeTruthy();
  });
});

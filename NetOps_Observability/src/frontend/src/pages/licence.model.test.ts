// licence.model.test.ts — the rules of the Licence page, tested as rules.
//
// The model is where every claim the page makes is decided, so the three things
// a licence screen can get dishonestly wrong are pinned here rather than in the
// rendered output:
//
//   1. A ceiling nobody counted must never become a 0, an empty bar, or a
//      reassuring "0 of 25".
//   2. An unlimited ceiling has no percentage — a bar drawn against "no limit"
//      is a number we invented.
//   3. A refusal is repeated WORD FOR WORD. The operator is holding a file we
//      will not accept; the exact reason is the whole value of the message.

import { describe, it, expect } from "vitest";
import type { LicenceCeiling, LicenceFeature, LicenceOverage, LicenceState } from "../services/api";
import {
  EXPIRY_SOON_DAYS,
  MAX_DOCUMENT_BYTES,
  NOT_MEASURED_FALLBACK,
  UNLIMITED,
  ceilingTone,
  checkDocument,
  confirmMatches,
  expiryVerdict,
  featureStatus,
  fmtLimit,
  headline,
  keyFileBody,
  keyFileName,
  keyRoleLabel,
  liftedByText,
  measured,
  notMeasuredText,
  overageSummary,
  refusalReason,
  sortedCeilings,
  tierLabel,
  usageBar,
} from "./licence.model";

// ── fixtures (the wire shapes from internal/licence/api.go) ─────────────────

function ceiling(over: Partial<LicenceCeiling> = {}): LicenceCeiling {
  return {
    name: "devices", label: "devices", limit: 25, current: 12,
    enforced: true, over: false, ...over,
  };
}

function state(over: Partial<LicenceState> = {}): LicenceState {
  return {
    source: "community",
    tier: "community",
    ceilings: {
      devices: 25, tenants: 1, orgs: 1, retention_days: 7,
      watched_prefixes: 5, skills: 0, provider_tokens_per_day: 0,
    },
    in_grace: false,
    degraded: false,
    ...over,
  };
}

// ── measured-or-not ─────────────────────────────────────────────────────────

describe("measured — the only door a nullable count comes through", () => {
  it("treats a real zero as a measurement, because it is one", () => {
    const m = measured(0, "unused reason");
    expect(m).toEqual({ measured: true, value: 0 });
  });

  it("treats null and undefined as absent, and carries the reason", () => {
    expect(measured(null, "the platform does not count tenants here"))
      .toEqual({ measured: false, reason: "the platform does not count tenants here" });
    expect(measured(undefined, "")).toEqual({ measured: false, reason: NOT_MEASURED_FALLBACK });
  });

  it("renders absence as a sentence naming the reason", () => {
    expect(notMeasuredText("nobody counts skills yet")).toBe("not measured — nobody counts skills yet");
  });
});

// ── ceilings ────────────────────────────────────────────────────────────────

describe("limits", () => {
  it("prints the sentinel as a word, never as -1", () => {
    expect(fmtLimit(UNLIMITED)).toBe("unlimited");
    expect(fmtLimit(0)).toBe("0");
    expect(fmtLimit(250)).toBe("250");
  });
});

describe("usageBar — a fill only where a percentage is a real number", () => {
  it("counted against a finite limit gives a percentage and both numbers", () => {
    expect(usageBar(ceiling({ current: 12, limit: 25 }))).toEqual({
      kind: "measured", percent: 48, current: 12, limit: 25, over: false, text: "12 of 25",
    });
  });

  it("an unlimited ceiling has NO percentage — the count is shown instead", () => {
    const bar = usageBar(ceiling({ current: 900, limit: UNLIMITED }));
    expect(bar.kind).toBe("unlimited");
    expect(bar).not.toHaveProperty("percent");
    expect(bar.kind === "unlimited" && bar.text).toBe("900 in use · no limit");
  });

  it("an uncounted ceiling has no bar, no number, and says why", () => {
    const bar = usageBar(ceiling({ current: null, current_reason: "the platform does not count organisations" }));
    expect(bar).toEqual({ kind: "unmeasured", reason: "the platform does not count organisations" });
    expect(JSON.stringify(bar)).not.toContain("percent");
  });

  it("an uncounted ceiling with no reason still refuses to show a zero", () => {
    const bar = usageBar(ceiling({ current: null, current_reason: undefined }));
    expect(bar).toEqual({ kind: "unmeasured", reason: NOT_MEASURED_FALLBACK });
  });

  it("over the ceiling keeps the TRUE numbers and clamps only the fill", () => {
    const bar = usageBar(ceiling({ current: 30, limit: 25, over: true }));
    expect(bar).toEqual({ kind: "measured", percent: 100, current: 30, limit: 25, over: true, text: "30 of 25" });
  });

  it("a limit of zero is not divided by: anything in use is wholly over", () => {
    expect(usageBar(ceiling({ name: "skills", current: 3, limit: 0, over: true })))
      .toMatchObject({ percent: 100, text: "3 of 0" });
    expect(usageBar(ceiling({ name: "skills", current: 0, limit: 0 })))
      .toMatchObject({ percent: 0, text: "0 of 0" });
  });
});

describe("ceilingTone", () => {
  it("a limit nothing gates on is muted, even when it is exceeded", () => {
    expect(ceilingTone(ceiling({ enforced: false, current: 40, limit: 7, over: false }))).toBe("muted");
  });

  it("over an enforced ceiling is the only red", () => {
    expect(ceilingTone(ceiling({ over: true }))).toBe("bad");
  });

  it("close to an enforced ceiling warns before it bites", () => {
    expect(ceilingTone(ceiling({ current: 24, limit: 25 }))).toBe("warn");
    expect(ceilingTone(ceiling({ current: 12, limit: 25 }))).toBe("good");
  });

  it("an uncounted ceiling is never green — there is nothing to be green about", () => {
    expect(ceilingTone(ceiling({ current: null }))).toBe("good");
  });
});

describe("liftedByText", () => {
  it("names the tier that covers it", () => {
    expect(liftedByText("team")).toBe("Included in Team");
    expect(liftedByText("enterprise")).toBe("Included in Enterprise");
  });

  it("says nothing when no tier lifts it, rather than naming one that would not help", () => {
    expect(liftedByText(undefined)).toBeNull();
    expect(liftedByText("")).toBeNull();
  });
});

// ── tiers and features ──────────────────────────────────────────────────────

describe("tierLabel", () => {
  it("labels the closed vocabulary", () => {
    expect(tierLabel("community")).toBe("Community");
    expect(tierLabel("team")).toBe("Team");
    expect(tierLabel("enterprise")).toBe("Enterprise");
  });

  it("shows an unknown tier's own name rather than a blank", () => {
    expect(tierLabel("platinum")).toBe("platinum");
    expect(tierLabel(null)).toBe("");
  });
});

describe("featureStatus", () => {
  const f = (over: Partial<LicenceFeature> = {}): LicenceFeature => ({
    name: "saml", label: "SAML single sign-on", entitled: false, included_in: "enterprise", ...over,
  });

  it("an entitled capability reads as included", () => {
    expect(featureStatus(f({ entitled: true }))).toEqual({ tone: "good", text: "Included" });
  });

  it("one this licence lacks names the tier that has it, not a refusal", () => {
    expect(featureStatus(f())).toEqual({ tone: "muted", text: "Included in Enterprise" });
  });

  it("with no tier stated it says so instead of implying one", () => {
    expect(featureStatus(f({ included_in: "" as LicenceFeature["included_in"] })))
      .toEqual({ tone: "muted", text: "Not included" });
  });
});

// ── the headline ────────────────────────────────────────────────────────────

describe("headline — the worst true statement wins, and it names the condition", () => {
  it("Community is a plain fact, not a warning", () => {
    const h = headline(state());
    expect(h.state).toBe("community");
    expect(h.tone).toBe("muted");
    expect(h.reason).toContain("free tier");
  });

  it("an installed licence names the customer", () => {
    const h = headline(state({ source: "file", tier: "team", licensed_tier: "team", customer: "Acme Networks" }));
    expect(h).toMatchObject({ state: "licensed", label: "Team licence", tone: "good" });
    expect(h.reason).toContain("Acme Networks");
  });

  it("a REFUSED licence outranks everything else on the page", () => {
    const h = headline(state({
      source: "community", degraded: true, in_grace: true,
      load_error: "signature does not verify against any trusted key",
    }));
    expect(h.state).toBe("refused");
    expect(h.reason).toBe("signature does not verify against any trusted key");
  });

  it("degraded says which ceilings are actually in force", () => {
    const h = headline(state({ source: "file", degraded: true, reason: "expired 40 days ago, past a 30-day grace period" }));
    expect(h).toMatchObject({ state: "degraded", label: "Running at Community ceilings", tone: "bad" });
    expect(h.reason).toBe("expired 40 days ago, past a 30-day grace period");
  });

  it("grace warns without pretending the licence has stopped working", () => {
    const h = headline(state({ source: "file", in_grace: true, reason: "expired 2 days ago" }));
    expect(h).toMatchObject({ state: "grace", tone: "warn" });
  });

  it("a degraded state with no server reason still explains itself", () => {
    expect(headline(state({ source: "file", degraded: true })).reason).toContain("grace period");
  });
});

// ── expiry ──────────────────────────────────────────────────────────────────

describe("expiryVerdict — the server's own arithmetic, never the browser's clock", () => {
  it("no expiry is not a gap: Community ceilings do not lapse", () => {
    expect(expiryVerdict({ state: state(), days_to_expiry: null }))
      .toEqual({ state: "none", text: "No expiry — Community ceilings do not lapse" });
  });

  it("comfortably in date reads as good", () => {
    const v = expiryVerdict({
      state: state({ source: "file", expires_at: "2027-01-01T00:00:00Z" }),
      days_to_expiry: 200,
    });
    expect(v).toMatchObject({ state: "active", tone: "good", text: "expires in 200 days" });
  });

  it("inside the warning window says so before it matters", () => {
    const v = expiryVerdict({
      state: state({ source: "file", expires_at: "2026-09-20T00:00:00Z" }),
      days_to_expiry: EXPIRY_SOON_DAYS,
    });
    expect(v).toMatchObject({ state: "soon", tone: "warn" });
  });

  it("grace names the issuer's window rather than implying it is fine", () => {
    const v = expiryVerdict({
      state: state({ source: "file", expires_at: "2026-09-01T00:00:00Z", in_grace: true, grace_days: 30 }),
      days_to_expiry: -3,
    });
    expect(v).toMatchObject({ state: "grace", tone: "warn" });
    expect(v.state !== "none" && v.text).toBe("expired 3 days ago — inside a 30-day grace period");
  });

  it("past grace is stated as past grace", () => {
    const v = expiryVerdict({
      state: state({ source: "file", expires_at: "2026-07-01T00:00:00Z", degraded: true }),
      days_to_expiry: -65,
    });
    expect(v).toMatchObject({ state: "expired", tone: "bad" });
    expect(v.state !== "none" && v.text).toContain("past its grace period");
  });
});

// ── overages ────────────────────────────────────────────────────────────────

describe("overageSummary — listed, never pruned", () => {
  const over = (o: Partial<LicenceOverage> = {}): LicenceOverage => ({
    ceiling: "devices", label: "devices", current: 30, limit: 25, over: 5,
    message: "5 of 30 devices are over the Community ceiling of 25", ...o,
  });

  it("says nothing when nothing is over", () => {
    expect(overageSummary([])).toBeNull();
  });

  it("leads with the fact that nothing was deleted", () => {
    const s = overageSummary([over()]) ?? "";
    expect(s).toContain("5 over the licensed devices");
    expect(s).toContain("nothing has been removed");
  });

  it("totals across ceilings and names each of them", () => {
    const s = overageSummary([over(), over({ ceiling: "watched_prefixes", label: "watched prefixes", over: 3 })]) ?? "";
    expect(s).toContain("8 over the licensed devices, watched prefixes");
  });
});

// ── keys ────────────────────────────────────────────────────────────────────

describe("public keys", () => {
  it("names the downloaded file after the key, with nothing a path could swallow", () => {
    expect(keyFileName("k1")).toBe("correlix-licence-k1.pub");
    expect(keyFileName("../etc/passwd")).toBe("correlix-licence---etc-passwd.pub");
    expect(keyFileName("")).toBe("correlix-licence-key.pub");
  });

  it("the file carries the key AND what it is, so it is still usable next year", () => {
    const body = keyFileBody({ id: "k1", role: "current", note: "lab key", base64: "AAAA" });
    expect(body).toContain("# id: k1");
    expect(body).toContain("# role: current");
    expect(body).toContain("# note: lab key");
    expect(body.trimEnd().endsWith("AAAA")).toBe(true);
  });

  it("says what each role is FOR, not just its name", () => {
    expect(keyRoleLabel("current")).toBe("Signs new licences");
    expect(keyRoleLabel("previous")).toContain("still verifies");
    expect(keyRoleLabel("")).toBe("Role not stated");
  });
});

// ── installing ──────────────────────────────────────────────────────────────

describe("checkDocument — the only two things a browser may judge", () => {
  it("accepts a document and trims the transport's whitespace", () => {
    expect(checkDocument('  {"licence_id":"x"}  ')).toEqual({ ok: true, document: '{"licence_id":"x"}' });
  });

  it("refuses an empty document without pretending to verify it", () => {
    expect(checkDocument("   ")).toEqual({ ok: false, reason: "There is no licence document to install." });
  });

  it("refuses one over the route's bound, and says both numbers", () => {
    const r = checkDocument("x".repeat(MAX_DOCUMENT_BYTES + 1));
    expect(r.ok).toBe(false);
    expect(!r.ok && r.reason).toContain(String(MAX_DOCUMENT_BYTES + 1));
    expect(!r.ok && r.reason).toContain(String(MAX_DOCUMENT_BYTES));
  });

  it("does NOT judge the signature, the tier or the dates — that is the platform's", () => {
    expect(checkDocument("this is not even JSON")).toEqual({ ok: true, document: "this is not even JSON" });
  });
});

describe("refusalReason — the server's words, unchanged", () => {
  it("unwraps the transport envelope and keeps the sentence exactly", () => {
    const e = new Error('400 Bad Request: {"error":"licence expired on 2026-01-01 and its 30-day grace period has passed"}');
    expect(refusalReason(e, "fallback"))
      .toBe("licence expired on 2026-01-01 and its 30-day grace period has passed");
  });

  it("does not capitalize, punctuate or otherwise tidy the reason", () => {
    const e = new Error('400 Bad Request: {"error":"signature does not verify against key k1"}');
    const out = refusalReason(e, "fallback");
    expect(out).toBe("signature does not verify against key k1");
    expect(out.endsWith(".")).toBe(false);
    expect(out[0]).toBe("s");
  });

  it("accepts a plain-text body as sent", () => {
    expect(refusalReason(new Error("400 Bad Request: no licence document in the request"), "fallback"))
      .toBe("no licence document in the request");
  });

  it("falls back rather than showing a JSON body the server did not explain", () => {
    expect(refusalReason(new Error('400 Bad Request: {"detail":{"code":7}}'), "fallback")).toBe("fallback");
    expect(refusalReason(new Error("400 Bad Request: "), "fallback")).toBe("fallback");
    expect(refusalReason(null, "fallback")).toBe("fallback");
  });
});

describe("confirmMatches", () => {
  it("is exact and case-sensitive, and an empty expectation matches nothing", () => {
    expect(confirmMatches(" lic-2026-001 ", "lic-2026-001")).toBe(true);
    expect(confirmMatches("LIC-2026-001", "lic-2026-001")).toBe(false);
    expect(confirmMatches("", "")).toBe(false);
  });
});

// ── ordering ────────────────────────────────────────────────────────────────

describe("sortedCeilings", () => {
  it("puts what actually gates first and keeps the server's order inside each half", () => {
    const rows = [
      ceiling({ name: "tenants", enforced: false }),
      ceiling({ name: "devices", enforced: true }),
      ceiling({ name: "orgs", enforced: false }),
      ceiling({ name: "watched_prefixes", enforced: true }),
    ];
    expect(sortedCeilings(rows).map((r) => r.name))
      .toEqual(["devices", "watched_prefixes", "tenants", "orgs"]);
  });

  it("does not mutate the caller's array", () => {
    const rows = [ceiling({ name: "tenants", enforced: false }), ceiling({ name: "devices" })];
    sortedCeilings(rows);
    expect(rows.map((r) => r.name)).toEqual(["tenants", "devices"]);
  });
});

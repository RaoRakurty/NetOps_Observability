// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// UpgradeCard.test.tsx — the one card every 402 in the product renders.
//
// WHAT THESE TESTS ARE FOR. A commercial limit reaching an operator as a fault
// is the failure this component exists to prevent, and it has three shapes:
//
//   1. A 403 rendered as an upsell, or a 402 rendered as "you lack access".
//      The parser keys on the status ALONE for exactly that reason, and the
//      first describe block is entirely about that boundary.
//   2. A machine token on the screen. `licence_ceiling` is what the SPA
//      switches on; it must never be what an operator reads.
//   3. A half-rendered card. A body missing a field either produces a written
//      sentence or produces nothing at all, so ordinary error handling runs.

import { describe, it, expect, afterEach } from "vitest";
import { render, screen, cleanup } from "@testing-library/react";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { scanCopy } from "../../copyVoice.test";
import { scanForEngineVocabulary } from "../rca/vocabulary.test";
import { httpFailure, operatorError } from "../../lib/errors";
import UpgradeCard, {
  licenceRefusalFromError,
  parseLicenceRefusal,
  refusedThing,
  type LicenceRefusal,
} from "./UpgradeCard";

afterEach(() => cleanup());

const CEILING_BODY = {
  error: "licence_ceiling",
  ceiling: "devices",
  current: 25,
  limit: 25,
  tier: "community",
  lifted_by: "team",
  message: "your Community licence covers 25 devices and 25 are in use — the Team tier raises it to 250",
};

const FEATURE_BODY = {
  error: "licence_feature",
  feature: "saml",
  tier: "team",
  lifted_by: "enterprise",
  message: "SAML single sign-on is not included in your Team licence — the Enterprise tier includes it",
};

// ── 1 · the status boundary ─────────────────────────────────────────────────

describe("parseLicenceRefusal — 402 and nothing else", () => {
  it("parses a ceiling refusal into every field the card needs", () => {
    expect(parseLicenceRefusal(402, CEILING_BODY)).toEqual({
      kind: "ceiling",
      ceiling: "devices",
      current: 25,
      limit: 25,
      tier: "community",
      liftedBy: "team",
      message: CEILING_BODY.message,
    });
  });

  it("parses a feature refusal, and carries no counts to invent", () => {
    const r = parseLicenceRefusal(402, FEATURE_BODY);
    expect(r).toMatchObject({ kind: "feature", feature: "saml", tier: "team", liftedBy: "enterprise" });
    expect(r).not.toHaveProperty("current");
    expect(r).not.toHaveProperty("limit");
  });

  it("a 403 is NEVER an upsell — an authorization failure is not a licence one", () => {
    expect(parseLicenceRefusal(403, CEILING_BODY)).toBeNull();
  });

  it("no other status produces a card either", () => {
    for (const s of [200, 400, 401, 404, 409, 500]) {
      expect(parseLicenceRefusal(s, CEILING_BODY), `status ${s}`).toBeNull();
    }
  });

  it("reads the body as raw text too, which is what a thrown error carries", () => {
    expect(parseLicenceRefusal(402, JSON.stringify(CEILING_BODY))).toMatchObject({ ceiling: "devices" });
  });

  it("answers null for anything that is not a licence refusal, so normal handling runs", () => {
    expect(parseLicenceRefusal(402, { error: "payment_required", message: "x" })).toBeNull();
    expect(parseLicenceRefusal(402, "not json at all")).toBeNull();
    expect(parseLicenceRefusal(402, "{ broken")).toBeNull();
    expect(parseLicenceRefusal(402, null)).toBeNull();
    expect(parseLicenceRefusal(402, 7)).toBeNull();
  });

  it("refuses to describe a refusal that names neither a ceiling nor a capability", () => {
    expect(parseLicenceRefusal(402, { error: "licence_ceiling", tier: "community", message: "no" })).toBeNull();
    expect(parseLicenceRefusal(402, { error: "licence_feature", tier: "community", message: "no" })).toBeNull();
  });

  it("writes a sentence when the platform sent no message, rather than a token", () => {
    const r = parseLicenceRefusal(402, { error: "licence_feature", feature: "scim", tier: "team" });
    expect(r?.message).toBe("scim is not included in your Team licence.");
    expect(r?.message).not.toContain("licence_feature");
  });

  it("ignores a count that is not a number instead of rendering one", () => {
    const r = parseLicenceRefusal(402, { ...CEILING_BODY, current: "lots", limit: null });
    expect(r).not.toHaveProperty("current");
    expect(r).not.toHaveProperty("limit");
  });
});

describe("licenceRefusalFromError — starting from what api.ts actually throws", () => {
  it("finds the refusal inside the transport envelope", () => {
    const e = new Error(`402 Payment Required: ${JSON.stringify(CEILING_BODY)}`);
    expect(licenceRefusalFromError(e)).toMatchObject({ kind: "ceiling", ceiling: "devices" });
  });

  it("leaves every other failure alone", () => {
    expect(licenceRefusalFromError(new Error('403 Forbidden: {"error":"forbidden"}'))).toBeNull();
    expect(licenceRefusalFromError(new Error("500 Internal Server Error: {}"))).toBeNull();
    expect(licenceRefusalFromError(new TypeError("x is not a function"))).toBeNull();
    expect(licenceRefusalFromError(undefined)).toBeNull();
  });
});

describe("httpFailure — the additive hook in lib/errors.ts", () => {
  it("splits the envelope into a status and the body exactly as sent", () => {
    expect(httpFailure(new Error('402 Payment Required: {"error":"licence_ceiling"}')))
      .toEqual({ status: 402, body: '{"error":"licence_ceiling"}' });
  });

  it("handles the bare form the download paths throw", () => {
    expect(httpFailure("402")).toEqual({ status: 402, body: "" });
    expect(httpFailure("404: nothing here")).toEqual({ status: 404, body: "nothing here" });
  });

  it("answers null for anything that is not an HTTP failure", () => {
    expect(httpFailure(new Error("The service did not answer."))).toBeNull();
    expect(httpFailure(null)).toBeNull();
  });

  it("leaves operatorError's own behaviour untouched", () => {
    expect(operatorError(new Error("500 Internal Server Error: {}"), "fallback"))
      .toBe("The service did not answer.");
  });
});

// ── 2 · the card ────────────────────────────────────────────────────────────

function refusal(over: Partial<LicenceRefusal> = {}): LicenceRefusal {
  return { kind: "ceiling", ceiling: "devices", current: 25, limit: 25, tier: "community", liftedBy: "team", message: CEILING_BODY.message, ...over };
}

describe("the card", () => {
  it("leads with the platform's own sentence", () => {
    render(<UpgradeCard refusal={refusal()} />);
    expect(screen.getByText(CEILING_BODY.message)).toBeTruthy();
  });

  it("names what was limited, in words rather than in wire spelling", () => {
    render(<UpgradeCard refusal={refusal({ ceiling: "watched_prefixes" })} />);
    expect(screen.getByText("watched prefixes")).toBeTruthy();
    expect(screen.queryByText("watched_prefixes")).toBeNull();
  });

  it("shows current against limit when the refusal carries them", () => {
    render(<UpgradeCard refusal={refusal()} />);
    const inUse = screen.getByText("In use").parentElement as HTMLElement;
    expect(inUse.textContent).toContain("25");
    expect(inUse.textContent).toContain("of");
  });

  it("shows no counts at all for a capability refusal, rather than zeros", () => {
    render(<UpgradeCard refusal={{ kind: "feature", feature: "saml", tier: "team", liftedBy: "enterprise", message: FEATURE_BODY.message }} />);
    expect(screen.queryByText("In use")).toBeNull();
    expect(screen.getByText("Capability")).toBeTruthy();
    expect(screen.getByText("saml")).toBeTruthy();
  });

  it("names the tier that covers it", () => {
    render(<UpgradeCard refusal={refusal()} />);
    expect(screen.getByText("Included in Team")).toBeTruthy();
  });

  it("says so plainly when no tier lifts it, instead of naming one that would not help", () => {
    render(<UpgradeCard refusal={refusal({ liftedBy: undefined })} />);
    expect(screen.getByText(/no higher tier lifts this/)).toBeTruthy();
    expect(screen.queryByText(/Included in/)).toBeNull();
  });

  it("states that nothing was lost — a limit is not a fault", () => {
    render(<UpgradeCard refusal={refusal()} />);
    expect(screen.getByText(/Nothing has been removed and nothing has stopped/)).toBeTruthy();
    // The reasoning ("a limit on what the licence covers, not a fault") moved to
    // ai/skills/explain/licence.limit-not-a-fault.md; the (i) is what carries it,
    // so it has to be here for the claim to still be reachable.
    expect(screen.getByRole("button", { name: /Ask Iris about a licence limit/ })).toBeTruthy();
  });

  it("takes the calling surface's own headline when it has one", () => {
    render(<UpgradeCard refusal={refusal()} title="This device was not added" />);
    expect(screen.getByText("This device was not added")).toBeTruthy();
  });

  it("never puts a machine token on the screen", () => {
    const { container } = render(<UpgradeCard refusal={refusal()} />);
    expect(container.textContent).not.toContain("licence_ceiling");
    expect(container.textContent).not.toContain("402");
  });

  it("is a named landmark, so a screen reader announces what it is", () => {
    render(<UpgradeCard refusal={refusal()} />);
    expect(screen.getByRole("note", { name: "Licence limit" })).toBeTruthy();
  });

  it("renders an unlimited limit as a word, never as -1", () => {
    render(<UpgradeCard refusal={refusal({ limit: -1 })} />);
    expect(screen.getByText("unlimited")).toBeTruthy();
  });
});

describe("refusedThing", () => {
  it("reads a vocabulary name as words and leaves an unknown one usable", () => {
    expect(refusedThing({ kind: "ceiling", ceiling: "provider_tokens_per_day", tier: "team", message: "x" }))
      .toBe("provider tokens per day");
    expect(refusedThing({ kind: "feature", feature: "brand_new", tier: "team", message: "x" }))
      .toBe("brand new");
  });
});

// ── 3 · copy guards on this component's own sources ─────────────────────────

describe("copy guards on this page's own sources", () => {
  const here = dirname(fileURLToPath(import.meta.url));
  const files = ["UpgradeCard.tsx"];

  it("shows no denied developer-speak", () => {
    const hits = files.flatMap((f) => scanCopy(readFileSync(join(here, f), "utf-8"), `components/licence/${f}`));
    expect(hits, hits.join("\n")).toEqual([]);
  });

  it("never puts the engine word on screen", () => {
    const hits = files.flatMap((f) => scanForEngineVocabulary(readFileSync(join(here, f), "utf-8"), `components/licence/${f}`));
    expect(hits, hits.join("\n")).toEqual([]);
  });
});

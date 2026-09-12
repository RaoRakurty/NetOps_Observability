// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// UpgradeCard.tsx — what a 402 looks like, everywhere in the product.
//
// WHY THIS IS ONE COMPONENT AND NOT TWENTY. Every licence gate on the server
// answers the same structured body (internal/entitlement.RefusalBody): WHICH
// limit or capability, WHERE the caller stands against it, and WHICH tier lifts
// it. If each surface rendered that itself, some would show the machine token
// ("licence_ceiling"), some would show a bare "402", and one would show a blank
// panel. All three are the same defect: a commercial limit reaching an operator
// as a fault.
//
// So there is one parser and one card. The rules they keep:
//
//   1. ONLY 402. The status is the discriminator, deliberately — a licence
//      refusal is 402 and an authorization failure is 403, and mis-rendering
//      one as the other is the failure mode this exists to prevent. A 403 must
//      never become an upsell, and a 402 must never read as "you lack access".
//   2. NEVER A RAW ERROR. The parser answers null for anything that is not a
//      licence refusal, so the caller's own error handling runs untouched. It
//      never half-renders: a body missing its message still produces a written
//      sentence, never a token.
//   3. THE REFUSAL IS NOT A FAILURE. It is styled as information, not as an
//      error — nothing is broken, nothing was lost, and the operator's data is
//      exactly where it was. The card says what is covered and what would cover
//      it, and stops there.

import type { ReactNode } from "react";
import { httpFailure } from "../../lib/errors";
import type { LicenceRefusalBody } from "../../services/api";
import { tierLabel } from "../../pages/licence.model";
import AskIris from "../AskIris";

/** The machine tokens the server uses. Switched on, never rendered. */
const KIND_CEILING = "licence_ceiling";
const KIND_FEATURE = "licence_feature";

/** A parsed 402. Exactly one of `ceiling` and `feature` is set. */
export type LicenceRefusal = {
  kind: "ceiling" | "feature";
  /** The ceiling's vocabulary name, for a ceiling refusal. */
  ceiling?: string;
  /** The feature's vocabulary name, for a feature refusal. */
  feature?: string;
  /** Where the caller stands. Present only on a ceiling refusal. */
  current?: number;
  /** The limit in force. Present only on a ceiling refusal. */
  limit?: number;
  /** The tier in force — display only. */
  tier: string;
  /** The lowest tier that removes this refusal, when one does. */
  liftedBy?: string;
  /** The server's operator sentence. */
  message: string;
};

function num(v: unknown): number | undefined {
  return typeof v === "number" && Number.isFinite(v) ? v : undefined;
}

function str(v: unknown): string {
  return typeof v === "string" ? v.trim() : "";
}

/**
 * The vocabulary name as a person reads it.
 *
 * This is presentation, not a second copy of the server's label table: the
 * underscores come out and nothing else changes, so a name we have never seen
 * still arrives readable instead of being dropped.
 */
export function refusedThing(r: LicenceRefusal): string {
  return (r.ceiling || r.feature || "").replace(/_/g, " ").trim();
}

/**
 * Parses a licence refusal, or answers null.
 *
 * @param status the HTTP status. Anything but 402 is null, by design.
 * @param body   the response body — already-parsed JSON, or the raw text.
 */
export function parseLicenceRefusal(status: number, body: unknown): LicenceRefusal | null {
  if (status !== 402) return null;

  let obj: unknown = body;
  if (typeof obj === "string") {
    const raw = obj.trim();
    if (!raw.startsWith("{")) return null;
    try {
      obj = JSON.parse(raw);
    } catch {
      return null;
    }
  }
  if (!obj || typeof obj !== "object") return null;

  const b = obj as LicenceRefusalBody;
  const error = str(b.error);
  if (error !== KIND_CEILING && error !== KIND_FEATURE) return null;

  const kind = error === KIND_FEATURE ? "feature" : "ceiling";
  const ceiling = str(b.ceiling);
  const feature = str(b.feature);
  // A body that names neither half is not a refusal we can describe. Answering
  // null hands it back to ordinary error handling rather than rendering a card
  // with a hole in it.
  if (kind === "ceiling" && !ceiling) return null;
  if (kind === "feature" && !feature) return null;

  const tier = str(b.tier);
  const liftedBy = str(b.lifted_by);
  const refusal: LicenceRefusal = {
    kind,
    tier,
    message: str(b.message),
    ...(ceiling ? { ceiling } : {}),
    ...(feature ? { feature } : {}),
    ...(liftedBy ? { liftedBy } : {}),
  };
  const current = num(b.current);
  const limit = num(b.limit);
  if (current !== undefined) refusal.current = current;
  if (limit !== undefined) refusal.limit = limit;

  if (!refusal.message) {
    // The server always sends one; a build that does not must still produce a
    // sentence rather than a card with an empty body.
    const at = tierLabel(tier) || "current";
    refusal.message =
      kind === "feature"
        ? `${refusedThing(refusal)} is not included in your ${at} licence.`
        : `Your ${at} licence does not cover more ${refusedThing(refusal)}.`;
  }
  return refusal;
}

/**
 * The same parse, starting from a value thrown by services/api.ts.
 *
 * This is the form nearly every call site has: a caught error, not a response.
 */
export function licenceRefusalFromError(e: unknown): LicenceRefusal | null {
  const f = httpFailure(e);
  return f ? parseLicenceRefusal(f.status, f.body) : null;
}

/**
 * The card.
 *
 * `title` lets a surface say what the operator was doing when the limit was
 * reached ("This device was not added"); without one the card states the
 * general fact.
 */
export default function UpgradeCard({ refusal, title, actions }: {
  refusal: LicenceRefusal;
  title?: string;
  actions?: ReactNode;
}) {
  const at = tierLabel(refusal.tier);
  const lifted = tierLabel(refusal.liftedBy ?? "");
  const thing = refusedThing(refusal);
  const showCounts = refusal.kind === "ceiling" && refusal.current !== undefined && refusal.limit !== undefined;

  return (
    <div className="lic-upgrade" role="note" aria-label="Licence limit">
      <div className="lic-upgrade-hd">
        <span className="lic-upgrade-title">
          {title || (refusal.kind === "feature" ? "Not included in this licence" : "At a licence limit")}
        </span>
        {at && <span className="lic-pill lic-muted">{at}</span>}
      </div>

      <p className="lic-upgrade-msg">{refusal.message}</p>

      <dl className="lic-upgrade-facts">
        <div>
          <dt>{refusal.kind === "feature" ? "Capability" : "Limit"}</dt>
          <dd>{thing || "not named by the platform"}</dd>
        </div>
        {showCounts && (
          <div>
            <dt>In use</dt>
            <dd>
              <span className="mono">{refusal.current}</span> of{" "}
              <span className="mono">{refusal.limit === -1 ? "unlimited" : refusal.limit}</span>
            </dd>
          </div>
        )}
        <div>
          <dt>Covered by</dt>
          <dd>
            {lifted ? (
              <span className="lic-pill lic-good">Included in {lifted}</span>
            ) : (
              <span className="lic-absent">no higher tier lifts this</span>
            )}
          </dd>
        </div>
      </dl>

      <p className="lic-upgrade-safe">
        Nothing has been removed and nothing has stopped.
        <AskIris topic="licence.limit-not-a-fault" label="a licence limit" />
      </p>

      {actions && <div className="lic-actions">{actions}</div>}
    </div>
  );
}

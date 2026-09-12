// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// ribbon.tsx — the seam ribbon.
//
// Device → LAN → WAN / SASE → ISP → DNS / CDN → cloud edge → app tier, with the
// failing segment lit red.
//
// It renders through pages/appobs/shell.tsx's AppPathStrip: that component
// already draws exactly this shape (labelled hop, sub-label, per-segment
// ok/degraded/unknown state, red arrows either side of a degraded hop), it is
// already in the design system, and duplicating it here would give the product
// two ribbons that drift apart.
//
// THE HONESTY RULE THAT SHAPES THIS FILE. Correlix measures the FAILING layer,
// not the healthy ones: nothing in the experience payload says "the LAN was
// fine". So every segment other than the implicated one renders `unknown`
// (muted), never `ok` (green). A ribbon of green boxes around one red one would
// be seven claims, six of which nobody made.

import { AppPathStrip } from "../appobs/shell";
import type { PathSeg } from "../appobs/shell";

/** The ordered spine. This is display vocabulary, not a measured path — the
 *  measured hop order belongs to the service path graph and is never invented
 *  here (see ExperiencePaths). */
export const SEAM_SEGMENTS = [
  "Device", "LAN", "WAN / SASE", "ISP", "DNS / CDN", "Cloud edge", "App tier",
] as const;

/**
 * `likely_layer` (experience.LayerFor) → the ribbon segment it lights.
 * Two of the server's layers deliberately have NO segment:
 *   - "network"     — a device configuration change, which can sit at any of
 *                     several segments; guessing one would be a fabrication.
 *   - "measurement" — the CHECK is suspect, not the path at all.
 * Both are reported in words beside the ribbon instead.
 */
const LAYER_SEGMENT: Record<string, string> = {
  device: "Device",
  LAN: "LAN",
  WAN: "WAN / SASE",
  ISP: "ISP",
  DNS: "DNS / CDN",
  "cloud edge": "Cloud edge",
  application: "App tier",
};

export function segmentForLayer(layer?: string): string | undefined {
  return layer ? LAYER_SEGMENT[layer] : undefined;
}

export function SeamRibbon({ layer, seam, owner, cause, label }: {
  /** The server's `likely_layer` for the leading hypothesis. */
  layer?: string;
  /** The owning handoff, when one was determined. */
  seam?: string;
  /** The team or provider that owns the fix. Empty is honest. */
  owner?: string;
  /** The leading cause sentence, shown on the lit segment. */
  cause?: string;
  label?: string;
}) {
  const lit = segmentForLayer(layer);
  const segments: PathSeg[] = SEAM_SEGMENTS.map((s) => (
    s === lit
      ? { label: s, state: "degraded", sub: [seam, owner].filter(Boolean).join(" · ") || cause }
      : { label: s, state: "unknown" }
  ));

  return (
    <div role="region" aria-label={label ?? "Seam ribbon"}>
      <AppPathStrip segments={segments} />
      <p className="dx-note">
        {lit ? (
          <>
            The <b>{lit}</b> segment is the one the evidence implicates
            {owner ? <> — owned by <b>{owner}</b></> : <> — no owner has been determined</>}
            {seam ? <> at the <b>{seam}</b> handoff</> : null}.
            {" "}Every other segment reads as unmeasured, not as healthy: nothing observed says they were well.
          </>
        ) : layer === "measurement" ? (
          <>The evidence points at the CHECK rather than at the path, so no segment is lit.</>
        ) : layer === "network" ? (
          <>
            The evidence points at a device configuration change, which is not tied to one
            segment of this ribbon. It is named in the hypotheses rather than guessed onto a segment.
          </>
        ) : (
          <>
            No segment is lit: no cause has enough evidence to place the failure on the path yet.
            A ribbon with nothing lit means undetermined, not healthy.
          </>
        )}
      </p>
    </div>
  );
}

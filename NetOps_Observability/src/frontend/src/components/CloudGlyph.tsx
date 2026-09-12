// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// CloudGlyph.tsx — the ORIGINAL Correlix cloud-glyph family.
//
// Licence audit D5 (2026-09-04): the official AWS Architecture Icons "AWS Cloud
// logo", the Azure Public Service Icon and the Google Cloud four-colour symbol
// used to be vendored under `src/assets/cloud/` and bundled into the SPA. They
// were TRADEMARK files carried under a terms-of-use posture, not a licence, so
// the owner decided to remove them and draw our own. Nothing here reproduces,
// approximates or recolours anyone's mark.
//
// The family is ONE silhouette in four variants. Geometry, viewBox, stroke
// width and joins are identical across all four — the ONLY difference is a
// small plain letter tag under the cloud:
//
//     (no tag) → a generic / unknown cloud     "AWS" → Amazon Web Services
//     "AZ"     → Microsoft Azure               "GCP" → Google Cloud
//
// The tag is a nominative TEXTUAL reference in the product's own UI face — a
// word, not a stylised wordmark — and it never implies endorsement: it says
// "this resource sits in that provider's cloud", nothing more. Colour is
// `currentColor` throughout, so the glyph is theme-aware and carries no brand
// hue whatsoever.
//
// The Go RCA report embeds the SAME geometry as standalone files
// (src/backend/internal/rca/cloudicons/*.svg) because the exported PDF must be
// self-contained; keep the path data below in step with those files.

import type { CSSProperties } from "react";

/** Every glyph in the family is drawn in this box. */
export const CLOUD_GLYPH_VIEWBOX = "0 0 24 24";

/**
 * The one cloud silhouette. Identical for the generic glyph and for all three
 * tagged variants — provider identity lives in the tag, never in the shape.
 * Byte-identical to the `d` attribute in cloudicons/{aws,azure,gcp}.svg.
 */
export const CLOUD_SILHOUETTE_PATH =
  "M6.6 14.5H16.8A3.5 3.5 0 0 0 17.3 7.6A5.2 5.2 0 0 0 7.3 6.9A3.9 3.9 0 0 0 6.6 14.5Z";

/** Stroke width in glyph units — the product's icon-set weight. */
export const CLOUD_GLYPH_STROKE = 1.6;

/**
 * Provider id → letter tag. Adding a provider is one entry here (plus the
 * matching cloudicons/<id>.svg when the RCA PDF should carry it too); a
 * provider with no entry renders the untagged generic cloud, which is the
 * honest answer — never another provider's glyph.
 */
export const CLOUD_TAG: Record<string, string> = {
  aws: "AWS",
  azure: "AZ",
  gcp: "GCP",
};

/** The tag for a provider id, or null for unknown / generic. */
export function cloudTag(provider?: string | null): string | null {
  const key = (provider ?? "").trim().toLowerCase();
  return (key && CLOUD_TAG[key]) || null;
}

/**
 * The glyph's drawing primitives, WITHOUT an <svg> wrapper, so a parent SVG can
 * place the family inside its own coordinate system (see graph/shapes.tsx,
 * which scales it into a 0 0 100 100 device shape). Callers own the transform
 * and the colour; `currentColor` resolves against the parent.
 */
export function CloudGlyphShape({
  tag,
  strokeWidth = CLOUD_GLYPH_STROKE,
}: {
  tag?: string | null;
  strokeWidth?: number;
}) {
  return (
    <>
      <path
        d={CLOUD_SILHOUETTE_PATH}
        fill="none"
        stroke="currentColor"
        strokeWidth={strokeWidth}
        strokeLinejoin="round"
        strokeLinecap="round"
      />
      {tag ? (
        <text
          x={12}
          y={21.4}
          textAnchor="middle"
          fontSize={7.2}
          fontWeight={800}
          fill="currentColor"
          stroke="none"
        >
          {tag}
        </text>
      ) : null}
    </>
  );
}

/**
 * The standalone glyph at a given box size. Pass a `label` to expose it to
 * assistive tech; omit it (the default) when adjacent text already names the
 * provider, and the glyph is hidden from the accessibility tree instead of
 * making a screen reader say the provider twice.
 */
export default function CloudGlyph({
  provider,
  size = 20,
  label,
  className,
  style,
}: {
  provider?: string | null;
  size?: number;
  label?: string;
  className?: string;
  style?: CSSProperties;
}) {
  const tag = cloudTag(provider);
  return (
    <svg
      width={size}
      height={size}
      viewBox={CLOUD_GLYPH_VIEWBOX}
      fill="none"
      className={className}
      role={label ? "img" : undefined}
      aria-hidden={label ? undefined : true}
      style={{ flex: "0 0 auto", ...style }}
    >
      {/* <title> is both the accessible name for role="img" AND the native
          hover tooltip, so labelled glyphs keep the tooltip the old <img>
          wrapper carried. */}
      {label ? <title>{label}</title> : null}
      <CloudGlyphShape tag={tag} />
    </svg>
  );
}

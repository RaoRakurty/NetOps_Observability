// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// ProviderMark.tsx — the cloud mark for a topology node.
//
// Licence audit D5 (2026-09-04): this used to render the providers' OFFICIAL
// vendored icons as `<img src={awsMark}>`. Those were trademark assets under a
// terms-of-use posture, and the owner decided to remove them. The mark is now
// ORIGINAL Correlix artwork drawn INLINE from components/CloudGlyph.tsx — one
// silhouette for every provider, distinguished only by a small plain letter tag
// (AWS / AZ / GCP), with the untagged generic cloud for anything else.
//
// Inline SVG (not an asset URL) is what makes it theme-aware: the glyph inherits
// `currentColor` from the node card's accent, so it reads correctly in light and
// dark without shipping two files. No asset is fetched (CSP / offline rule) and
// no provider colour appears anywhere.

import CloudGlyph, { cloudTag } from "../../../components/CloudGlyph";

/**
 * Left-rule accent per provider — lets a multi-cloud canvas sort by provider.
 *
 * These are the PRODUCT's own accent ramp (the indigo→violet values already in
 * styles.css: --accent #4f46e5, --accent-bright #6366f1, --accent-2 #8b5cf6),
 * deliberately NOT the provider brand hexes they replaced (#ff9900 / #0078d4 /
 * #4285f4, removed by licence-audit D5). They are hex literals rather than
 * `var(--token)` because NodeCard composes them with hex-suffix alpha
 * (`${accent}44`) and `color-mix`, which a var() would break. Provider identity
 * is carried by the glyph's letter TAG, never by colour — these values are only
 * a sorting affordance and can be re-picked freely from the product palette.
 */
export const PROVIDER_ACCENT: Record<string, string> = {
  aws: "#4f46e5", // --accent (indigo)
  azure: "#6366f1", // --accent-bright
  gcp: "#8b5cf6", // --accent-2 (violet)
};
/** Neutral violet for an unknown / generic provider. */
export const GENERIC_CLOUD_ACCENT = "#7c3aed";

export function providerAccent(provider?: string): string {
  return (provider && PROVIDER_ACCENT[provider.toLowerCase()]) || GENERIC_CLOUD_ACCENT;
}

/**
 * The cloud glyph at a given box size. A provider we recognise gets its letter
 * tag and an accessible label; anything else gets the untagged generic cloud —
 * so a cloud node is never iconless and never wears a provider mark we did not
 * actually measure.
 */
export default function ProviderMark({ provider, size = 20 }: { provider?: string; size?: number }) {
  const tagged = cloudTag(provider) !== null;
  return (
    <CloudGlyph
      provider={provider}
      size={size}
      label={tagged ? `${provider} resource` : undefined}
    />
  );
}

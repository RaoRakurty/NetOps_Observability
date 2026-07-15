// ProviderMark.tsx — renders the OFFICIAL cloud-provider mark for a topology node.
//
// Reuses the SAME vendored official icons as the RCA report path
// (src/assets/cloud/*.svg — source + terms in assets/cloud/README.md): the mark
// is rendered AS-IS, only composited onto a neutral tile for contrast when it is
// transparent (Azure, GCP) — never recoloured, cropped, flipped or reshaped.
// Providers without a vendored official mark fall back to a monogram badge, so
// the component is provider-parametric and degrades honestly. No external assets
// are fetched (CSP / offline rule) — the SVGs are bundled at build time as URLs.

import awsMark from "../../../assets/cloud/aws.svg";
import azureMark from "../../../assets/cloud/azure.svg";
import gcpMark from "../../../assets/cloud/gcp.svg";

/** Official marks keyed by provider. `tile` is drawn behind a transparent mark. */
const PROVIDER_ICON: Record<string, { href: string; tile?: string }> = {
  aws: { href: awsMark }, // ships its own navy tile
  azure: { href: azureMark, tile: "#FFFFFF" }, // transparent mark → white tile
  gcp: { href: gcpMark, tile: "#FFFFFF" }, // transparent mark → white tile
};

/** Monogram fallback for providers with no vendored official mark (none today). */
const PROVIDER_MARK: Record<string, { bg: string; fg: string; text: string }> = {};

/** Left-rule accent per provider — lets a multi-cloud canvas sort by provider. */
export const PROVIDER_ACCENT: Record<string, string> = {
  aws: "#ff9900",
  azure: "#0078d4",
  gcp: "#4285f4",
};
/** Neutral violet for an unknown / generic provider. */
export const GENERIC_CLOUD_ACCENT = "#7c3aed";

export function providerAccent(provider?: string): string {
  return (provider && PROVIDER_ACCENT[provider.toLowerCase()]) || GENERIC_CLOUD_ACCENT;
}

/**
 * The official provider mark at a given box size. Falls back to a monogram badge,
 * then to a generic cloud glyph when the provider is unknown — always renders
 * SOMETHING so a cloud node is never iconless.
 */
export default function ProviderMark({ provider, size = 20 }: { provider?: string; size?: number }) {
  const key = provider?.toLowerCase();
  const icon = key ? PROVIDER_ICON[key] : undefined;
  const mark = key && !icon ? PROVIDER_MARK[key] : undefined;

  if (icon) {
    return (
      <span
        aria-label={`${provider} resource`}
        title={`${provider} resource`}
        style={{
          display: "inline-flex",
          width: size,
          height: size,
          borderRadius: 4,
          overflow: "hidden",
          background: icon.tile,
          boxShadow: icon.tile ? "inset 0 0 0 1px rgba(255,255,255,0.25)" : undefined,
          flex: "0 0 auto",
        }}
      >
        <img src={icon.href} width={size} height={size} alt="" draggable={false} />
      </span>
    );
  }

  if (mark) {
    return (
      <span
        aria-label={`${provider} resource`}
        title={`${provider} resource`}
        style={{
          display: "inline-flex",
          alignItems: "center",
          justifyContent: "center",
          width: size,
          height: size,
          borderRadius: 4,
          background: mark.bg,
          color: mark.fg,
          fontSize: size * 0.62,
          fontWeight: 800,
          letterSpacing: 0.3,
          flex: "0 0 auto",
        }}
      >
        {mark.text}
      </span>
    );
  }

  // Unknown / generic provider — a neutral cloud glyph (never a hyperscaler mark).
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" aria-hidden="true" style={{ flex: "0 0 auto" }}>
      <path
        d="M7 18h10a4 4 0 0 0 .6-7.95A5.5 5.5 0 0 0 6.7 9.2 3.8 3.8 0 0 0 7 18Z"
        stroke="currentColor"
        strokeWidth={1.6}
        strokeLinejoin="round"
      />
    </svg>
  );
}

import { useId } from "react";
import { BRAND } from "../../brand";

// Correlix brand mark (owner directive 2026-07-19).
//
// CorrelixEyeO — the signature glyph: the letter O as a wide-open eye. A
// gradient ring (the eye outline, indigo→cyan→emerald — the same sweep as the
// login artwork and BrandMark) around a deep-space iris: a near-black radial
// field with an indigo rim glow, holding a miniature network constellation —
// six device nodes joined by hairline links around one brighter cyan hub.
// Entirely hand-crafted inline SVG: no raster assets, no filters, no
// animation (static by design — prefers-reduced-motion safe); the "glow" is
// layered low-opacity circles.
//
// The ring's gradient stops read theme tokens (--brand-ring-a/b/c, defined in
// styles.css): deep tones on light chrome, luminous tones on dark surfaces —
// ≥3:1 against the rail/topbar in both themes. The iris interior stays deep
// space in every theme; that darkness IS the brand.
//
// CorrelixLogo — the full wordmark: C‹eye›RRELIX. The letters are real text
// in the login wordmark's face (Space Grotesk 700, bundled) so app-shell and
// login typography can never drift apart; the eye is sized in em so the whole
// lockup scales off one font-size. Screen readers get the brand name exactly
// once (role="img" + aria-label); the split glyphs are decorative.

type EyeProps = {
  /** Rendered box (px number or any CSS length, e.g. "1.16em"). */
  size?: number | string;
  /** Accessible name. Omit (default) to render as a decorative glyph. */
  label?: string;
};

export function CorrelixEyeO({ size = 24, label }: EyeProps) {
  const uid = useId().replace(/:/g, "");
  const ring = `${uid}-cxring`;
  const space = `${uid}-cxspace`;
  return (
    <svg
      viewBox="0 0 48 48"
      width={size}
      height={size}
      fill="none"
      role={label ? "img" : undefined}
      aria-label={label}
      aria-hidden={label ? undefined : true}
    >
      <defs>
        <linearGradient id={ring} x1="6" y1="8" x2="42" y2="40" gradientUnits="userSpaceOnUse">
          {/* stop-color can't resolve var() as an attribute — style works. */}
          <stop offset="0%" style={{ stopColor: "var(--brand-ring-a, #818cf8)" }} />
          <stop offset="55%" style={{ stopColor: "var(--brand-ring-b, #22d3ee)" }} />
          <stop offset="100%" style={{ stopColor: "var(--brand-ring-c, #34d399)" }} />
        </linearGradient>
        <radialGradient id={space} cx="0.5" cy="0.46" r="0.56">
          <stop offset="0%" stopColor="#04050e" />
          <stop offset="55%" stopColor="#0a0f24" />
          <stop offset="85%" stopColor="#1e1b4b" />
          <stop offset="100%" stopColor="#312e81" />
        </radialGradient>
      </defs>

      {/* Deep-space iris. */}
      <circle cx="24" cy="24" r="18.2" fill={`url(#${space})`} />

      {/* Constellation links — hairlines out of the hub + two rim ties. */}
      <g stroke="#7dd3fc" strokeWidth="1" strokeLinecap="round">
        <line x1="25.5" y1="21.5" x2="15.5" y2="13.5" opacity="0.55" />
        <line x1="25.5" y1="21.5" x2="31.5" y2="12.8" opacity="0.45" />
        <line x1="25.5" y1="21.5" x2="35.5" y2="27" opacity="0.5" />
        <line x1="25.5" y1="21.5" x2="28" y2="34.5" opacity="0.5" />
        <line x1="25.5" y1="21.5" x2="14" y2="30" opacity="0.4" />
        <line x1="15.5" y1="13.5" x2="11.5" y2="20" opacity="0.35" />
        <line x1="14" y1="30" x2="11.5" y2="20" opacity="0.4" />
        <line x1="35.5" y1="27" x2="28" y2="34.5" opacity="0.35" />
      </g>

      {/* Device nodes (layered circles = static glow, no filters). */}
      <circle cx="15.5" cy="13.5" r="3" fill="#e0e7ff" opacity="0.14" />
      <circle cx="15.5" cy="13.5" r="1.5" fill="#e0e7ff" opacity="0.92" />
      <circle cx="31.5" cy="12.8" r="1.3" fill="#a5b4fc" opacity="0.85" />
      <circle cx="35.5" cy="27" r="2.8" fill="#fbbf24" opacity="0.16" />
      <circle cx="35.5" cy="27" r="1.4" fill="#fbbf24" opacity="0.9" />
      <circle cx="28" cy="34.5" r="3" fill="#67e8f9" opacity="0.14" />
      <circle cx="28" cy="34.5" r="1.5" fill="#67e8f9" opacity="0.9" />
      <circle cx="14" cy="30" r="1.3" fill="#e0e7ff" opacity="0.8" />
      <circle cx="11.5" cy="20" r="1.1" fill="#a5b4fc" opacity="0.75" />
      {/* The hub — the one slightly brighter accent node. */}
      <circle cx="25.5" cy="21.5" r="6.5" fill="#22d3ee" opacity="0.09" />
      <circle cx="25.5" cy="21.5" r="4.2" fill="#22d3ee" opacity="0.22" />
      <circle cx="25.5" cy="21.5" r="1.9" fill="#22d3ee" opacity="0.98" />

      {/* Eye outline — the O's ring. Stroke weight tuned so at wordmark scale
          it matches Space Grotesk 700's letter stroke. */}
      <circle cx="24" cy="24" r="20.4" stroke={`url(#${ring})`} strokeWidth="5.2" />
    </svg>
  );
}

export default function CorrelixLogo({ size = 17, className }: { size?: number; className?: string }) {
  return (
    <span
      className={className ? `cx-logo ${className}` : "cx-logo"}
      role="img"
      aria-label={BRAND}
      style={{ fontSize: size }}
    >
      <span aria-hidden="true">C</span>
      <CorrelixEyeO size="1.16em" />
      <span aria-hidden="true">RRELIX</span>
    </span>
  );
}

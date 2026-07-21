import { useId } from "react";
import { BRAND } from "../../brand";

// Correlix brand mark (owner selection 2026-07-21 — brand board candidate 5:
// "the O IS the eye — a glowing network hub inside the wordmark, bright,
// luminous X"). Supersedes the candidate-3 standalone-eye lockup: the owner
// wants the eye to replace the O, not stand beside it, and the mark to read
// BRIGHT — never black ink.
//
// CorrelixEye — the signature logomark: a wide pointed-almond eye (it doubles
// as the wordmark's O) whose interior is a deep-navy field lit by a glowing
// hub-and-spoke constellation — the product in one glyph: Correlix watches the
// network and correlates it. The lids ride `currentColor` (the lockup sets a
// bright brand blue; the rail sets its own ink); the interior is self-coloured
// (fixed navy field + luminous cyan hub) so it reads identically on light and
// dark chrome. Candidate 5's device icons around the hub become plain nodes —
// icons are illegible at topbar scale. Entirely inline SVG: no raster, no
// filters, no animation (static by design → prefers-reduced-motion safe).
//
// CorrelixLogo — the full lockup: C‹eye›RRELIX. Letters are real text in the
// login wordmark's face (Space Grotesk 700, bundled) so app-shell and login
// typography can never drift apart; the final X carries the second accent
// (blue→bright-cyan gradient, styles.css `.cx-logo-x`). Screen readers get the
// brand name exactly once (role="img" + aria-label); the glyphs and split
// letters are decorative.

type EyeProps = {
  /** Rendered width (px number or any CSS length, e.g. "1.5em"). Height
   *  follows the 64:44 viewBox ratio so the almond keeps its proportions. */
  size?: number | string;
  /** Accessible name. Omit (default) to render as a decorative glyph. */
  label?: string;
};

// Interior constellation — a luminous hub with spokes to six nodes, all inside
// the almond. Fixed coordinates (viewBox space) so every instance renders the
// same mark.
const HUB_X = 32;
const HUB_Y = 22;
const NODES: Array<[number, number]> = [
  [32, 10],
  [44.5, 15],
  [46, 28.5],
  [33.5, 33.5],
  [19.5, 29.5],
  [18, 15.5],
];

// One closed pointed almond — lid stroke, interior field and clip all share it.
const ALMOND = "M2.5 22 C12 6.5, 52 6.5, 61.5 22 C52 37.5, 12 37.5, 2.5 22 Z";

export function CorrelixEye({ size = 24, label }: EyeProps) {
  const uid = useId().replace(/:/g, "");
  const field = `${uid}-field`;
  const clip = `${uid}-clip`;
  return (
    <svg
      viewBox="0 0 64 44"
      width={size}
      fill="none"
      role={label ? "img" : undefined}
      aria-label={label}
      aria-hidden={label ? undefined : true}
    >
      <defs>
        <radialGradient id={field} cx="0.5" cy="0.5" r="0.6">
          {/* Deep-navy interior, brightest under the hub — the dark ground that
              makes the glow read as light, on any chrome. */}
          <stop offset="0%" stopColor="#2f5fd0" />
          <stop offset="45%" stopColor="#16307a" />
          <stop offset="100%" stopColor="#0a1734" />
        </radialGradient>
        <clipPath id={clip}>
          <path d={ALMOND} />
        </clipPath>
      </defs>

      {/* Interior — the lit navy field, clipped to the almond. */}
      <path d={ALMOND} fill={`url(#${field})`} />

      <g clipPath={`url(#${clip})`}>
        {/* Spokes hub→node — bright cyan, candidate 5's radiating links. */}
        <g stroke="#7dd3fc" strokeOpacity="0.85" strokeWidth="1">
          {NODES.map(([x, y], i) => (
            <line key={`s-${i}`} x1={HUB_X} y1={HUB_Y} x2={x} y2={y} />
          ))}
        </g>
        {/* Nodes — each with a soft halo (layered circles, no glow filter). */}
        {NODES.map(([x, y], i) => (
          <g key={`n-${i}`}>
            <circle cx={x} cy={y} r="3" fill="#38bdf8" opacity="0.25" />
            <circle cx={x} cy={y} r="1.5" fill="#bae6fd" />
          </g>
        ))}
        {/* Hub — the white-hot centre of the mark (layered halo). */}
        <circle cx={HUB_X} cy={HUB_Y} r="9" fill="#38bdf8" opacity="0.18" />
        <circle cx={HUB_X} cy={HUB_Y} r="5.5" fill="#38bdf8" opacity="0.32" />
        <circle cx={HUB_X} cy={HUB_Y} r="2.9" fill="#7dd3fc" />
        <circle cx={HUB_X} cy={HUB_Y} r="1.5" fill="#e0f2fe" />
      </g>

      {/* Lids — pointed almond at the wordmark's weight, in the lockup's ink
          (currentColor → the bright brand blue in the topbar, rail ink in the
          rail). Drawn last so the rim stays crisp over the field. */}
      <path d={ALMOND} stroke="currentColor" strokeWidth="4.2" strokeLinejoin="round" />
    </svg>
  );
}

export default function CorrelixLogo({ size = 18, className }: { size?: number; className?: string }) {
  return (
    <span
      className={className ? `cx-logo ${className}` : "cx-logo"}
      role="img"
      aria-label={BRAND}
      style={{ fontSize: size }}
    >
      <span aria-hidden="true">C</span>
      {/* 1.5em wide → ~1.03em tall (64:44): the eye-O runs a shade taller and
          wider than the caps, exactly candidate 5's proportion. */}
      <CorrelixEye size="1.5em" />
      <span aria-hidden="true">RRELI</span>
      <span aria-hidden="true" className="cx-logo-x">X</span>
    </span>
  );
}

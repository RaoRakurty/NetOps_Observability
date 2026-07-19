import { useId } from "react";
import { BRAND } from "../../brand";

// Correlix brand mark (owner directive 2026-07-19, redesign 2 — "authoritative,
// like a real product logo; O looks like an eye; drop the loud colours and the
// decorative circle").
//
// CorrelixEyeO — the signature glyph: the letter O rendered as a calm, watchful
// eye. It is built to read as a LETTER first (a ring at Space Grotesk 700's O
// weight) and an eye second (a single-tone iris, a deep pupil, one small
// catchlight). Deliberately restrained: ONE accent colour for the iris, ink for
// everything else — no gradient sweep, no constellation of coloured nodes, no
// glow. That restraint is what makes it read as an enterprise product mark
// rather than an illustration. Entirely inline SVG: no raster, no filters, no
// animation (static by design → prefers-reduced-motion safe).
//
// Colour discipline: the ring + pupil ride `currentColor` (the wordmark's ink,
// or the rail's foreground), so the eye is the SAME ink as the letters around
// it. Only the iris carries brand colour, from the single `--brand-iris` token
// (styles.css) — one confident indigo, tuned per surface for contrast.
//
// CorrelixLogo — the full wordmark: C‹eye›RRELIX. The letters are real text in
// the login wordmark's face (Space Grotesk 700, bundled) so the app-shell and
// login typography can never drift apart; the eye is sized in em so the whole
// lockup scales off one font-size and the O sits on the same baseline as the
// caps. Screen readers get the brand name exactly once (role="img" +
// aria-label); the split glyphs are decorative.

type EyeProps = {
  /** Rendered box (px number or any CSS length, e.g. "1.03em"). */
  size?: number | string;
  /** Accessible name. Omit (default) to render as a decorative glyph. */
  label?: string;
};

export function CorrelixEyeO({ size = 24, label }: EyeProps) {
  const uid = useId().replace(/:/g, "");
  const iris = `${uid}-iris`;
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
        <radialGradient id={iris} cx="0.42" cy="0.4" r="0.72">
          {/* A single hue with a soft centre-to-rim falloff — depth without a
              multi-colour sweep. stop-color needs style to resolve var(). */}
          <stop offset="0%" style={{ stopColor: "var(--brand-iris-hi, #6366f1)" }} />
          <stop offset="100%" style={{ stopColor: "var(--brand-iris, #4f46e5)" }} />
        </radialGradient>
      </defs>

      {/* Iris — the one coloured element. */}
      <circle cx="24" cy="24" r="8.6" fill={`url(#${iris})`} />
      {/* Limbal ring — a real eye's darker iris edge; adds authority, no colour. */}
      <circle cx="24" cy="24" r="8.6" stroke="#05060d" strokeOpacity="0.22" strokeWidth="1" />
      {/* Pupil — deep, fixed (must stay dark in both themes). */}
      <circle cx="24" cy="24" r="3.9" fill="#05060d" />
      {/* Catchlight — the glint that makes it read as a living eye, not a target. */}
      <circle cx="21.2" cy="21.1" r="1.5" fill="#f8fafc" opacity="0.92" />

      {/* The O — eye outline at Space Grotesk 700's stroke weight, in the ink
          of the surrounding letters (currentColor). */}
      <circle cx="24" cy="24" r="19.4" stroke="currentColor" strokeWidth="5.4" />
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
      {/* 1.03em: a circle set at exactly cap height reads slightly small next to
          flat-topped caps, so the eye is nudged up a hair to sit optically level
          with the C·R·R·E·L·I·X — standard wordmark practice. */}
      <span aria-hidden="true">C</span>
      <CorrelixEyeO size="1.03em" />
      <span aria-hidden="true">RRELIX</span>
    </span>
  );
}

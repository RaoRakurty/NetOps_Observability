import { useId } from "react";
import { CloudGlyphShape, cloudTag } from "../CloudGlyph";

// shapes.tsx — a small network-topology shape kit. Following the universal
// convention (Cisco/Kentik/Auvik/Lucidchart): DEVICE TYPE = shape, HEALTH =
// color + glow, VENDOR = the logo inside the shape. Shapes beat boxes — an
// operator reads "router vs firewall vs cloud" at a glance without reading text.
//
// Every shape draws in a 0 0 100 100 viewBox so it scales to any size. Fill is a
// faint wash of the tone; stroke is the tone; a CSS drop-shadow gives the glow.

// "unknown" is the BLIND hop — a path hop that did not respond or was filtered
// (contract §2.4: unknown hops are preserved, never dropped, never bridged).
// "evidence" is an off-spine evidence branch (metrics/logs/flows/alerts/traces),
// deliberately NOT a device shape so it never reads as part of the path.
// WCAG 2.3.3 / reduced-motion: the fault-ring pulse is SVG SMIL, which the
// global CSS `prefers-reduced-motion` guard cannot reach — gate it in JS.
export function prefersReducedMotion(): boolean {
  return typeof window !== "undefined" && typeof window.matchMedia === "function"
    ? window.matchMedia("(prefers-reduced-motion: reduce)").matches
    : false;
}

export type ShapeKind =
  | "core" | "router" | "switch" | "firewall" | "gateway" | "access"
  | "cloud" | "server" | "vantage" | "target" | "unknown" | "evidence";

// Role/label → shape. Unknown roles fall back to a switch (the commonest access
// device). Cloud/internet/transit destinations get the cloud.
export function kindForRole(role: string): ShapeKind {
  const r = (role || "").toLowerCase();
  if (/core/.test(r)) return "core";
  if (/(^|\b)(router|rtr|edge-router|pe|p-router)\b/.test(r)) return "router";
  if (/(fire ?wall|fw|ngfw|palo|forti|asa)/.test(r)) return "firewall";
  if (/(gateway|gw|edge|wan|sd-?wan|vpn|tgw|transit)/.test(r)) return "gateway";
  if (/(cloud|internet|inet|aws|azure|gcp|saas)/.test(r)) return "cloud";
  if (/(server|host|vm|compute|reflector|prober|agent)/.test(r)) return "server";
  if (/(switch|sw|leaf|spine|dist|agg|access|lan)/.test(r)) return "switch";
  return "switch";
}

// A glyph drawn faintly inside the shape (a hint, not the main signal — the shape
// already carries the type). Kept monochrome so the tone reads cleanly.
const GLYPH: Record<ShapeKind, string> = {
  core: "◇", router: "⇄", switch: "▤", firewall: "⛨", gateway: "⬢",
  access: "▤", cloud: "☁", server: "▦", vantage: "◎", target: "◉",
  unknown: "?", evidence: "◫",
};

function shapeEls(kind: ShapeKind, tone: string, fill: string): JSX.Element {
  const stroke = tone;
  const sw = 5;
  switch (kind) {
    case "core":
      return (
        <>
          <circle cx="50" cy="50" r="42" fill={fill} stroke={stroke} strokeWidth={sw} />
          <circle cx="50" cy="50" r="29" fill="none" stroke={stroke} strokeWidth={2.5} opacity={0.6} />
        </>
      );
    case "router":
      return <circle cx="50" cy="50" r="42" fill={fill} stroke={stroke} strokeWidth={sw} />;
    case "switch":
    case "access":
      // hexagon
      return <polygon points="50,8 88,29 88,71 50,92 12,71 12,29" fill={fill} stroke={stroke} strokeWidth={sw} strokeLinejoin="round" />;
    case "firewall":
      // shield
      return <path d="M50 7 L86 21 V51 C86 73 69 88 50 95 C31 88 14 73 14 51 V21 Z" fill={fill} stroke={stroke} strokeWidth={sw} strokeLinejoin="round" />;
    case "gateway":
      // diamond
      return <polygon points="50,6 94,50 50,94 6,50" fill={fill} stroke={stroke} strokeWidth={sw} strokeLinejoin="round" />;
    case "server":
      // rounded tower
      return <rect x="22" y="12" width="56" height="76" rx="12" fill={fill} stroke={stroke} strokeWidth={sw} />;
    case "cloud":
      return <path d="M28 74 C16 74 12 58 24 54 C20 38 44 30 52 42 C58 30 82 34 80 52 C92 54 90 74 76 74 Z" fill={fill} stroke={stroke} strokeWidth={sw} strokeLinejoin="round" />;
    case "vantage":
      // radar / concentric — an observation point
      return (
        <>
          <circle cx="50" cy="50" r="42" fill="none" stroke={stroke} strokeWidth={2} opacity={0.4} />
          <circle cx="50" cy="50" r="28" fill="none" stroke={stroke} strokeWidth={2.5} opacity={0.7} />
          <circle cx="50" cy="50" r="13" fill={fill} stroke={stroke} strokeWidth={sw} />
        </>
      );
    case "target":
      // bullseye — the destination
      return (
        <>
          <circle cx="50" cy="50" r="42" fill={fill} stroke={stroke} strokeWidth={sw} />
          <circle cx="50" cy="50" r="26" fill="none" stroke={stroke} strokeWidth={3} opacity={0.7} />
          <circle cx="50" cy="50" r="10" fill={stroke} />
        </>
      );
    case "unknown":
      // blind hop — DASHED outline: we know a hop is here, we don't know what it is.
      // The dash is the honesty signal (an unresolved hop never looks like a device).
      return <circle cx="50" cy="50" r="40" fill={fill} stroke={stroke} strokeWidth={4} strokeDasharray="9 7" strokeLinecap="round" />;
    case "evidence":
      // off-spine evidence branch — a note card, not a device.
      return <rect x="14" y="20" width="72" height="60" rx="9" fill={fill} stroke={stroke} strokeWidth={4} strokeDasharray="0" />;
  }
}

// ShapeSVG — the device shape at `size`px: glossy (gradient fill + specular
// highlight), a vivid toned stroke, and a soft glow so it pops on the dark NOC
// canvas. `pulse` adds a breathing ring (for a fault). A faint type glyph hints
// the device type.
// Cloud-provider marks (VENDOR = the mark inside the shape, per the kit
// convention above). Licence audit D5 (2026-09-04) removed the providers'
// official vendored icons; what draws here now is ORIGINAL Correlix artwork
// from components/CloudGlyph.tsx — one cloud silhouette for every provider,
// distinguished only by a small plain letter tag (AWS / AZ / GCP). A provider
// with no tag renders the untagged generic cloud, never another provider's
// mark, and no provider colour appears: the glyph inherits `currentColor`.
//
// The glyph is authored in a 0 0 24 24 box and this kit draws in 0 0 100 100,
// so it is placed with a translate+scale — which scales its 1.6 stroke with it,
// keeping the glyph's weight PROPORTIONAL (the same relationship to its own box
// as everywhere else the family is drawn).
const PROVIDER_GLYPH_SCALE = 2;
const PROVIDER_GLYPH_OFFSET = 50 - (24 * PROVIDER_GLYPH_SCALE) / 2; // centre the 24-box

export function ShapeSVG({ kind, tone, size = 56, glyph = true, pulse = false, provider }: {
  kind: ShapeKind; tone: string; size?: number; glyph?: boolean; pulse?: boolean;
  // aws | azure | gcp — declared-inventory claim, stamped by the backend.
  provider?: string;
}) {
  const uid = useId().replace(/[^a-zA-Z0-9]/g, "");
  const gid = `g-${uid}`;
  // A declared provider replaces the generic type glyph with the cloud glyph;
  // an unrecognised provider still draws the cloud, just untagged.
  const providerTag = provider ? cloudTag(provider) : null;
  const showProviderGlyph = Boolean(provider);
  return (
    <svg width={size} height={size} viewBox="0 0 100 100"
      style={{ filter: `drop-shadow(0 0 7px ${tone}88) drop-shadow(0 3px 5px rgba(0,0,0,.45))`, overflow: "visible" }}>
      <defs>
        {/* glossy sheen: bright tone top-left → deep tone bottom-right */}
        <radialGradient id={gid} cx="38%" cy="30%" r="80%">
          <stop offset="0%" stopColor={tone} stopOpacity={0.55} />
          <stop offset="55%" stopColor={tone} stopOpacity={0.18} />
          <stop offset="100%" stopColor={tone} stopOpacity={0.07} />
        </radialGradient>
      </defs>
      {/* Fault ring: static under prefers-reduced-motion (SMIL isn't covered by
          the CSS reduced-motion guard), breathing otherwise. */}
      {pulse && (
        <circle cx="50" cy="50" r="44" fill="none" stroke={tone} strokeWidth={3} opacity={0.5}>
          {!prefersReducedMotion() && (
            <>
              <animate attributeName="r" values="40;52;40" dur="1.8s" repeatCount="indefinite" />
              <animate attributeName="opacity" values="0.6;0;0.6" dur="1.8s" repeatCount="indefinite" />
            </>
          )}
        </circle>
      )}
      {shapeEls(kind, tone, `url(#${gid})`)}
      {/* specular highlight — the "gloss" */}
      <ellipse cx="40" cy="30" rx="22" ry="13" fill="#ffffff" opacity={0.14} transform="rotate(-18 40 30)" />
      {glyph && !showProviderGlyph && (
        <text x="50" y="51" textAnchor="middle" dominantBaseline="central"
          fontSize="28" fill="#ffffff" opacity={0.92} style={{ fontWeight: 800 }}>
          {GLYPH[kind]}
        </text>
      )}
      {showProviderGlyph && (
        // The cloud glyph replaces the generic type glyph. It is drawn in white
        // on the toned shape (monochrome, no tile, no brand hue) — `color` is
        // what the glyph's `currentColor` resolves against.
        <g color="#ffffff" opacity={0.92}
          transform={`translate(${PROVIDER_GLYPH_OFFSET} ${PROVIDER_GLYPH_OFFSET}) scale(${PROVIDER_GLYPH_SCALE})`}>
          <CloudGlyphShape tag={providerTag} />
        </g>
      )}
    </svg>
  );
}

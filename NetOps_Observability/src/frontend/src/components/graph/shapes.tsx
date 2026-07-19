import { useId } from "react";
import awsMark from "../../assets/cloud/aws.svg";
import azureMark from "../../assets/cloud/azure.svg";
import gcpMark from "../../assets/cloud/gcp.svg";

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
// global CSS `prefers-reduced-motion` guard cannot reach — gate it in JS
// (same pattern as FlowEdge).
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
// Cloud-provider marks (VENDOR = the logo inside the shape, per the kit
// convention above). aws/azure/gcp use the OFFICIAL icons vendored from the
// providers' official packages (source + terms in
// src/assets/cloud/README.md) — rendered as-is, only composited onto a tile
// for contrast. Providers without a vendored official mark keep the
// monogram badge fallback (none today).
const PROVIDER_ICON: Record<string, { href: string; tile?: string }> = {
  aws:   { href: awsMark },                // ships its own navy tile
  azure: { href: azureMark, tile: "#FFFFFF" }, // transparent mark → white tile
  gcp:   { href: gcpMark, tile: "#FFFFFF" },   // transparent mark → white tile
};
const PROVIDER_MARK: Record<string, { bg: string; fg: string; text: string }> = {};

export function ShapeSVG({ kind, tone, size = 56, glyph = true, pulse = false, provider }: {
  kind: ShapeKind; tone: string; size?: number; glyph?: boolean; pulse?: boolean;
  // aws | azure | gcp — declared-inventory claim, stamped by the backend.
  provider?: string;
}) {
  const uid = useId().replace(/[^a-zA-Z0-9]/g, "");
  const gid = `g-${uid}`;
  const icon = provider ? PROVIDER_ICON[provider.toLowerCase()] : undefined;
  const mark = provider && !icon ? PROVIDER_MARK[provider.toLowerCase()] : undefined;
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
      {glyph && !mark && !icon && (
        <text x="50" y="51" textAnchor="middle" dominantBaseline="central"
          fontSize="28" fill="#ffffff" opacity={0.92} style={{ fontWeight: 800 }}>
          {GLYPH[kind]}
        </text>
      )}
      {icon && (
        <g>
          {/* the OFFICIAL provider mark replaces the generic glyph. The tile
              (when the mark is transparent) sits BEHIND it for contrast — the
              icon itself is untouched, per the providers' icon terms. */}
          {icon.tile && (
            <rect x="31" y="31" width="38" height="38" rx="7" fill={icon.tile}
              stroke="#ffffff" strokeOpacity={0.25} strokeWidth={1.5} />
          )}
          <image href={icon.href} x="34" y="34" width="32" height="32" />
        </g>
      )}
      {mark && (
        <g>
          {/* monogram badge fallback for providers without a vendored official mark */}
          <rect x="28" y="36" width="44" height="28" rx="7"
            fill={mark.bg} stroke="#ffffff" strokeOpacity={0.25} strokeWidth={1.5} />
          <text x="50" y="50.5" textAnchor="middle" dominantBaseline="central"
            fontSize={mark.text.length > 2 ? 16 : 18} fill={mark.fg}
            style={{ fontWeight: 800, letterSpacing: 0.5 }}>
            {mark.text}
          </text>
        </g>
      )}
    </svg>
  );
}

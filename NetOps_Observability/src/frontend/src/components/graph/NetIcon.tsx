import { useId } from "react";

// NetIcon.tsx — original, presentation-grade network device icons for the Device
// Topology map. Design language (the "modern network-diagram" look): a bold WHITE
// duotone glyph on a COLOURFUL rounded tile, with the device TYPE carried by the
// tile hue (router=blue, switch=cyan, firewall=rose, load-balancer=teal, …) and
// HEALTH carried by a glowing ring + status dot around the tile. Type-on-tile +
// health-on-ring keeps both readable at a glance and reads at small node sizes.
//
// 100% original artwork: offline, dependency-free, no third-party stencils. Each
// device type can be overridden with a custom image per the topology's type-icon
// editor (pass `src`); the tile + health ring still frame it for a consistent look.

export type NetKind =
  | "core" | "router" | "switch" | "firewall" | "loadbalancer"
  | "gateway" | "cloud" | "server" | "vantage" | "target";

// Role/label → device icon. Extends the shape kit's mapping with load balancers.
export function kindForDevice(role: string): NetKind {
  const r = (role || "").toLowerCase();
  if (/(load ?balan|lb|haproxy|f5|netscaler|alb|nlb|gslb|vip)/.test(r)) return "loadbalancer";
  if (/core/.test(r)) return "core";
  if (/(fire ?wall|fw|ngfw|palo|forti|asa|srx|checkpoint)/.test(r)) return "firewall";
  if (/(^|\b)(router|rtr|edge-router|pe|p-router|cpe)\b/.test(r)) return "router";
  if (/(gateway|gw|edge|wan|sd-?wan|vpn|tgw|transit)/.test(r)) return "gateway";
  if (/(cloud|internet|inet|aws|azure|gcp|saas)/.test(r)) return "cloud";
  if (/(server|host|vm|compute|reflector|prober|agent)/.test(r)) return "server";
  if (/(switch|sw|leaf|spine|dist|agg|access|lan)/.test(r)) return "switch";
  return "switch";
}

// type → tile gradient [top, bottom]. ELEGANT, DESATURATED jewel tones over a dark
// base — a muted instrument-grade palette (not a rainbow). Each type keeps a quiet
// hue identity; the only loud colour on the map is the health alert ring.
const TILE: Record<NetKind, [string, string]> = {
  core:         ["#4A4880", "#322F57"], // muted indigo
  router:       ["#3E5A82", "#293D59"], // dusty blue
  switch:       ["#2F6470", "#1F434C"], // muted teal-cyan
  firewall:     ["#8A4A55", "#5E2F38"], // muted clay rose
  loadbalancer: ["#357066", "#234A43"], // muted teal
  gateway:      ["#8A6A39", "#5C4623"], // muted bronze
  server:       ["#4C5868", "#333C49"], // slate
  cloud:        ["#41607D", "#2B4055"], // muted steel
  vantage:      ["#5A4880", "#3D3057"], // muted violet
  target:       ["#3E6B52", "#2A4838"], // muted green
};

// glyph colour — white, with per-element opacity for the duotone effect.
const W = "#ffffff";

// device glyphs — bold, simple, centred in a 64×64 tile (≈x18–46 / y16–48 usable).
// Drawn so each silhouette is unmistakable at small node sizes.
function glyph(kind: NetKind, tileBottom: string): JSX.Element {
  const sw = 2.6; // stroke weight for line accents
  switch (kind) {
    case "router":
      return (
        <>
          {/* chassis */}
          <rect x="15" y="36" width="34" height="13" rx="3.5" fill={W} />
          <circle cx="21" cy="42.5" r="1.7" fill={tileBottom} />
          <circle cx="27" cy="42.5" r="1.7" fill={tileBottom} />
          <rect x="38" y="40.5" width="8" height="4" rx="2" fill={tileBottom} opacity={0.5} />
          {/* routing arrows (↔) */}
          <g stroke={W} strokeWidth={sw} fill="none" strokeLinecap="round" strokeLinejoin="round">
            <path d="M23 30 H41" /><path d="M37.5 26.5 L41 30 L37.5 33.5" />
            <path d="M41 23 H23" opacity={0.85} /><path d="M26.5 19.5 L23 23 L26.5 26.5" opacity={0.85} />
          </g>
        </>
      );
    case "core":
      return (
        <>
          {/* stacked backbone chassis */}
          <rect x="15" y="38" width="34" height="11" rx="3" fill={W} />
          <rect x="15" y="25" width="34" height="11" rx="3" fill={W} opacity={0.78} />
          <circle cx="21" cy="43.5" r="1.5" fill={tileBottom} />
          <circle cx="26" cy="43.5" r="1.5" fill={tileBottom} />
          <circle cx="21" cy="30.5" r="1.5" fill={tileBottom} />
          <circle cx="26" cy="30.5" r="1.5" fill={tileBottom} />
          {/* routing arrows */}
          <g stroke={W} strokeWidth={sw} fill="none" strokeLinecap="round" strokeLinejoin="round">
            <path d="M34 20 H44" /><path d="M40.5 16.5 L44 20 L40.5 23.5" />
          </g>
        </>
      );
    case "switch":
      return (
        <>
          {/* wide chassis with a port row */}
          <rect x="13" y="34" width="38" height="14" rx="3.5" fill={W} />
          {[18, 23, 28, 33, 38, 43].map((x) => (
            <rect key={x} x={x} y="41" width="3" height="4" rx="1" fill={tileBottom} />
          ))}
          {/* switching double-arrow */}
          <g stroke={W} strokeWidth={sw} fill="none" strokeLinecap="round" strokeLinejoin="round">
            <path d="M24 22 H40" /><path d="M36.5 18.5 L40 22 L36.5 25.5" />
            <path d="M40 28 H24" /><path d="M27.5 24.5 L24 28 L27.5 31.5" />
          </g>
        </>
      );
    case "firewall":
      return (
        <>
          {/* brick wall */}
          <g fill={W}>
            <rect x="15" y="17" width="15" height="7.5" rx="1.5" />
            <rect x="33" y="17" width="15" height="7.5" rx="1.5" opacity={0.8} />
            <rect x="15" y="27" width="9.5" height="7.5" rx="1.5" opacity={0.8} />
            <rect x="27.5" y="27" width="15" height="7.5" rx="1.5" />
            <rect x="15" y="37" width="15" height="7.5" rx="1.5" opacity={0.8} />
          </g>
          {/* shield + check, sitting over the wall's lower-right */}
          <path d="M40 28 L48 31 V37.5 C48 42.5 44.5 45.5 40 47 C35.5 45.5 32 42.5 32 37.5 V31 Z"
            fill={W} stroke={tileBottom} strokeWidth={1.6} strokeLinejoin="round" />
          <path d="M36.5 37 L39 39.5 L43.5 34.5" stroke={tileBottom} strokeWidth={2.4} fill="none" strokeLinecap="round" strokeLinejoin="round" />
        </>
      );
    case "loadbalancer":
      return (
        <>
          {/* one source fanning to three targets */}
          <circle cx="32" cy="18" r="4.5" fill={W} />
          <g stroke={W} strokeWidth={sw} fill="none" strokeLinecap="round">
            <path d="M32 22.5 V30" />
            <path d="M32 30 C20 30 18 33 18 40" />
            <path d="M32 30 V40" />
            <path d="M32 30 C44 30 46 33 46 40" />
          </g>
          <circle cx="18" cy="44" r="4" fill={W} />
          <circle cx="32" cy="44" r="4" fill={W} />
          <circle cx="46" cy="44" r="4" fill={W} />
        </>
      );
    case "gateway":
      return (
        <>
          {/* portal / arch */}
          <path d="M19 46 V28 C19 21 25 17 32 17 C39 17 45 21 45 28 V46"
            fill="none" stroke={W} strokeWidth={3.2} strokeLinecap="round" />
          {/* arrow through the gate */}
          <g stroke={W} strokeWidth={sw} fill="none" strokeLinecap="round" strokeLinejoin="round">
            <path d="M24 33 H40" /><path d="M36 29 L40 33 L36 37" />
          </g>
          <rect x="17" y="45" width="30" height="3.5" rx="1.75" fill={W} />
        </>
      );
    case "server":
      return (
        <g fill={W}>
          {[18, 29.5, 41].map((y, i) => (
            <g key={i}>
              <rect x="16" y={y} width="32" height="9" rx="2.5" />
              <circle cx="21" cy={y + 4.5} r="1.6" fill={tileBottom} />
              <rect x="27" y={y + 3} width="15" height="3" rx="1.5" fill={tileBottom} opacity={0.4} />
            </g>
          ))}
        </g>
      );
    case "cloud":
      return (
        <path d="M23 44 C16 44 13 35 21 33 C19 24 32 21 35 28 C39 22 51 25 49 34 C55 35 54 44 46 44 Z"
          fill={W} />
      );
    case "vantage":
      return (
        <>
          <circle cx="32" cy="34" r="16" fill="none" stroke={W} strokeWidth={2} opacity={0.45} />
          <circle cx="32" cy="34" r="10" fill="none" stroke={W} strokeWidth={2.4} opacity={0.7} />
          <circle cx="32" cy="34" r="4.5" fill={W} />
          <path d="M32 34 L45 21" stroke={W} strokeWidth={2.6} strokeLinecap="round" />
        </>
      );
    case "target":
      return (
        <>
          <circle cx="32" cy="32" r="16" fill="none" stroke={W} strokeWidth={2.6} />
          <circle cx="32" cy="32" r="9.5" fill="none" stroke={W} strokeWidth={2.4} opacity={0.7} />
          <circle cx="32" cy="32" r="3.5" fill={W} />
          <path d="M32 12 V20 M32 44 V52 M12 32 H20 M44 32 H52" stroke={W} strokeWidth={2.2} strokeLinecap="round" opacity={0.6} />
        </>
      );
  }
  return <></>;
}

// NetIcon — a device tile at `size`px. The tile colour encodes the device TYPE.
// HEALTH is calm when fine and loud when not: a healthy node gets a subtle white
// bezel + soft shadow, while `alert` (warning/critical) adds a bold `tone` ring +
// coloured glow, and `pulse` (critical) adds a breathing ring. This keeps the map
// quiet until something is wrong. `src` renders a custom override image instead of
// the built-in glyph (the per-type icon editor).
export function NetIcon({ kind, tone, size = 58, alert = false, pulse = false, src }: {
  kind: NetKind; tone: string; size?: number; alert?: boolean; pulse?: boolean; src?: string;
}) {
  const uid = useId().replace(/[^a-zA-Z0-9]/g, "");
  const gid = `nt-${uid}`;
  const [top, bottom] = TILE[kind];
  const inset = 11; // viewBox padding for override images (centred 42×42 in the 64 tile)
  const filter = alert
    ? `drop-shadow(0 0 8px ${tone}88) drop-shadow(0 4px 7px rgba(0,0,0,.45))`
    : `drop-shadow(0 4px 7px rgba(0,0,0,.4))`;
  return (
    <svg width={size} height={size} viewBox="0 0 64 64" style={{ filter, overflow: "visible" }}>
      <defs>
        <linearGradient id={gid} x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor={top} />
          <stop offset="100%" stopColor={bottom} />
        </linearGradient>
      </defs>
      {pulse && (
        <rect x="3" y="3" width="58" height="58" rx="15" fill="none" stroke={tone} strokeWidth={3}>
          <animate attributeName="opacity" values="0.7;0;0.7" dur="1.8s" repeatCount="indefinite" />
          <animate attributeName="x" values="3;0;3" dur="1.8s" repeatCount="indefinite" />
          <animate attributeName="y" values="3;0;3" dur="1.8s" repeatCount="indefinite" />
          <animate attributeName="width" values="58;64;58" dur="1.8s" repeatCount="indefinite" />
          <animate attributeName="height" values="58;64;58" dur="1.8s" repeatCount="indefinite" />
        </rect>
      )}
      {/* tile */}
      <rect x="4" y="4" width="56" height="56" rx="15" fill={`url(#${gid})`} />
      {/* top sheen */}
      <rect x="4" y="4" width="56" height="22" rx="15" fill="#ffffff" opacity={0.07} />
      {/* bezel (calm) or health ring (alert) */}
      <rect x="4" y="4" width="56" height="56" rx="15" fill="none"
        stroke={alert ? tone : "#ffffff"} strokeWidth={alert ? 2.6 : 1.4} opacity={alert ? 0.95 : 0.22} />
      {/* glyph or override image */}
      {src ? (
        <image href={src} x={inset} y={inset} width={64 - 2 * inset} height={64 - 2 * inset} preserveAspectRatio="xMidYMid meet" />
      ) : glyph(kind, bottom)}
    </svg>
  );
}

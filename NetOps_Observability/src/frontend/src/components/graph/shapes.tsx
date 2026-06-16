// shapes.tsx — a small network-topology shape kit. Following the universal
// convention (Cisco/Kentik/Auvik/Lucidchart): DEVICE TYPE = shape, HEALTH =
// color + glow, VENDOR = the logo inside the shape. Shapes beat boxes — an
// operator reads "router vs firewall vs cloud" at a glance without reading text.
//
// Every shape draws in a 0 0 100 100 viewBox so it scales to any size. Fill is a
// faint wash of the tone; stroke is the tone; a CSS drop-shadow gives the glow.

export type ShapeKind =
  | "core" | "router" | "switch" | "firewall" | "gateway" | "access"
  | "cloud" | "server" | "vantage" | "target";

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
};

function shapeEls(kind: ShapeKind, tone: string): JSX.Element {
  const fill = tone + "1f";
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
  }
}

// ShapeSVG — the device shape at `size`px, toned + glowing, with a faint type
// glyph. `pulse` adds a breathing ring (for a fault). `logo` (data/URL) overlays
// the vendor mark; pass it via the wrapper instead when you want crisp <img>.
export function ShapeSVG({ kind, tone, size = 56, glyph = true, pulse = false }: {
  kind: ShapeKind; tone: string; size?: number; glyph?: boolean; pulse?: boolean;
}) {
  return (
    <svg width={size} height={size} viewBox="0 0 100 100"
      style={{ filter: `drop-shadow(0 0 5px ${tone}66) drop-shadow(0 2px 4px rgba(0,0,0,.3))`, overflow: "visible" }}>
      {pulse && (
        <circle cx="50" cy="50" r="44" fill="none" stroke={tone} strokeWidth={3} opacity={0.5}>
          <animate attributeName="r" values="40;52;40" dur="1.8s" repeatCount="indefinite" />
          <animate attributeName="opacity" values="0.6;0;0.6" dur="1.8s" repeatCount="indefinite" />
        </circle>
      )}
      {shapeEls(kind, tone)}
      {glyph && (
        <text x="50" y="50" textAnchor="middle" dominantBaseline="central"
          fontSize="30" fill={tone} opacity={0.85} style={{ fontWeight: 700 }}>
          {GLYPH[kind]}
        </text>
      )}
    </svg>
  );
}

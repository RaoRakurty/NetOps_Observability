// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// NmsControllerArt.tsx — how Correlix identifies an NMS / CONTROLLER platform.
//
// TRACKER 251 (2026-09-05). This file replaces the retired per-vendor art
// component, which carried the last place in the product where a third-party
// BRAND COLOUR was doing the work of identity: a table of per-vendor palettes
// (Meraki green, the Cisco blue, the Versa violets, the Prime greys) painted
// onto a per-vendor two-letter monogram chip, and onto a dashboard-preview
// scene whose window title imitated that vendor's own console, hostname and
// all. The retired names and literals are pinned in NmsControllerArt.test.tsx,
// which is where they belong: this file must not contain them.
//
// It is resolved the SAME way licence decision D5 (2026-09-04, the AWS / Azure
// / Google Cloud marks) and tracker 239 (2026-09-05, the six connector marks)
// were resolved:
//
//   controller identity = a GENERIC FUNCTIONAL GLYPH + the vendor's product
//                         name as plain, factual text.
//
// The glyph says what the controller IS — a wireless controller, an SD-WAN
// controller, a fabric controller, an orchestrator, an NMS. The text says
// whose. Naming a vendor to describe interoperability is ordinary nominative
// use; wearing the vendor's colours is not, so we do the first and never the
// second.
//
// RULES that keep this file clean (the same four as ConnectorGlyph.tsx):
//
//   • NEVER a vendor colour. There is ONE palette here, built from the
//     product's own theme tokens, and every controller shares it. A palette
//     keyed by vendor is pseudo-branding even when the shapes are abstract —
//     that is precisely what 251 is about.
//   • NEVER a vendor silhouette, monogram or wordmark. A stylised initial in
//     the vendor's hue is a mark by another route. Marks here are glyphs from
//     components/Icon.tsx, unchanged, in `currentColor`.
//   • NEVER identity by artwork alone. The same glyph and the same scene
//     deliberately serve several controllers; the visible NAME distinguishes
//     them, so a screen reader and a monochrome display lose nothing.
//   • ALWAYS an honest fallback. An unknown controller renders the generic
//     integration plug and the normalized-ingest scene — never a broken tile,
//     never another vendor's artwork.
//
// The DASHBOARD PREVIEW survives, because it was never the problem: it is an
// original, functional depiction of WHAT A CLASS OF CONTROLLER KNOWS (coverage
// and clients, assurance scores, overlay tunnels, spine/leaf state, a service
// chain, tenant sync, an alarm browser, a normalized event stream). It is now
// keyed by that functional SCENE rather than by vendor, drawn in theme tokens,
// and therefore legible in light mode as well as dark.
//
// Adding a controller is ONE ENTRY in NMS_CONTROLLER_REGISTRY below. Adding an
// official third-party mark instead requires an explicit owner review with the
// usage terms recorded in scripts/license-data.json first — see
// docs/design/UI_CONNECTOR_MARKS.md.

import { useId } from "react";
import type { CSSProperties } from "react";
import Icon from "./Icon";

/**
 * The functional taxonomy. A controller is presented by WHAT IT IS, which is
 * why one category legitimately covers several vendors and products.
 */
export type NmsCategory =
  | "Wireless controller"
  | "Campus assurance"
  | "SD-WAN controller"
  | "Fabric controller"
  | "Secure edge services"
  | "Multi-tenant orchestration"
  | "NMS"
  | "Controller";

/**
 * The functional preview scenes. Named for the CLASS OF STATE they draw, never
 * for a product — `wireless`, not `meraki`.
 */
export type NmsSceneId =
  | "wireless"
  | "assurance"
  | "overlay"
  | "fabric"
  | "services"
  | "orchestration"
  | "alarms"
  | "stream";

export type NmsControllerPresentation = {
  /** Canonical controller id (lower-case, as used by the API). */
  id: string;
  /** The vendor / product name, shown as plain text. Never a wordmark. */
  displayName: string;
  /** Functional category — what this platform is, not who sells it. */
  category: NmsCategory;
  /** Glyph name in components/Icon.tsx. Functional, never vendor-shaped. */
  icon: string;
  /** Functional preview scene. */
  scene: NmsSceneId;
  /** One-line statement of what the connector ingests. */
  capability: string;
};

/**
 * The single source of truth for controller presentation. No component may
 * branch on a controller id to draw its own artwork — it asks here.
 */
export const NMS_CONTROLLER_REGISTRY: Record<string, Omit<NmsControllerPresentation, "id">> = {
  meraki: {
    displayName: "Meraki",
    category: "Wireless controller",
    icon: "wireless",
    scene: "wireless",
    capability: "Cloud-managed wireless, switching and appliance state.",
  },
  catalyst_center: {
    displayName: "Catalyst Center",
    category: "Campus assurance",
    icon: "monitoring",
    scene: "assurance",
    capability: "Campus assurance scores, issues and inventory.",
  },
  vmanage: {
    displayName: "SD-WAN Manager",
    category: "SD-WAN controller",
    icon: "topology",
    scene: "overlay",
    capability: "SD-WAN overlay health — tunnels, BFD and app-route SLA.",
  },
  ndfc: {
    displayName: "Nexus Dashboard",
    category: "Fabric controller",
    icon: "infrastructure",
    scene: "fabric",
    capability: "Data-centre fabric state and switch health.",
  },
  versa_director: {
    displayName: "Versa Director",
    category: "Secure edge services",
    icon: "stack",
    scene: "services",
    capability: "SD-WAN / SASE appliance service state.",
  },
  versa_concerto: {
    displayName: "Versa Concerto",
    category: "Multi-tenant orchestration",
    icon: "automation",
    scene: "orchestration",
    capability: "Multi-tenant orchestration state across managed tenants.",
  },
  prime: {
    displayName: "Prime Infrastructure",
    category: "NMS",
    icon: "alerts",
    scene: "alarms",
    capability: "Alarms and inventory from a legacy campus NMS.",
  },
};

/**
 * What an unrecognised controller renders. Deliberately the integration plug
 * and the normalized-stream scene: it reads as "some controller", claims
 * nothing, and can never be mistaken for a vendor.
 */
export const GENERIC_CONTROLLER: NmsControllerPresentation = {
  id: "generic",
  displayName: "Controller",
  category: "Controller",
  icon: "plug",
  scene: "stream",
  capability: "Any controller with REST or webhooks — normalized ingest.",
};

/** Presentation for a controller id — the generic plug for anything unknown. */
export function controllerPresentation(vendor?: string | null): NmsControllerPresentation {
  const id = (vendor ?? "").trim().toLowerCase();
  const hit = id ? NMS_CONTROLLER_REGISTRY[id] : undefined;
  return hit ? { id, ...hit } : GENERIC_CONTROLLER;
}

/** The functional glyph name for a controller id. */
export function controllerIcon(vendor?: string | null): string {
  return controllerPresentation(vendor).icon;
}

/**
 * The controller's mark. Decorative by default — every controller surface
 * prints the product name beside it, so the glyph is hidden from assistive
 * tech unless a caller passes an explicit `label`.
 */
export function NmsMark({
  vendor,
  size = 34,
  label,
  className,
  style,
}: {
  vendor?: string | null;
  size?: number;
  label?: string;
  className?: string;
  style?: CSSProperties;
}) {
  return (
    <Icon
      name={controllerPresentation(vendor).icon}
      size={size}
      label={label}
      className={className}
      style={style}
    />
  );
}

// ── the one palette ───────────────────────────────────────────────────────────
//
// Every scene, every controller, one theme, all of it from the product's own
// tokens. `var(--token, #fallback)` is the sanctioned theme-aware pattern (see
// scripts/ui-consistency-check.mjs): the token governs, the hex only keeps the
// artwork drawable if a token is ever missing. NONE of these values is, or
// resembles, a third-party brand colour.

const ART = {
  /** Primary accent — the product's own. */
  a: "var(--accent, #4f46e5)",
  /** Secondary accent, for gradient ramps. */
  b: "var(--accent-2, #8b5cf6)",
  /** Panel ground the preview is drawn on. */
  panel: "var(--surface, #ffffff)",
  /** A faint accent wash used for glows and fills. */
  wash: "var(--accent-soft, rgba(99, 102, 241, 0.10))",
  /** Hairlines: grid, card edges, chrome. */
  line: "var(--panel-border, #d7dbe3)",
  /** Body and label text. */
  fg: "var(--fg, #161d29)",
  muted: "var(--muted, #64708a)",
  /** STATUS colours — semantic, never decorative and never vendor-derived. */
  warn: "var(--warn, #d97706)",
  bad: "var(--bad, #d64550)",
} as const;

const MONO = "var(--font-mono, ui-monospace, monospace)";
const SANS = "var(--font-sans, 'Inter', system-ui, sans-serif)";

// ── shared preview chrome ─────────────────────────────────────────────────────

const W = 400;
const H = 168;

function Chrome({ uid, title, children }: { uid: string; title: string; children: React.ReactNode }) {
  return (
    <svg viewBox={`0 0 ${W} ${H}`} className="nms-art" preserveAspectRatio="xMidYMid slice" aria-hidden focusable="false">
      <defs>
        <linearGradient id={`${uid}-ln`} x1="0" y1="0" x2="1" y2="0">
          <stop offset="0" stopColor={ART.a} />
          <stop offset="1" stopColor={ART.b} />
        </linearGradient>
        <radialGradient id={`${uid}-halo`} cx="0.5" cy="0.5" r="0.5">
          <stop offset="0" stopColor={ART.a} stopOpacity="0.22" />
          <stop offset="1" stopColor={ART.a} stopOpacity="0" />
        </radialGradient>
      </defs>
      <rect width={W} height={H} fill={ART.panel} />
      <rect width={W} height={H} fill={ART.wash} />
      {/* faint grid */}
      {[...Array(7)].map((_, i) => (
        <line key={`h${i}`} x1="0" y1={28 + i * 20} x2={W} y2={28 + i * 20} stroke={ART.line} strokeWidth="1" opacity=".45" />
      ))}
      {[...Array(12)].map((_, i) => (
        <line key={`v${i}`} x1={30 + i * 32} y1="22" x2={30 + i * 32} y2={H} stroke={ART.line} strokeWidth="1" opacity=".3" />
      ))}
      {/* window bar — a plain product-neutral strip, NOT an imitation of any
          console's chrome */}
      <rect width={W} height="22" fill={ART.wash} />
      <line x1="0" y1="22" x2={W} y2="22" stroke={ART.line} strokeWidth="1" />
      <rect x="10" y="7.5" width="18" height="7" rx="3.5" fill={ART.a} opacity=".45" />
      <text x="36" y="15" fontSize="9" fill={ART.muted} fontFamily={MONO}>
        {title}
      </text>
      <circle cx={W - 14} cy="11" r="3" fill={ART.a}>
        <animate attributeName="opacity" values="1;.25;1" dur="2.4s" repeatCount="indefinite" />
      </circle>
      {children}
    </svg>
  );
}

function Spark({ uid, d, x = 0, y = 0, w = W, strong = false }: { uid: string; d: string; x?: number; y?: number; w?: number; strong?: boolean }) {
  return (
    <g transform={`translate(${x},${y})`}>
      <path d={`${d} L ${w} 40 L 0 40 Z`} fill={`url(#${uid}-halo)`} opacity=".9" />
      <path d={d} fill="none" stroke={`url(#${uid}-ln)`} strokeWidth={strong ? 2.2 : 1.6} strokeLinecap="round" />
    </g>
  );
}

function Kpis({ items, x = 14, y = 34 }: { items: [string, string][]; x?: number; y?: number }) {
  return (
    <g>
      {items.map(([v, l], i) => (
        <g key={l} transform={`translate(${x + i * 76},${y})`}>
          <rect width="68" height="30" rx="6" fill={ART.panel} stroke={ART.line} />
          <text x="8" y="13" fontSize="10" fontWeight={700} fill={i === 0 ? ART.a : ART.fg} fontFamily={MONO}>{v}</text>
          <text x="8" y="24" fontSize="7" fill={ART.muted} fontFamily={SANS}>{l}</text>
        </g>
      ))}
    </g>
  );
}

// ── functional scenes ─────────────────────────────────────────────────────────
// Each one draws a CLASS of controller state. None is named after a product and
// none may be given a per-product variant.

function OverlayScene({ uid, title }: { uid: string; title: string }) {
  // WAN overlay: hub + branches, tunnel arcs, path-quality spark.
  const sites: [number, number, number][] = [[70, 78, 7], [200, 52, 9], [330, 82, 7], [140, 108, 5.5], [268, 112, 5.5]];
  return (
    <Chrome uid={uid} title={title}>
      <path d="M70 78 Q135 30 200 52" fill="none" stroke={ART.a} strokeWidth="1.8" opacity=".9" strokeDasharray="5 4">
        <animate attributeName="stroke-dashoffset" values="18;0" dur="1.6s" repeatCount="indefinite" />
      </path>
      <path d="M200 52 Q265 40 330 82" fill="none" stroke={ART.b} strokeWidth="1.8" opacity=".9" strokeDasharray="5 4">
        <animate attributeName="stroke-dashoffset" values="18;0" dur="2s" repeatCount="indefinite" />
      </path>
      <path d="M70 78 Q140 128 268 112" fill="none" stroke={ART.a} strokeWidth="1.4" opacity=".55" strokeDasharray="3 5" />
      <path d="M140 108 Q200 88 330 82" fill="none" stroke={ART.bad} strokeWidth="1.6" opacity=".8" strokeDasharray="2 4" />
      {sites.map(([x, y, r], i) => (
        <g key={i}>
          <circle cx={x} cy={y} r={r + 6} fill={`url(#${uid}-halo)`} />
          <circle cx={x} cy={y} r={r} fill={i === 1 ? ART.a : ART.panel} stroke={ART.a} strokeWidth="1.6" />
        </g>
      ))}
      <Spark uid={uid} x={0} y={126} d="M0 30 C 40 26, 60 12, 100 16 S 170 30, 210 22 S 300 4, 340 12 S 390 26, 400 22" />
      <Kpis items={[["12.4ms", "TUNNEL LATENCY"], ["0.4%", "LOSS"], ["9.2", "PATH SCORE"]]} x={220} y={128} />
    </Chrome>
  );
}

function WirelessScene({ uid, title }: { uid: string; title: string }) {
  // Wireless controller: AP field with coverage rings + per-band client bars.
  const aps: [number, number][] = [[54, 62], [126, 48], [198, 66], [270, 46], [338, 64], [90, 104], [162, 96], [234, 108], [306, 98]];
  return (
    <Chrome uid={uid} title={title}>
      {aps.map(([x, y], i) => (
        <g key={i}>
          <circle cx={x} cy={y} r={i % 3 === 0 ? 17 : 12} fill="none" stroke={ART.a} strokeWidth="1" opacity=".35" />
          <circle cx={x} cy={y} r={i % 3 === 0 ? 26 : 19} fill="none" stroke={ART.a} strokeWidth="1" opacity=".16" />
          <circle cx={x} cy={y} r="3.4" fill={i === 4 ? ART.warn : ART.a} />
        </g>
      ))}
      {[...Array(16)].map((_, i) => {
        const h = 6 + 14 * Math.abs(Math.sin(i * 1.7));
        return <rect key={i} x={16 + i * 24} y={150 - h} width="10" height={h} rx="2" fill={`url(#${uid}-ln)`} opacity=".75" />;
      })}
      <Kpis items={[["214", "CLIENTS"], ["9 / 9", "APs UP"], ["18%", "CH UTIL"]]} x={240} y={30} />
    </Chrome>
  );
}

function AssuranceScene({ uid, title }: { uid: string; title: string }) {
  // Assurance: health donut + per-category bars.
  const score = 0.86;
  const R = 34;
  const C = 2 * Math.PI * R;
  const cats: [string, number][] = [["WLAN", 0.92], ["Switch", 0.84], ["Router", 0.78], ["WAN", 0.66]];
  return (
    <Chrome uid={uid} title={title}>
      <g transform="translate(78,94)">
        <circle r={R + 14} fill={`url(#${uid}-halo)`} />
        <circle r={R} fill="none" stroke={ART.line} strokeWidth="9" />
        <circle
          r={R} fill="none" stroke={`url(#${uid}-ln)`} strokeWidth="9" strokeLinecap="round"
          strokeDasharray={`${C * score} ${C}`} transform="rotate(-90)"
        />
        <text y="5" textAnchor="middle" fontSize="18" fontWeight={700} fill={ART.fg} fontFamily={MONO}>86</text>
        <text y="18" textAnchor="middle" fontSize="7" fill={ART.muted} fontFamily={SANS}>NETWORK HEALTH</text>
      </g>
      {cats.map(([l, v], i) => (
        <g key={l} transform={`translate(160,${44 + i * 26})`}>
          <text x="0" y="9" fontSize="8" fill={ART.muted} fontFamily={SANS}>{l}</text>
          <rect x="52" y="2" width="170" height="8" rx="4" fill={ART.line} />
          <rect x="52" y="2" width={170 * v} height="8" rx="4" fill={`url(#${uid}-ln)`} />
          <text x="232" y="10" fontSize="8" fill={ART.a} fontFamily={MONO}>{Math.round(v * 100)}</text>
        </g>
      ))}
    </Chrome>
  );
}

function FabricScene({ uid, title }: { uid: string; title: string }) {
  // Spine-leaf DC fabric.
  const spines = [140, 260];
  const leaves = [60, 160, 240, 340];
  return (
    <Chrome uid={uid} title={title}>
      {spines.map((sx) =>
        leaves.map((lx) => (
          <line key={`${sx}-${lx}`} x1={sx} y1={52} x2={lx} y2={112} stroke={`url(#${uid}-ln)`} strokeWidth="1.2" opacity=".5" />
        )),
      )}
      {spines.map((x, i) => (
        <g key={x}>
          <rect x={x - 26} y={40} width="52" height="18" rx="4" fill={ART.panel} stroke={ART.a} strokeWidth="1.4" />
          <text x={x} y={52} textAnchor="middle" fontSize="8" fill={ART.a} fontFamily={MONO}>SPINE{i + 1}</text>
        </g>
      ))}
      {leaves.map((x, i) => (
        <g key={x}>
          <rect x={x - 22} y={104} width="44" height="16" rx="4" fill={ART.panel} stroke={i === 2 ? ART.warn : ART.a} strokeWidth="1.3" />
          <text x={x} y={115} textAnchor="middle" fontSize="7.5" fill={ART.fg} fontFamily={MONO}>LEAF{i + 1}</text>
        </g>
      ))}
      {[...Array(8)].map((_, i) => (
        <rect key={i} x={30 + i * 44} y={138} width="30" height="6" rx="3" fill={`url(#${uid}-ln)`} opacity={0.25 + 0.09 * (i % 4)} />
      ))}
      <Kpis items={[["48", "SWITCHES"], ["0", "FAULTS"]]} x={244} y={28} />
    </Chrome>
  );
}

function ServicesScene({ uid, title }: { uid: string; title: string }) {
  // Secure edge: a layered service chain + service arcs to the head end.
  const layers = ["SECURITY", "SD-WAN", "ROUTING", "ANALYTICS"];
  return (
    <Chrome uid={uid} title={title}>
      {layers.map((l, i) => (
        <g key={l} transform={`translate(28,${36 + i * 27})`}>
          <rect width="150" height="20" rx="5" fill={ART.panel} stroke={ART.a} strokeWidth="1.1" opacity={1 - i * 0.14} />
          <circle cx="12" cy="10" r="3" fill={ART.a} />
          <text x="24" y="13.5" fontSize="8" fill={ART.fg} fontFamily={MONO}>{l}</text>
          <text x="132" y="13.5" fontSize="8" fill={ART.a} fontFamily={MONO}>OK</text>
        </g>
      ))}
      <path d="M195 46 Q 275 30 350 58" fill="none" stroke={`url(#${uid}-ln)`} strokeWidth="1.8" strokeDasharray="5 4">
        <animate attributeName="stroke-dashoffset" values="18;0" dur="1.8s" repeatCount="indefinite" />
      </path>
      <path d="M195 90 Q 280 92 348 74" fill="none" stroke={ART.a} strokeWidth="1.4" opacity=".6" strokeDasharray="3 5" />
      <path d="M195 130 Q 270 148 350 96" fill="none" stroke={ART.b} strokeWidth="1.4" opacity=".6" strokeDasharray="3 5" />
      <circle cx="352" cy="70" r="16" fill={`url(#${uid}-halo)`} />
      <circle cx="352" cy="70" r="9" fill={ART.panel} stroke={ART.a} strokeWidth="2" />
      <text x="352" y="102" textAnchor="middle" fontSize="7.5" fill={ART.muted} fontFamily={SANS}>HEAD END</text>
      <Spark uid={uid} x={200} y={122} w={200} d="M0 30 C 30 24, 50 10, 85 16 S 150 32, 200 18" />
    </Chrome>
  );
}

function OrchestrationScene({ uid, title }: { uid: string; title: string }) {
  // Concentric orchestration rings with orbiting tenants.
  return (
    <Chrome uid={uid} title={title}>
      <g transform="translate(120,96)">
        <circle r="52" fill="none" stroke={ART.line} strokeWidth="1" />
        <circle r="36" fill="none" stroke={ART.a} strokeWidth="1.1" opacity=".5" strokeDasharray="3 4" />
        <circle r="20" fill="none" stroke={ART.b} strokeWidth="1.2" opacity=".7" />
        <circle r="24" fill={`url(#${uid}-halo)`} />
        <circle r="8" fill={`url(#${uid}-ln)`} />
        <g>
          <circle cx="36" cy="0" r="4" fill={ART.b} />
          <circle cx="-25" cy="-26" r="4" fill={ART.a} />
          <circle cx="-18" cy="31" r="4" fill={ART.a} />
          <animateTransform attributeName="transform" type="rotate" from="0" to="360" dur="24s" repeatCount="indefinite" />
        </g>
      </g>
      {["tenant-east", "tenant-west", "tenant-eu"].map((l, i) => (
        <g key={l} transform={`translate(216,${44 + i * 30})`}>
          <rect width="164" height="22" rx="5" fill={ART.panel} stroke={ART.line} />
          <circle cx="12" cy="11" r="3.2" fill={i === 1 ? ART.warn : ART.a} />
          <text x="24" y="14.5" fontSize="8.5" fill={ART.fg} fontFamily={MONO}>{l}</text>
          <text x="150" y="14.5" textAnchor="end" fontSize="8" fill={ART.a} fontFamily={MONO}>{i === 1 ? "SYNC" : "OK"}</text>
        </g>
      ))}
      <Spark uid={uid} x={216} y={128} w={164} d="M0 28 C 25 22, 40 12, 70 18 S 130 30, 164 16" />
    </Chrome>
  );
}

function AlarmsScene({ uid, title }: { uid: string; title: string }) {
  // NMS alarm browser: alarm table + severity bars.
  const rows: [string, string, string][] = [
    ["core-sw-01", "LINK DOWN Gi1/0/24", "CRIT"],
    ["dist-rtr-02", "CPU 94% sustained", "MAJ"],
    ["edge-fw-01", "Config drift detected", "MIN"],
    ["access-ap-17", "Client auth failures", "WARN"],
  ];
  // Severity reads from the product's own status tokens, descending — the same
  // scale the rest of the SPA uses, so it stays legible in both themes.
  const sev: Record<string, string> = { CRIT: ART.bad, MAJ: ART.warn, MIN: ART.a, WARN: ART.muted };
  return (
    <Chrome uid={uid} title={title}>
      {rows.map(([d, m, s], i) => (
        <g key={d} transform={`translate(14,${34 + i * 24})`}>
          <rect width="266" height="19" rx="4" fill={i % 2 ? ART.panel : ART.wash} />
          <circle cx="10" cy="9.5" r="3" fill={sev[s]} />
          <text x="22" y="13" fontSize="8" fill={ART.fg} fontFamily={MONO}>{d}</text>
          <text x="96" y="13" fontSize="8" fill={ART.muted} fontFamily={SANS}>{m}</text>
          <text x="256" y="13" textAnchor="end" fontSize="7.5" fontWeight={700} fill={sev[s]} fontFamily={MONO}>{s}</text>
        </g>
      ))}
      {[0.9, 0.55, 0.4, 0.72, 0.3].map((v, i) => (
        <g key={i}>
          <rect x={300 + i * 18} y={130 - 90 * v} width="11" height={90 * v} rx="2" fill={`url(#${uid}-ln)`} opacity=".8" />
        </g>
      ))}
      <text x="300" y="148" fontSize="7" fill={ART.muted} fontFamily={SANS}>ALARMS / 24H</text>
    </Chrome>
  );
}

function StreamScene({ uid, title }: { uid: string; title: string }) {
  // Generic REST/webhook: normalized JSON stream into the 3-class router.
  const lines = [
    `{ "event": "controller_alarm",`,
    `  "severity": "high",`,
    `  "device_id": "edge-07",`,
    `  "normalized": true }`,
  ];
  return (
    <Chrome uid={uid} title={title}>
      <rect x="14" y="32" width="212" height="118" rx="8" fill={ART.panel} stroke={ART.line} />
      {lines.map((l, i) => (
        <text key={i} x="26" y={56 + i * 18} fontSize="9.5" fill={i === 0 ? ART.a : ART.fg} fontFamily={MONO}>
          {l}
        </text>
      ))}
      <text x="26" y={140} fontSize="9" fill={ART.a} fontFamily={MONO}>
        ▌
        <animate attributeName="opacity" values="1;0;1" dur="1.2s" repeatCount="indefinite" />
      </text>
      <path d="M226 74 C 260 74, 258 96, 292 96" fill="none" stroke={`url(#${uid}-ln)`} strokeWidth="1.8" strokeDasharray="5 4">
        <animate attributeName="stroke-dashoffset" values="18;0" dur="1.5s" repeatCount="indefinite" />
      </path>
      <g transform="translate(292,72)">
        <rect width="94" height="48" rx="8" fill={ART.panel} stroke={ART.a} strokeWidth="1.2" />
        <text x="47" y="20" textAnchor="middle" fontSize="8.5" fill={ART.fg} fontFamily={SANS}>3-class router</text>
        <text x="47" y="36" textAnchor="middle" fontSize="7.5" fill={ART.a} fontFamily={MONO}>metric · state · event</text>
      </g>
    </Chrome>
  );
}

const SCENES: Record<NmsSceneId, (p: { uid: string; title: string }) => JSX.Element> = {
  wireless: WirelessScene,
  assurance: AssuranceScene,
  overlay: OverlayScene,
  fabric: FabricScene,
  services: ServicesScene,
  orchestration: OrchestrationScene,
  alarms: AlarmsScene,
  stream: StreamScene,
};

/**
 * Scene window titles. FUNCTIONAL: they name the class of state on screen, and
 * deliberately never imitate a vendor console's own title or hostname.
 */
export const SCENE_TITLE: Record<NmsSceneId, string> = {
  wireless: "wireless controller — coverage and clients",
  assurance: "campus assurance — health and issues",
  overlay: "SD-WAN controller — overlay health",
  fabric: "fabric controller — spine / leaf state",
  services: "secure edge — service chain status",
  orchestration: "orchestrator — tenant sync",
  alarms: "NMS — alarm browser",
  stream: "controller — normalized HTTP ingest",
};

/** Functional dashboard-preview art for a controller card. */
export function NmsDashArt({ vendor }: { vendor?: string | null }) {
  const uid = useId();
  const scene = controllerPresentation(vendor).scene;
  const Scene = SCENES[scene];
  return <Scene uid={uid} title={SCENE_TITLE[scene]} />;
}

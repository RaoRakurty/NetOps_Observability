import { useId } from "react";

// NmsVendorArt — the visual identity of the NMS connector gallery (#95).
// Each vendor gets (1) a compact abstract MARK (stylized monogram chip — not a
// trademark reproduction) and (2) a rich DASHBOARD PREVIEW: a dark-chrome
// product-screenshot-style SVG scene themed in the vendor's palette, drawn to
// read as "this is what that controller knows" (WAN arcs, AP fields, fabrics,
// gauges). Pure inline SVG — zero assets, works offline, crisp at any DPI.

export type NmsVendorId =
  | "meraki"
  | "catalyst_center"
  | "vmanage"
  | "ndfc"
  | "versa_director"
  | "versa_concerto"
  | "prime"
  | "generic";

type Theme = { a: string; b: string; bg0: string; bg1: string; glow: string };

export const NMS_THEMES: Record<NmsVendorId, Theme> = {
  meraki:          { a: "#67b346", b: "#a3e07c", bg0: "#0a1f10", bg1: "#12341c", glow: "#67b34655" },
  catalyst_center: { a: "#049fd9", b: "#67d8f5", bg0: "#05202e", bg1: "#0a3347", glow: "#049fd955" },
  vmanage:         { a: "#2f6ef3", b: "#22d3ee", bg0: "#081733", bg1: "#0e2a52", glow: "#2f6ef355" },
  ndfc:            { a: "#3b82f6", b: "#a5c6ff", bg0: "#0a1530", bg1: "#122548", glow: "#3b82f655" },
  versa_director:  { a: "#7c3aed", b: "#c4b5fd", bg0: "#150a2e", bg1: "#241347", glow: "#7c3aed55" },
  versa_concerto:  { a: "#d946ef", b: "#f0abfc", bg0: "#23092b", bg1: "#3a1245", glow: "#d946ef55" },
  prime:           { a: "#8aa0b8", b: "#cfdbe8", bg0: "#101826", bg1: "#1b2a3f", glow: "#8aa0b855" },
  generic:         { a: "#14b8a6", b: "#7ae9dc", bg0: "#08201d", bg1: "#0f3531", glow: "#14b8a655" },
};

const MONOGRAM: Record<NmsVendorId, string> = {
  meraki: "MK",
  catalyst_center: "CC",
  vmanage: "SD",
  ndfc: "ND",
  versa_director: "VD",
  versa_concerto: "VC",
  prime: "PI",
  generic: "◇",
};

/** Compact vendor mark: rounded gradient tile + monogram. */
export function NmsMark({ vendor, size = 40 }: { vendor: NmsVendorId; size?: number }) {
  const t = NMS_THEMES[vendor] ?? NMS_THEMES.generic;
  const uid = useId();
  return (
    <svg width={size} height={size} viewBox="0 0 48 48" aria-hidden focusable="false">
      <defs>
        <linearGradient id={`${uid}-g`} x1="0" y1="0" x2="1" y2="1">
          <stop offset="0" stopColor={t.a} />
          <stop offset="1" stopColor={t.b} />
        </linearGradient>
      </defs>
      <rect x="2" y="2" width="44" height="44" rx="12" fill={`url(#${uid}-g)`} />
      <rect x="2" y="2" width="44" height="44" rx="12" fill="none" stroke="rgba(255,255,255,.28)" strokeWidth="1" />
      <text
        x="24" y="30" textAnchor="middle"
        fontFamily="'Inter','Segoe UI',system-ui,sans-serif"
        fontWeight={700} fontSize={vendor === "generic" ? 22 : 17}
        fill="#fff" style={{ letterSpacing: "0.02em" }}
      >
        {MONOGRAM[vendor]}
      </text>
    </svg>
  );
}

// ── shared preview chrome ─────────────────────────────────────────────────────

const W = 400;
const H = 168;

function Chrome({ t, uid, title, children }: { t: Theme; uid: string; title: string; children: React.ReactNode }) {
  return (
    <svg viewBox={`0 0 ${W} ${H}`} className="nms-art" preserveAspectRatio="xMidYMid slice" aria-hidden focusable="false">
      <defs>
        <linearGradient id={`${uid}-bg`} x1="0" y1="0" x2="0.9" y2="1">
          <stop offset="0" stopColor={t.bg0} />
          <stop offset="1" stopColor={t.bg1} />
        </linearGradient>
        <linearGradient id={`${uid}-ln`} x1="0" y1="0" x2="1" y2="0">
          <stop offset="0" stopColor={t.a} />
          <stop offset="1" stopColor={t.b} />
        </linearGradient>
        <radialGradient id={`${uid}-halo`} cx="0.5" cy="0.5" r="0.5">
          <stop offset="0" stopColor={t.glow} />
          <stop offset="1" stopColor="transparent" />
        </radialGradient>
      </defs>
      <rect width={W} height={H} fill={`url(#${uid}-bg)`} />
      {/* faint grid */}
      {[...Array(7)].map((_, i) => (
        <line key={`h${i}`} x1="0" y1={28 + i * 20} x2={W} y2={28 + i * 20} stroke="rgba(255,255,255,.045)" strokeWidth="1" />
      ))}
      {[...Array(12)].map((_, i) => (
        <line key={`v${i}`} x1={30 + i * 32} y1="22" x2={30 + i * 32} y2={H} stroke="rgba(255,255,255,.03)" strokeWidth="1" />
      ))}
      {/* window bar */}
      <rect width={W} height="22" fill="rgba(0,0,0,.35)" />
      <circle cx="12" cy="11" r="3.2" fill="#ff5f57" opacity=".85" />
      <circle cx="24" cy="11" r="3.2" fill="#febc2e" opacity=".85" />
      <circle cx="36" cy="11" r="3.2" fill="#28c840" opacity=".85" />
      <text x="52" y="15" fontSize="9" fill="rgba(255,255,255,.55)" fontFamily="'JetBrains Mono',ui-monospace,monospace">
        {title}
      </text>
      <circle cx={W - 14} cy="11" r="3" fill={t.b}>
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

function Kpis({ t, items, x = 14, y = 34 }: { t: Theme; items: [string, string][]; x?: number; y?: number }) {
  return (
    <g>
      {items.map(([v, l], i) => (
        <g key={l} transform={`translate(${x + i * 76},${y})`}>
          <rect width="68" height="30" rx="6" fill="rgba(255,255,255,.05)" stroke="rgba(255,255,255,.09)" />
          <text x="8" y="13" fontSize="10" fontWeight={700} fill={i === 0 ? t.b : "rgba(255,255,255,.92)"} fontFamily="'JetBrains Mono',ui-monospace,monospace">{v}</text>
          <text x="8" y="24" fontSize="7" fill="rgba(255,255,255,.5)" fontFamily="'Inter',system-ui,sans-serif">{l}</text>
        </g>
      ))}
    </g>
  );
}

// ── per-vendor scenes ─────────────────────────────────────────────────────────

function SdwanScene({ t, uid, title }: { t: Theme; uid: string; title: string }) {
  // WAN overlay map: hub + branches, colored tunnel arcs, path-quality spark.
  const sites: [number, number, number][] = [[70, 78, 7], [200, 52, 9], [330, 82, 7], [140, 108, 5.5], [268, 112, 5.5]];
  return (
    <Chrome t={t} uid={uid} title={title}>
      <path d="M70 78 Q135 30 200 52" fill="none" stroke={t.a} strokeWidth="1.8" opacity=".9" strokeDasharray="5 4">
        <animate attributeName="stroke-dashoffset" values="18;0" dur="1.6s" repeatCount="indefinite" />
      </path>
      <path d="M200 52 Q265 40 330 82" fill="none" stroke={t.b} strokeWidth="1.8" opacity=".9" strokeDasharray="5 4">
        <animate attributeName="stroke-dashoffset" values="18;0" dur="2s" repeatCount="indefinite" />
      </path>
      <path d="M70 78 Q140 128 268 112" fill="none" stroke={t.a} strokeWidth="1.4" opacity=".55" strokeDasharray="3 5" />
      <path d="M140 108 Q200 88 330 82" fill="none" stroke="#f87171" strokeWidth="1.6" opacity=".8" strokeDasharray="2 4" />
      {sites.map(([x, y, r], i) => (
        <g key={i}>
          <circle cx={x} cy={y} r={r + 6} fill={`url(#${uid}-halo)`} />
          <circle cx={x} cy={y} r={r} fill={i === 1 ? t.b : "rgba(255,255,255,.85)"} stroke={t.a} strokeWidth="1.6" />
        </g>
      ))}
      <Spark uid={uid} x={0} y={126} d="M0 30 C 40 26, 60 12, 100 16 S 170 30, 210 22 S 300 4, 340 12 S 390 26, 400 22" />
      <Kpis t={t} items={[["12.4ms", "TUNNEL LATENCY"], ["0.4%", "LOSS"], ["9.2", "vQoE"]]} x={220} y={128} />
    </Chrome>
  );
}

function CampusScene({ t, uid, title }: { t: Theme; uid: string; title: string }) {
  // Cloud-managed campus: AP field with coverage rings + client bars.
  const aps: [number, number][] = [[54, 62], [126, 48], [198, 66], [270, 46], [338, 64], [90, 104], [162, 96], [234, 108], [306, 98]];
  return (
    <Chrome t={t} uid={uid} title={title}>
      {aps.map(([x, y], i) => (
        <g key={i}>
          <circle cx={x} cy={y} r={i % 3 === 0 ? 17 : 12} fill="none" stroke={t.a} strokeWidth="1" opacity=".28" />
          <circle cx={x} cy={y} r={i % 3 === 0 ? 26 : 19} fill="none" stroke={t.a} strokeWidth="1" opacity=".12" />
          <circle cx={x} cy={y} r="3.4" fill={i === 4 ? "#fbbf24" : t.b} />
        </g>
      ))}
      {[...Array(16)].map((_, i) => {
        const h = 6 + 14 * Math.abs(Math.sin(i * 1.7));
        return <rect key={i} x={16 + i * 24} y={150 - h} width="10" height={h} rx="2" fill={`url(#${uid}-ln)`} opacity=".75" />;
      })}
      <Kpis t={t} items={[["214", "CLIENTS"], ["9 / 9", "APs UP"], ["18%", "CH UTIL"]]} x={240} y={30} />
    </Chrome>
  );
}

function AssuranceScene({ t, uid, title }: { t: Theme; uid: string; title: string }) {
  // Assurance: health donut + per-category bars.
  const score = 0.86;
  const R = 34;
  const C = 2 * Math.PI * R;
  const cats: [string, number][] = [["WLAN", 0.92], ["Switch", 0.84], ["Router", 0.78], ["WAN", 0.66]];
  return (
    <Chrome t={t} uid={uid} title={title}>
      <g transform="translate(78,94)">
        <circle r={R + 14} fill={`url(#${uid}-halo)`} />
        <circle r={R} fill="none" stroke="rgba(255,255,255,.12)" strokeWidth="9" />
        <circle
          r={R} fill="none" stroke={`url(#${uid}-ln)`} strokeWidth="9" strokeLinecap="round"
          strokeDasharray={`${C * score} ${C}`} transform="rotate(-90)"
        />
        <text y="5" textAnchor="middle" fontSize="19" fontWeight={700} fill="#fff" fontFamily="'JetBrains Mono',ui-monospace,monospace">86</text>
        <text y="18" textAnchor="middle" fontSize="7" fill="rgba(255,255,255,.55)" fontFamily="'Inter',system-ui,sans-serif">NETWORK HEALTH</text>
      </g>
      {cats.map(([l, v], i) => (
        <g key={l} transform={`translate(160,${44 + i * 26})`}>
          <text x="0" y="9" fontSize="8" fill="rgba(255,255,255,.7)" fontFamily="'Inter',system-ui,sans-serif">{l}</text>
          <rect x="52" y="2" width="170" height="8" rx="4" fill="rgba(255,255,255,.08)" />
          <rect x="52" y="2" width={170 * v} height="8" rx="4" fill={`url(#${uid}-ln)`} />
          <text x="232" y="10" fontSize="8" fill={t.b} fontFamily="'JetBrains Mono',ui-monospace,monospace">{Math.round(v * 100)}</text>
        </g>
      ))}
    </Chrome>
  );
}

function FabricScene({ t, uid, title }: { t: Theme; uid: string; title: string }) {
  // Spine-leaf DC fabric.
  const spines = [140, 260];
  const leaves = [60, 160, 240, 340];
  return (
    <Chrome t={t} uid={uid} title={title}>
      {spines.map((sx) =>
        leaves.map((lx) => (
          <line key={`${sx}-${lx}`} x1={sx} y1={52} x2={lx} y2={112} stroke={`url(#${uid}-ln)`} strokeWidth="1.2" opacity=".5" />
        )),
      )}
      {spines.map((x, i) => (
        <g key={x}>
          <rect x={x - 26} y={40} width="52" height="18" rx="4" fill="rgba(255,255,255,.09)" stroke={t.a} strokeWidth="1.4" />
          <text x={x} y={52} textAnchor="middle" fontSize="8" fill={t.b} fontFamily="'JetBrains Mono',ui-monospace,monospace">SPINE{i + 1}</text>
        </g>
      ))}
      {leaves.map((x, i) => (
        <g key={x}>
          <rect x={x - 22} y={104} width="44" height="16" rx="4" fill="rgba(255,255,255,.09)" stroke={i === 2 ? "#fbbf24" : t.a} strokeWidth="1.3" />
          <text x={x} y={115} textAnchor="middle" fontSize="7.5" fill="rgba(255,255,255,.8)" fontFamily="'JetBrains Mono',ui-monospace,monospace">LEAF{i + 1}</text>
        </g>
      ))}
      {[...Array(8)].map((_, i) => (
        <rect key={i} x={30 + i * 44} y={138} width="30" height="6" rx="3" fill={`url(#${uid}-ln)`} opacity={0.25 + 0.09 * (i % 4)} />
      ))}
      <Kpis t={t} items={[["48", "SWITCHES"], ["0", "FAULTS"]]} x={244} y={28} />
    </Chrome>
  );
}

function SaseScene({ t, uid, title }: { t: Theme; uid: string; title: string }) {
  // Layered SASE/appliance stack + service arcs.
  const layers = ["SECURITY", "SD-WAN", "ROUTING", "ANALYTICS"];
  return (
    <Chrome t={t} uid={uid} title={title}>
      {layers.map((l, i) => (
        <g key={l} transform={`translate(28,${36 + i * 27})`}>
          <rect width="150" height="20" rx="5" fill="rgba(255,255,255,.06)" stroke={t.a} strokeWidth="1.1" opacity={1 - i * 0.14} />
          <circle cx="12" cy="10" r="3" fill={t.b} />
          <text x="24" y="13.5" fontSize="8" fill="rgba(255,255,255,.85)" fontFamily="'JetBrains Mono',ui-monospace,monospace">{l}</text>
          <text x="132" y="13.5" fontSize="8" fill={t.b} fontFamily="'JetBrains Mono',ui-monospace,monospace">OK</text>
        </g>
      ))}
      <path d="M195 46 Q 275 30 350 58" fill="none" stroke={`url(#${uid}-ln)`} strokeWidth="1.8" strokeDasharray="5 4">
        <animate attributeName="stroke-dashoffset" values="18;0" dur="1.8s" repeatCount="indefinite" />
      </path>
      <path d="M195 90 Q 280 92 348 74" fill="none" stroke={t.a} strokeWidth="1.4" opacity=".6" strokeDasharray="3 5" />
      <path d="M195 130 Q 270 148 350 96" fill="none" stroke={t.b} strokeWidth="1.4" opacity=".6" strokeDasharray="3 5" />
      <circle cx="352" cy="70" r="16" fill={`url(#${uid}-halo)`} />
      <circle cx="352" cy="70" r="9" fill="rgba(255,255,255,.9)" stroke={t.a} strokeWidth="2" />
      <text x="352" y="102" textAnchor="middle" fontSize="7.5" fill="rgba(255,255,255,.6)" fontFamily="'Inter',system-ui,sans-serif">HEAD END</text>
      <Spark uid={uid} x={200} y={122} w={200} d="M0 30 C 30 24, 50 10, 85 16 S 150 32, 200 18" />
    </Chrome>
  );
}

function OrchestrationScene({ t, uid, title }: { t: Theme; uid: string; title: string }) {
  // Concerto: concentric orchestration rings with orbiting tenants.
  return (
    <Chrome t={t} uid={uid} title={title}>
      <g transform="translate(120,96)">
        <circle r="52" fill="none" stroke="rgba(255,255,255,.1)" strokeWidth="1" />
        <circle r="36" fill="none" stroke={t.a} strokeWidth="1.1" opacity=".5" strokeDasharray="3 4" />
        <circle r="20" fill="none" stroke={t.b} strokeWidth="1.2" opacity=".7" />
        <circle r="24" fill={`url(#${uid}-halo)`} />
        <circle r="8" fill={`url(#${uid}-ln)`} />
        <g>
          <circle cx="36" cy="0" r="4" fill={t.b} />
          <circle cx="-25" cy="-26" r="4" fill="rgba(255,255,255,.85)" />
          <circle cx="-18" cy="31" r="4" fill={t.a} />
          <animateTransform attributeName="transform" type="rotate" from="0" to="360" dur="24s" repeatCount="indefinite" />
        </g>
      </g>
      {["tenant-east", "tenant-west", "tenant-eu"].map((l, i) => (
        <g key={l} transform={`translate(216,${44 + i * 30})`}>
          <rect width="164" height="22" rx="5" fill="rgba(255,255,255,.05)" stroke="rgba(255,255,255,.1)" />
          <circle cx="12" cy="11" r="3.2" fill={i === 1 ? "#fbbf24" : t.b} />
          <text x="24" y="14.5" fontSize="8.5" fill="rgba(255,255,255,.85)" fontFamily="'JetBrains Mono',ui-monospace,monospace">{l}</text>
          <text x="150" y="14.5" textAnchor="end" fontSize="8" fill={t.b} fontFamily="'JetBrains Mono',ui-monospace,monospace">{i === 1 ? "SYNC" : "OK"}</text>
        </g>
      ))}
      <Spark uid={uid} x={216} y={128} w={164} d="M0 28 C 25 22, 40 12, 70 18 S 130 30, 164 16" />
    </Chrome>
  );
}

function LegacyScene({ t, uid, title }: { t: Theme; uid: string; title: string }) {
  // Prime-era ops console: alarm table + severity bars.
  const rows: [string, string, string][] = [
    ["core-sw-01", "LINK DOWN Gi1/0/24", "CRIT"],
    ["dist-rtr-02", "CPU 94% sustained", "MAJ"],
    ["edge-fw-01", "Config drift detected", "MIN"],
    ["access-ap-17", "Client auth failures", "WARN"],
  ];
  const sev: Record<string, string> = { CRIT: "#f87171", MAJ: "#fb923c", MIN: "#fbbf24", WARN: t.b };
  return (
    <Chrome t={t} uid={uid} title={title}>
      {rows.map(([d, m, s], i) => (
        <g key={d} transform={`translate(14,${34 + i * 24})`}>
          <rect width="266" height="19" rx="4" fill={i % 2 ? "rgba(255,255,255,.03)" : "rgba(255,255,255,.06)"} />
          <circle cx="10" cy="9.5" r="3" fill={sev[s]} />
          <text x="22" y="13" fontSize="8" fill="rgba(255,255,255,.9)" fontFamily="'JetBrains Mono',ui-monospace,monospace">{d}</text>
          <text x="96" y="13" fontSize="8" fill="rgba(255,255,255,.55)" fontFamily="'Inter',system-ui,sans-serif">{m}</text>
          <text x="256" y="13" textAnchor="end" fontSize="7.5" fontWeight={700} fill={sev[s]} fontFamily="'JetBrains Mono',ui-monospace,monospace">{s}</text>
        </g>
      ))}
      {[0.9, 0.55, 0.4, 0.72, 0.3].map((v, i) => (
        <g key={i}>
          <rect x={300 + i * 18} y={130 - 90 * v} width="11" height={90 * v} rx="2" fill={`url(#${uid}-ln)`} opacity=".8" />
        </g>
      ))}
      <text x="300" y="148" fontSize="7" fill="rgba(255,255,255,.5)" fontFamily="'Inter',system-ui,sans-serif">ALARMS / 24H</text>
    </Chrome>
  );
}

function GenericScene({ t, uid, title }: { t: Theme; uid: string; title: string }) {
  // Generic REST/webhook: normalized JSON stream.
  const lines = [
    `{ "event": "controller_alarm",`,
    `  "severity": "high",`,
    `  "device_id": "edge-07",`,
    `  "normalized": true }`,
  ];
  return (
    <Chrome t={t} uid={uid} title={title}>
      <rect x="14" y="32" width="212" height="118" rx="8" fill="rgba(0,0,0,.32)" stroke="rgba(255,255,255,.1)" />
      {lines.map((l, i) => (
        <text key={i} x="26" y={56 + i * 18} fontSize="9.5" fill={i === 0 ? t.b : "rgba(255,255,255,.78)"} fontFamily="'JetBrains Mono',ui-monospace,monospace">
          {l}
        </text>
      ))}
      <text x="26" y={140} fontSize="9" fill={t.a} fontFamily="'JetBrains Mono',ui-monospace,monospace">
        ▌
        <animate attributeName="opacity" values="1;0;1" dur="1.2s" repeatCount="indefinite" />
      </text>
      <path d="M226 74 C 260 74, 258 96, 292 96" fill="none" stroke={`url(#${uid}-ln)`} strokeWidth="1.8" strokeDasharray="5 4">
        <animate attributeName="stroke-dashoffset" values="18;0" dur="1.5s" repeatCount="indefinite" />
      </path>
      <g transform="translate(292,72)">
        <rect width="94" height="48" rx="8" fill="rgba(255,255,255,.06)" stroke={t.a} strokeWidth="1.2" />
        <text x="47" y="20" textAnchor="middle" fontSize="8.5" fill="rgba(255,255,255,.9)" fontFamily="'Inter',system-ui,sans-serif">3-class router</text>
        <text x="47" y="36" textAnchor="middle" fontSize="7.5" fill={t.b} fontFamily="'JetBrains Mono',ui-monospace,monospace">metric · state · event</text>
      </g>
    </Chrome>
  );
}

const SCENES: Record<NmsVendorId, (p: { t: Theme; uid: string; title: string }) => JSX.Element> = {
  meraki: CampusScene,
  catalyst_center: AssuranceScene,
  vmanage: SdwanScene,
  ndfc: FabricScene,
  versa_director: SaseScene,
  versa_concerto: OrchestrationScene,
  prime: LegacyScene,
  generic: GenericScene,
};

const ART_TITLE: Record<NmsVendorId, string> = {
  meraki: "dashboard.meraki.com — wireless overview",
  catalyst_center: "Catalyst Center — assurance",
  vmanage: "SD-WAN Manager — overlay health",
  ndfc: "Nexus Dashboard — fabric controller",
  versa_director: "Versa Director — appliance services",
  versa_concerto: "Versa Concerto — orchestration",
  prime: "Prime Infrastructure — alarm browser",
  generic: "generic controller — HTTP integration",
};

/** Rich dashboard-preview art for a vendor card. */
export function NmsDashArt({ vendor }: { vendor: NmsVendorId }) {
  const uid = useId();
  const v: NmsVendorId = SCENES[vendor] ? vendor : "generic";
  const Scene = SCENES[v];
  return <Scene t={NMS_THEMES[v]} uid={uid} title={ART_TITLE[v]} />;
}

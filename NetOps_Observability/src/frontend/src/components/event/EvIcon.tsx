// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// EvIcon — the event panel's small outline glyphs. Drawn here from plain geometry
// (no third-party path data), stroked in currentColor so they follow the theme and
// the severity tone. Always decorative: every glyph sits beside the words it stands
// for, so it is hidden from assistive technology.

import type { EvIconName } from "../../lib/eventModel";

const PATHS: Record<EvIconName, JSX.Element> = {
  triangle: <><path d="M12 3.5 22 20.5H2Z" /><path d="M12 10v4.5" /><path d="M12 17.5v.01" /></>,
  octagon: <><path d="M8 2.5h8l5.5 5.5v8L16 21.5H8L2.5 16V8Z" /><path d="M12 7.5v5.5" /><path d="M12 16.5v.01" /></>,
  info: <><circle cx="12" cy="12" r="9.5" /><path d="M12 11v6" /><path d="M12 7.5v.01" /></>,
  check: <><circle cx="12" cy="12" r="9.5" /><path d="m7.5 12.5 3 3 6-6.5" /></>,
  bug: <><rect x="7" y="7" width="10" height="13" rx="5" /><path d="M12 7V4M7 12H3M21 12h-4M7 17l-3 2M17 17l3 2M7 8 4.5 6M17 8l2.5-2" /></>,
  cpu: <><rect x="6" y="6" width="12" height="12" rx="2" /><rect x="9.5" y="9.5" width="5" height="5" /><path d="M9 2.5V6M15 2.5V6M9 18v3.5M15 18v3.5M2.5 9H6M2.5 15H6M18 9h3.5M18 15h3.5" /></>,
  memory: <><rect x="3" y="7" width="18" height="10" rx="1.5" /><path d="M7 10v4M11 10v4M15 10v4M6 17v3M10 17v3M14 17v3M18 17v3" /></>,
  pulse: <path d="M2.5 12h4l2.5-6 4 12 2.5-6h6" />,
  layers: <><path d="m12 3 9.5 5-9.5 5-9.5-5Z" /><path d="m2.5 12.5 9.5 5 9.5-5" /><path d="m2.5 16.5 9.5 5 9.5-5" /></>,
  "arrow-up": <><path d="M12 20V5" /><path d="m5.5 11 6.5-6.5 6.5 6.5" /></>,
  "arrow-down": <><path d="M12 4v15" /><path d="m5.5 13 6.5 6.5 6.5-6.5" /></>,
  refresh: <><path d="M20 12a8 8 0 1 1-2.3-5.6" /><path d="M20.5 3.5V8H16" /></>,
  list: <><path d="M8.5 6.5H21M8.5 12H21M8.5 17.5H21" /><path d="M3.5 6.5h.01M3.5 12h.01M3.5 17.5h.01" /></>,
  chart: <><path d="M3.5 3.5v17h17" /><path d="m7 15 4-5 3.5 3L20 6.5" /></>,
  clock: <><circle cx="12" cy="12" r="9.5" /><path d="M12 6.5V12l3.5 2.5" /></>,
  code: <><path d="m8 7-5 5 5 5" /><path d="m16 7 5 5-5 5" /><path d="m13.5 4.5-3 15" /></>,
  braces: <><path d="M8.5 3.5H8a2.5 2.5 0 0 0-2.5 2.5v3.5L3.5 12l2 2.5V18A2.5 2.5 0 0 0 8 20.5h.5" /><path d="M15.5 3.5h.5a2.5 2.5 0 0 1 2.5 2.5v3.5l2 2.5-2 2.5V18a2.5 2.5 0 0 1-2.5 2.5h-.5" /></>,
  server: <><path d="M12 3c4.7 0 8.5 1.3 8.5 3s-3.8 3-8.5 3-8.5-1.3-8.5-3 3.8-3 8.5-3Z" /><path d="M3.5 6v6c0 1.7 3.8 3 8.5 3s8.5-1.3 8.5-3V6" /><path d="M3.5 12v6c0 1.7 3.8 3 8.5 3s8.5-1.3 8.5-3v-6" /></>,
  calendar: <><rect x="3.5" y="5" width="17" height="15.5" rx="2" /><path d="M3.5 10h17M8 3v4M16 3v4" /></>,
  grid: <><rect x="3.5" y="3.5" width="7" height="7" rx="1" /><rect x="13.5" y="3.5" width="7" height="7" rx="1" /><rect x="3.5" y="13.5" width="7" height="7" rx="1" /><rect x="13.5" y="13.5" width="7" height="7" rx="1" /></>,
  wrench: <path d="M14.5 6.5a4 4 0 0 1 5.3-3.7l-2.6 2.6.4 2.5 2.5.4 2.6-2.6a4 4 0 0 1-5.4 5L8.5 19.5a2.1 2.1 0 0 1-3-3l8.8-8.8a4 4 0 0 1 .2-1.2Z" />,
  fingerprint: <><path d="M12 3a8 8 0 0 1 8 8v2" /><path d="M4 13v-2a8 8 0 0 1 4.5-7.2" /><path d="M8 12a4 4 0 0 1 8 0v2a10 10 0 0 1-1.5 5" /><path d="M12 12v3a7 7 0 0 1-2 5" /></>,
  copy: <><rect x="8.5" y="8.5" width="12" height="12" rx="2" /><path d="M15.5 8.5V5.5a2 2 0 0 0-2-2h-8a2 2 0 0 0-2 2v8a2 2 0 0 0 2 2h3" /></>,
  circle: <circle cx="12" cy="12" r="8.5" />,
  share: <><circle cx="18" cy="5.5" r="2.5" /><circle cx="6" cy="12" r="2.5" /><circle cx="18" cy="18.5" r="2.5" /><path d="m8.2 10.8 7.6-4.1M8.2 13.2l7.6 4.1" /></>,
  external: <><path d="M14 3.5h6.5V10" /><path d="M20.5 3.5 11 13" /><path d="M18 14v5a1.5 1.5 0 0 1-1.5 1.5h-11A1.5 1.5 0 0 1 4 19V7.5A1.5 1.5 0 0 1 5.5 6h5" /></>,
  close: <path d="M6 6l12 12M18 6 6 18" />,
  doc: <><path d="M6 2.5h8l4.5 4.5v14.5H6Z" /><path d="M14 2.5V7h4.5M9 12h6.5M9 15.5h6.5" /></>,
  chevron: <path d="m9 5.5 6.5 6.5L9 18.5" />,
  "arrow-right": <><path d="M3.5 12h16" /><path d="m13 5.5 6.5 6.5-6.5 6.5" /></>,
  network: <><rect x="9" y="2.5" width="6" height="5" rx="1" /><rect x="2.5" y="16.5" width="6" height="5" rx="1" /><rect x="15.5" y="16.5" width="6" height="5" rx="1" /><path d="M12 7.5V12M5.5 16.5V12h13v4.5" /></>,
  flow: <><circle cx="5" cy="12" r="2.5" /><circle cx="19" cy="12" r="2.5" /><path d="M7.5 12h9" /><path d="m13.5 8.5 3 3.5-3 3.5" /></>,
  terminal: <><rect x="2.5" y="4" width="19" height="16" rx="2" /><path d="m6.5 9 3 3-3 3M12 15h5" /></>,
  user: <><circle cx="12" cy="8" r="4" /><path d="M4 21a8 8 0 0 1 16 0" /></>,
  cloud: <path d="M7 18.5a4.5 4.5 0 0 1-.6-9A6 6 0 0 1 18 8.6a5 5 0 0 1-1 9.9Z" />,
  shield: <><path d="M12 2.5 20 5.5v6c0 5-3.4 8.6-8 10-4.6-1.4-8-5-8-10v-6Z" /><path d="m8.5 12 2.5 2.5 4.5-5" /></>,
  inbox: <><path d="M3 13.5 5.5 4.5h13l2.5 9v6H3Z" /><path d="M3 13.5h5l1.5 2.5h5L16 13.5h5" /></>,
  tag: <><path d="M3 3h8l10 10-8 8L3 11Z" /><circle cx="7.5" cy="7.5" r="1.3" /></>,
  link: <><path d="M10 14a4.5 4.5 0 0 0 6.4 0l3-3a4.5 4.5 0 0 0-6.4-6.4l-1 1" /><path d="M14 10a4.5 4.5 0 0 0-6.4 0l-3 3a4.5 4.5 0 0 0 6.4 6.4l1-1" /></>,
  "plus-doc": <><path d="M6 2.5h8l4.5 4.5v14.5H6Z" /><path d="M14 2.5V7h4.5M12 10.5v7M8.5 14h7" /></>,
  vendor: <><circle cx="12" cy="12" r="9.5" /><path d="M2.5 12h19M12 2.5c2.6 2.6 3.8 6 3.8 9.5S14.6 18.9 12 21.5c-2.6-2.6-3.8-6-3.8-9.5S9.4 5.1 12 2.5Z" /></>,
};

export default function EvIcon({ name, size = 16, className }: { name: EvIconName; size?: number; className?: string }) {
  return (
    <svg
      className={className ? `evd-ico ${className}` : "evd-ico"}
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={1.8}
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      focusable="false"
    >
      {PATHS[name]}
    </svg>
  );
}

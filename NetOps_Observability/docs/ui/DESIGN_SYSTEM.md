# Design system

The rules new and changed UI code follows. The tokens live on `:root` in
`src/frontend/src/styles.css` (and are redefined per theme); this page says
which to use, and why. The audit that measures adoption is
[FRONTEND_UI_AUDIT.md](FRONTEND_UI_AUDIT.md).

## Principles

- **Readable first.** Operators read this on a wall screen and on a laptop at
  2am: anything a person reads is **≥ 14px** (owner, 2026-09-06). Smaller sizes
  are for non-reading marks only (sort arrows, chip counts).
- **Plain words.** No environment-variable names, no internal state names, US
  English. `copyVoice.test.ts` enforces the list of removed phrases.
- **Context-appropriate layouts, not identical screens.** A canvas (Topology)
  is full-bleed; a document page has a reading width; a table page lets the
  table scroll, never the page.
- **Tokens, not values.** A colour, size, radius or gap is a token reference;
  a raw value needs a comment saying why no token fits.

## Type

| Token | Size | Use |
|---|---|---|
| `--fs-micro` | 12px | Non-reading marks only: sort arrows, count badges |
| `--fs-meta` | 13px | Being retired for reading text (U1) — use `--fs-sm` |
| `--fs-sm` | 14px | Dense body: tables, nav, buttons, form labels |
| `--fs-base` | 15px | Body copy |
| `--fs-md` | 18px | Sub-headings |
| `--fs-lg` | 24px | Page / section titles |
| `--fs-xl` … `--fs-3xl` | 30–48px | KPI numerals |

Families: `--font-ui` (Inter) for UI, `--font-mono` (JetBrains Mono) for
addresses, ids, versions and code, `--font-display` (Space Grotesk) for KPI
numerals and brand headings only.

## Spacing and shape

- Gaps and padding: `--sp-1` (4px) … `--sp-7` (32px).
- Radius: `--r-1` (6px) small controls, `--r-2` (8px) inputs and chips,
  `--r-3` (10px) cards and panels, `--r-4` (12px) dialogs; `999px` only for
  pills.

## Colour

- Surfaces and text: `--bg`, `--surface`, `--panel`, `--fg`, `--fg-muted`,
  `--fg-subtle`, `--border`.
- State: `--good`, `--warn`, `--bad` (and the `--sev-*` severity ramp) — the
  same token for the same meaning on every page.
- Module accents (`--mod-*`) colour an area's chrome, never its data.

## Layout rules

- **Grid and panel children may shrink** (`min-width: 0`); a wide table scrolls
  inside its own box (`DataTable` / `.dtv` does; a plain `<table>` gets a
  scroll box at phone width).
- **Phone width (≤ 640px):** the top bar shows icon controls (labels stay for
  screen readers); breadcrumb and leaf tabs stack, the tabs scroll as one
  strip; KPI rows are two columns.
- Shared components first: `DataTable`, `Panel`/`Section`, `StepFlow`,
  `FeatureOffNotice`, `AskIris` — before a page-local variant.

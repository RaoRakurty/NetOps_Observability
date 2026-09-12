# Typography — decision memo (2026-09-06)

Owner: *"Fonts across the site looks lighter I believe it should look more
stronger. Research on typography and fonts."* Earlier the same day: *"fonts are
too small… watchable font, elegant and crisp and easy on eye"*, *"less words,
clean"*. Owner's references: **Inter** (tall x-height, the most-used SaaS UI
face), **Geist Sans** (Swiss, dense data dashboards), **DM Sans**, **Satoshi**,
**JetBrains Mono** (tables/code); trends: mixed weights, variable axes.

## What was actually wrong

The brief assumed no font was bundled. It was — via four `@fontsource` npm
packages imported from `main.tsx`. The real defects were subtler and all
weight-related:

1. **Only discrete static weights shipped** (Inter 400/500/600/700, Space
   Grotesk 500/600/700, IBM Plex Mono 500/600). Nothing between 400 and 500
   existed, and `body` inherited **400** — the single largest reason the UI read
   thin. No `opsz` axis, so small text got the display cut.
2. **Three UI faces at once.** `--font-sans`/`--font-ui` said Inter; `.shell-v2`
   re-pointed `--font-sans` at *Manrope Variable*; ~40 rules hard-coded
   `"Space Grotesk"`; 30+ hard-coded a raw `ui-monospace, SFMono-Regular, …`
   stack, bypassing `--font-mono` entirely. `--font-mono` itself named IBM Plex
   Mono, while several rules named **JetBrains Mono, which was never bundled**.
3. **Secondary text below the small-text contrast bar.** `--fg-subtle` measured
   4.63:1 (light) and 4.45:1 (dark) on the worst surface — AA, but these tokens
   carry 10–13px text, where WCAG 1.4.6 asks 7:1.
4. `-webkit-font-smoothing: antialiased` was set globally on `:root`. On macOS
   that swaps subpixel rendering for greyscale AA and makes text visibly
   *thinner* ([MDN](https://developer.mozilla.org/en-US/docs/Web/CSS/-webkit-font-smoothing)).
5. Bundling the faces through the JS graph emitted **99 hashed font files
   (1.36 MB)** into `dist/assets/`, at URLs `index.html` cannot preload — so
   first paint always showed fallback text.

## Decision

| Role | Face | Licence | Why |
|---|---|---|---|
| UI text (`--font-sans`, `--font-ui`) | **Inter Variable** — `wght` 100–900, `opsz` 14–32 | OFL-1.1 | The owner's first reference and the correct one. Tall x-height, and the `opsz` axis is the deciding feature: the small cut is drawn with a taller x-height and ink-traps *for* small sizes, which is exactly the 11–14px band this product lives in. |
| Commands, ids, tabular data (`--font-mono`) | **JetBrains Mono Variable** — `wght` 100–800 | OFL-1.1 | The owner's own choice for tables/code. Its stated design intent is a maximised lowercase height at standard width, plus unambiguous `1 l I` / `0 O` — the properties that matter for device names, prefixes and AS numbers. |
| KPI numerals, page/section titles (`--font-display`) | **Space Grotesk Variable** — `wght` 300–700 | OFL-1.1 | Already the established brand display face; a geometric adaptation of Space Mono that keeps its technical character at title size. **Display only** — never body copy. |

**Geist Sans was evaluated and not chosen.** It is genuinely OFL-1.1 and ships a
variable woff2, so licensing was not the blocker. No published evidence was
found that it outperforms Inter at 13–14px in dense tables, its public material
is design-language marketing rather than metric data, and it has no `opsz` axis.
Swapping a proven face for an unproven one, against the owner's own first
reference, is not a change this evidence supports.

**Satoshi is excluded on licence grounds.** It is distributed by Fontshare
(Indian Type Foundry), not under OFL. Repeated attempts to read the licence text
failed (the site is a JS-rendered SPA), and we cannot establish that embedding
and redistributing the binaries inside a shipped commercial product is
permitted. Correlix ships fonts to customers; an unverifiable redistribution
right is a hard stop. **DM Sans** (OFL) was not needed once Inter was retained.

## Weight scale

| Use | Weight |
|---|---|
| Body / table cells | **450** (`body`), with `font-optical-sizing: auto` |
| Labels, column headers, chips | **500–600** |
| Headings | **600–650** (`h1–h4` remain 700) |
| KPI numerals | **700** |

450 is a real interpolated instance, not synthesis — that is the whole point of
moving to variable files. It reads materially more solid than 400 at 12–14px
without the "everything is semibold" flatness 500 gives to body copy.

## Contrast floor

**≥ 7:1 for anything ≤ 13px; ≥ 4.5:1 otherwise** (WCAG AA is 4.5:1 normal /
3:1 large; AAA is 7:1 / 4.5:1; "large" = ≥18pt regular or ≥14pt bold). Measured
against the *worst* surface in each theme, not the canvas:

| Theme | Token | Before | After |
|---|---|---|---|
| light (on `--surface-2` #f1f3f7) | `--fg-muted` | #586173 · 5.61:1 | **#3c424f · 9.07:1** |
| light | `--fg-subtle` | #646e80 · 4.63:1 | **#4b5260 · 7.07:1** |
| dark/oled (on `--overlay` #1f2843) | `--fg-muted` | #a8b5cf · 7.05:1 | **#c3ccde · 9.02:1** |
| dark/oled | `--fg-subtle` | #848ea8 · 4.45:1 | **#adb4c5 · 7.01:1** |
| indigo (on #221f33) | `--fg-subtle` | #8b88a0 · 4.67:1 | **#acaabb · 7.03:1** |
| graphite (on #232932) | `--fg-muted` / `--fg-subtle` | 6.77:1 / 3.76:1 | **#c7ccd2 · 9.06:1 / #aeb4bb · 7.00:1** |

`--fg-muted` is lifted further than `--fg-subtle` on purpose: raising both to
exactly 7:1 would collapse the two-step ramp into one flat grey.

## Delivery

Offline-first, so nothing is fetched at runtime. Six variable `.woff2` (latin +
latin-ext only) are checked into `src/frontend/public/fonts/` — **303 084 bytes
total, replacing 1 362 496 bytes**, a net **−1.03 MB** in the frontend image.
Filenames carry the first 8 hex of each file's own SHA-256, so nginx serves
`/fonts/` `immutable, 1y` truthfully and `index.html` can `<link rel="preload">`
the two primary faces. `gen-licenses.mjs` re-verifies, on every build, that each
shipped file matches its pinned upstream package byte-for-byte and that the
OFL-1.1 text beside it is the upstream text verbatim. Provenance and checksums:
`src/frontend/public/fonts/README.md`.

All three families are declared **once**, at the top of `src/styles.css`. Do not
re-point a family token per shell or per theme, and do not import `@fontsource`
CSS from TypeScript — those two mistakes are what produced the drift above.

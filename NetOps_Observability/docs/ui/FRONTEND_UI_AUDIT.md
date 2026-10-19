# Frontend UI audit

Living inventory for the app-wide fonts / colours / alignment pass (owner queue
item C, 2026-10-18). Measured, not eyeballed: every number below comes from the
crawl in **How it is measured**. Re-run it after each slice and update the
tables; [VISUAL_QA_REPORT.md](VISUAL_QA_REPORT.md) records each run.

## How it is measured

A Playwright crawl signs in to a running stack, selects the platform workspace,
and visits every leaf route in `src/frontend/src/nav.tsx` (68 at the
2026-10-19 baseline) in three viewports: dark 1440×900, light 1440×900,
dark 390×844. Per route it records page errors, whether the document scrolls
sideways, and the computed font size of every visible text element.

## Baseline (2026-10-19, main @ 38b3df36)

### Phone width (390px)

**68 of 68 routes scrolled sideways.** Causes, in order of reach:

1. **Top bar** — the brand image (38px tall) left no room; search, scope, time
   range, help, health and Iris were pushed off-screen on every route.
2. **Grid tracks grow to their content** — `1fr` is `minmax(auto, 1fr)`, so a
   wide table stretched its track and the page instead of scrolling in its box.
3. **119 plain `<table>`s** (40 `ds-table`) have no scroll wrapper.
4. **Sub-nav** beside the breadcrumb was squeezed to a one-word-wide column.
5. **KPI rows** stayed four columns wide.

Fixed in C1 (this change) → **68 of 68** routes fit. The last one
(`security/overview`) was a table's sr-only labels (`position: absolute`)
escaping its scroll box; the table is now their containing block.

### Type sizes (dark 1440, all routes)

The NOC-admin standard (owner 2026-09-06): **body ≥ 14px, headings ≥ 16px,
nothing below 12.5px**. Text elements by computed size:

| Size | Elements |
|---|---|
| 12.5px | 4071 |
| 12px | 2223 |
| 14px | 1645 |
| 11px | 869 |
| 11.5px | 731 |
| 13px | 551 |
| 10px | 190 |
| 9px | 98 |
| 10.5px | 98 |
| 30px | 85 |
| 10.58px | 47 |
| 15px | 45 |

Routes with the most text below 14px:

| Route | Elements < 14px |
|---|---|
| `platform/data-protection` | 1171 |
| `investigate/wan-paths` | 634 |
| `admin/transport` | 514 |
| `investigate/rca` | 438 |
| `analytics/device-monitoring` | 409 |
| `explore/logs` | 395 |
| `investigate/tunnels` | 386 |
| `explore/events` | 369 |
| `analytics/demo` | 289 |
| `operations/incidents` | 279 |
| `admin/audit` | 267 |
| `overview/home` | 261 |
| `investigate/findings` | 259 |
| `admin/licence` | 259 |
| `operations/queue` | 244 |

Source of the drift: `styles.css` declares 12.5px 237 times, 13px 78, 12px 77,
11px 53 (and 10–11.5px a further 73), against a token scale (`--fs-*`) that
is used only 134 times. 792 inline `style={{ fontSize | color }}` props in the
TSX bypass the stylesheet altogether.

### Colour, radius, spacing

- 373 raw hex colours in `styles.css` outside the token blocks.
- Border radius: eight distinct values in use (4, 5, 6, 7, 8, 9, 10, 999px)
  against four `--r-*` tokens.
- Spacing tokens (`--sp-1…7`) are the most adopted (340 uses).

### Desktop details seen in the screenshots

- Inventory: the IP column truncates IPv4 addresses ("192.168.222.…") and the
  Status header truncates ("STATUS…").

## Open findings

| # | Finding | Next step |
|---|---|---|
| U1 | Text below the 12.5px floor (≈2,000 elements at 9–12px) and body text (tables) at 12.5px instead of 14px | C2: lift everything to the floor, table/body text to `--fs-sm`, migrate raw sizes to tokens, with before/after shots |
| U2 | Inline font sizes/colours in TSX (792) | Migrate with each page slice; new code uses tokens (see DESIGN_SYSTEM.md) |
| U4 | Inventory IP / Status columns truncate | Widen with the C2 table pass |
| U5 | Raw hex colours (373) and radius spread | C3: map to tokens |

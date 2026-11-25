# Correlix visual language

Owner decision, 2026-11-24: Correlix uses icons beside every menu item, groups
its menus and panels with dividers and collapsible sections, and uses colour
only where colour means something. The approved mockup is
`/var/tmp/correlix-segregation-mock.png` on the lab box. The references the
owner pointed to are a DNS-security screen (icons on every menu item, green
Allow and red Deny pills with an icon, neutral type chips) and a quotes screen
(divider-separated groups, left-chevron sections, compact neutral dropdowns).

These rules apply to every screen. A change that breaks one of them needs an
owner decision first.

## Rules

1. **Icons.** Every menu item at every level carries a 16px line icon from
   `src/frontend/src/components/Icon.tsx`, in that file's thin-stroke style
   (24 viewBox, round caps). Icons are grey by default. No icon font and no
   icon package: new glyphs are added to `Icon.tsx`.
2. **One accent colour.** The accent marks only: the active or selected item,
   the primary action on a screen, links, keyboard focus and checked
   checkboxes. Sections, modules and pages do not get colours of their own.
3. **Semantic colour, always with a word or an icon.** Green means up, allowed
   or healthy. Red means down, denied or critical. Amber means degraded, warning
   or suspected. Blue means information. A status is never shown by colour
   alone: the chip also carries an icon and a word (for example "✓ Up").
4. **Descriptive values stay neutral.** Types, vendors, sites, kinds, sources,
   counts and tags use neutral chips or plain text.
5. **Type.** Body and menu text is at least 14px (the NOC standard). Small
   uppercase group labels may use 12.5px, the type-floor minimum.
6. **Grouping.** Groups are separated by a thin divider and whitespace, not by
   boxes. A collapsible section has its chevron on the left. Secondary values
   (counts, prices, states) sit right-aligned and quiet.

## Menu

The expanded menu is `components/NavTree.tsx`, shown inside the rail
(`components/IconRail.tsx`). It is the default view; the collapse button at the
foot of the rail switches to the icon-only rail, and the choice is remembered.

- Home, Overview, My dashboards and Iris sit at the top, flat.
- The work sections follow in zones, each after a thin divider: Operations;
  Investigate and Explore; Infrastructure and Security; Analytics.
- Administration and Platform sit at the foot, after a divider. Platform is
  shown only to the platform owner.
- Each section header is its label with a left chevron and folds its pages.
  The section you are in is always open. Folding is remembered per browser.
- Each page has its icon (`NavLeaf.icon`, required by the type and checked by
  `nav.icons.test.ts`). The page you are on is the only coloured row: a soft
  accent tint with accent text and icon.
- Groups inside a section (for example Monitors, Configuration) show as small
  uppercase labels. In-page tabs show under the page you are on, or under an
  opened collapsible page (Digital Experience, Cloud).
- The collapsed icon rail and its hover menus use the same rules: grey icons,
  and the accent only on hover and on the active section.

All menu colours come from the theme's `--rail-*` tokens, so every theme
restyles the menu without rules of its own. `nav.icons.test.ts` fails if a menu
component hard-codes a colour.

## Components

The shared kit lives in `src/frontend/src/components/kit/` (import from
`components/kit`). Every colour in `kit.css` is a theme token, so all five
themes restyle the kit; `kit.test.tsx` fails on a literal colour in that file.
**Infrastructure → Devices is the reference page** that uses all of it.

| Component | Use it for | Do not use it for |
|---|---|---|
| `StatusChip` | Any state: up/down, allow/deny, healthy/degraded/critical, confirmed/suspected, in sync/drifted. Pass a `kind` and the word; it picks the icon and the semantic colour. | Descriptive values (vendor, site, type, source, tags). Those are plain text or a neutral chip. |
| `PageHeader` | The top of a page: icon tile (the page's menu icon), title, count badge, actions on the right. | Section headings inside a page. |
| `OutlinedButton` | Page and row actions ("Add device", "Open ›", "Back up now"). `chevron` for a row action that navigates; `label` names an icon-only button. | The one primary action of a form (that keeps the accent button). |
| `PillSelect` | Compact toolbar filters and sort ("Health ⌄", "Site ⌄"), with a quiet lead word or icon. Options show their counts. | Choices inside a form (use a form field). |
| `FieldSelect` | A full-width selector in a panel ("All sites ⌄"), borderless until hovered. | Toolbars. |
| `SortLabel` | The "Sort by ⇅" word in front of a sort pill. | — |
| `FilterSection` | A collapsible filter group: left chevron, checkbox rows, right-aligned counts, optional accent action ("Clear"). | Navigation (that is the menu). |

Rules the kit enforces:

- **A state is never colour alone.** `StatusChip` always renders an icon and
  the word; the icon is hidden from screen readers and the word is the text.
  It is not a live region, so a table of chips stays quiet.
- **Dropdowns are native selects.** Keyboard, screen readers and phone pickers
  work without custom code; the kit only dresses them.
- **Tables never collapse a column.** `DataTable` gives every flexible column a
  floor from its header text (at least 80px) and puts the summed floor on the
  table, so a narrow window scrolls sideways instead of squeezing a column to
  zero.
- **Descriptive distributions use shades of one neutral.** Where slices must be
  told apart (a stacked bar of vendors or types), use falling strengths of the
  muted text colour, not hues: a hue reads as a state.

## Administration headers

`AdminPageHeader` is the kit PageHeader when given its page's menu `icon`, and a
neutral section title without one. The Administration group colours of
2026-10-18 (the `.adm-scope` accent re-point, coloured header bar and tinted
card tops) are retired: Administration uses the one accent like every page.

## Guard

`src/frontend/src/visualLanguage.guard.test.ts` keeps the rules from eroding.
It scans every `.ts`, `.tsx` and `.css` file under `src/` (comments stripped;
the kit and tests exempt) and counts, per file:

- hard-coded colours: `#hex`, `rgb()/rgba()`, `hsl()/hsla()`;
- per-section hue maps (`MOD_HUE`, `*_HUE`, `hueFor`, the retired admin hues);
- state badges that are not a StatusChip (`className="badge good|warn|bad"`,
  `` badge ${tone} ``).

Today's counts live in `src/frontend/src/visualLanguage.ledger.json`, each file
with the reason it is still there (theme token files, chart palettes, the
printed RCA document, pages awaiting their sweep). The ledger only shrinks:

- a file may not gain an occurrence, and a file not in the ledger may have none;
- when a file drops below its number, the test asks for the ledger to be
  lowered, so the gain is kept;
- regenerate after a cleanup with
  `UPDATE_VL_LEDGER=1 npx vitest run src/visualLanguage.guard.test.ts`, which
  refuses to raise any number.

## Still to do

- Finish the sweep of the remaining screens (the ledger lists them) and keep
  lowering the ledger as pages move onto the kit.

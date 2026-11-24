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

## Still to do

- Shared components: one dropdown (full-width selector and compact pill), one
  collapsible filter section, one page header (icon tile, title, count) and one
  status chip (icon plus semantic colour).
- A sweep of every screen against these rules, with a guard test against
  decorative colour.

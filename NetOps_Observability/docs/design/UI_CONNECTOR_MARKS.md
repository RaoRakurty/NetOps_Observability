# UI guidance — icons, connector marks and third-party artwork

**Status: binding.** Owner decision D5 (2026-09-04, cloud provider marks) and
tracker 239 (2026-09-05, connector marks) settled this for the whole product.
Read this before drawing, importing or vendoring ANY glyph into the SPA.

---

## 1. The default: Correlix generic functional glyphs

> **Correlix uses generic functional glyphs for third-party service connectors
> by default. Third-party trademarks and official brand artwork are not used
> unless explicitly reviewed and accompanied by recorded usage terms.**

> **New third-party connectors should default to Correlix generic functional
> glyphs. Official third-party marks require explicit review and recorded usage
> terms before they may be added.**

A connector's identity in the UI is:

```
[ generic functional glyph ]  Vendor Name        <- text carries the identity
                              Category · Status  <- what it does, how it is
```

The glyph says what the connector **does**. The text says **who** it talks to.
Naming a vendor to describe interoperability is ordinary nominative use;
reproducing the vendor's artwork is not. We do the first and never the second.

**Vendor names are never removed.** "ServiceNow connector", "Post alerts to a
Slack channel", "Twilio Account SID" are factual product copy and must stay.

## 2. Where it lives

| Concern | File |
|---|---|
| Connector → display name, category, glyph, capability | `src/frontend/src/components/ConnectorGlyph.tsx` |
| The glyph shapes themselves | `src/frontend/src/components/Icon.tsx` |
| Cloud provider identity (AWS / Azure / GCP) | `src/frontend/src/components/CloudGlyph.tsx` |
| Chip styling (`.conn-logo`) | `src/frontend/src/styles.css` — theme tokens only |
| Register of every third-party mark and its terms | `scripts/license-data.json` |

**Adding a connector is ONE ENTRY in `CONNECTOR_REGISTRY`.** No component may
branch on a connector id to draw its own artwork. If you find yourself writing
`if (connector === "slack") return <svg…>`, stop — that is the pattern this
document exists to prevent.

## 3. The functional taxonomy

The same glyph deliberately serves several vendors: identity comes from the
name, so a shared glyph costs nothing and a per-vendor glyph is how brand
artwork creeps back in.

| Category | Glyph | Connectors today |
|---|---|---|
| ITSM | `ticket` — a service-desk ticket stub | ServiceNow |
| Issue tracking | `board` — a work-item board | Jira |
| Chat | `chat` — a message bubble | Slack |
| Collaboration | `users` — two collaborators | Microsoft Teams |
| Messaging | `phone` — a handset | Twilio |
| Incident response | `incident` — an alerting beacon | PagerDuty |
| Push | `bell` | ntfy |
| Email | `mail` | SMTP |
| Webhook | `webhook` — a link between endpoints | generic HTTP |
| **Integration (fallback)** | `plug` | anything unrecognised |

An unknown connector renders the **plug** — never a broken image, never another
vendor's glyph.

## 4. The trademark boundary

A glyph is acceptable only if it is recognisable as its FUNCTION and
unrecognisable as anyone's brand. Specifically, do **not**:

- trace an official logo, or simplify one while preserving its geometry;
- recolour an official logo, or strip the wordmark off one;
- reproduce a distinctive brand motif (a silhouette, a monogram, a signature
  shape) in a "neutral" colour — a recoloured lookalike is still the mark;
- keep a vendor's brand palette as a chip tint, an icon colour or a hover
  state. Brand colour used as identity is pseudo-branding.

## 5. Colour and theme

Every glyph is `currentColor`. Every chip colour comes from a design token
(`var(--accent)`, `var(--surface)`, `var(--panel-border)`, `color-mix` over
them). This is not only a trademark rule — the theme is chosen at login, and a
hardcoded light-mode tint is invisible or illegible in dark mode.

`src/frontend/scripts/ui-consistency-check.mjs` fails on a hardcoded colour in a
component; `ConnectorGlyph.test.tsx` fails on a retired brand hex anywhere in
`src/`.

## 6. Accessibility

- Identity never rests on the glyph. The vendor name is always present as text,
  so a screen reader and a monochrome display lose nothing.
- Decorative glyphs are hidden (`aria-hidden`); a glyph that is the only carrier
  of meaning takes an explicit `label`, which becomes its accessible name and
  its hover tooltip.
- Colour is never the only differentiator between two connectors.

## 7. Icon system

The product's glyphs are inline stroke SVG in `components/Icon.tsx`, drawn in a
`0 0 24 24` box, `currentColor`, round caps and joins, bbox-centred on (12,12)
(`Icon.geometry.test.ts` enforces the centring). Some reproduce **Feather (MIT)**
or **Lucide (ISC)** path data verbatim; those carry an inline `upstream:` note
and the licence notice ships at `/licenses/icons/feather-lucide-NOTICE.txt`.

- **No new icon dependency.** Draw in this language, or copy from Feather/Lucide
  and add the `upstream:` note.
- **No asset files.** Glyphs are inline so they inherit the theme and cost no
  request. `src/frontend/src/assets/cloud/README.md` records why that directory
  is deliberately empty.

## 8. If a real mark is ever genuinely needed

It is an **owner decision**, and it needs, before the artwork lands:

1. the exact source package the artwork came from,
2. the vendor's brand/trademark terms URL and what they permit,
3. an entry in `scripts/license-data.json` (`vendored` + `exceptions`) so the
   mark is visible to `scripts/license-audit.py` on every run,
4. the terms recorded **beside the artwork in the tree**, so they travel with the
   artifact that carries it (the `cloudicons/README.md` pattern).

Without all four the answer is the generic glyph.

---

### History

- **2026-09-04 — D5.** The official AWS Smile, the Azure gradient chevron and
  the Google Cloud four-colour "G" were deleted and replaced by one original
  Correlix cloud silhouette with a plain letter tag (`CloudGlyph.tsx`).
- **2026-09-05 — tracker 239.** **ServiceNow, Jira, Slack, Twilio, PagerDuty and
  Microsoft Teams connector marks were replaced with generic Correlix glyphs.**
  They had been verbatim brand path data in brand colours, bundled into the
  shipped SPA with no usage terms recorded. `ConnectorGlyph.tsx` and this
  document are the replacement.

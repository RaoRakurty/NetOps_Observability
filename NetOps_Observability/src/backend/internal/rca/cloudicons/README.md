# Cloud glyphs — ORIGINAL Correlix artwork

**No provider mark is vendored, embedded, or redistributed here.** The AWS
Architecture Icons "AWS Cloud logo", the Azure Public Service Icon and the
Google Cloud four-colour symbol that used to live in this directory were
**deleted on 2026-09-04** (owner decision D5 of
`docs/security/LICENSE_AUDIT_2026-09-03.md`): they were trademark files carried
under a terms-of-use posture rather than a licence, they were `go:embed`'d into
the shipped backend binary, and the terms did not travel with that binary.

What ships now is drawn by us:

| File | Content | Licence |
|------|---------|---------|
| `aws.svg` | One original cloud silhouette + the plain letter tag `AWS` | Correlix's own — same licence as the rest of this repository |
| `azure.svg` | The SAME silhouette + the plain letter tag `AZ` | Correlix's own |
| `gcp.svg` | The SAME silhouette + the plain letter tag `GCP` | Correlix's own |

Design rules these files must keep:

- **One geometry.** All three carry byte-identical silhouette path data
  (`M6.6 14.5H16.8A3.5 …`), a 0 0 24 24 viewBox, `stroke="currentColor"`,
  1.6 stroke width and round joins — the product's own icon style. Only the
  text tag differs. `rca_report_icons_test.go` enforces this.
- **No provider colour, ever.** No `#ff9900`, `#0078d4`, `#4285f4`, `#EA4335`,
  `#34A853`, `#FBBC05`, and no Azure gradient. Colour comes from `currentColor`
  (the `color` attribute gives an isolated `<image>` context the product's
  neutral slate); the tests fail the build if a brand hex reappears.
- **The tag is a word, not a wordmark.** `AWS` / `AZ` / `GCP` are plain
  letterforms in the product's own UI face — a nominative textual reference to
  whose cloud a hop sits in, not a reproduction of anyone's logo.
- **Never imply endorsement.** These glyphs say "this hop is in that provider's
  cloud". They must never be used to represent Correlix itself, to suggest that
  a provider sponsors, certifies or endorses this product, or to decorate
  marketing material in a way that reads as a partnership.
- **Honest fallback.** A provider we have no glyph for renders its name as text
  (`rca_report_html.go`) — never another provider's glyph.

These are `go:embed`'d into the RCA report's path-causality SVG (see
`rca_report_icons.go`) so the exported document stays self-contained (Gotenberg
renders it with no network). The SPA draws the SAME family inline from
`src/frontend/src/components/CloudGlyph.tsx` — that module is the frontend's
copy of this geometry; keep the path data in step when either side changes.

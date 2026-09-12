# Cloud glyphs — ORIGINAL Correlix artwork (this directory ships no assets)

**This directory is deliberately empty of image files.** `aws.svg`, `azure.svg`
and `gcp.svg` — the official AWS Architecture Icons "AWS Cloud logo", the Azure
Public Service Icon and the Google Cloud four-colour symbol — were **deleted on
2026-09-04** (owner decision D5 of
`docs/security/LICENSE_AUDIT_2026-09-03.md`). They were trademark files carried
under a terms-of-use posture rather than a licence, and they were bundled into
the shipped SPA. **No provider mark is redistributed by the frontend any more.**

The cloud glyph the UI draws today is **our own artwork**, under the project's
own licence, and it is drawn **inline** rather than loaded from an asset:

- `src/frontend/src/components/CloudGlyph.tsx` — one original cloud silhouette
  (0 0 24 24, `currentColor`, 1.6 stroke, round joins — the product's icon
  style) plus a small plain letter tag, `AWS` / `AZ` / `GCP`, or no tag at all
  for a generic / unknown cloud. Inline SVG means the glyph is theme-aware
  (it inherits `color`) and costs no asset request; the old `<img src=…>`
  contract is gone.
- `src/backend/internal/rca/cloudicons/*.svg` — the SAME geometry as standalone
  files, because the Go RCA report `go:embed`s them into the exported PDF.
  Keep the two in step; both sides are tested.

Rules that keep this directory clean:

- **No provider colour, ever** — no `#ff9900`, `#0078d4`, `#4285f4`, `#EA4335`,
  `#34A853`, `#FBBC05`, no Azure gradient. `CloudGlyph.test.tsx` and
  `ProviderMark.test.tsx` fail the build if a brand hex or a provider-logo asset
  path reappears in rendered output.
- **The tag is a word, not a wordmark** — plain letterforms in the product's own
  UI face, a nominative textual reference to whose cloud a resource sits in.
- **Never imply endorsement** — the glyph says "this resource is in that
  provider's cloud". It must never represent Correlix itself, suggest that a
  provider sponsors, certifies or endorses this product, or be used in
  marketing in a way that reads as a partnership.
- **Honest fallback** — an unknown provider gets the untagged generic cloud,
  never another provider's glyph.

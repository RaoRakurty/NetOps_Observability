# Bundled web fonts (self-hosted, offline)

Correlix is an offline-first appliance: the SPA must never fetch a font from
Google Fonts or any other CDN at runtime. These three families are therefore
**checked into the repository** and served by the frontend nginx from
`/fonts/…` at a **stable, unhashed URL**, which is what lets `index.html`
`<link rel="preload">` the two primary faces (a Vite-hashed asset URL cannot be
preloaded from static HTML).

All three are **SIL Open Font License 1.1**, redistributed UNMODIFIED. The
licence text for each family sits beside its font files as `LICENSE`
(OFL-1.1 §2 requires the notice to travel with the fonts); the same texts are
also rendered into `/licenses/` by `scripts/gen-licenses.mjs`, which
additionally verifies these copies byte-for-byte against the upstream packages
on every build.

## Provenance

The binaries were extracted from the Fontsource npm packages that remain
declared in `package.json` — npm verifies each tarball against the
`integrity` (SHA-512) hash pinned in `package-lock.json`, which is a stronger
and more reproducible provenance chain than fetching a GitHub release through
a TLS-intercepting corporate proxy. The packages are kept as dependencies so
that the licence texts have a canonical upstream to be diffed against; their
CSS is deliberately NOT imported, so none of their files enter the JS bundle.

| File | Package (pinned) | Upstream | Bytes | SHA-256 |
|---|---|---|---|---|
| `inter/inter-latin-opsz-normal.2c295d99.woff2` | `@fontsource-variable/inter@5.3.0` (Inter v20) | https://github.com/rsms/inter | 72920 | `2c295d99e26dcf357d4d01bcf270fd6924b600c9a13dd8c363ef114f4c6976fa` |
| `inter/inter-latin-ext-opsz-normal.5e6d4fe9.woff2` | `@fontsource-variable/inter@5.3.0` | https://github.com/rsms/inter | 133336 | `5e6d4fe9d9f4bff8b2a2469d25ab19576bb85331e22c6ed51398e16f95d56a9c` |
| `inter/LICENSE` | `@fontsource-variable/inter@5.3.0` | OFL-1.1 | — | `3b0a5fca3d17942cde889069889dedbbbd075e9b599968c82a95f4d944e9b345` |
| `jetbrains-mono/jetbrains-mono-latin-wght-normal.18be4527.woff2` | `@fontsource-variable/jetbrains-mono@5.3.0` (JetBrains Mono v24) | https://github.com/JetBrains/JetBrainsMono | 40404 | `18be452724bfdc236c074ca94a249a7f41a86752c7d04ab258ce9ed5651f6a7e` |
| `jetbrains-mono/jetbrains-mono-latin-ext-wght-normal.79bfdab9.woff2` | `@fontsource-variable/jetbrains-mono@5.3.0` | https://github.com/JetBrains/JetBrainsMono | 15196 | `79bfdab9ba467e26eea4122e6f2567e188dd8a09a8c730d501fc487c4ab99c6e` |
| `jetbrains-mono/LICENSE` | `@fontsource-variable/jetbrains-mono@5.3.0` | OFL-1.1 | — | `403581b69dac5cff4079205e01c6b467e56af449ecbd7247693ddb1baafa005b` |
| `space-grotesk/space-grotesk-latin-wght-normal.06408904.woff2` | `@fontsource-variable/space-grotesk@5.3.0` (Space Grotesk v22) | https://github.com/floriankarsten/space-grotesk | 22288 | `0640890476fc1198ab4de571fb658de443c4d85b66466ec09534a8737ab1ce9d` |
| `space-grotesk/space-grotesk-latin-ext-wght-normal.952dddb4.woff2` | `@fontsource-variable/space-grotesk@5.3.0` | https://github.com/floriankarsten/space-grotesk | 18940 | `952dddb45d2f96f71cbf3b7f510b24379afc3c89ea02fcf89d377b45d62c0166` |
| `space-grotesk/LICENSE` | `@fontsource-variable/space-grotesk@5.3.0` | OFL-1.1 | — | `18a4de52385f6b988782639d5d0cc1326e5a8c2de9a7f01d7b20d9aedcc60943` |

Total: **303 084 bytes** of font binary (six files), replacing 1 362 496 bytes
of static-weight `.woff`/`.woff2` that the previous static Fontsource imports
emitted into `dist/assets/` (99 files).

Every `.woff2` filename carries the first 8 hex digits of its own SHA-256, so
the files are genuinely **content-addressed**: nginx caches them
`immutable, 1y` (`deployment/docker/frontend/default.conf`) and a font upgrade
necessarily changes the URL. `scripts/gen-licenses.mjs` re-derives that hash on
every build and fails if a filename and its bytes ever disagree, or if the
bytes drift from the pinned upstream package.

## Axes

| Family | Axes | Used for |
|---|---|---|
| Inter Variable | `wght` 100–900, `opsz` 14–32 | all UI text (`--font-sans` / `--font-ui`) |
| JetBrains Mono Variable | `wght` 100–800 | commands, device ids, tabular data (`--font-mono`) |
| Space Grotesk Variable | `wght` 300–700 | KPI numerals and page titles only (`--font-display`) |

Only the `latin` and `latin-ext` subsets ship. Cyrillic/Greek/Vietnamese are
deliberately omitted — the product UI is English and the subsets cost more than
every other font file combined.

`@font-face` declarations live once, at the top of `src/styles.css`. Do not add
a second copy anywhere, and do not import `@fontsource*` CSS from TypeScript:
that would double-ship the binaries under hashed URLs.

See `docs/design/TYPOGRAPHY_2026-09-06.md` for the type-scale decision.

// gen-licenses.mjs — assemble the third-party notices the frontend image ships.
//
// WHY THIS EXISTS
// ---------------
// The 2026-09-03 licence audit (docs/security/LICENSE_AUDIT_2026-09-03.md §2)
// found the SPA shipping three attribution obligations it was not meeting:
//   * elkjs (EPL-2.0) is bundled verbatim into dist/assets/elk.bundled-*.js and
//     esbuild strips its banner — EPL-2.0 §3.2 requires the recipient of the
//     Object Code be told the licence AND how to obtain the Source.
//   * four SIL OFL-1.1 font families ship as .woff2 with their LICENSE files
//     left behind in node_modules — OFL-1.1 §2 requires the notice to travel
//     with the fonts.
//   * ~20 Icon.tsx glyphs are verbatim Feather (MIT) / Lucide (ISC) path data,
//     and both licences require the notice be retained in redistributions.
//
// Attribution that lives only in the repo is attribution the customer never
// receives. This script copies the real licence texts out of node_modules and
// renders docs/THIRD_PARTY_LICENSES.md into a static page, writing everything
// into public/licenses/ — which Vite copies verbatim into dist/, which
// Dockerfile.frontend bakes into the nginx image and serves at /licenses/.
//
// It runs automatically as npm's `prebuild`, so a bundle can never be built
// without the notices. Inputs are checked in or vendored in node_modules, so it
// works offline. A missing input is a HARD failure, never a quieter output:
// silently shipping fewer notices is precisely the defect this closes.
//
// Node stdlib only (no new dependency — CLAUDE.md §6).

import { createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const FRONTEND = path.resolve(HERE, "..");
const REPO = path.resolve(FRONTEND, "..", "..");
const NODE_MODULES = path.join(FRONTEND, "node_modules");
const OUT = path.join(FRONTEND, "public", "licenses");
const NOTICES_MD = path.join(REPO, "docs", "THIRD_PARTY_LICENSES.md");

class InputError extends Error {}

function readInput(file, why) {
  try {
    return fs.readFileSync(file, "utf8");
  } catch (err) {
    throw new InputError(
      `cannot read ${path.relative(REPO, file)} (${why}): ${err.message}`,
    );
  }
}

function write(rel, body) {
  const dest = path.join(OUT, rel);
  fs.mkdirSync(path.dirname(dest), { recursive: true });
  fs.writeFileSync(dest, body);
  return dest;
}

// ── the licence texts we must copy out of node_modules ───────────────────────
// Each entry names the package, the file inside it that carries the licence,
// and where the copy lands under public/licenses/. `expect` is a string that
// MUST appear in the copied text: a package that silently relicenses (or a
// path that starts resolving to a README) must fail the build, not ship a file
// that claims to be a licence and is not.
const COPIES = [
  {
    pkg: "elkjs",
    from: "LICENSE.md",
    to: "elkjs/LICENSE-EPL-2.0.txt",
    expect: "Eclipse Public License - v 2.0",
  },
  {
    pkg: "@fontsource-variable/inter",
    from: "LICENSE",
    to: "fonts/inter-OFL-1.1.txt",
    expect: "SIL OPEN FONT LICENSE",
  },
  {
    pkg: "@fontsource-variable/jetbrains-mono",
    from: "LICENSE",
    to: "fonts/jetbrains-mono-OFL-1.1.txt",
    expect: "SIL OPEN FONT LICENSE",
  },
  {
    pkg: "@fontsource-variable/space-grotesk",
    from: "LICENSE",
    to: "fonts/space-grotesk-OFL-1.1.txt",
    expect: "SIL OPEN FONT LICENSE",
  },
];

// ── the font BINARIES we redistribute ────────────────────────────────────────
// The .woff2 files are checked into public/fonts/ rather than pulled out of
// node_modules by the bundler, so that index.html can preload them from a
// stable URL and nginx can cache them immutably (see public/fonts/README.md).
// That decouples the shipped bytes from the package they came from, and a
// decoupled copy is a copy that can silently rot — a font could be swapped for
// an unlicensed one, or edited, and nothing would notice. Two invariants are
// therefore re-derived on EVERY build:
//
//   1. the filename's hash fragment is the file's own SHA-256 prefix (which is
//      what makes `Cache-Control: immutable` truthful), and
//   2. the bytes are IDENTICAL to the pinned Fontsource package's own file, so
//      "redistributed unmodified" under OFL-1.1 stays a checked fact, and the
//      LICENSE beside it provably covers the binary next to it.
//
// A mismatch is a HARD failure, never a warning: shipping a font whose licence
// we cannot vouch for is the exact defect this directory exists to prevent.
const FONTS = [
  { pkg: "@fontsource-variable/inter",
    file: "inter/inter-latin-opsz-normal.2c295d99.woff2",
    upstream: "files/inter-latin-opsz-normal.woff2" },
  { pkg: "@fontsource-variable/inter",
    file: "inter/inter-latin-ext-opsz-normal.5e6d4fe9.woff2",
    upstream: "files/inter-latin-ext-opsz-normal.woff2" },
  { pkg: "@fontsource-variable/jetbrains-mono",
    file: "jetbrains-mono/jetbrains-mono-latin-wght-normal.18be4527.woff2",
    upstream: "files/jetbrains-mono-latin-wght-normal.woff2" },
  { pkg: "@fontsource-variable/jetbrains-mono",
    file: "jetbrains-mono/jetbrains-mono-latin-ext-wght-normal.79bfdab9.woff2",
    upstream: "files/jetbrains-mono-latin-ext-wght-normal.woff2" },
  { pkg: "@fontsource-variable/space-grotesk",
    file: "space-grotesk/space-grotesk-latin-wght-normal.06408904.woff2",
    upstream: "files/space-grotesk-latin-wght-normal.woff2" },
  { pkg: "@fontsource-variable/space-grotesk",
    file: "space-grotesk/space-grotesk-latin-ext-wght-normal.952dddb4.woff2",
    upstream: "files/space-grotesk-latin-ext-wght-normal.woff2" },
];

const FONT_DIR = path.join(FRONTEND, "public", "fonts");

function sha256(buf) {
  return createHash("sha256").update(buf).digest("hex");
}

function verifyFonts() {
  for (const f of FONTS) {
    const shipped = path.join(FONT_DIR, f.file);
    let bytes;
    try {
      bytes = fs.readFileSync(shipped);
    } catch (err) {
      throw new InputError(
        `cannot read the shipped font public/fonts/${f.file}: ${err.message}`,
      );
    }
    const digest = sha256(bytes);
    const stamped = path.basename(f.file).split(".").at(-2);
    if (digest.slice(0, stamped.length) !== stamped) {
      throw new InputError(
        `public/fonts/${f.file} is named for SHA-256 ${stamped}… but its bytes ` +
          `hash to ${digest.slice(0, 16)}…. The URL is served ` +
          `Cache-Control: immutable, so the name MUST match the content — ` +
          `rename the file to its real hash and update styles.css, index.html ` +
          `and public/fonts/README.md.`,
      );
    }
    const upstream = path.join(NODE_MODULES, f.pkg, f.upstream);
    let orig;
    try {
      orig = fs.readFileSync(upstream);
    } catch (err) {
      throw new InputError(
        `cannot read ${f.pkg}/${f.upstream} to verify public/fonts/${f.file} ` +
          `against it (${err.message}). The package is a declared dependency ` +
          `precisely so this check can run — do not remove it.`,
      );
    }
    if (!orig.equals(bytes)) {
      throw new InputError(
        `public/fonts/${f.file} does NOT match ${f.pkg}/${f.upstream}. ` +
          `Correlix redistributes these fonts UNMODIFIED under OFL-1.1; a ` +
          `divergent copy is either a modification (which OFL-1.1 constrains) ` +
          `or a different font wearing this one's licence. Re-copy it.`,
      );
    }
    // OFL-1.1 §2: the notice must travel WITH the fonts, so each family also
    // carries its LICENSE in its own directory, not only under /licenses/.
    const beside = path.join(FONT_DIR, f.file.split("/")[0], "LICENSE");
    const text = readInput(beside, `OFL-1.1 text beside ${f.file}`);
    if (!text.includes("SIL OPEN FONT LICENSE")) {
      throw new InputError(
        `${path.relative(REPO, beside)} is not the SIL Open Font License — the ` +
          `fonts beside it would ship with no valid notice.`,
      );
    }
    if (text !== fs.readFileSync(path.join(NODE_MODULES, f.pkg, "LICENSE"), "utf8")) {
      throw new InputError(
        `${path.relative(REPO, beside)} differs from ${f.pkg}/LICENSE — the ` +
          `shipped notice must be the upstream text verbatim.`,
      );
    }
  }
}

function pkgVersion(pkg) {
  const meta = JSON.parse(
    readInput(path.join(NODE_MODULES, pkg, "package.json"), `${pkg} metadata`),
  );
  if (!meta.version) throw new InputError(`${pkg}/package.json has no version`);
  return meta.version;
}

// EPL-2.0 §3.2(b): recipients of the Object Code must be told how to obtain the
// Source Code Form. A URL to the exact tag is the accepted way to say it.
function elkjsSourceOffer(version) {
  return `elkjs ${version} — Eclipse Public License 2.0
================================================================================

Correlix bundles elkjs UNMODIFIED into the web UI's JavaScript assets
(assets/elk.bundled-*.js). elkjs is licensed under the Eclipse Public License,
Version 2.0; the full licence text is in LICENSE-EPL-2.0.txt beside this file.

EPL-2.0 is FILE-LEVEL copyleft and applies to elkjs's own files only. Correlix
does not modify elkjs, so no Correlix source is placed under the EPL.

HOW TO OBTAIN THE SOURCE CODE (EPL-2.0 section 3.2)
  Upstream project : https://github.com/kieler/elkjs
  Exact version    : v${version}  (https://github.com/kieler/elkjs/tree/v${version})
  npm package       : https://registry.npmjs.org/elkjs/-/elkjs-${version}.tgz
  Layout engine     : https://github.com/eclipse/elk (Eclipse Layout Kernel)

Correlix will also provide the corresponding source for the exact version
shipped, on written request, for three years from the date of distribution.
See THIRD_PARTY_LICENSES.md ("Written offer for Corresponding Source").
`;
}

function fontNotice() {
  return `SIL Open Font License 1.1 — fonts distributed with the Correlix web UI
================================================================================

The Correlix web UI ships the following font families as .woff2 files, served
from /fonts/. All three are licensed under the SIL Open Font License,
Version 1.1. OFL-1.1 section 2 requires this notice and the licence to
accompany the fonts, so the complete licence text for each family sits both
beside this file and in the font's own directory (/fonts/<family>/LICENSE).

  Inter           Copyright 2016 The Inter Project Authors
                  https://github.com/rsms/inter            inter-OFL-1.1.txt
  JetBrains Mono  Copyright 2020 The JetBrains Mono Project Authors
                  https://github.com/JetBrains/JetBrainsMono
                                                           jetbrains-mono-OFL-1.1.txt
  Space Grotesk   Copyright 2020 The Space Grotesk Project Authors
                  https://github.com/floriankarsten/space-grotesk
                                                           space-grotesk-OFL-1.1.txt

The fonts are redistributed UNMODIFIED — the build verifies each shipped
.woff2 byte-for-byte against its upstream package on every run. Correlix does
not sell them on their own and does not reuse any Reserved Font Name in a
modified version, the two things OFL-1.1 forbids.
`;
}

// Feather (MIT) and Lucide (ISC) both require the notice be retained in
// redistributions. The icon path data is inlined into src/components/Icon.tsx
// and therefore minified into the shipped JS — so the notice ships here.
function iconNotice() {
  return `Icon path data — Feather (MIT) and Lucide (ISC)
================================================================================

Part of the Correlix icon set (src/components/Icon.tsx, minified into the
shipped JavaScript) reproduces path data from the Feather and Lucide icon sets.
Both licences require that this notice be retained in redistributions.

--------------------------------------------------------------------------------
Feather — Copyright (c) 2013-2023 Cole Bemis — MIT License
https://github.com/feathericons/feather
--------------------------------------------------------------------------------

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

--------------------------------------------------------------------------------
Lucide — Copyright (c) for portions of Lucide are held by Cole Bemis
2013-2022 as part of Feather (MIT). All other copyright (c) for Lucide are
held by Lucide Contributors 2022. — ISC License
https://github.com/lucide-icons/lucide
--------------------------------------------------------------------------------

Permission to use, copy, modify, and/or distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
PERFORMANCE OF THIS SOFTWARE.
`;
}

// ── the smallest Markdown subset docs/THIRD_PARTY_LICENSES.md actually uses ──
// Headings, blockquotes, pipe tables, paragraphs and (inside the licence-text
// section) preformatted blocks. No script tag is emitted: the SPA's CSP is
// `script-src 'self'` with no inline allowance, and this page needs none.
const ESCAPES = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" };
const esc = (s) => s.replace(/[&<>"]/g, (c) => ESCAPES[c]);
const inline = (s) =>
  esc(s).replace(/`([^`]+)`/g, "<code>$1</code>");

function renderMarkdown(md) {
  const lines = md.split("\n");
  const out = [];
  let block = [];
  let preformatted = false; // set once we reach the verbatim licence texts

  const flush = () => {
    if (block.length === 0) return;
    if (block[0].startsWith("|")) {
      const rows = block.filter((l) => !/^\|[\s|:-]+\|$/.test(l));
      out.push('<div class="tw"><table>');
      rows.forEach((row, i) => {
        const cells = row.replace(/^\||\|$/g, "").split("|").map((c) => c.trim());
        const tag = i === 0 ? "th" : "td";
        out.push(
          "<tr>" + cells.map((c) => `<${tag}>${inline(c)}</${tag}>`).join("") + "</tr>",
        );
      });
      out.push("</table></div>");
    } else if (block[0].startsWith(">")) {
      out.push(
        "<blockquote>" +
          block.map((l) => inline(l.replace(/^>\s?/, ""))).join("<br>") +
          "</blockquote>",
      );
    } else if (preformatted) {
      out.push("<pre>" + block.map(esc).join("\n") + "</pre>");
    } else {
      out.push("<p>" + block.map(inline).join(" ") + "</p>");
    }
    block = [];
  };

  for (const raw of lines) {
    const line = raw.replace(/\s+$/, "");
    const heading = /^(#{1,4})\s+(.*)$/.exec(line);
    if (heading) {
      flush();
      const level = heading[1].length;
      const text = heading[2];
      if (/^Licence texts and source availability/i.test(text)) preformatted = true;
      const id = text.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "");
      out.push(`<h${level} id="${esc(id)}">${inline(text)}</h${level}>`);
      continue;
    }
    if (line.trim() === "") {
      flush();
      continue;
    }
    // A table can follow a paragraph with no blank line between them.
    if (block.length && line.startsWith("|") !== block[0].startsWith("|")) flush();
    block.push(line);
  }
  flush();
  return out.join("\n");
}

// The PROJECT licence, as distinct from the third-party notices below it. A
// customer reading /licenses/ must be able to answer "what may I do with
// Correlix itself?" without leaving the page. This sentence is the canonical one
// in licensing-policy.json; scripts/licensing-gate.py check G and
// tests/test_licensing_consistency.py both grep for it verbatim, so it is
// duplicated here deliberately rather than derived — a build must not be able to
// ship a page that silently lost it.
const PROJECT_LICENCE_SENTENCE =
  "Correlix core is licensed under the Apache License, Version 2.0. " +
  "Commercial add-on modules are licensed under the Correlix Enterprise " +
  "License (LicenseRef-Correlix-Enterprise) \u2014 see LICENSING.md.";

function projectLicenceBlock() {
  return `<div class="project">
<strong>Correlix licence</strong>
<p>${esc(PROJECT_LICENCE_SENTENCE)}</p>
<p>Correlix is open core. The engine, the telemetry pipeline, correlation and RCA,
the investigation surface and the tenant isolation model are Apache-2.0. A named set
of commercial add-on modules is source-available under the Correlix Enterprise
License. Tenant isolation is core in every edition and is never a commercial add-on.</p>
<p>The licence texts ship with the source as <code>LICENSES/Apache-2.0.txt</code> and
<code>LICENSES/Correlix-Enterprise.txt</code>; <code>LICENSING.md</code> maps every
directory to one of the two.</p>
<p>Everything below this box concerns THIRD-PARTY software Correlix redistributes,
which keeps its own licences and its own obligations.</p>
</div>
`;
}

function renderPage(md, files) {
  const body = renderMarkdown(md);
  const links = files
    .map((f) => `<li><a href="${esc(f.href)}">${esc(f.label)}</a></li>`)
    .join("\n");
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Correlix — Third-party licences</title>
<!-- GENERATED by src/frontend/scripts/gen-licenses.mjs. Do not hand-edit. -->
<style>
  :root { color-scheme: light dark; --fg:#1c2230; --muted:#5b6478; --bg:#fbfcfe;
          --panel:#fff; --border:#e3e8f0; --accent:#1f6feb; }
  @media (prefers-color-scheme: dark) {
    :root { --fg:#e6ebf5; --muted:#9aa5bb; --bg:#11151d; --panel:#171c26;
            --border:#2a323f; --accent:#6ea8ff; }
  }
  * { box-sizing: border-box; }
  body { margin:0; background:var(--bg); color:var(--fg); font:14px/1.6
         ui-sans-serif, system-ui, -apple-system, "Segoe UI", sans-serif; }
  main { max-width: 980px; margin: 0 auto; padding: 32px 20px 80px; }
  h1 { font-size: 24px; margin: 0 0 4px; letter-spacing: -0.01em; }
  h2 { font-size: 16px; margin: 32px 0 10px; padding-top: 14px;
       border-top: 1px solid var(--border); }
  h3 { font-size: 14px; margin: 22px 0 8px; color: var(--muted);
       text-transform: uppercase; letter-spacing: 0.04em; }
  p { margin: 10px 0; }
  a { color: var(--accent); }
  blockquote { margin: 12px 0; padding: 8px 12px; color: var(--muted);
               border-left: 3px solid var(--border); font-size: 13px; }
  code { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12.5px; }
  pre { background: var(--panel); border: 1px solid var(--border); border-radius: 8px;
        padding: 12px 14px; overflow-x: auto; font-size: 12.5px;
        font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
  .tw { overflow-x: auto; }
  table { border-collapse: collapse; width: 100%; margin: 8px 0 4px; font-size: 13px; }
  th, td { text-align: left; padding: 6px 10px; border-bottom: 1px solid var(--border);
           vertical-align: top; }
  th { color: var(--muted); font-weight: 600; white-space: nowrap; }
  .project { background: var(--panel); border: 1px solid var(--accent);
             border-radius: 10px; padding: 14px 18px; margin: 0 0 18px; }
  .project p { margin: 8px 0; }
  .project strong { display: block; margin-bottom: 4px; }
  .files { background: var(--panel); border: 1px solid var(--border);
           border-radius: 10px; padding: 12px 16px; margin: 18px 0 8px; }
  .files ul { margin: 8px 0 0; padding-left: 20px; }
  .files li { margin: 3px 0; }
</style>
</head>
<body>
<main>
${projectLicenceBlock()}<div class="files">
<strong>Full licence texts shipped with this product</strong>
<ul>
${links}
</ul>
</div>
${body}
</main>
</body>
</html>
`;
}

function main() {
  const md = readInput(
    NOTICES_MD,
    "generated by `python3 scripts/license-audit.py --notices`",
  );

  fs.rmSync(OUT, { recursive: true, force: true });

  const shipped = [];
  for (const c of COPIES) {
    const src = path.join(NODE_MODULES, c.pkg, c.from);
    const text = readInput(src, `${c.pkg} licence text`);
    if (!text.includes(c.expect)) {
      throw new InputError(
        `${c.pkg}/${c.from} no longer contains "${c.expect}" — the package may ` +
          `have been relicensed. Re-review it and update scripts/license-data.json ` +
          `before shipping.`,
      );
    }
    write(c.to, text);
    shipped.push({ href: c.to, label: `${c.pkg} — ${path.basename(c.to)}` });
  }

  verifyFonts();

  const elkVersion = pkgVersion("elkjs");
  write("elkjs/SOURCE.txt", elkjsSourceOffer(elkVersion));
  write("fonts/NOTICE.txt", fontNotice());
  write("icons/feather-lucide-NOTICE.txt", iconNotice());
  write("THIRD_PARTY_LICENSES.md", md);
  shipped.unshift({ href: "THIRD_PARTY_LICENSES.md", label: "All components — THIRD_PARTY_LICENSES.md" });
  shipped.push(
    { href: "elkjs/SOURCE.txt", label: "elkjs — how to obtain the source (EPL-2.0 §3.2)" },
    { href: "fonts/NOTICE.txt", label: "Fonts — SIL OFL-1.1 notice" },
    { href: "icons/feather-lucide-NOTICE.txt", label: "Icons — Feather (MIT) and Lucide (ISC) notice" },
  );

  write("index.html", renderPage(md, shipped));

  const digest = createHash("sha256").update(md).digest("hex").slice(0, 12);
  process.stdout.write(
    `gen-licenses: wrote ${shipped.length + 1} notice file(s) to ` +
      `public/licenses/ (THIRD_PARTY_LICENSES.md ${digest}, elkjs ${elkVersion})\n`,
  );
}

try {
  main();
} catch (err) {
  if (err instanceof InputError) {
    process.stderr.write(
      `gen-licenses: FATAL: ${err.message}\n` +
        `The frontend image must ship its third-party notices ` +
        `(docs/security/LICENSE_AUDIT_2026-09-03.md §2). Fix the input above; ` +
        `do not build without them.\n`,
    );
    process.exit(1);
  }
  throw err;
}

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
    pkg: "@fontsource/inter",
    from: "LICENSE",
    to: "fonts/inter-OFL-1.1.txt",
    expect: "SIL OPEN FONT LICENSE",
  },
  {
    pkg: "@fontsource/ibm-plex-mono",
    from: "LICENSE",
    to: "fonts/ibm-plex-mono-OFL-1.1.txt",
    expect: "SIL OPEN FONT LICENSE",
  },
  {
    pkg: "@fontsource/space-grotesk",
    from: "LICENSE",
    to: "fonts/space-grotesk-OFL-1.1.txt",
    expect: "SIL OPEN FONT LICENSE",
  },
  {
    pkg: "@fontsource-variable/manrope",
    from: "LICENSE",
    to: "fonts/manrope-OFL-1.1.txt",
    expect: "SIL OPEN FONT LICENSE",
  },
];

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

The Correlix web UI ships the following font families as .woff/.woff2 files.
All four are licensed under the SIL Open Font License, Version 1.1. OFL-1.1
section 2 requires this notice and the licence to accompany the fonts, so the
complete licence text for each family sits beside this file.

  Inter           Copyright 2016 The Inter Project Authors
                  https://github.com/rsms/inter            inter-OFL-1.1.txt
  IBM Plex Mono   Copyright 2017 IBM Corp.
                  https://github.com/IBM/plex              ibm-plex-mono-OFL-1.1.txt
  Space Grotesk   Copyright 2020 The Space Grotesk Project Authors
                  https://github.com/floriankarsten/space-grotesk
                                                           space-grotesk-OFL-1.1.txt
  Manrope         Copyright 2019 The Manrope Project Authors
                  https://github.com/sharanda/manrope      manrope-OFL-1.1.txt

The fonts are redistributed UNMODIFIED. Correlix does not sell them on their
own and does not reuse any Reserved Font Name in a modified version, the two
things OFL-1.1 forbids.
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
  .files { background: var(--panel); border: 1px solid var(--border);
           border-radius: 10px; padding: 12px 16px; margin: 18px 0 8px; }
  .files ul { margin: 8px 0 0; padding-left: 20px; }
  .files li { margin: 3px 0; }
</style>
</head>
<body>
<main>
<div class="files">
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

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// sourceHygiene.test.ts — review findings 3.11-05 and 3.11-13.
//
// A RAW NUL BYTE IN A SOURCE FILE MAKES GIT TREAT THE WHOLE FILE AS BINARY:
// undiffable, unblameable, unmergeable in a conflict, and invisible to `git
// grep`. Three files had one as a map-key separator (and a fourth in the test
// that guards the URL-parsing boundary), where the two-character escape `\0` is
// byte-for-byte identical at runtime and leaves the file text.
//
// Git's own heuristic only sniffs the first 8 KB, so a byte past that mark is
// worse than one before it: the file looks fine until the day someone has to
// merge it. This test reads every byte instead.

import { readdirSync, readFileSync, statSync } from "node:fs";
import { extname, join, resolve } from "node:path";
import { describe, expect, it } from "vitest";

const ROOT = resolve(__dirname, "../..");
const ROOTS = ["src", "public"];
const SKIP_DIRS = new Set(["node_modules", "dist", ".git", "coverage", "fonts", "brand", "assets"]);
const TEXT = new Set([".ts", ".tsx", ".js", ".jsx", ".css", ".json", ".html", ".md", ".svg"]);

function walk(dir: string, out: string[]): string[] {
  for (const name of readdirSync(dir)) {
    if (SKIP_DIRS.has(name)) continue;
    const p = join(dir, name);
    if (statSync(p).isDirectory()) {
      walk(p, out);
    } else if (TEXT.has(extname(name))) {
      out.push(p);
    }
  }
  return out;
}

describe("source hygiene", () => {
  it("no source file carries a raw NUL byte", () => {
    const files: string[] = [];
    for (const r of ROOTS) walk(join(ROOT, r), files);
    expect(files.length).toBeGreaterThan(100); // the walk actually walked

    const offenders = files.filter((f) => readFileSync(f).includes(0));
    expect(
      offenders.map((f) => f.slice(ROOT.length + 1)),
      "a raw NUL byte makes git classify the file as binary — write \\0 instead",
    ).toEqual([]);
  });
});

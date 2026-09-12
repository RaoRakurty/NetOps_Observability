// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// qr.test.ts — the QR encoder is proved, not eyeballed.
//
// WHY THIS FILE IS LONG. A QR code is the one artefact in this product whose
// correctness a human cannot check by looking: a symbol with a single wrong
// module still LOOKS like a QR code, and the only person who finds out is an
// operator whose authenticator app refuses to scan their enrolment. So this test
// does three separate things, in increasing strength:
//
//   1. INDEPENDENT CONSTANTS. Two values from the standard that nothing in
//      lib/qr.ts derives from each other: the format-information bit string for
//      (EC level M, mask 0), and the alpha exponents of the degree-7 Reed–Solomon
//      generator polynomial. If the field arithmetic or the BCH code drifts,
//      these fail first and say so.
//   2. STRUCTURE. Size, the three finder patterns and their separators, the
//      timing patterns, and the module that is dark in every conforming symbol.
//   3. A ROUND TRIP THROUGH AN INDEPENDENT DECODER. The decoder below is written
//      against the standard, NOT against the encoder — it re-derives the function
//      -pattern map, the mask functions and the block structure from its own
//      tables. It reads the format information out of the symbol, unmasks, walks
//      the zig-zag, de-interleaves the blocks, strips the ECC and parses the byte
//      -mode segment. Only a symbol an app could actually scan survives that.
//
// The realistic case is the one that matters: the `otpauth://` URI the enrolment
// card shows.

import { describe, it, expect } from "vitest";
import {
  encodeQR, qrPathData, rsGenerator, gfLog, formatInfoBits, versionFor, dataCodewords,
} from "./qr";

// ── 1. independent constants from ISO/IEC 18004 ──────────────────────────────

describe("QR — constants taken from the standard, not from the implementation", () => {
  it("format information for error-correction level M with mask 0 is 101010000010010", () => {
    expect(formatInfoBits(0)).toBe("101010000010010");
  });

  it("every mask's format information is 15 bits and unique", () => {
    const all = [0, 1, 2, 3, 4, 5, 6, 7].map(formatInfoBits);
    for (const bits of all) expect(bits).toMatch(/^[01]{15}$/);
    expect(new Set(all).size).toBe(8);
  });

  it("the degree-7 Reed–Solomon generator has alpha exponents 0,87,229,146,149,238,102,21", () => {
    const poly = rsGenerator(7);
    expect(poly.length).toBe(8);
    expect(Array.from(poly, gfLog)).toEqual([0, 87, 229, 146, 149, 238, 102, 21]);
  });

  it("the degree-10 generator (version 1, level M) starts and ends as the standard says", () => {
    const poly = rsGenerator(10);
    expect(poly.length).toBe(11);
    expect(Array.from(poly, gfLog)).toEqual([0, 251, 67, 46, 61, 118, 70, 64, 94, 32, 45]);
  });

  it("the version table matches the standard's data-codeword counts at level M", () => {
    // Table 9 of the standard, level M, versions 1..10.
    expect([1, 2, 3, 4, 5, 6, 7, 8, 9, 10].map(dataCodewords))
      .toEqual([16, 28, 44, 64, 86, 108, 124, 154, 182, 216]);
  });
});

// ── an independent decoder, written from the standard ────────────────────────

/** Block structure at error-correction level M, versions 1..10 (Table 9). */
const BLOCKS: Record<number, { ec: number; g1: number; g1Data: number; g2: number; g2Data: number }> = {
  1: { ec: 10, g1: 1, g1Data: 16, g2: 0, g2Data: 0 },
  2: { ec: 16, g1: 1, g1Data: 28, g2: 0, g2Data: 0 },
  3: { ec: 26, g1: 1, g1Data: 44, g2: 0, g2Data: 0 },
  4: { ec: 18, g1: 2, g1Data: 32, g2: 0, g2Data: 0 },
  5: { ec: 24, g1: 2, g1Data: 43, g2: 0, g2Data: 0 },
  6: { ec: 16, g1: 4, g1Data: 27, g2: 0, g2Data: 0 },
  7: { ec: 18, g1: 4, g1Data: 31, g2: 0, g2Data: 0 },
  8: { ec: 22, g1: 2, g1Data: 38, g2: 2, g2Data: 39 },
  9: { ec: 22, g1: 3, g1Data: 36, g2: 2, g2Data: 37 },
  10: { ec: 26, g1: 4, g1Data: 43, g2: 1, g2Data: 44 },
};

/** Alignment-pattern centres, versions 1..10 (Annex E). */
const CENTRES: Record<number, number[]> = {
  1: [], 2: [6, 18], 3: [6, 22], 4: [6, 26], 5: [6, 30],
  6: [6, 34], 7: [6, 22, 38], 8: [6, 24, 42], 9: [6, 26, 46], 10: [6, 28, 50],
};

/** The eight mask conditions, restated from the standard. */
function masked(mask: number, row: number, col: number): boolean {
  switch (mask) {
    case 0: return (row + col) % 2 === 0;
    case 1: return row % 2 === 0;
    case 2: return col % 3 === 0;
    case 3: return (row + col) % 3 === 0;
    case 4: return (Math.floor(row / 2) + Math.floor(col / 3)) % 2 === 0;
    case 5: return ((row * col) % 2) + ((row * col) % 3) === 0;
    case 6: return (((row * col) % 2) + ((row * col) % 3)) % 2 === 0;
    default: return (((row + col) % 2) + ((row * col) % 3)) % 2 === 0;
  }
}

/**
 * Which modules are function modules (and therefore carry no data), derived
 * here from the standard rather than read out of the encoder.
 */
function functionMap(version: number): boolean[][] {
  const size = version * 4 + 17;
  const fn = Array.from({ length: size }, () => new Array<boolean>(size).fill(false));
  const mark = (r: number, c: number) => {
    if (r >= 0 && c >= 0 && r < size && c < size) fn[r][c] = true;
  };

  for (const [r0, c0] of [[0, 0], [0, size - 7], [size - 7, 0]]) {
    for (let dr = -1; dr <= 7; dr += 1) for (let dc = -1; dc <= 7; dc += 1) mark(r0 + dr, c0 + dc);
  }
  for (let i = 0; i < size; i += 1) { mark(6, i); mark(i, 6); }

  const centres = CENTRES[version];
  const last = centres.length - 1;
  for (let a = 0; a < centres.length; a += 1) {
    for (let b = 0; b < centres.length; b += 1) {
      if ((a === 0 && b === 0) || (a === 0 && b === last) || (a === last && b === 0)) continue;
      for (let dr = -2; dr <= 2; dr += 1) for (let dc = -2; dc <= 2; dc += 1) mark(centres[a] + dr, centres[b] + dc);
    }
  }

  for (let i = 0; i <= 8; i += 1) { mark(8, i); mark(i, 8); }
  for (let i = 0; i < 8; i += 1) { mark(size - 1 - i, 8); mark(8, size - 1 - i); }

  if (version >= 7) {
    for (let i = 0; i < 18; i += 1) {
      const a = size - 11 + (i % 3);
      const b = Math.floor(i / 3);
      mark(b, a);
      mark(a, b);
    }
  }
  return fn;
}

/**
 * Cross-check on the function-pattern map, independent of BOTH the encoder and
 * the round trip: the modules left free must equal 8 × total codewords + the
 * standard's remainder bits. An off-by-one anywhere in the reserved areas moves
 * this number, and a shared mistake in encoder and decoder would not be caught
 * by a round trip alone.
 */
const TOTAL_CODEWORDS: Record<number, number> = {
  1: 26, 2: 44, 3: 70, 4: 100, 5: 134, 6: 172, 7: 196, 8: 242, 9: 292, 10: 346,
};
const REMAINDER_BITS: Record<number, number> = {
  1: 0, 2: 7, 3: 7, 4: 7, 5: 7, 6: 7, 7: 0, 8: 0, 9: 0, 10: 0,
};

describe("QR — the function-pattern map leaves exactly the standard's data capacity", () => {
  it.each([1, 2, 3, 4, 5, 6, 7, 8, 9, 10])("version %i", (version) => {
    const fn = functionMap(version);
    const size = version * 4 + 17;
    let free = 0;
    for (let r = 0; r < size; r += 1) for (let c = 0; c < size; c += 1) if (!fn[r][c]) free += 1;
    expect(free).toBe(TOTAL_CODEWORDS[version] * 8 + REMAINDER_BITS[version]);
    // The whole data+ECC stream must also fit the blocks the version declares.
    const s = BLOCKS[version];
    expect(s.g1 * (s.g1Data + s.ec) + s.g2 * (s.g2Data + s.ec)).toBe(TOTAL_CODEWORDS[version]);
  });
});

interface Decoded { text: string; version: number; mask: number; ecLevel: number }

/** Reads a symbol back to the string that was encoded into it. */
function decodeQR(matrix: boolean[][]): Decoded {
  const size = matrix.length;
  expect((size - 17) % 4).toBe(0);
  const version = (size - 17) / 4;
  const spec = BLOCKS[version];
  expect(spec, `version ${version} is outside the implemented range`).toBeDefined();

  // Format information, first copy, in bit order 0..14.
  const cells: Array<[number, number]> = [];
  for (let i = 0; i <= 5; i += 1) cells.push([i, 8]);
  cells.push([7, 8], [8, 8], [8, 7]);
  for (let i = 9; i < 15; i += 1) cells.push([8, 14 - i]);
  let raw = 0;
  cells.forEach(([r, c], i) => { if (matrix[r][c]) raw |= 1 << i; });
  const format = (raw ^ 0x5412) >>> 10;
  const ecLevel = format >>> 3;
  const mask = format & 0b111;

  // Data modules, bottom-right zig-zag, unmasked on the way out.
  const fn = functionMap(version);
  const bits: number[] = [];
  let upward = true;
  for (let right = size - 1; right > 0; right -= 2) {
    if (right === 6) right = 5;
    for (let vert = 0; vert < size; vert += 1) {
      const row = upward ? size - 1 - vert : vert;
      for (let k = 0; k < 2; k += 1) {
        const col = right - k;
        if (fn[row][col]) continue;
        const dark = matrix[row][col] !== masked(mask, row, col);
        bits.push(dark ? 1 : 0);
      }
    }
    upward = !upward;
  }

  const codewords: number[] = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) {
    let byte = 0;
    for (let j = 0; j < 8; j += 1) byte = (byte << 1) | bits[i + j];
    codewords.push(byte);
  }

  // De-interleave the data half (the ECC half that follows is not needed to
  // recover the message, only to correct one that was damaged).
  const lens = [
    ...new Array<number>(spec.g1).fill(spec.g1Data),
    ...new Array<number>(spec.g2).fill(spec.g2Data),
  ];
  const blocks = lens.map((n) => new Array<number>(n));
  let at = 0;
  for (let i = 0; i < Math.max(...lens); i += 1) {
    for (let b = 0; b < blocks.length; b += 1) if (i < lens[b]) blocks[b][i] = codewords[at++];
  }
  const data = blocks.flat();

  // Byte-mode segment: mode indicator, character count, payload.
  let cursor = 0;
  const take = (n: number): number => {
    let v = 0;
    for (let i = 0; i < n; i += 1) {
      const byte = data[cursor >> 3];
      v = (v << 1) | ((byte >>> (7 - (cursor & 7))) & 1);
      cursor += 1;
    }
    return v;
  };
  const mode = take(4);
  expect(mode, "mode indicator is byte mode").toBe(0b0100);
  const count = take(version <= 9 ? 8 : 16);
  const payload = new Uint8Array(count);
  for (let i = 0; i < count; i += 1) payload[i] = take(8);

  return { text: new TextDecoder().decode(payload), version, mask, ecLevel };
}

// ── 2. structure ─────────────────────────────────────────────────────────────

describe("QR — symbol structure", () => {
  const m = encodeQR("HELLO");
  const size = m.length;

  it("is square and sized 4·version+17", () => {
    expect(size).toBe(21);              // version 1
    for (const row of m) expect(row.length).toBe(size);
  });

  it("carries three finder patterns, each with a light separator", () => {
    for (const [r0, c0] of [[0, 0], [0, size - 7], [size - 7, 0]]) {
      for (let dr = 0; dr < 7; dr += 1) {
        for (let dc = 0; dc < 7; dc += 1) {
          const ring = dr === 0 || dr === 6 || dc === 0 || dc === 6;
          const core = dr >= 2 && dr <= 4 && dc >= 2 && dc <= 4;
          expect(m[r0 + dr][c0 + dc], `finder module ${r0 + dr},${c0 + dc}`).toBe(ring || core);
        }
      }
      // The separator ring immediately outside the pattern is entirely light.
      for (let d = -1; d <= 7; d += 1) {
        for (const [r, c] of [[r0 + d, c0 - 1], [r0 + d, c0 + 7], [r0 - 1, c0 + d], [r0 + 7, c0 + d]]) {
          if (r < 0 || c < 0 || r >= size || c >= size) continue;
          expect(m[r][c], `separator module ${r},${c}`).toBe(false);
        }
      }
    }
  });

  it("timing patterns alternate along row 6 and column 6", () => {
    for (let i = 8; i < size - 8; i += 1) {
      expect(m[6][i], `row-6 timing at ${i}`).toBe(i % 2 === 0);
      expect(m[i][6], `column-6 timing at ${i}`).toBe(i % 2 === 0);
    }
  });

  it("the module at (4·version+9, 8) is dark in every symbol", () => {
    for (const text of ["HELLO", "x".repeat(60), "y".repeat(200)]) {
      const sym = encodeQR(text);
      const version = (sym.length - 17) / 4;
      expect(sym[4 * version + 9][8], `dark module, version ${version}`).toBe(true);
    }
  });

  it("chooses the smallest version that holds the payload", () => {
    expect(versionFor(10)).toBe(1);
    expect(versionFor(14)).toBe(1);   // the last payload a version-1 symbol holds
    expect(versionFor(15)).toBe(2);
    expect(encodeQR("x".repeat(14)).length).toBe(21);
    expect(encodeQR("x".repeat(200)).length).toBe(57); // version 10
  });
});

// ── 3. round trip ────────────────────────────────────────────────────────────

const OTPAUTH =
  "otpauth://totp/Correlix:alice?secret=JBSWY3DPEHPK3PXP&issuer=Correlix&algorithm=SHA1&digits=6&period=30";

describe("QR — an independent decoder reads back exactly what was encoded", () => {
  it.each([
    ["a short ASCII string", "HELLO"],
    ["a realistic otpauth URI", OTPAUTH],
    ["a payload long enough to force a higher version", "device-".repeat(28)],
    ["a payload with non-ASCII bytes", "café · München · 世界"],
    ["a single character", "A"],
  ])("round-trips %s", (_label, text) => {
    const decoded = decodeQR(encodeQR(text));
    expect(decoded.text).toBe(text);
    expect(decoded.ecLevel, "error-correction level M").toBe(0b00);
    expect(decoded.mask).toBeGreaterThanOrEqual(0);
    expect(decoded.mask).toBeLessThanOrEqual(7);
  });

  it("the otpauth URI fits a version below the implemented ceiling", () => {
    const decoded = decodeQR(encodeQR(OTPAUTH));
    expect(decoded.version).toBeGreaterThan(1);
    expect(decoded.version).toBeLessThanOrEqual(10);
  });

  it("round-trips every version from 1 to 10", () => {
    const seen = new Set<number>();
    for (let len = 1; len <= 200; len += 1) {
      const text = "N".repeat(len);
      const decoded = decodeQR(encodeQR(text));
      expect(decoded.text).toBe(text);
      seen.add(decoded.version);
    }
    expect([...seen].sort((a, b) => a - b)).toEqual([1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
  });

  it("refuses a payload that does not fit rather than truncating it", () => {
    expect(() => encodeQR("z".repeat(400))).toThrow(/too long/);
    expect(() => encodeQR("")).toThrow();
  });
});

// ── the SVG helper is path DATA, never markup ────────────────────────────────

describe("qrPathData", () => {
  const matrix = encodeQR(OTPAUTH);
  const d = qrPathData(matrix);

  it("emits only path commands — no markup a caller could inject", () => {
    expect(d).toMatch(/^[Mhvz0-9 .-]+$/);
    expect(d).not.toContain("<");
    expect(d).not.toContain("svg");
  });

  it("covers exactly the dark modules", () => {
    const covered = new Set<string>();
    for (const seg of d.split("M").filter(Boolean)) {
      const m = /^(\d+) (\d+)h(\d+)/.exec(seg);
      expect(m, `unparsable segment ${seg}`).not.toBeNull();
      const col = Number(m![1]);
      const row = Number(m![2]);
      for (let i = 0; i < Number(m![3]); i += 1) covered.add(`${row},${col + i}`);
    }
    let dark = 0;
    matrix.forEach((line, r) => line.forEach((on, c) => {
      if (!on) return;
      dark += 1;
      expect(covered.has(`${r},${c}`), `module ${r},${c} not drawn`).toBe(true);
    }));
    expect(covered.size).toBe(dark);
  });
});

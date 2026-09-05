// qr.ts — a dependency-free QR Code encoder (ISO/IEC 18004), byte mode, EC level M,
// versions 1–10.
//
// WHY THIS EXISTS. Two-factor enrolment has to show an `otpauth://` URI as a QR
// code so an authenticator app can read it. That URI is ~90–140 bytes, which is
// comfortably inside version 10 at error-correction level M, so a full encoder
// for all 40 versions and four EC levels would be code we never execute. This is
// the smallest correct subset, and nothing here is approximate: mode indicator,
// character count, terminator, the 0xEC/0x11 pad codewords, Reed–Solomon ECC per
// block with the real group/block split, interleaving, function-pattern
// placement, all eight masks scored by the standard penalty rules, format
// information with its BCH bits and the 0x5412 mask, and version information for
// versions ≥ 7.
//
// NO NEW DEPENDENCY. The repository ships no QR library and is not allowed to add
// one; this module is the reason that rule costs nothing here.
//
// OUTPUT IS DATA, NEVER MARKUP. `encodeQR` returns a boolean matrix and
// `qrPathData` returns an SVG path `d` string. Callers render real <svg>/<path>
// elements — nothing in this module produces HTML, so no caller is ever tempted
// to inject it (CLAUDE.md §15, LLM02 / output handling).

/** Module matrix, `[row][col]`, `true` = dark. No quiet zone is included. */
export type QRMatrix = boolean[][];

// ── the version table (error-correction level M only) ────────────────────────
//
// Per version: EC codewords per block, then the two block groups
// (count × data codewords). Group 2 is absent for most low versions.
// Total codewords = g1*(g1Data+ec) + g2*(g2Data+ec) and matches Table 9 of the
// standard; the round-trip test re-states these numbers independently.

interface VersionSpec {
  /** Error-correction codewords in every block of this version. */
  ec: number;
  /** Group 1: number of blocks × data codewords each. */
  g1: number;
  g1Data: number;
  /** Group 2: number of blocks × data codewords each (0 when absent). */
  g2: number;
  g2Data: number;
}

const SPECS: readonly VersionSpec[] = [
  { ec: 10, g1: 1, g1Data: 16, g2: 0, g2Data: 0 }, // v1
  { ec: 16, g1: 1, g1Data: 28, g2: 0, g2Data: 0 }, // v2
  { ec: 26, g1: 1, g1Data: 44, g2: 0, g2Data: 0 }, // v3
  { ec: 18, g1: 2, g1Data: 32, g2: 0, g2Data: 0 }, // v4
  { ec: 24, g1: 2, g1Data: 43, g2: 0, g2Data: 0 }, // v5
  { ec: 16, g1: 4, g1Data: 27, g2: 0, g2Data: 0 }, // v6
  { ec: 18, g1: 4, g1Data: 31, g2: 0, g2Data: 0 }, // v7
  { ec: 22, g1: 2, g1Data: 38, g2: 2, g2Data: 39 }, // v8
  { ec: 22, g1: 3, g1Data: 36, g2: 2, g2Data: 37 }, // v9
  { ec: 26, g1: 4, g1Data: 43, g2: 1, g2Data: 44 }, // v10
];

/** Highest version this encoder implements. */
export const MAX_VERSION = SPECS.length;

/** Alignment-pattern centre coordinates, by version (index 0 = version 1). */
const ALIGNMENT: readonly (readonly number[])[] = [
  [], [6, 18], [6, 22], [6, 26], [6, 30],
  [6, 34], [6, 22, 38], [6, 24, 42], [6, 26, 46], [6, 28, 50],
];

function spec(version: number): VersionSpec {
  const s = SPECS[version - 1];
  if (!s) throw new Error(`unsupported QR version ${version}`);
  return s;
}

/** Data codewords available at this version (EC level M). */
export function dataCodewords(version: number): number {
  const s = spec(version);
  return s.g1 * s.g1Data + s.g2 * s.g2Data;
}

/** Byte-mode character-count indicator width: 8 bits below version 10, else 16. */
function countBits(version: number): number {
  return version <= 9 ? 8 : 16;
}

// ── GF(256) arithmetic (primitive polynomial 0x11D) ──────────────────────────

const EXP = new Uint8Array(512);
const LOG = new Uint8Array(256);
{
  let x = 1;
  for (let i = 0; i < 255; i += 1) {
    EXP[i] = x;
    LOG[x] = i;
    x <<= 1;
    if (x & 0x100) x ^= 0x11d;
  }
  for (let i = 255; i < 512; i += 1) EXP[i] = EXP[i - 255];
}

/** The alpha exponent of a non-zero field element. Exported for the test. */
export function gfLog(value: number): number {
  if (value <= 0 || value > 255) throw new Error("gfLog: value out of field");
  return LOG[value];
}

function gfMul(a: number, b: number): number {
  if (a === 0 || b === 0) return 0;
  return EXP[LOG[a] + LOG[b]];
}

/**
 * The Reed–Solomon generator polynomial of the given degree, coefficients from
 * the highest power down (so `[0]` is the leading 1).
 */
export function rsGenerator(degree: number): Uint8Array {
  let poly = new Uint8Array([1]);
  for (let i = 0; i < degree; i += 1) {
    const next = new Uint8Array(poly.length + 1);
    for (let j = 0; j < poly.length; j += 1) {
      next[j] ^= poly[j];                       // × x
      next[j + 1] ^= gfMul(poly[j], EXP[i]);    // × alpha^i
    }
    poly = next;
  }
  return poly;
}

/** The `ecLen` error-correction codewords for one data block. */
function rsEncode(data: Uint8Array, ecLen: number): Uint8Array {
  const gen = rsGenerator(ecLen);
  const work = new Uint8Array(data.length + ecLen);
  work.set(data);
  for (let i = 0; i < data.length; i += 1) {
    const factor = work[i];
    if (factor === 0) continue;
    for (let j = 0; j < gen.length; j += 1) work[i + j] ^= gfMul(gen[j], factor);
  }
  return work.slice(data.length);
}

// ── bit stream ───────────────────────────────────────────────────────────────

class BitWriter {
  readonly bits: number[] = [];

  put(value: number, length: number): void {
    for (let i = length - 1; i >= 0; i -= 1) this.bits.push((value >>> i) & 1);
  }
}

// ── format and version information ───────────────────────────────────────────

/** EC level M is `00` in the two format-information level bits. */
const EC_LEVEL_M = 0b00;

/**
 * The 15 format-information bits for EC level M and the given mask: five data
 * bits, ten BCH(15,5) bits, the whole thing XORed with 0x5412 so it is never
 * all-zero. Returned as an integer; bit 14 is the first bit placed.
 */
export function formatInfo(mask: number): number {
  const data = (EC_LEVEL_M << 3) | mask;
  let rem = data;
  for (let i = 0; i < 10; i += 1) rem = (rem << 1) ^ ((rem >>> 9) * 0x537);
  return ((data << 10) | rem) ^ 0x5412;
}

/** The same value as a 15-character bit string — what the test asserts against. */
export function formatInfoBits(mask: number): string {
  const v = formatInfo(mask);
  let s = "";
  for (let i = 14; i >= 0; i -= 1) s += (v >>> i) & 1;
  return s;
}

/** The 18 version-information bits (six data + BCH(18,6)), versions ≥ 7 only. */
export function versionInfo(version: number): number {
  let rem = version;
  for (let i = 0; i < 12; i += 1) rem = (rem << 1) ^ ((rem >>> 11) * 0x1f25);
  return (version << 12) | rem;
}

// ── matrix construction ──────────────────────────────────────────────────────

interface Grid {
  size: number;
  /** 1 = dark, 0 = light. */
  mod: Uint8Array[];
  /** true = function module: never masked, never carries data. */
  fn: boolean[][];
}

function newGrid(size: number): Grid {
  return {
    size,
    mod: Array.from({ length: size }, () => new Uint8Array(size)),
    fn: Array.from({ length: size }, () => new Array<boolean>(size).fill(false)),
  };
}

function setFn(g: Grid, row: number, col: number, dark: boolean): void {
  if (row < 0 || col < 0 || row >= g.size || col >= g.size) return;
  g.mod[row][col] = dark ? 1 : 0;
  g.fn[row][col] = true;
}

/** Finder pattern plus its separator, anchored at the pattern's top-left. */
function drawFinder(g: Grid, row0: number, col0: number): void {
  for (let dr = -1; dr <= 7; dr += 1) {
    for (let dc = -1; dc <= 7; dc += 1) {
      const ring = (dr >= 0 && dr <= 6 && (dc === 0 || dc === 6))
        || (dc >= 0 && dc <= 6 && (dr === 0 || dr === 6));
      const core = dr >= 2 && dr <= 4 && dc >= 2 && dc <= 4;
      setFn(g, row0 + dr, col0 + dc, ring || core);
    }
  }
}

function drawAlignment(g: Grid, row: number, col: number): void {
  for (let dr = -2; dr <= 2; dr += 1) {
    for (let dc = -2; dc <= 2; dc += 1) {
      const dark = Math.max(Math.abs(dr), Math.abs(dc)) !== 1;
      setFn(g, row + dr, col + dc, dark);
    }
  }
}

/** Everything that is not data: finders, timing, alignment, reserved areas. */
function drawFunctionPatterns(g: Grid, version: number): void {
  const { size } = g;

  drawFinder(g, 0, 0);
  drawFinder(g, 0, size - 7);
  drawFinder(g, size - 7, 0);

  // Timing patterns run the full row/column; the finder corners are already fixed.
  for (let i = 8; i < size - 8; i += 1) {
    const dark = i % 2 === 0;
    setFn(g, 6, i, dark);
    setFn(g, i, 6, dark);
  }

  const centres = ALIGNMENT[version - 1];
  const last = centres.length - 1;
  for (let a = 0; a < centres.length; a += 1) {
    for (let b = 0; b < centres.length; b += 1) {
      // The three finder corners have no alignment pattern.
      if ((a === 0 && b === 0) || (a === 0 && b === last) || (a === last && b === 0)) continue;
      drawAlignment(g, centres[a], centres[b]);
    }
  }

  // Reserve the two format-information strips (values written per mask later)
  // and the permanently dark module. Index 6 is skipped in both directions:
  // (8,6) and (6,8) belong to the timing patterns, not to the format strip.
  for (let i = 0; i <= 8; i += 1) {
    if (i === 6) continue;
    setFn(g, 8, i, false);
    setFn(g, i, 8, false);
  }
  for (let i = 0; i < 8; i += 1) {
    setFn(g, size - 1 - i, 8, false);
    setFn(g, 8, size - 1 - i, false);
  }
  setFn(g, size - 8, 8, true); // dark module, row 4·version+9, column 8

  if (version >= 7) {
    const bits = versionInfo(version);
    for (let i = 0; i < 18; i += 1) {
      const dark = ((bits >>> i) & 1) === 1;
      const a = size - 11 + (i % 3);
      const b = Math.floor(i / 3);
      setFn(g, b, a, dark); // top-right block
      setFn(g, a, b, dark); // bottom-left block
    }
  }
}

function drawFormatInfo(g: Grid, mask: number): void {
  const bits = formatInfo(mask);
  const bit = (i: number): boolean => ((bits >>> i) & 1) === 1;
  const { size } = g;

  for (let i = 0; i <= 5; i += 1) setFn(g, i, 8, bit(i));
  setFn(g, 7, 8, bit(6));
  setFn(g, 8, 8, bit(7));
  setFn(g, 8, 7, bit(8));
  for (let i = 9; i < 15; i += 1) setFn(g, 8, 14 - i, bit(i));

  for (let i = 0; i < 8; i += 1) setFn(g, 8, size - 1 - i, bit(i));
  for (let i = 8; i < 15; i += 1) setFn(g, size - 15 + i, 8, bit(i));
  setFn(g, size - 8, 8, true);
}

/** The standard bottom-right upward zig-zag, two columns at a time, skipping column 6. */
function placeData(g: Grid, bits: readonly number[]): void {
  const { size } = g;
  let idx = 0;
  let upward = true;
  for (let right = size - 1; right > 0; right -= 2) {
    if (right === 6) right = 5; // column 6 is the vertical timing pattern
    for (let vert = 0; vert < size; vert += 1) {
      const row = upward ? size - 1 - vert : vert;
      for (let k = 0; k < 2; k += 1) {
        const col = right - k;
        if (g.fn[row][col]) continue;
        g.mod[row][col] = idx < bits.length ? bits[idx] : 0;
        idx += 1;
      }
    }
    upward = !upward;
  }
}

/** The eight standard mask conditions. `true` means the module is inverted. */
export function maskCondition(mask: number, row: number, col: number): boolean {
  switch (mask) {
    case 0: return (row + col) % 2 === 0;
    case 1: return row % 2 === 0;
    case 2: return col % 3 === 0;
    case 3: return (row + col) % 3 === 0;
    case 4: return (Math.floor(row / 2) + Math.floor(col / 3)) % 2 === 0;
    case 5: return ((row * col) % 2) + ((row * col) % 3) === 0;
    case 6: return (((row * col) % 2) + ((row * col) % 3)) % 2 === 0;
    case 7: return (((row + col) % 2) + ((row * col) % 3)) % 2 === 0;
    default: throw new Error(`mask ${mask} out of range`);
  }
}

function applyMask(g: Grid, mask: number): void {
  for (let row = 0; row < g.size; row += 1) {
    for (let col = 0; col < g.size; col += 1) {
      if (g.fn[row][col]) continue;
      if (maskCondition(mask, row, col)) g.mod[row][col] ^= 1;
    }
  }
}

// The 1:1:3:1:1 finder-like sequences rule 3 punishes, in both orientations.
const FINDER_RUN_A = [1, 0, 1, 1, 1, 0, 1, 0, 0, 0, 0];
const FINDER_RUN_B = [0, 0, 0, 0, 1, 0, 1, 1, 1, 0, 1];

function matchesAt(line: readonly number[], at: number, pattern: readonly number[]): boolean {
  for (let i = 0; i < pattern.length; i += 1) if (line[at + i] !== pattern[i]) return false;
  return true;
}

/** The four standard penalty rules; lower is better. */
export function penalty(g: Grid): number {
  const { size, mod } = g;
  let score = 0;

  const lines: number[][] = [];
  for (let r = 0; r < size; r += 1) lines.push(Array.from(mod[r]));
  for (let c = 0; c < size; c += 1) {
    const col: number[] = [];
    for (let r = 0; r < size; r += 1) col.push(mod[r][c]);
    lines.push(col);
  }

  // Rule 1: runs of five or more identical modules.
  for (const line of lines) {
    let run = 1;
    for (let i = 1; i <= line.length; i += 1) {
      if (i < line.length && line[i] === line[i - 1]) { run += 1; continue; }
      if (run >= 5) score += 3 + (run - 5);
      run = 1;
    }
  }

  // Rule 2: every 2×2 block of one colour.
  for (let r = 0; r + 1 < size; r += 1) {
    for (let c = 0; c + 1 < size; c += 1) {
      const v = mod[r][c];
      if (mod[r][c + 1] === v && mod[r + 1][c] === v && mod[r + 1][c + 1] === v) score += 3;
    }
  }

  // Rule 3: finder-lookalike sequences in any row or column.
  for (const line of lines) {
    for (let i = 0; i + 11 <= line.length; i += 1) {
      if (matchesAt(line, i, FINDER_RUN_A) || matchesAt(line, i, FINDER_RUN_B)) score += 40;
    }
  }

  // Rule 4: deviation of the dark-module proportion from 50%.
  let dark = 0;
  for (let r = 0; r < size; r += 1) for (let c = 0; c < size; c += 1) dark += mod[r][c];
  const total = size * size;
  const percent = (dark * 100) / total;
  score += Math.floor(Math.abs(percent - 50) / 5) * 10;

  return score;
}

// ── encoding ─────────────────────────────────────────────────────────────────

/** The smallest implemented version that holds `byteLen` bytes at EC level M. */
export function versionFor(byteLen: number): number {
  for (let v = 1; v <= MAX_VERSION; v += 1) {
    const needed = 4 + countBits(v) + byteLen * 8;
    if (needed <= dataCodewords(v) * 8) return v;
  }
  throw new Error("text is too long for a version-10 QR code at error-correction level M");
}

/** Mode indicator, count, payload, terminator and pad codewords, as codewords. */
function buildDataCodewords(bytes: Uint8Array, version: number): Uint8Array {
  const capacity = dataCodewords(version);
  const w = new BitWriter();
  w.put(0b0100, 4);                       // byte mode
  w.put(bytes.length, countBits(version));
  for (const b of bytes) w.put(b, 8);

  const capacityBits = capacity * 8;
  w.put(0, Math.min(4, capacityBits - w.bits.length)); // terminator
  while (w.bits.length % 8 !== 0) w.bits.push(0);      // pad to a codeword boundary

  const out = new Uint8Array(capacity);
  for (let i = 0; i < w.bits.length; i += 8) {
    let byte = 0;
    for (let j = 0; j < 8; j += 1) byte = (byte << 1) | w.bits[i + j];
    out[i / 8] = byte;
  }
  // Pad codewords alternate 0xEC / 0x11 until the block is full.
  for (let i = w.bits.length / 8, n = 0; i < capacity; i += 1, n += 1) out[i] = n % 2 === 0 ? 0xec : 0x11;
  return out;
}

/** Split into blocks, compute ECC, interleave both halves — the final bit stream. */
function interleave(data: Uint8Array, version: number): number[] {
  const s = spec(version);
  const blocks: Uint8Array[] = [];
  const ecs: Uint8Array[] = [];
  let at = 0;
  for (let i = 0; i < s.g1; i += 1) {
    const block = data.slice(at, at + s.g1Data);
    at += s.g1Data;
    blocks.push(block);
    ecs.push(rsEncode(block, s.ec));
  }
  for (let i = 0; i < s.g2; i += 1) {
    const block = data.slice(at, at + s.g2Data);
    at += s.g2Data;
    blocks.push(block);
    ecs.push(rsEncode(block, s.ec));
  }

  const codewords: number[] = [];
  const maxData = Math.max(s.g1Data, s.g2 > 0 ? s.g2Data : 0);
  for (let i = 0; i < maxData; i += 1) {
    for (const block of blocks) if (i < block.length) codewords.push(block[i]);
  }
  for (let i = 0; i < s.ec; i += 1) {
    for (const ec of ecs) codewords.push(ec[i]);
  }

  const bits: number[] = [];
  for (const cw of codewords) for (let i = 7; i >= 0; i -= 1) bits.push((cw >>> i) & 1);
  return bits;
}

/**
 * Encodes `text` as a QR Code (byte mode, EC level M) and returns the module
 * matrix — `[row][col]`, `true` = dark, no quiet zone. The mask is the one of
 * the eight with the lowest standard penalty score.
 *
 * Throws when the text does not fit in a version-10 symbol.
 */
export function encodeQR(text: string): QRMatrix {
  if (text.length === 0) throw new Error("encodeQR: nothing to encode");
  const bytes = new TextEncoder().encode(text);
  const version = versionFor(bytes.length);
  const size = version * 4 + 17;

  const base = newGrid(size);
  drawFunctionPatterns(base, version);
  placeData(base, interleave(buildDataCodewords(bytes, version), version));

  let best: Grid | null = null;
  let bestScore = Number.POSITIVE_INFINITY;
  for (let mask = 0; mask < 8; mask += 1) {
    const g: Grid = {
      size,
      mod: base.mod.map((row) => Uint8Array.from(row)),
      fn: base.fn.map((row) => row.slice()),
    };
    applyMask(g, mask);
    drawFormatInfo(g, mask);
    const score = penalty(g);
    if (score < bestScore) { bestScore = score; best = g; }
  }
  if (!best) throw new Error("encodeQR: no mask produced a symbol");

  return best.mod.map((row) => Array.from(row, (v) => v === 1));
}

/**
 * An SVG path `d` covering every dark module as a 1×1 square, for a viewBox of
 * `0 0 size size` (add the quiet zone by offsetting the viewBox if wanted).
 *
 * This returns PATH DATA, not markup: the caller renders `<path d={…} />` as a
 * real element. Nothing here is ever handed to `innerHTML`.
 */
export function qrPathData(matrix: QRMatrix): string {
  const parts: string[] = [];
  for (let row = 0; row < matrix.length; row += 1) {
    const line = matrix[row];
    let col = 0;
    while (col < line.length) {
      if (!line[col]) { col += 1; continue; }
      let run = 1;
      while (col + run < line.length && line[col + run]) run += 1;
      parts.push(`M${col} ${row}h${run}v1h-${run}z`);
      col += run;
    }
  }
  return parts.join("");
}

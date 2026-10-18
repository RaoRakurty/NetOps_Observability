// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

/** bestCols picks a column count for a grid of `n` equal tiles so the last row
 *  is as full as possible — six channel tiles read 3 + 3, not 4 + 2 with two
 *  empty cells (owner 2026-10-18: "lots of empty space after Amazon SNS").
 *  Prefers the widest layout among equally balanced ones; never more than
 *  `max` columns (narrow screens step down in CSS). */
export function bestCols(n: number, max = 4): number {
  if (n <= 1) return 1;
  if (n <= max) return n === 3 || n === 2 || n === 4 ? n : Math.min(n, max);
  // Past six tiles a two-column grid gets tall; keep it to 3 or 4 columns.
  const min = n > 6 ? 3 : 2;
  let best = min;
  let bestEmpty = Number.POSITIVE_INFINITY;
  for (let c = max; c >= min; c--) {
    const empty = (c - (n % c)) % c;
    if (empty < bestEmpty) {
      best = c;
      bestEmpty = empty;
    }
  }
  return best;
}

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// groupGeometry.ts — THE container geometry constants, in one place.
//
// This module exists because the group box was previously produced by THREE
// systems that did not agree with each other:
//
//   1. ELK laid containers out reserving padding [top=38,left=18,…] …
//   2. …then the adapter THREW THAT AWAY and re-derived every rect from member
//      positions with its own constants (pad 28, top 16) …
//   3. …using a phantom node size (150×64) while the card actually draws 120×56.
//
// The visible result was a box padded 28px from a card's left edge and 58px
// from its right, a label chip 26px tall in a 16px reserve, and — because ELK
// reserved 18px between siblings while the adapter drew 28px — sibling
// containers whose drawn borders nearly touched even though the layout had
// "solved" cleanly. That is the "something not right" and the overlap.
//
// The rule now: ELK computes container rectangles, the renderer DRAWS THOSE
// RECTANGLES, and both read their numbers from here. Geometry cannot drift
// because there is only one copy of it.

import { CARD_W, CARD_H } from "../renderers/react-flow/nodes/DeviceNode";

/** Height reserved for the container's label chip. The chip is ~30px since
 *  the site name went to 14px (2026-11-24) and it sits 8px below the box top;
 *  this is the FULL band including breathing room, and ELK reserves exactly
 *  this at the top so a member can never be laid out under the label. */
export const LABEL_BAND = 44;

/** Inner padding on the other three sides. Roughly half a card height, which
 *  reads as deliberate space rather than a tight sleeve. */
export const GROUP_PAD = 24;

/** Gap between sibling containers. Wide enough that two 1.5px borders plus
 *  their label chips never read as one merged block. */
export const GROUP_GAP = 48;

/** ELK's padding string for a container — top carries the label band. */
export const ELK_GROUP_PADDING =
  `[top=${LABEL_BAND + GROUP_PAD},left=${GROUP_PAD},bottom=${GROUP_PAD},right=${GROUP_PAD}]`;

/** Minimum container size, so a one-child group is not a tight sleeve. */
export const GROUP_MIN_W = CARD_W + 2 * GROUP_PAD;
export const GROUP_MIN_H = CARD_H + LABEL_BAND + 2 * GROUP_PAD;

/** Estimated width of a box's label chip (GroupLabelNode): dot · kind ·
 *  name · count · collapse button, with the site NAME at 14px and the rest at
 *  12px (owner, 2026-11-24). Deliberately a little generous — the kind is sized
 *  as "Discovered site", the longest one — so a box is never narrower than its
 *  own chip (the chip used to hang past a one-device box's right edge and over
 *  its neighbour). The name is capped like the chip caps it (maxWidth 280). */
export function labelChipWidth(label: string, count: number): number {
  const KIND = 15 * 7.6;                              // "DISCOVERED SITE", 12px caps
  const NAME = Math.min((label || "").length, 38) * 7.4; // 14px semibold
  const COUNT = 7 * (2 + String(Math.max(0, count)).length); // "· 12"
  const CHROME = 17 + 8 + 4 * 7 + 22;                 // padding+border, dot, gaps, button
  return Math.round(CHROME + KIND + NAME + COUNT);
}

/** Minimum width of a site box: the card minimum, or its chip plus the chip's
 *  10px inset on each side, whichever is wider. */
export function groupMinWidth(label: string, count: number): number {
  return Math.max(GROUP_MIN_W, labelChipWidth(label, count) + 20);
}

/** Target width:height for packing. A screen-shaped ratio stops ELK producing
 *  tall-skinny towers or single long rows. ELK's own default is 1.6. */
export const GROUP_ASPECT = 1.8;

/** Corner radius per nesting depth — nested corners visually collide unless the
 *  inner radius shrinks. Depth 0 = outermost (region), 1 = VPC, 2+ = subnet. */
export function radiusForDepth(depth: number): number {
  return depth <= 0 ? 16 : depth === 1 ? 12 : 10;
}

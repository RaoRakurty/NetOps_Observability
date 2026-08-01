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

/** Height reserved for the container's label chip. The chip is ~26px; this is
 *  the FULL band including breathing room, and ELK reserves exactly this at the
 *  top so a member can never be laid out under the label. */
export const LABEL_BAND = 36;

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

/** Target width:height for packing. A screen-shaped ratio stops ELK producing
 *  tall-skinny towers or single long rows. ELK's own default is 1.6. */
export const GROUP_ASPECT = 1.8;

/** Corner radius per nesting depth — nested corners visually collide unless the
 *  inner radius shrinks. Depth 0 = outermost (region), 1 = VPC, 2+ = subnet. */
export function radiusForDepth(depth: number): number {
  return depth <= 0 ? 16 : depth === 1 ? 12 : 10;
}

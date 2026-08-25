// savedLayoutStore.ts — localStorage-backed operator-pinned node positions, keyed
// per view.
//
// ⚠️ Saved layouts are an OVERLAY on top of the domain graph, never part of it
// (PDF §12 "saved layout rule"). A bad/stale pin must NEVER corrupt the resolved
// TopologyView: the renderer applies these positions as hints, and the layout
// service fills in everything that isn't pinned. We therefore keep this store
// completely separate from the graph model and tolerate any read/parse failure
// (quota, private mode, corrupted JSON) by falling back to "no pins".

export type SavedPosition = { x: number; y: number };
export type SavedLayout = Record<string, SavedPosition>;

const KEY_PREFIX = "correlix.topology.layout:";

function keyFor(viewId: string): string {
  return `${KEY_PREFIX}${viewId}`;
}

function storage(): Storage | null {
  try {
    return typeof window !== "undefined" ? window.localStorage : null;
  } catch {
    return null;
  }
}

/** Load pinned positions for a view. Returns {} on any error (never throws). */
export function loadSavedLayout(viewId: string): SavedLayout {
  const ls = storage();
  if (!ls) return {};
  try {
    const raw = ls.getItem(keyFor(viewId));
    if (!raw) return {};
    const parsed = JSON.parse(raw);
    if (!parsed || typeof parsed !== "object") return {};
    const out: SavedLayout = {};
    for (const [id, pos] of Object.entries(parsed as Record<string, unknown>)) {
      if (
        pos &&
        typeof pos === "object" &&
        typeof (pos as SavedPosition).x === "number" &&
        typeof (pos as SavedPosition).y === "number"
      ) {
        out[id] = { x: (pos as SavedPosition).x, y: (pos as SavedPosition).y };
      }
    }
    return out;
  } catch {
    return {};
  }
}

/** Pin one node's position. Silently no-ops on quota/serialization failure. */
export function saveNodePosition(viewId: string, nodeId: string, pos: SavedPosition): void {
  const ls = storage();
  if (!ls) return;
  try {
    const current = loadSavedLayout(viewId);
    current[nodeId] = { x: pos.x, y: pos.y };
    ls.setItem(keyFor(viewId), JSON.stringify(current));
  } catch {
    // Quota exceeded / serialization error — pins are best-effort, drop silently.
  }
}

/** Forget all pins for a view (reset to computed layout). */
export function clearSavedLayout(viewId: string): void {
  const ls = storage();
  if (!ls) return;
  try {
    ls.removeItem(keyFor(viewId));
  } catch {
    // ignore
  }
}

/** Clear EVERY saved layout whose key starts with the given view prefix.
 *
 * The renderer's layout key embeds a content signature (node+edge ids), so a
 * topology refresh that adds or drops a single adjacency re-keys the store and
 * ORPHANS the operator's pins under the old key (found 2026-08-25: "Reset
 * doesn't work any more" — the button gated itself on pins under the current
 * key only, while stale pin-sets accumulated invisibly). Reset now sweeps the
 * whole family for the view. Same failure tolerance as the rest of the store.
 */
export function clearSavedLayoutsMatching(viewIdPrefix: string): number {
  const ls = storage();
  if (!ls) return 0;
  let removed = 0;
  try {
    const doomed: string[] = [];
    for (let i = 0; i < ls.length; i++) {
      const k = ls.key(i);
      if (k && k.startsWith(KEY_PREFIX + viewIdPrefix)) doomed.push(k);
    }
    for (const k of doomed) {
      ls.removeItem(k);
      removed++;
    }
  } catch {
    // ignore — worst case some stale pins survive; they are inert overlays
  }
  return removed;
}

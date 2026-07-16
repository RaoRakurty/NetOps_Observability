// useInvestigationDrawer (#7 Wave 2) — open a correlation object INSIDE Service
// View with no context-losing navigation. Under shell-v2 it docks into the
// shared workspace Inspector (the same right pane the RCA candidate list uses:
// ESC/X close, drag-resize, pin); under the v1 shell the caller renders the
// returned `inlineId` in the page-local EvidenceDrawer. Either way the open
// object's id is mirrored into the URL (`?inv=<id>`) so refresh / a shared link
// reopens the same investigation over the same tab.

import { useCallback, useEffect, useRef, useState } from "react";
import { useWorkspace } from "../../context/workspace";
import { friendlyProblemId } from "../../components/rca/labels";
import InvestigationDrawer from "./InvestigationDrawer";
import { hashWithInv, hashWithoutInv, invFromHash } from "./investigationUrl";

export interface InvestigationDrawerApi {
  /** open the investigation drawer for one correlation object */
  open: (correlationId: string) => void;
  /** v1-shell fallback: the id to render inline (null under shell-v2) */
  inlineId: string | null;
  /** v1-shell fallback: close the inline panel (also clears the URL) */
  closeInline: () => void;
}

export function useInvestigationDrawer(): InvestigationDrawerApi {
  const ws = useWorkspace();
  const [inlineId, setInlineId] = useState<string | null>(null);
  const openedRef = useRef(false);          // we put the current Inspector content there
  const curIdRef = useRef<string | null>(null); // currently-open object (dedup guard)

  const open = useCallback((id: string) => {
    if (!id || curIdRef.current === id) return;
    curIdRef.current = id;
    location.hash = hashWithInv(location.hash, id);
    if (ws.enabled) {
      openedRef.current = true;
      ws.openInspector(<InvestigationDrawer id={id} />, {
        title: `Investigation · ${friendlyProblemId(id)}`,
        subtitle: "Service View",
      });
    } else {
      setInlineId(id);
    }
  }, [ws]);

  // URL → drawer: a refresh or a pasted link with ?inv=<id> reopens the object.
  const openRef = useRef(open);
  openRef.current = open;
  useEffect(() => {
    const apply = () => {
      const id = invFromHash(location.hash);
      if (id) openRef.current(id);
    };
    apply();
    window.addEventListener("hashchange", apply);
    return () => window.removeEventListener("hashchange", apply);
  }, []);

  // Inspector closed (ESC / X) → drop the URL param so the closed state is
  // shareable/refresh-true as well.
  useEffect(() => {
    if (!ws.enabled) return;
    if (openedRef.current && !ws.inspector) {
      openedRef.current = false;
      curIdRef.current = null;
      location.hash = hashWithoutInv(location.hash);
    }
  }, [ws.enabled, ws.inspector]);

  const closeInline = useCallback(() => {
    setInlineId(null);
    curIdRef.current = null;
    location.hash = hashWithoutInv(location.hash);
  }, []);

  return { open, inlineId, closeInline };
}

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

import { useEffect, useSyncExternalStore } from "react";

// viewContext.ts — what the operator is LOOKING AT, for Iris (tracker 337
// N-E4). A page that shows one incident or one device registers it while it
// is on screen (useIrisView); every Iris ask then carries it, so "why is this
// down?" typed into the Iris box on a device page means THAT device.
//
// TRUST. This is a hint from the browser, nothing more. The server
// re-resolves every id inside the caller's own workspace before anything
// routes (backend ai/view_binding.go) and drops — with a one-line disclosure —
// anything that does not resolve. So the shapes are checked here only to keep
// junk off the wire; nothing here is an authority. Only ids travel: labels
// stay in the browser for the panel's chip and are never sent.

export type IrisView =
  | { kind: "incident"; id: string; label: string }
  | { kind: "device"; id: string; label: string };

const reUUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
// Device ids and hostnames: letters, digits and . _ : - /, at most 128.
const reDeviceRef = /^[A-Za-z0-9._:/-]{1,128}$/;

/** A view whose id is the right shape, or null. */
export function validView(v: IrisView | null | undefined): IrisView | null {
  if (!v) return null;
  const id = (v.id || "").trim();
  if (v.kind === "incident" && reUUID.test(id)) return { ...v, id };
  if (v.kind === "device" && reDeviceRef.test(id)) return { ...v, id };
  return null;
}

let current: IrisView | null = null;
const listeners = new Set<() => void>();

function emit() {
  listeners.forEach((l) => l());
}

/** Replace what is in view (null = nothing). Invalid views clear it. */
export function setIrisView(v: IrisView | null): void {
  const next = validView(v);
  if (next?.kind === current?.kind && next?.id === current?.id && next?.label === current?.label) return;
  current = next;
  emit();
}

/** What is in view right now (null = nothing). */
export function currentIrisView(): IrisView | null {
  return current;
}

function subscribe(l: () => void): () => void {
  listeners.add(l);
  return () => listeners.delete(l);
}

/** Read what is in view, re-rendering when it changes (the panel's chip). */
export function useCurrentIrisView(): IrisView | null {
  return useSyncExternalStore(subscribe, currentIrisView, currentIrisView);
}

/**
 * Register what this page shows while it is mounted. Pass null to show
 * nothing. On unmount the view is cleared only if it is still this page's,
 * so a page that opens over another does not wipe the one underneath.
 */
export function useIrisView(v: IrisView | null): void {
  const kind = v?.kind;
  const id = v?.id;
  const label = v?.label;
  useEffect(() => {
    if (!kind || !id) return undefined;
    const mine = validView({ kind, id, label: label ?? "" } as IrisView);
    setIrisView(mine);
    return () => {
      if (mine && current?.kind === mine.kind && current?.id === mine.id) setIrisView(null);
    };
  }, [kind, id, label]);
}

/** The ui-context keys a view adds to an ask. */
export function viewContextKeys(v: IrisView | null = current): Record<string, string> {
  const ok = validView(v);
  if (!ok) return {};
  return ok.kind === "incident" ? { correlation_id: ok.id } : { device_id: ok.id };
}

/**
 * The context an Iris ask sends: what is in view, merged UNDER the caller's
 * own context (an explicit correlation_id or topic always wins).
 */
export function withViewContext(context?: Record<string, string>, v: IrisView | null = current): Record<string, string> | undefined {
  const keys = viewContextKeys(v);
  if (Object.keys(keys).length === 0) return context;
  // An explicit subject of either kind replaces the screen's.
  if (context && (context.correlation_id || context.problem_id || context.device_id || context.device)) return context;
  return { ...keys, ...(context ?? {}) };
}

/** The chip text for what is in view ("Device · edge-1"). */
export function viewChipLabel(v: IrisView | null): string | undefined {
  const ok = validView(v);
  if (!ok) return undefined;
  const label = (ok.label || "").trim() || ok.id;
  return ok.kind === "incident" ? `Incident · ${label}` : `Device · ${label}`;
}

/** Test seam: forget the current view. */
export function resetIrisViewForTest(): void {
  current = null;
  emit();
}

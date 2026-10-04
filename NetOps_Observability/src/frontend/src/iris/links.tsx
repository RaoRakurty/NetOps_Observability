// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// links.tsx — every entity / incident / change reference in an Iris answer
// renders through here, and every href through the existing `safeCiteHref`
// allowlist (IrisLane.tsx): a same-origin relative path or nothing. The ids are
// data from the answer, so they are URL-encoded into a CLOSED route map; an
// entity kind without a page renders as plain text, never as a guessed link.

import type { ReactNode } from "react";
import { safeCiteHref } from "../pages/troubleshoot/IrisLane";

/** Entity kinds that have a page to open. Anything else is text. */
const ROUTES: Record<string, (id: string) => string> = {
  incident: (id) => `/#/investigate/rca?id=${encodeURIComponent(id)}`,
  change: (id) => `/#/operations/digital-experience/changes?id=${encodeURIComponent(id)}`,
  device: (id) => `/#/infrastructure/devices?q=${encodeURIComponent(id)}`,
  site: (id) => `/#/infrastructure/sites/sites?q=${encodeURIComponent(id)}`,
};

/** The safe href for one entity reference, or null (render as text). */
export function irisHref(kind: string, id: string): string | null {
  // Own keys only: "__proto__" / "constructor" must not resolve to Object's.
  if (!Object.prototype.hasOwnProperty.call(ROUTES, kind)) return null;
  const route = ROUTES[kind];
  if (typeof id !== "string" || id.trim() === "") return null;
  return safeCiteHref(route(id.trim()));
}

/**
 * The safe href for a citation on an Iris answer, or null (render as text).
 * The engine writes in-app citations as hash routes ("#/monitoring/…"), which
 * cannot leave the document; a "/…" path goes through safeCiteHref. Everything
 * else — "" (a query citation has no page), "javascript:", "https://…",
 * "//host" — is not a link: an empty href is a full reload of the app, and the
 * others are the reasons links are checked at all.
 */
export function answerCiteHref(href: string | undefined): string | null {
  const h = (href || "").trim();
  if (h.startsWith("#/")) return h;
  return safeCiteHref(h);
}

/**
 * A reference that is a link when it can be one. `href` (e.g. from a
 * recommendation) is checked with safeCiteHref; otherwise kind+id is mapped.
 */
export function SafeLink({
  kind,
  id,
  href,
  children,
  className,
}: {
  kind?: string;
  id?: string;
  href?: string;
  children: ReactNode;
  className?: string;
}) {
  const h = href !== undefined ? safeCiteHref(href) : kind && id ? irisHref(kind, id) : null;
  if (!h) return <span className={className}>{children}</span>;
  return (
    <a className={className ? `iris-link ${className}` : "iris-link"} href={h}>
      {children}
    </a>
  );
}

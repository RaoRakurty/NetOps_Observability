// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

import type { ReactNode } from "react";

// AdminSection — one collapsible section of an Administration hub page.
//
// Its body is MOUNTED ONLY WHILE OPEN. A <details> element mounts its children
// even when closed, so a hub of five live pages would start five refresh loops
// (and five server reads) the moment it opened; here a closed section costs
// nothing. Opening is controlled by the hub, so a deep link can open one.
export default function AdminSection({ id, title, summary, open, onToggle, children }: {
  id: string;
  title: string;
  summary?: string;
  open: boolean;
  onToggle: (id: string) => void;
  children: ReactNode;
}) {
  const bodyId = `adm-section-${id}`;
  return (
    <section className={`adm-section${open ? " open" : ""}`} data-section={id}>
      <button type="button" className="adm-section-head" aria-expanded={open} aria-controls={bodyId} onClick={() => onToggle(id)}>
        <span className="adm-section-chevron" aria-hidden>{open ? "▾" : "▸"}</span>
        <span className="adm-section-title">{title}</span>
        {summary ? <span className="adm-section-summary">{summary}</span> : null}
      </button>
      {open ? <div id={bodyId} className="adm-section-body">{children}</div> : null}
    </section>
  );
}

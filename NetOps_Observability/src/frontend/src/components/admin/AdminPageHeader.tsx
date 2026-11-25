// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

import AskIris from "../AskIris";
import { PageHeader } from "../kit";

// AdminPageHeader — the one Administration page header (was three copies:
// tabs/admin.tsx, tabs/TransportSecurity.tsx, pages/telemetry/TelemetryCoverage.tsx).
// `sub` is one SHORT line at most; the sentence that teaches what the screen is
// for lives in ai/skills/explain/<topic>.md behind the (i) beside the title
// (tracker 270).
//
// Visual language (owner 2026-11-24, docs/design/visual-language.md): with an
// `icon` (a page's own menu glyph) it IS the kit PageHeader — icon tile, title,
// the (i) on the right. Without one it titles a section inside a page in the
// same neutral type. No per-group colour either way: the Administration group
// hues of 2026-10-18 are retired (one accent, colour only where it means
// something).
export default function AdminPageHeader({ title, sub, topic, icon }: {
  title: string; sub?: string; topic?: string; icon?: string;
}) {
  const ask = topic ? <AskIris topic={topic} label={title} /> : undefined;
  if (icon) {
    return (
      <div className="admin-head">
        <PageHeader icon={icon} title={title} subtitle={sub} actions={ask} />
      </div>
    );
  }
  return (
    <div className="admin-head">
      <h2 className="admin-section-title">
        {title}
        {ask}
      </h2>
      {sub ? <p className="admin-sub">{sub}</p> : null}
    </div>
  );
}

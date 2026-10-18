// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

import AskIris from "../AskIris";

// AdminPageHeader — the one Administration page header (was three copies:
// tabs/admin.tsx, tabs/TransportSecurity.tsx, pages/telemetry/TelemetryCoverage.tsx).
// `sub` is one SHORT line at most; the sentence that teaches what the screen is
// for lives in ai/skills/explain/<topic>.md behind the (i) beside the title
// (tracker 270). Inside `.adm-scope` the header carries the group's colour.
export default function AdminPageHeader({ title, sub, topic }: { title: string; sub?: string; topic?: string }) {
  return (
    <div className="admin-head">
      <h2 style={{ margin: 0, fontSize: "var(--fs-lg)" }}>
        {title}
        {topic ? <AskIris topic={topic} label={title} /> : null}
      </h2>
      {sub ? <p className="admin-sub">{sub}</p> : null}
    </div>
  );
}

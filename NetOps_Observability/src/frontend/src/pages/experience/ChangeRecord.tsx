// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// ChangeRecord — one change-ledger record, opened by id (`?id=` on the Changes
// tab). Iris's "Open the change record" lands here (tracker 337, N-E5 slice
// gap a): the record from GET /api/changes/{id} and what it did from
// /api/changes/{id}/diff, both the caller's own. Another workspace's id
// answers 404 and is said plainly; it never falls back to the feed as if the
// change were simply missing from it.
//
// Every value is escaped React text.

import { api, type ChangeRecord as Record_ } from "../../services/api";
import { fmtDateTime } from "../../lib/time";
import ChangeDiff, { changeDiffError } from "./ChangeDiff";
import { Loading, Panel } from "./honest";
import { useDemRead } from "./state";

function typeWords(t: string): string {
  return t.replace(/_/g, " ").toLowerCase();
}

function Row({ label, value }: { label: string; value?: string }) {
  return (
    <>
      <dt>{label}</dt>
      <dd>{value ? value : <span className="dx-subtle">not recorded</span>}</dd>
    </>
  );
}

export default function ChangeRecord({ id, onShowAll }: { id: string; onShowAll: () => void }) {
  const res = useDemRead<Record_>(() => api.change(id), [id]);
  const back = (
    <button type="button" className="btn" style={{ fontSize: 14 }} onClick={onShowAll}>
      Show all changes
    </button>
  );
  return (
    <Panel title="Change record" label="Change record" actions={back}>
      {res.status === "loading" && <Loading what="the change record" />}
      {res.status === "error" && (
        <p className="dx-note" role="alert">
          {changeDiffError(new Error(res.error))}
        </p>
      )}
      {res.status === "ready" && res.data && (
        <>
          <p className="dx-note">{res.data.summary}</p>
          <dl className="iris-kv">
            <Row label="When" value={res.data.event_at ? fmtDateTime(res.data.event_at) : ""} />
            <Row label="Kind" value={res.data.type ? typeWords(res.data.type) : ""} />
            <Row label="Object" value={res.data.object} />
            <Row label="Who" value={res.data.actor} />
            <Row label="Site" value={res.data.site} />
            <Row label="Ticket" value={res.data.ticket_ref} />
          </dl>
          {res.data.has_diff ? (
            <ChangeDiff id={res.data.id} initiallyOpen />
          ) : (
            <p className="dx-note">No before/after was recorded for this change.</p>
          )}
        </>
      )}
    </Panel>
  );
}

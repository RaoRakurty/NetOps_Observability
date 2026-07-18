// InvestigationChanges (Wave 4 #12 slice 3) — the change→incident correlation
// card MADE REAL: for one open cloud investigation, the provider change events
// (cloud_change / cloud_audit) recorded in the onset-anchored window on the
// investigation's OWN affected resources — served by
// /api/cloud/investigations/{id}/changes (tenant-scoped, bounded).
//
// Honesty rules: each row is "recorded N before/after onset" — proximity, never
// a causal claim; when the engine recorded no blast radius we say changes can't
// be scoped; when nothing landed in the window we say exactly that.

import { useEffect, useState } from "react";
import { loadInvestigationChanges, type InvestigationChanges as Data } from "./api";
import { ConsoleLink } from "./badges";

// fmtOffset renders the onset-relative time fact: "14m before onset",
// "2h 05m after onset", "at onset". Pure — unit-tested.
export function fmtOffset(offsetSeconds: number): string {
  const abs = Math.abs(offsetSeconds);
  if (abs < 30) return "at onset";
  const side = offsetSeconds < 0 ? "before onset" : "after onset";
  const min = Math.round(abs / 60);
  if (min < 1) return `${abs}s ${side}`;
  if (min < 60) return `${min}m ${side}`;
  const h = Math.floor(min / 60);
  const rem = min % 60;
  return `${h}h ${String(rem).padStart(2, "0")}m ${side}`;
}

export default function InvestigationChanges({ id }: { id: string }) {
  const [data, setData] = useState<Data | null>(null);
  const [err, setErr] = useState(false);

  useEffect(() => {
    let alive = true;
    setData(null); setErr(false);
    loadInvestigationChanges(id)
      .then((d) => { if (alive) setData(d); })
      .catch(() => { if (alive) setErr(true); });
    return () => { alive = false; };
  }, [id]);

  return (
    <div className="inv-changes" data-testid="investigation-changes">
      <div className="inv-changes-h">
        Changes near onset
        {data && (
          <span className="inv-changes-meta">
            window: {data.lookbackHours}h before onset → now · affected resources only
          </span>
        )}
      </div>
      {err ? (
        <span className="ao-muted">change correlation unavailable</span>
      ) : !data ? (
        <span className="ao-muted">checking recorded changes…</span>
      ) : data.basis === "no_affected_resources" ? (
        <span className="ao-muted">
          this investigation records no affected cloud resources — changes cannot be scoped to it honestly
        </span>
      ) : data.basis === "onset_unknown" ? (
        <span className="ao-muted">the investigation&apos;s onset time is unknown — no change window can be anchored</span>
      ) : data.changes.length === 0 ? (
        <span className="ao-muted">no changes recorded in the window</span>
      ) : (
        data.changes.map((c, i) => (
          <div className="inv-changes-row" key={`${c.time}-${c.resource}-${i}`}>
            <span className="inv-changes-when">{fmtOffset(c.offsetSeconds)}</span>
            <span>{c.changeType.replace(/_/g, " ")}</span>
            <span>· {c.resource}</span>
            {c.actor && c.actor !== "—" && <span className="inv-changes-actor">by {c.actor}</span>}
            {c.cloudRef?.logUrl && <ConsoleLink href={c.cloudRef.logUrl} label="audit record" compact />}
            {!c.cloudRef?.logUrl && c.cloudRef?.consoleUrl && (
              <ConsoleLink href={c.cloudRef.consoleUrl} label="console" compact />
            )}
          </div>
        ))
      )}
    </div>
  );
}

// Quarantine — Platform → Tools → Quarantine.
//
// WHY THIS EXISTS. When a device-lane event's identity is a registry MISS, the
// router cannot attribute it to a tenant, so it seals the whole event inside a
// metadata envelope and parks it in the operator-only quarantine index rather
// than guessing an owner (F-11 seal-or-quarantine, ADR-SEC-009). That is the
// right call, and it is also silent: telemetry an operator believes is flowing
// is instead sitting in a place nothing in the console showed. This page is the
// operator's view of what is held.
//
// WHAT IT DELIBERATELY DOES NOT DO. It never shows a payload — the API's
// projection excludes it and the type cannot serialize it — and it offers no
// re-attribution control. Unsealing and re-injecting is dual-gated break-glass
// (platform admin AND sensitive_data:admin) run deliberately from the runbook,
// not a button next to a table.
//
// GATE. `/api/quarantine` is requirePlatformAdmin: the quarantine holds OTHER
// tenants' unattributable data by definition, so no tenant principal may see
// it. That gate is why the page lives in the provider-only Platform section
// (docs/design/ADMIN_IA_2026-09-05.md §1: the gate decides the section).
//
// HONESTY RULES:
//   · A 501 means sealing custody is off, so there is no quarantine STAGE at
//     all on this deployment — a different fact from an empty quarantine.
//   · A 503 means the index could not be read. The page says the depth is
//     unknown; it never renders that as zero.
//   · The lane breakdown is computed from the rows ON THIS PAGE, and says so.
//     `summary.total` is the real depth and is reported separately.
//   · An envelope with a restore claim but no produced stamp is STRANDED — a
//     restore took it and may or may not have re-injected it. That is its own
//     state and is rendered as itself, never folded into "waiting".

import { useCallback, useEffect, useMemo, useState } from "react";
import { api, QuarantineDoc } from "../../services/api";
import { fmtDateTime } from "../../lib/time";
import { httpFailure, operatorError } from "../../lib/errors";
import { Stat, StatStrip } from "../../components/ui";
import AskIris from "../../components/AskIris";

const PAGE = 50;

type Load =
  | { kind: "loading" }
  | { kind: "unavailable" }
  | { kind: "denied" }
  | { kind: "unreadable"; message: string }
  | { kind: "ready"; docs: QuarantineDoc[]; total: number; oldest: string | null };

/** How far an envelope is through a restore, as three distinguishable states. */
function restoreState(d: QuarantineDoc): { label: string; tone: string; hint?: string } {
  if (d.cx_restored_produced) {
    return { label: "re-injected", tone: "chip-ok", hint: "the bus accepted the produce; only the tombstone remains" };
  }
  if (d.cx_restored_at) {
    return { label: "stranded claim", tone: "chip-crit", hint: "a restore claimed this envelope and may or may not have produced it" };
  }
  return { label: "held", tone: "", hint: "sealed and waiting; nothing has claimed it" };
}

function ageDays(iso: string | null): string {
  if (!iso) return "not stated";
  const t = Date.parse(iso);
  if (!Number.isFinite(t)) return "not stated";
  const days = Math.floor((Date.now() - t) / 86_400_000);
  if (days <= 0) return "less than a day";
  return `${days} day${days === 1 ? "" : "s"}`;
}

export default function Quarantine() {
  const [load, setLoad] = useState<Load>({ kind: "loading" });
  const [offset, setOffset] = useState(0);

  const read = useCallback(async (from: number) => {
    setLoad({ kind: "loading" });
    try {
      const r = await api.quarantineList(PAGE, from);
      setLoad({
        kind: "ready",
        docs: r.quarantine ?? [],
        total: r.summary?.total ?? 0,
        oldest: r.summary?.oldest_received_at ?? null,
      });
    } catch (e) {
      const f = httpFailure(e);
      if (f?.status === 501) setLoad({ kind: "unavailable" });
      else if (f?.status === 403) setLoad({ kind: "denied" });
      else setLoad({ kind: "unreadable", message: operatorError(e, "The quarantine index could not be read.") });
    }
  }, []);

  useEffect(() => { void read(offset); }, [read, offset]);

  const byLane = useMemo(() => {
    if (load.kind !== "ready") return [];
    const m = new Map<string, number>();
    for (const d of load.docs) m.set(d.lane || "not stated", (m.get(d.lane || "not stated") ?? 0) + 1);
    return [...m.entries()].sort((a, b) => b[1] - a[1]);
  }, [load]);

  const head = (
    <div className="adm admin-head">
      <h2 style={{ margin: 0, fontSize: "var(--fs-lg)" }}>
        Quarantine
        <AskIris topic="quarantine.why-held" label="Quarantine" />
      </h2>
      <p className="admin-sub">Events no tenant owns. Metadata only.</p>
    </div>
  );

  if (load.kind === "loading") {
    return <>{head}<div className="empty" role="status">Reading the quarantine index…</div></>;
  }
  if (load.kind === "unavailable") {
    return (
      <>{head}
        <div className="empty">
          No quarantine stage on this deployment.
          <AskIris topic="quarantine.not-enabled" label="no quarantine stage" />
        </div>
      </>
    );
  }
  if (load.kind === "denied") {
    return <>{head}<div className="empty">Reading the quarantine needs platform-owner access.<AskIris topic="quarantine.platform-only" label="platform-owner access" /></div></>;
  }
  if (load.kind === "unreadable") {
    return (
      <>{head}
        <div className="empty" role="alert" style={{ color: "var(--bad)" }}>
          {load.message} The depth is unknown — this is not an empty quarantine.
        </div>
      </>
    );
  }

  const { docs, total, oldest } = load;
  const shown = docs.length;
  const hasMore = offset + shown < total;

  return (
    <div className="adm">
      {head}
      <div className="admin-head-row" style={{ marginTop: "var(--sp-2)" }}>
        <StatStrip>
          <Stat label="Envelopes held" value={total.toLocaleString()} tone={total > 0 ? "bad" : "good"} />
          <Stat label="Oldest" value={oldest ? fmtDateTime(oldest) : "none held"} />
          <Stat label="Oldest age" value={oldest ? ageDays(oldest) : "—"} />
        </StatStrip>
      </div>
      <p className="adm-line">
        Held for a bounded window, then deleted.
        <AskIris topic="quarantine.retention" label="how long an envelope is held" />
      </p>

      {total === 0 ? (
        <div className="empty">
          Nothing is held.
          <AskIris topic="quarantine.nothing-held" label="nothing is held" />
        </div>
      ) : (
        <>
          <p className="adm-line">
            Lanes on this page ({shown.toLocaleString()} of {total.toLocaleString()} envelopes):{" "}
            {byLane.map(([lane, n], i) => (
              <span key={lane}>{i > 0 ? " · " : ""}<b>{lane}</b> {n.toLocaleString()}</span>
            ))}
          </p>
          <table className="ds-table" aria-label="Quarantined envelopes">
            <thead>
              <tr>
                <th scope="col">Received</th>
                <th scope="col">Lane</th>
                <th scope="col">Reason</th>
                <th scope="col">Identity (hashed)</th>
                <th scope="col">Source address</th>
                <th scope="col">Restore state</th>
                <th scope="col">Index</th>
              </tr>
            </thead>
            <tbody>
              {docs.map((d) => {
                const rs = restoreState(d);
                return (
                  <tr key={d.cx_event_id || `${d._index}-${d.identity_sha}-${d.received_at}`}>
                    <th scope="row" style={{ fontWeight: 500, textAlign: "left" }}>
                      {d.received_at ? fmtDateTime(d.received_at) : "not stated"}
                    </th>
                    <td>{d.lane || "not stated"}</td>
                    <td>{d.reason || "not stated"}</td>
                    <td className="mono" title={d.identity_sha}>{(d.identity_sha || "").slice(0, 12) || "not stated"}…</td>
                    <td>{d.source_ip || "none recorded"}</td>
                    <td><span className={`chip ${rs.tone}`} title={rs.hint}>{rs.label}</span></td>
                    <td>{d._index || "not stated"}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
          <div className="admin-head-row">
            <p className="adm-line">
              Showing {offset + 1}–{offset + shown} of {total.toLocaleString()}.
            </p>
            <button type="button" className="btn" disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - PAGE))}>
              Previous
            </button>
            <button type="button" className="btn" disabled={!hasMore} onClick={() => setOffset(offset + PAGE)}>
              Next
            </button>
          </div>
          <p className="adm-line">
            The hashed identity is what the sender claimed.
            <AskIris topic="quarantine.hashed-identity" label="the hashed identity" />
          </p>
        </>
      )}
    </div>
  );
}

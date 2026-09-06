// RpkiPanel — "Prefix origin problems": is the AS announcing each of the
// tenant's prefixes actually authorised to?
//
// The heading is the NOC admin's question; RPKI and ROA live in the section's
// secondary line and in the chip tooltips (owner, 2026-09-06). Nothing was
// removed — the validator name and the "unavailable is not a verdict" caveat
// moved behind the Details disclosure.
//
// The panel's job is to make "which of MY prefixes is not protected" answerable
// in one glance, so it sorts worst-first (the API already does) and keeps
// "could not check" visually distinct from "no ROA published": collapsing those
// two would overstate coverage, which is the one mistake an RPKI screen must
// never make.

import { useEffect, useState } from "react";
import { api, type BgpRpkiResp, type BgpRpkiState } from "../../services/api";
import { Chip } from "../../components/noc";
import { rpkiStateTone, rpkiSummary } from "./bgpDepth.model";
import { Details, Section, ShowAll, useCap } from "./Section";

/** Rows shown before the operator asks for the rest (one-page view, 2026-09-03). */
const FIRST_ROWS = 8;

const ORDER: BgpRpkiState[] = ["invalid", "unavailable", "unknown", "valid"];

export function RpkiPanel({ resource }: { resource?: string }) {
  const [data, setData] = useState<BgpRpkiResp | null>(null);
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(true);
  const [at, setAt] = useState<number | null>(null);

  useEffect(() => {
    let alive = true;
    setBusy(true); setErr(""); setData(null);
    api.bgpRpki(resource)
      .then((d) => { if (alive) { setData(d); setAt(Date.now()); } })
      .catch((e: Error) => { if (alive) setErr(e.message || "RPKI lookup failed"); })
      .finally(() => { if (alive) setBusy(false); });
    return () => { alive = false; };
  }, [resource]);

  const summary = data ? rpkiSummary(data.results) : null;
  const cap = useCap(data?.results ?? [], FIRST_ROWS);

  return (
    <Section
      id="rpki"
      title="Prefix origin problems"
      sub="RPKI — is the AS announcing each prefix authorised to announce it?"
      updatedAt={at}
    >
      {busy && <div className="empty">Checking who is authorised…</div>}
      {err && <p className="mini-meta" style={{ color: "var(--bad)" }} role="alert">{err}</p>}

      {data && summary && (
        <>
          <div style={{ display: "flex", gap: 8, flexWrap: "wrap", marginBottom: 10 }}>
            {ORDER.filter((s) => summary[s] > 0).map((s) => {
              const t = rpkiStateTone(s);
              return <Chip key={s} label={`${summary[s]} ${t.label}`} tone={t.tone} title={t.detail} />;
            })}
            {data.from_watchlist && <Chip label="from your watchlist" title="These are the prefixes this tenant watches." />}
          </div>

          {data.truncated && (
            <p className="mini-meta" style={{ color: "var(--warn)" }}>
              Only the first {data.max_prefixes} watched prefixes were checked — the sweep is bounded.
            </p>
          )}

          {data.results.length === 0 && (
            <div className="empty">
              {data.from_watchlist
                ? "No prefixes are watched yet. Watch one and its origin state shows up here."
                : "Nothing to check."}
            </div>
          )}

          {data.results.length > 0 && (
            <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
              {cap.rows.map((r) => {
                const t = rpkiStateTone(r.state, r.reason, r.error);
                return (
                  <div key={r.prefix} className="bgp-row">
                    <span className="mono" style={{ minWidth: 160 }}>{r.prefix}</span>
                    <Chip label={t.label} tone={t.tone} title={t.detail} />
                    {r.origin && <span className="mini-meta">announced by {r.origin}</span>}
                    {r.roas?.length ? (
                      <span className="mini-meta" title={r.roas.map((a) => `${a.prefix} → AS${a.origin} (maxLen ${a.max_length}, ${a.validity})`).join(" · ")}>
                        {r.roas.length} authorisation{r.roas.length === 1 ? "" : "s"} published
                      </span>
                    ) : null}
                    {r.validator && <span className="mini-meta">checked by {r.validator}</span>}
                    {r.error && <span className="mini-meta" style={{ color: "var(--warn)" }}>{r.error}</span>}
                    <span className="mini-meta" style={{ marginLeft: "auto" }} title="When this answer was fetched">
                      {r.fetched_at ? new Date(r.fetched_at).toLocaleTimeString() : ""}
                    </span>
                  </div>
                );
              })}
              <ShowAll cap={cap} noun="prefixes" />
            </div>
          )}
          <Details summary="How this was checked">
            <p className="mini-meta" style={{ marginBottom: 0 }}>
              Each prefix is checked against the route origin authorisations (ROAs) published in RPKI, read through
              RIPE NCC&apos;s Routinator view. A prefix we could not check is one whose validator was unreachable —
              that is not a verdict, and is never counted as authorised.
            </p>
          </Details>
        </>
      )}
    </Section>
  );
}

export default RpkiPanel;

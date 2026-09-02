// RpkiPanel — origin validation for the tenant's watchlist (or one prefix).
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

const ORDER: BgpRpkiState[] = ["invalid", "unavailable", "unknown", "valid"];

export function RpkiPanel({ resource }: { resource?: string }) {
  const [data, setData] = useState<BgpRpkiResp | null>(null);
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(true);

  useEffect(() => {
    let alive = true;
    setBusy(true); setErr(""); setData(null);
    api.bgpRpki(resource)
      .then((d) => { if (alive) setData(d); })
      .catch((e: Error) => { if (alive) setErr(e.message || "RPKI lookup failed"); })
      .finally(() => { if (alive) setBusy(false); });
    return () => { alive = false; };
  }, [resource]);

  const summary = data ? rpkiSummary(data.results) : null;

  return (
    <div className="card" style={{ marginTop: 12 }}>
      <h2>RPKI origin validation</h2>
      {busy && <div className="empty">Checking ROAs…</div>}
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
              Only the first {data.max_prefixes} watched prefixes were validated — the sweep is bounded.
            </p>
          )}

          {data.results.length === 0 && (
            <div className="empty">
              {data.from_watchlist
                ? "No prefixes on this tenant's watchlist yet. Watch a prefix and its ROA state shows up here."
                : "Nothing to validate."}
            </div>
          )}

          {data.results.length > 0 && (
            <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
              {data.results.map((r) => {
                const t = rpkiStateTone(r.state, r.reason, r.error);
                return (
                  <div key={r.prefix} style={{
                    display: "flex", gap: 10, alignItems: "center", flexWrap: "wrap",
                    padding: "6px 8px", borderRadius: 6, border: "1px solid var(--border)",
                  }}>
                    <span className="mono" style={{ minWidth: 160 }}>{r.prefix}</span>
                    <Chip label={t.label} tone={t.tone} title={t.detail} />
                    {r.origin && <span className="mini-meta">origin {r.origin}</span>}
                    {r.roas?.length ? (
                      <span className="mini-meta" title={r.roas.map((a) => `${a.prefix} → AS${a.origin} (maxLen ${a.max_length}, ${a.validity})`).join(" · ")}>
                        {r.roas.length} ROA{r.roas.length === 1 ? "" : "s"}
                      </span>
                    ) : null}
                    {r.validator && <span className="mini-meta">via {r.validator}</span>}
                    {r.error && <span className="mini-meta" style={{ color: "var(--warn)" }}>{r.error}</span>}
                    <span className="mini-meta" style={{ marginLeft: "auto" }} title="When this verdict was fetched">
                      {r.fetched_at ? new Date(r.fetched_at).toLocaleTimeString() : ""}
                    </span>
                  </div>
                );
              })}
            </div>
          )}
          <p className="mini-meta" style={{ marginBottom: 0 }}>
            Validated against RIPE NCC's Routinator view. <strong>Unavailable</strong> means the validator could not be
            reached — it is not a verdict, and is never counted as valid.
          </p>
        </>
      )}
    </div>
  );
}

export default RpkiPanel;

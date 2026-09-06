// GeofeedPanel — RFC 8805 self-published geolocation, discovered per RFC 9092
// from the registry object (a "geofeed:" attribute or a "Geofeed <url>" remark).
//
// Honesty rules this panel keeps:
//   * "no geofeed published" is a FACT and gets its own calm empty state — it is
//     not an error and must not look like one.
//   * every row shown was published BY THE HOLDER about address space inside the
//     queried resource; rows about other space are filtered out server-side, so
//     a feed cannot make claims about someone else's prefixes through this view.
//   * the parser drops malformed rows and the panel SAYS how many.

import { useEffect, useState } from "react";
import { api, type BgpGeofeedResp } from "../../services/api";
import { Chip } from "../../components/noc";
import { geofeedCountries } from "./bgpDepth.model";
import { Details, Section, ShowAll, useCap } from "./Section";

/** Rows shown before the operator asks for the rest (one-page view, 2026-09-03). */
const FIRST_ROWS = 8;

export function GeofeedPanel({ resource }: { resource?: string }) {
  const [data, setData] = useState<BgpGeofeedResp | null>(null);
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);
  const [at, setAt] = useState<number | null>(null);

  useEffect(() => {
    if (!resource) { setData(null); setErr(""); return; }
    let alive = true;
    setBusy(true); setErr(""); setData(null);
    api.bgpGeofeed(resource)
      .then((d) => { if (alive) { setData(d); setAt(Date.now()); } })
      .catch((e: Error) => { if (alive) setErr(e.message || "geofeed lookup failed"); })
      .finally(() => { if (alive) setBusy(false); });
    return () => { alive = false; };
  }, [resource]);

  const countries = data ? geofeedCountries(data) : [];
  const cap = useCap(data?.entries ?? [], FIRST_ROWS);

  return (
    <Section
      id="geofeed"
      title="Where this address space is used"
      sub="Geofeed (RFC 8805) — locations the address-space holder publishes about it"
      updatedAt={at}
      wide
    >
      {!resource && <div className="empty">Pick a prefix or AS to see the locations its holder publishes.</div>}
      {busy && <div className="empty">Looking for published locations…</div>}
      {err && <p className="mini-meta" style={{ color: "var(--bad)" }} role="alert">{err}</p>}

      {data && data.error && (
        <p className="mini-meta" style={{ color: "var(--warn)" }}>{data.error}</p>
      )}

      {data && !data.published && !data.error && (
        <div className="empty" style={{ textAlign: "left" }}>
          The holder of {data.resource} publishes no locations for it, so anything claiming to know where this address
          space is used is a third-party guess.
          <Details summary="How a holder publishes them">
            <p className="mini-meta" style={{ margin: 0 }}>
              A holder advertises a geofeed with a <span className="mono">geofeed:</span> attribute (or a{" "}
              <span className="mono">Geofeed &lt;url&gt;</span> remark) on their inet(6)num registry object.
            </p>
            {data.note && <p className="mini-meta" style={{ margin: "6px 0 0" }}>{data.note}</p>}
          </Details>
        </div>
      )}

      {data?.published && (
        <>
          <div style={{ display: "flex", gap: 8, flexWrap: "wrap", marginBottom: 8 }}>
            <Chip label={`${data.rows_kept} row${data.rows_kept === 1 ? "" : "s"} in scope`} tone="var(--ok)" />
            <Chip label={`${data.rows_scanned} scanned`} title="Rows read from the published feed" />
            {data.rows_dropped > 0 && (
              <Chip label={`${data.rows_dropped} malformed`} tone="var(--warn)"
                title="Rows dropped because the prefix or the ISO-3166 country was not valid — dropped, never repaired." />
            )}
            {countries.slice(0, 6).map((c) => <Chip key={c.country} label={`${c.country} ${c.rows}`} />)}
          </div>
          {data.truncated && (
            <p className="mini-meta" style={{ color: "var(--warn)" }}>
              The published list is larger than this view shows — rows are capped.
            </p>
          )}
          <div className="bgp-scroll">
            <table className="dm-table bgp-tbl" style={{ width: "100%" }}>
              <thead>
                <tr><th>Prefix</th><th>Country</th><th>Region</th><th>City</th><th>Postal</th></tr>
              </thead>
              <tbody>
                {cap.rows.map((e) => (
                  <tr key={e.prefix + (e.city ?? "")}>
                    <td className="mono">{e.prefix}</td>
                    <td>{e.country || "—"}</td>
                    <td>{e.region || "—"}</td>
                    <td>{e.city || "—"}</td>
                    <td>{e.postal || "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <ShowAll cap={cap} noun="rows" />
          <Details summary="Where this came from">
            {data.source_url && (
              <p className="mini-meta">
                Published by the holder at{" "}
                <a href={data.source_url} target="_blank" rel="noreferrer" className="mono">{data.source_url}</a>
              </p>
            )}
            <p className="mini-meta" style={{ marginBottom: 0 }}>
              Only rows about address space inside {data.resource} are kept, so a published list cannot make claims
              about somebody else&apos;s prefixes through this view. Malformed rows are dropped, never repaired.
              {data.note ? ` ${data.note}` : ""}
            </p>
          </Details>
        </>
      )}
    </Section>
  );
}

export default GeofeedPanel;

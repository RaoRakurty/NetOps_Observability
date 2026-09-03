// BogonsPanel — the Bogons tab (BGP ops tracker #1).
//
// A bogon is address space that must never appear in the global routing table.
// The panel shows TWO things and keeps them apart, because they age completely
// differently:
//
//   * the SET IN FORCE — the embedded IANA/RFC special-purpose blocks, with the
//     source and the transcription date stated, plus the OPTIONAL Team Cymru
//     full-bogons feed when the operator enabled it. An operator has to be able
//     to see how old the offline half of the answer is.
//   * the SIGHTINGS — bogon prefixes actually observed on this tenant's own BMP
//     feed and update ring, with the peer and first/last seen.
//
// Empty is never silently "clean": with the evaluator off, or the feed off, the
// panel says which half is not running.

import { useEffect, useState } from "react";
import { api, type BgpBogonsResp } from "../../services/api";
import { Chip } from "../../components/noc";
import { groupSightings } from "./bgpAlerts.model";

export function BogonsPanel() {
  const [data, setData] = useState<BgpBogonsResp | null>(null);
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(true);

  useEffect(() => {
    let alive = true;
    setBusy(true); setErr("");
    api.bgpBogons()
      .then((d) => { if (alive) setData(d); })
      .catch((e: Error) => { if (alive) setErr(e.message || "The bogon listing could not be read."); })
      .finally(() => { if (alive) setBusy(false); });
    return () => { alive = false; };
  }, []);

  const groups = data ? groupSightings(data.sightings) : [];

  return (
    <>
      <div className="card" style={{ marginTop: 12 }}>
        <h2>Bogon set in force</h2>
        {busy && <div className="empty">Reading the bogon set…</div>}
        {err && <p className="mini-meta" role="alert" style={{ color: "var(--bad)" }}>{err}</p>}
        {data && (
          <>
            <div style={{ display: "flex", gap: 8, flexWrap: "wrap", marginBottom: 8 }}>
              <Chip label={`${data.set.blocks} embedded blocks`} title={data.set.source} />
              <Chip label={`as of ${data.set.date}`} title="The transcription date of the embedded IANA/RFC tables." />
              {data.feed.enabled ? (
                <Chip
                  label={`full-bogons: ${data.feed.entries}`}
                  tone={data.feed.error ? "var(--warn)" : "var(--ok)"}
                  title={data.feed.error || data.feed.url || "Team Cymru full-bogons feed"}
                />
              ) : (
                <Chip label="full-bogons: off" tone="var(--muted)" title={data.feed.note} />
              )}
            </div>
            <p className="mini-meta">{data.set.note}</p>
            {!data.feed.enabled && data.feed.note && (
              <p className="mini-meta" style={{ color: "var(--muted)" }}>{data.feed.note}</p>
            )}
            {data.feed.enabled && data.feed.error && (
              <p className="mini-meta" style={{ color: "var(--warn)" }}>
                The full-bogons feed did not refresh: {data.feed.error}. The embedded set is still in force — nothing
                has been un-flagged.
              </p>
            )}
            {data.feed.enabled && data.feed.fetched_at && !data.feed.error && (
              <p className="mini-meta">Feed last fetched {new Date(data.feed.fetched_at).toLocaleString()}.</p>
            )}
          </>
        )}
      </div>

      <div className="card" style={{ marginTop: 12 }}>
        <h2>Bogons seen</h2>
        {data && data.note && <p className="mini-meta" style={{ color: "var(--warn)" }}>{data.note}</p>}
        {data && groups.length === 0 && (
          <div className="empty">
            {data.note
              ? "No sighting register is running, so nothing has been screened."
              : "No bogon prefix has been seen on this tenant's BMP feed or update ring. That is the healthy answer — and it is a measured one."}
          </div>
        )}
        {groups.map((g) => (
          <div key={g.block} style={{ marginBottom: 12 }}>
            <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
              <span className="mono" style={{ fontWeight: 600 }}>{g.block}</span>
              <Chip label={`${g.rows.length} prefix${g.rows.length === 1 ? "" : "es"}`} tone="var(--crit)" />
              <span className="mini-meta">{g.why}</span>
            </div>
            <div style={{ overflowX: "auto" }}>
              <table className="tbl" style={{ width: "100%" }}>
                <thead>
                  <tr><th>Prefix</th><th>Source</th><th>Peer</th><th>Origin</th><th>First seen</th><th>Last seen</th><th>Times</th></tr>
                </thead>
                <tbody>
                  {g.rows.map((r) => (
                    <tr key={`${r.prefix}|${r.source}|${r.peer ?? ""}`}>
                      <td className="mono">{r.prefix}</td>
                      <td className="mini-meta">{r.source}</td>
                      <td className="mono">{r.peer || "—"}</td>
                      <td className="mono">{r.origin ? `AS${r.origin}` : "—"}</td>
                      <td className="mini-meta">{new Date(r.first_seen).toLocaleString()}</td>
                      <td className="mini-meta">{new Date(r.last_seen).toLocaleString()}</td>
                      <td className="mono">{r.count}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        ))}
        <p className="mini-meta" style={{ marginBottom: 0 }}>
          Sightings come from this tenant's OWN feeds only. A bogon here is either a leak into your network or a
          misconfigured neighbour — it is never normal.
        </p>
      </div>
    </>
  );
}

export default BogonsPanel;

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// BogonsPanel — "Addresses that should never be routed" (BGP ops tracker #1).
//
// The heading is the NOC admin's sentence; the word "bogon" survives in the
// section's secondary line and in the row tooltips (owner, 2026-09-06).
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
import { Details, Section, ShowAll, SubBlock, useCap } from "./Section";
import AskIris from "../../components/AskIris";

/** Rows shown before the operator asks for the rest (one-page view, 2026-09-03). */
const FIRST_SIGHTINGS = 8;

/** One matched reserved block and the prefixes seen inside it. Its own component
 *  so each group owns its own row cap (a hook cannot live inside a map). */
function BogonGroup({ g }: { g: ReturnType<typeof groupSightings>[number] }) {
  const cap = useCap(g.rows, FIRST_SIGHTINGS);
  return (
    <div style={{ marginBottom: 10 }}>
      <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
        <span className="mono" style={{ fontWeight: 600 }}>{g.block}</span>
        <Chip label={`${g.rows.length} prefix${g.rows.length === 1 ? "" : "es"}`} tone="var(--crit)" />
        <span className="fact-line">{g.why}</span>
      </div>
      <div className="bgp-scroll">
        <table className="tbl bgp-tbl" style={{ width: "100%" }}>
          <thead>
            <tr><th>Prefix</th><th>Seen by</th><th>Neighbour</th><th>Announced by</th><th>First seen</th><th>Last seen</th><th className="num">Times</th></tr>
          </thead>
          <tbody>
            {cap.rows.map((r) => (
              <tr key={`${r.prefix}|${r.source}|${r.peer ?? ""}`}>
                <td className="mono">{r.prefix}</td>
                <td className="fact-line">{r.source}</td>
                <td className="mono">{r.peer || "—"}</td>
                <td className="mono">{r.origin ? `AS${r.origin}` : "—"}</td>
                <td className="fact-line">{new Date(r.first_seen).toLocaleString()}</td>
                <td className="fact-line">{new Date(r.last_seen).toLocaleString()}</td>
                <td className="mono num">{r.count}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <ShowAll cap={cap} noun="sightings" />
    </div>
  );
}

export function BogonsPanel() {
  const [data, setData] = useState<BgpBogonsResp | null>(null);
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(true);
  const [at, setAt] = useState<number | null>(null);

  useEffect(() => {
    let alive = true;
    setBusy(true); setErr("");
    api.bgpBogons()
      .then((d) => { if (alive) { setData(d); setAt(Date.now()); } })
      .catch((e: Error) => { if (alive) setErr(e.message || "The bogon listing could not be read."); })
      .finally(() => { if (alive) setBusy(false); });
    return () => { alive = false; };
  }, []);

  const groups = data ? groupSightings(data.sightings) : [];

  return (
    <Section
      id="bogons"
      title="Addresses that should never be routed"
      sub="Bogons — reserved space seen on your network"
      updatedAt={at}
    >
      <SubBlock title="Blocklist in use">
        {busy && <div className="empty">Reading the blocklist…</div>}
        {err && <p className="fact-line fact-bad" role="alert">{err}</p>}
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
            {data.feed.enabled && data.feed.error && (
              <p className="fact-line fact-warn">
                The full-bogons feed did not refresh: {data.feed.error}. The embedded set is still in force — nothing
                has been un-flagged.
              </p>
            )}
            <Details summary="What is on this list">
              <p className="fact-line">{data.set.note}</p>
              {!data.feed.enabled && data.feed.note && (
                <p className="fact-line">{data.feed.note}</p>
              )}
              {data.feed.enabled && data.feed.fetched_at && !data.feed.error && (
                <p className="fact-line" style={{ marginBottom: 0 }}>
                  Feed last fetched {new Date(data.feed.fetched_at).toLocaleString()}.
                </p>
              )}
            </Details>
          </>
        )}
      </SubBlock>

      <SubBlock title="Seen on your network">
        {data && data.note && <p className="fact-line fact-warn">{data.note}</p>}
        {data && groups.length === 0 && (
          <div className="empty">
            {data.note
              ? "Nothing is watching for these addresses, so nothing has been screened."
              : "None of this address space has been seen on your own routers or in the update feed. That is the healthy answer — and it is a measured one."}
          </div>
        )}
        {groups.map((g) => <BogonGroup key={g.block} g={g} />)}
        <p className="mini-meta" style={{ marginBottom: 0 }}>
          A leak or a misconfigured neighbour, never normal.
          <AskIris topic="bgp.bogon-sighting" label="Seen on your network" />
        </p>
      </SubBlock>
    </Section>
  );
}

export default BogonsPanel;

// AspaCard — ASPA (AS Provider Authorization).
//
// THE HONEST CARD. There is no public per-ASN ASPA API: RIPEstat has no ASPA
// data call, and rpki-client's console publishes ASPA objects only inside a
// ~104 MB global dump with no query interface (both verified 2026-09-02). So
// with nothing configured this card SAYS there is no source and tells the
// operator how to point it at their own validator. It never renders a verdict
// it does not have — an operator trusting a fabricated "ASPA valid" would be a
// materially worse outcome than an empty panel.

import { useEffect, useState } from "react";
import { api, type BgpAspaResp } from "../../services/api";
import { Chip } from "../../components/noc";
import { Section } from "./Section";
import AskIris from "../../components/AskIris";

export function AspaCard({ asn }: { asn?: string }) {
  const [data, setData] = useState<BgpAspaResp | null>(null);
  const [err, setErr] = useState("");
  const [at, setAt] = useState<number | null>(null);

  useEffect(() => {
    if (!asn) { setData(null); setErr(""); return; }
    let alive = true;
    setErr(""); setData(null);
    api.bgpAspa(asn)
      .then((d) => { if (alive) { setData(d); setAt(Date.now()); } })
      .catch((e: Error) => { if (alive) setErr(e.message || "ASPA lookup failed"); })
      .finally(() => { /* no busy state: this card is never the slow one */ });
    return () => { alive = false; };
  }, [asn]);

  return (
    <Section
      id="aspa"
      title="Approved upstream providers"
      sub="ASPA — carriers the AS holder authorised"
      updatedAt={at}
    >
      {!asn && <div className="empty">Pick an AS or prefix to see its approved carriers.</div>}
      {err && <p className="fact-line fact-bad" role="alert">{err}</p>}

      {data && !data.status.configured && (
        <div className="empty bgp-honest">
          <Chip label="No source configured" tone="var(--muted)" title="ASPA — no data source is configured for it." />
          <p style={{ margin: "6px 0 0" }}>{data.status.reason}</p>
          {data.status.how_to && <p className="fact-line" style={{ margin: 0 }}>{data.status.how_to}</p>}
        </div>
      )}

      {data?.status.configured && data.error && (
        <p className="fact-line fact-warn">
          {data.status.host ? `${data.status.host}: ` : ""}{data.error}
        </p>
      )}

      {data?.aspa && (
        <>
          <div style={{ display: "flex", gap: 8, flexWrap: "wrap", marginBottom: 8 }}>
            <Chip label={`AS${data.aspa.customer_asn}`} title="The AS whose holder published this list." />
            <Chip
              label={`${data.aspa.providers.length} approved provider${data.aspa.providers.length === 1 ? "" : "s"}`}
              tone={data.aspa.providers.length ? "var(--ok)" : "var(--muted)"}
            />
            {data.status.host && <Chip label={data.status.host} title="The configured ASPA source." />}
          </div>
          {data.aspa.providers.length === 0 ? (
            <div className="empty">The source holds no record naming approved providers for this AS.</div>
          ) : (
            <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
              {data.aspa.providers.map((p) => (
                <span key={`${p.asn}-${p.afi ?? ""}`} className="mono" style={{
                  padding: "2px 8px", borderRadius: 999, border: "1px solid var(--border)", fontSize: 13,
                }} title={p.afi ? `address family: ${p.afi}` : undefined}>
                  AS{p.asn}{p.afi && p.afi !== "any" ? ` · ${p.afi}` : ""}
                </span>
              ))}
            </div>
          )}
          {data.aspa.truncated && <p className="fact-line fact-warn">The provider list is cut short.</p>}
          <p className="fact-line">Source: {data.aspa.source}</p>
          <p className="mini-meta">
            Read it, do not alert on it.
            <AskIris topic="aspa.draft-status" label="Approved upstream providers" />
          </p>
        </>
      )}
    </Section>
  );
}

export default AspaCard;

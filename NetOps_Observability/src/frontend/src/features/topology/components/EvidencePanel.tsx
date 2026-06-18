// EvidencePanel — lists the evidence behind a node or edge. Enforces the
// "every link explainable / missing evidence explicit" rule (PDF §3, rule 6):
// every row shows its source, summary, confidence and observation time, and we
// surface ignored / missing evidence rather than hiding it.

import type { EvidenceRef } from "../api/topologyTypes";
import { SOURCE_LABEL, confidencePct } from "../utils/topologyHealth";

function formatWhen(iso: string): string {
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return iso;
  return new Date(t).toLocaleString(undefined, {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

export default function EvidencePanel({
  evidence,
  title,
}: {
  evidence: EvidenceRef[];
  title?: string;
}) {
  return (
    <section style={{ marginTop: 14 }}>
      <div
        style={{
          fontSize: 11,
          fontWeight: 600,
          letterSpacing: 0.4,
          textTransform: "uppercase",
          color: "var(--fg-subtle)",
          marginBottom: 8,
        }}
      >
        {title ?? "Evidence"}
      </div>

      {evidence.length === 0 ? (
        <div
          style={{
            fontSize: 12,
            color: "var(--fg-muted)",
            padding: "10px 12px",
            border: "1px dashed var(--border)",
            borderRadius: 6,
            background: "var(--surface)",
          }}
        >
          No evidence recorded for this object.
        </div>
      ) : (
        <ul style={{ listStyle: "none", margin: 0, padding: 0, display: "grid", gap: 8 }}>
          {evidence.map((ev, i) => (
            <li
              key={`${ev.raw_ref}-${i}`}
              style={{
                border: "1px solid var(--border)",
                borderRadius: 6,
                background: "var(--surface)",
                padding: "8px 10px",
              }}
            >
              <div style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 4 }}>
                <span
                  style={{
                    fontSize: 10,
                    fontWeight: 700,
                    letterSpacing: 0.3,
                    color: "var(--fg)",
                    background: "var(--panel)",
                    border: "1px solid var(--border)",
                    borderRadius: 4,
                    padding: "1px 6px",
                    fontFamily: "var(--font-mono, ui-monospace, monospace)",
                  }}
                >
                  {SOURCE_LABEL[ev.source] ?? ev.source}
                </span>
                {ev.used_by_rca ? (
                  <span
                    style={{
                      fontSize: 9,
                      fontWeight: 700,
                      letterSpacing: 0.4,
                      color: "var(--accent)",
                      border: "1px solid var(--accent)",
                      borderRadius: 4,
                      padding: "1px 5px",
                    }}
                  >
                    USED BY RCA
                  </span>
                ) : null}
                <span
                  style={{
                    marginLeft: "auto",
                    fontSize: 11,
                    fontFamily: "var(--font-mono, ui-monospace, monospace)",
                    color: "var(--fg-muted)",
                  }}
                >
                  {confidencePct(ev.confidence)}
                </span>
              </div>

              <div style={{ fontSize: 12, color: "var(--fg)", lineHeight: 1.4 }}>{ev.summary}</div>

              <div style={{ fontSize: 11, color: "var(--fg-subtle)", marginTop: 4 }}>
                {formatWhen(ev.observed_at)}
              </div>

              {ev.ignored_reason ? (
                <div
                  style={{
                    fontSize: 11,
                    color: "var(--warn)",
                    marginTop: 5,
                    textDecoration: "line-through",
                    textDecorationColor: "var(--warn)",
                  }}
                >
                  ignored: {ev.ignored_reason}
                </div>
              ) : null}

              {ev.missing_evidence_if_any ? (
                <div style={{ fontSize: 11, color: "var(--bad)", marginTop: 4 }}>
                  missing: {ev.missing_evidence_if_any}
                </div>
              ) : null}
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}

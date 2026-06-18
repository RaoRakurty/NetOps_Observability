// ConfidencePanel — a calm, honest read on how sure we are about the selected
// object. Band + bar colored by tone, percent, and a one-line explanation
// derived from the supporting evidence (no overclaiming — PDF §8).

import type { EvidenceRef } from "../api/topologyTypes";
import { HEALTH_COLOR, confidenceBand, confidencePct } from "../utils/topologyHealth";

function explain(confidence: number, evidence?: EvidenceRef[]): string {
  const ev = evidence ?? [];
  const used = ev.filter((e) => e.used_by_rca).length;
  const independent = new Set(ev.map((e) => e.source)).size;
  const hasMissing = ev.some((e) => e.missing_evidence_if_any);

  if (independent >= 2) {
    return `Confirmed by ${independent} independent sources${used ? ` (${used} used by RCA)` : ""}.`;
  }
  if (independent === 1) {
    return hasMissing
      ? "Single one-way observation — reverse evidence missing."
      : "Single-source observation — not yet corroborated.";
  }
  if (confidence >= 0.85) return "High confidence, but no evidence records attached.";
  return "Inferred — no direct evidence attached.";
}

export default function ConfidencePanel({
  confidence,
  evidence,
}: {
  confidence: number;
  evidence?: EvidenceRef[];
}) {
  const band = confidenceBand(confidence);
  const color = HEALTH_COLOR[band.tone];
  const pct = Math.round(Math.max(0, Math.min(1, confidence)) * 100);

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
        Confidence
      </div>

      <div style={{ display: "flex", alignItems: "baseline", gap: 8, marginBottom: 6 }}>
        <span style={{ fontSize: 13, fontWeight: 600, color }}>{band.label}</span>
        <span
          style={{
            marginLeft: "auto",
            fontSize: 12,
            fontFamily: "var(--font-mono, ui-monospace, monospace)",
            color: "var(--fg-muted)",
          }}
        >
          {confidencePct(confidence)}
        </span>
      </div>

      <div
        style={{
          height: 6,
          borderRadius: 3,
          background: "var(--surface)",
          border: "1px solid var(--border)",
          overflow: "hidden",
        }}
      >
        <div
          style={{
            width: `${pct}%`,
            height: "100%",
            background: color,
            borderRadius: 3,
            transition: "width 160ms ease",
          }}
        />
      </div>

      <div style={{ fontSize: 11, color: "var(--fg-muted)", marginTop: 7, lineHeight: 1.4 }}>
        {explain(confidence, evidence)}
      </div>
    </section>
  );
}

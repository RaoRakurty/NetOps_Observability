// ConfidencePanel — a calm, honest read on how sure we are about the selected
// object. Band + bar colored by tone, percent, and a short line derived from the
// supporting evidence (no overclaiming — PDF §8).
//
// UI-words sweep 4 (tracker 270): the line STATES what the evidence is, in as
// few words as the claim survives ("One observation, not corroborated"); what
// corroboration MEANS left the panel for ai/skills/explain/topo.confidence.md,
// behind the `(i)` beside the band.

import type { EvidenceRef } from "../api/topologyTypes";
import { HEALTH_COLOR, confidenceBand, confidencePct } from "../utils/topologyHealth";
import AskIris from "../../../components/AskIris";

function explain(confidence: number, evidence?: EvidenceRef[]): string {
  const ev = evidence ?? [];
  const used = ev.filter((e) => e.used_by_rca).length;
  const independent = new Set(ev.map((e) => e.source)).size;
  const hasMissing = ev.some((e) => e.missing_evidence_if_any);

  if (independent >= 2) {
    return `${independent} independent sources agree${used ? ` · ${used} used by RCA` : ""}`;
  }
  if (independent === 1) {
    return hasMissing ? "One-way observation, no reverse evidence" : "One observation, not corroborated";
  }
  if (confidence >= 0.85) return "No evidence records attached";
  return "Inferred, no direct evidence";
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
          display: "flex",
          alignItems: "center",
          gap: 4,
          fontSize: 12.5,
          fontWeight: 600,
          color: "var(--fg-subtle)",
          marginBottom: 8,
        }}
      >
        Confidence
        <AskIris topic="topo.confidence" label="Confidence" />
      </div>

      <div style={{ display: "flex", alignItems: "baseline", gap: 8, marginBottom: 6 }}>
        <span style={{ fontSize: 13, fontWeight: 600, color }}>{band.label}</span>
        <span
          style={{
            marginLeft: "auto",
            fontSize: 12.5,
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

      <div style={{ fontSize: 12.5, color: "var(--fg-muted)", marginTop: 7, lineHeight: 1.4 }}>
        {explain(confidence, evidence)}
      </div>
    </section>
  );
}

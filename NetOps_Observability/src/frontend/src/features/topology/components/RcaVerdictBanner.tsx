// RcaVerdictBanner — the anti-black-box narrative for a pinned incident (#77).
//
// When Investigate mode pins a real correlation object, the canvas renders its
// RCA fault path (rcaPathToView). The path shows WHERE; this banner shows WHY:
// the server-computed verdict, confidence, title, summary and recommended action,
// plus an HONEST "what's missing to confirm" list. All wording is authored
// server-side (rca_path_view.go `narrate`) — this component only renders it, so
// the UI never overclaims beyond the engine's grounded verdict.

import type { RcaPathView } from "../../../services/api";

/** Verdict → severity colour token + display label. */
function verdictTone(verdict: string): { color: string; label: string } {
  switch ((verdict || "").toLowerCase()) {
    case "confirmed":
      return { color: "var(--crit, #e5484d)", label: "Confirmed" };
    case "suspected":
    case "likely":
      return { color: "var(--warn, #f5a524)", label: "Suspected" };
    case "undetermined":
    case "inconclusive":
      return { color: "var(--fg-muted)", label: "Undetermined" };
    default:
      return { color: "var(--fg-muted)", label: verdict || "—" };
  }
}

const OWNER_LABEL: Record<string, string> = {
  network_ops: "Network Ops",
  wan_provider: "WAN provider",
  platform: "Platform",
};

export default function RcaVerdictBanner({
  overlay,
  onClear,
}: {
  overlay: RcaPathView;
  onClear: () => void;
}) {
  const tone = verdictTone(overlay.verdict);
  const pct = Math.round((overlay.confidence || 0) * 100);
  // Owner is carried per-annotation; take the first non-empty as the headline owner.
  const owner = overlay.annotations?.find((a) => a.owner)?.owner;
  const missing = overlay.missing_evidence_summary ?? [];

  return (
    <section className="topo-rca-banner" aria-label="Incident verdict">
      <header className="topo-rca-banner-head">
        <span className="topo-rca-verdict" style={{ color: tone.color, borderColor: tone.color }}>
          {tone.label}
        </span>
        <span className="topo-rca-conf" title="Engine confidence in this verdict">
          {pct}% confidence
        </span>
        {overlay.internal && (
          <span className="topo-rca-tag" title="Locus is inside the platform's own stack">
            Internal
          </span>
        )}
        {owner && <span className="topo-rca-owner">{OWNER_LABEL[owner] ?? owner}</span>}
        <button className="topo-rca-clear" onClick={onClear} title="Unpin incident — back to the live projection" aria-label="Unpin incident">
          ✕
        </button>
      </header>

      {overlay.title && <div className="topo-rca-title">{overlay.title}</div>}
      {overlay.summary && <p className="topo-rca-summary">{overlay.summary}</p>}

      {overlay.recommended_action && (
        <div className="topo-rca-action">
          <span className="topo-rca-action-label">Next</span>
          {overlay.recommended_action}
        </div>
      )}

      <div className="topo-rca-missing">
        {missing.length > 0 ? (
          <>
            <span className="topo-rca-missing-label">Missing to confirm</span>
            {missing.map((m, i) => (
              <span key={i} className="topo-rca-missing-chip">
                {m}
              </span>
            ))}
          </>
        ) : (
          <span className="topo-rca-grounded">Fully grounded — no evidence gaps</span>
        )}
      </div>
    </section>
  );
}

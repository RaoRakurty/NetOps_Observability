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

/** Modality class → operator-facing label (no backend vocabulary leaks). */
const MODALITY_LABEL: Record<string, string> = {
  active_probe: "Active probe",
  control_plane: "Control plane",
  device_telemetry: "Device telemetry",
  passive_flow: "Flow",
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

  // The evidence ledger — the WHY behind the verdict, shown not asserted. The engine
  // exports the independent confirming pair it actually used, the decisive (trusted)
  // modalities, the blast radius, and a one-line reason. This is the anti-black-box
  // differentiator: a confirmation is two independent witnesses, named on the canvas.
  const ev = (overlay.evidence_summary ?? {}) as Record<string, unknown>;
  const pair = Array.isArray(ev.confirming_pair) && ev.confirming_pair.length === 2 ? (ev.confirming_pair as string[]) : null;
  const modalities = Array.isArray(ev.decisive_modalities) ? (ev.decisive_modalities as string[]) : [];
  const reason = typeof ev.verdict_reason === "string" ? (ev.verdict_reason as string) : "";
  const blast = ev.blast_radius && typeof ev.blast_radius === "object" ? (ev.blast_radius as Record<string, number>) : null;
  const blastParts = blast
    ? (["devices", "paths", "interfaces"] as const)
        .filter((k) => (blast[k] ?? 0) > 0)
        .map((k) => `${blast[k]} ${blast[k] === 1 ? k.replace(/s$/, "") : k}`)
    : [];
  // Guided remediation runbook (engine first-steps) — read-only, operator-driven.
  const runbook = Array.isArray(ev.runbook) ? (ev.runbook as string[]) : [];

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

      {(pair || blastParts.length > 0) && (
        <div className="topo-rca-evidence">
          {pair && (
            <div className="topo-rca-evrow">
              <span className="topo-rca-evlabel">Confirmed by</span>
              <span className="topo-rca-pair">
                <span className="topo-rca-witness">{pair[0]}</span>
                <span className="topo-rca-perp" aria-label="independent of" title="independent of — different observer, modality and failure fate">⟂</span>
                <span className="topo-rca-witness">{pair[1]}</span>
              </span>
              {modalities.length > 0 && (
                <span className="topo-rca-mods">
                  {modalities.map((m) => (
                    <span key={m} className="topo-rca-mod">{MODALITY_LABEL[m] ?? m}</span>
                  ))}
                </span>
              )}
            </div>
          )}
          {blastParts.length > 0 && (
            <div className="topo-rca-evrow">
              <span className="topo-rca-evlabel">Blast radius</span>
              <span className="topo-rca-blast">{blastParts.join(" · ")}</span>
            </div>
          )}
          {reason && <div className="topo-rca-reason" title="Why the engine reached this verdict">{reason}</div>}
        </div>
      )}

      {overlay.recommended_action && (
        <div className="topo-rca-action">
          <span className="topo-rca-action-label">Next</span>
          {overlay.recommended_action}
        </div>
      )}

      {runbook.length > 0 && (
        <details className="topo-rca-runbook">
          <summary>Runbook · {runbook.length} steps</summary>
          <ol className="topo-rca-runbook-list">
            {runbook.map((step, i) => (
              <li key={i}>{step}</li>
            ))}
          </ol>
        </details>
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

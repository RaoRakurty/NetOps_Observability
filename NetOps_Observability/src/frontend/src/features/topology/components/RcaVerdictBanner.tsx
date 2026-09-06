// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// RcaVerdictBanner — the anti-black-box narrative for a pinned incident (#77).
//
// When Investigate mode pins a real correlation object, the canvas renders its
// RCA fault path (rcaPathToView). The path shows WHERE; this banner shows WHY:
// the server-computed verdict, confidence, title, summary and recommended action,
// plus an HONEST "what's missing to confirm" list. All wording is authored
// server-side (rca_path_view.go `narrate`) — this component only renders it, so
// the UI never overclaims beyond the engine's grounded verdict.

import type { RcaPathView, RcaLayerCoverage } from "../../../services/api";

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

/** Causal layer → operator-facing name (no schema vocabulary). */
const LAYER_LABEL: Record<string, string> = {
  device: "Device / hardware",
  physical: "Physical (optics)",
  link: "Link / interface",
  network: "Routing",
  transport: "Reachability / latency",
  service: "Service (DNS/TLS)",
  application: "Application",
};

/** Peak severity → colour token for the observed-layer dot. */
function sevColor(sev: string): string {
  switch (sev) {
    case "crit": return "var(--crit, #e5484d)";
    case "high": return "var(--warn, #f5a524)";
    case "warn": return "var(--accent)";
    default: return "var(--fg-muted)";
  }
}

/** OSI badge text: L1..L7, or "HW" for the device layer (no OSI layer). */
function osiBadge(osi: string): string {
  return osi === "device" ? "HW" : osi || "—";
}

// RcaLayerStack — the C4 differentiator: an evidence-grounded CROSS-LAYER causal
// stack (root → impact across L1–L7), rendered top-down (L7 application at top,
// hardware at the bottom). Observed layers carry their peak severity; UNOBSERVED
// layers BETWEEN root and impact are flagged as blind spots — the honest "what we
// can't see" no leader surfaces. Pure render of the engine's projection.
function RcaLayerStack({ cov }: { cov: RcaLayerCoverage }) {
  const ladder = cov.layers; // engine order = bottom-up (device→application)
  const idx = (name: string) => ladder.findIndex((l) => l.layer === name);
  const rootIdx = idx(cov.root_layer);
  const impactIdx = idx(cov.impact_layer);
  // top-down for display (application first), so the stack reads like an OSI model.
  const rows = [...ladder].reverse();
  return (
    <div className="topo-rca-layers" aria-label="Causal layer stack">
      <div className="topo-rca-layers-head">
        <span className="topo-rca-evlabel">Layer stack</span>
        {cov.root_layer && cov.impact_layer && (
          <span className="topo-rca-layers-span">
            root <b>{LAYER_LABEL[cov.root_layer] ?? cov.root_layer}</b>
            {cov.impact_layer !== cov.root_layer && (
              <> → impact <b>{LAYER_LABEL[cov.impact_layer] ?? cov.impact_layer}</b></>
            )}
          </span>
        )}
      </div>
      <ul className="topo-rca-layers-list">
        {rows.map((l) => {
          const li = idx(l.layer);
          const blindSpot = !l.observed && rootIdx >= 0 && li > rootIdx && li < impactIdx;
          const isRoot = l.layer === cov.root_layer;
          const isImpact = l.layer === cov.impact_layer;
          return (
            <li
              key={l.layer}
              className={`topo-rca-layer${l.observed ? " is-observed" : ""}${blindSpot ? " is-blind" : ""}`}
              title={l.observed ? l.entities.join(" · ") : blindSpot ? "No evidence at this layer between root and impact" : "Not in this incident"}
            >
              <span className="topo-rca-layer-osi">{osiBadge(l.osi)}</span>
              <span className="topo-rca-layer-dot" style={{ color: l.observed ? sevColor(l.peak_severity) : "var(--border)" }}>
                {l.observed ? "●" : "○"}
              </span>
              <span className="topo-rca-layer-name">{LAYER_LABEL[l.layer] ?? l.layer}</span>
              {l.observed && l.entities.length > 0 && (
                <span className="topo-rca-layer-count">{l.entities.length}</span>
              )}
              {isRoot && <span className="topo-rca-layer-pill is-root">Root</span>}
              {isImpact && !isRoot && <span className="topo-rca-layer-pill is-impact">Impact</span>}
              {blindSpot && <span className="topo-rca-layer-blind">blind spot</span>}
            </li>
          );
        })}
      </ul>
      {cov.unmapped_kinds.length > 0 && (
        <div className="topo-rca-layers-unmapped" title="Evidence types not yet mapped to a causal layer — surfaced, never silently dropped">
          {cov.unmapped_kinds.length} signal{cov.unmapped_kinds.length === 1 ? "" : "s"} not layer-mapped
        </div>
      )}
    </div>
  );
}

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
  // "Explain why not": when the verdict is short of confirmed, the gate reasons say
  // exactly what's blocking it — Correlix refuses to guess, and shows why.
  const whyNot = Array.isArray(ev.why_not_confirmed) ? (ev.why_not_confirmed as string[]) : [];
  // Discriminating/contradicting evidence the engine used to rule out competing causes.
  const contradicting = Array.isArray(ev.contradicting) ? (ev.contradicting as string[]) : [];

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

      {overlay.layer_coverage && overlay.layer_coverage.root_layer && (
        <RcaLayerStack cov={overlay.layer_coverage} />
      )}

      {overlay.recommended_action && (
        <div className="topo-rca-action">
          <span className="topo-rca-action-label">Next</span>
          {overlay.recommended_action}
        </div>
      )}

      {whyNot.length > 0 && (
        <div className="topo-rca-whynot">
          <span className="topo-rca-whynot-label">Why not confirmed</span>
          <ul className="topo-rca-whynot-list">
            {whyNot.map((w, i) => (
              <li key={i}>{w}</li>
            ))}
          </ul>
        </div>
      )}

      {contradicting.length > 0 && (
        <div className="topo-rca-missing">
          <span className="topo-rca-missing-label" style={{ color: "var(--accent)" }}>Ruled out</span>
          {contradicting.map((c, i) => (
            <span key={i} className="topo-rca-missing-chip">{c}</span>
          ))}
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

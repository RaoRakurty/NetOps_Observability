import { useMemo, useState } from "react";
import { CorrTimeline, Seam } from "../../services/api";
import {
  MODALITY_META, MODALITY_ORDER, modalityLabel,
  signatureName, kindMeta, kindLabel,
} from "./labels";
import { episodeEntity } from "./SeamGraph";

// RcaSummary — the operator-facing RCA story (not an engine dump). Leads with a
// plain-English sentence ("this appears to be a weak ISP/DIA-seam probe
// degradation candidate…"), then a clean header, a mini seam preview, per-plane
// diagnostic coverage, and a human-readable "what would upgrade this" checklist.
// The engine wording lives under an expandable "Why?" / Debug view. Read-only.

type Quality = "strong" | "candidate" | "weak/noisy";
const QUALITY_CLASS: Record<Quality, string> = {
  strong: "sev-critical", candidate: "sev-warning", "weak/noisy": "",
};

// Coverage-card semantics (operator legend).
const COV = {
  linked: { color: "#3fb950", bg: "#3fb95018" },   // green — linked evidence
  present: { color: "#4c8dff", bg: "#4c8dff18" },   // blue — present, not linked
  absent: { color: "#8b949e", bg: "transparent" }, // gray — absent
  required: { color: "#d29922", bg: "#d2992218" },  // orange — missing & required
};

type MissingItem = { signature: string; needs: string[]; note: string };

// evidence_missing lines are either "sig: needs a|b|c" (clause gaps) or
// "sig: <gate reason>" (verdict shortfalls, e.g. "single modality class…").
function parseMissing(raw: string): MissingItem[] {
  let lines: string[] = [];
  try { lines = JSON.parse(raw || "[]"); } catch { lines = []; }
  return lines.map((line) => {
    const i = line.indexOf(": ");
    const signature = i >= 0 ? line.slice(0, i) : line;
    const rest = i >= 0 ? line.slice(i + 2) : "";
    if (rest.startsWith("needs ")) {
      return { signature, needs: rest.slice(6).split("|").map((s) => s.trim()).filter(Boolean), note: "" };
    }
    return { signature, needs: [], note: rest };
  });
}

export default function RcaSummary({
  timeline, seams, view, state, version, nodeCount,
}: {
  timeline: CorrTimeline;
  seams: Record<string, Seam>;
  view: "operator" | "debug";
  state: string;
  version: number;
  nodeCount: number;
}) {
  const c = timeline.counts;
  const [showWhy, setShowWhy] = useState(false);
  const muted: React.CSSProperties = { color: "var(--muted)" };

  const presentKinds = useMemo(() => {
    const s = new Set<string>();
    for (const sig of timeline.signals) if (!sig.kind.endsWith("_clear")) s.add(sig.kind);
    return s;
  }, [timeline.signals]);

  const attachedModalities = useMemo(
    () => Object.entries(c.attached_by_modality ?? {}).filter(([, v]) => v > 0).length,
    [c.attached_by_modality],
  );
  const grounded = timeline.edges.length > 0;
  const signatureMatch = timeline.verdict_tier === "confirmed" || timeline.verdict_tier === "suspected";
  const observers = c.attached_observers ?? 0;
  const probeOnly = useMemo(() => {
    const present = Object.entries(c.by_modality ?? {}).filter(([, v]) => v > 0).map(([k]) => k);
    return present.length > 0 && present.every((k) => k === "active_probe");
  }, [c.by_modality]);

  const quality: Quality =
    signatureMatch && grounded && attachedModalities >= 2 && observers >= 2 ? "strong"
    : !grounded || c.attached <= 1 || attachedModalities <= 1 || probeOnly ? "weak/noisy"
    : "candidate";

  const missing = useMemo(() => parseMissing(timeline.evidence_missing), [timeline.evidence_missing]);

  // seams on the causal path
  const seamRefs = useMemo(() => {
    const refs = new Set<string>();
    for (const e of timeline.edges) if (e.grounding_kind === "seam") refs.add(e.grounding_ref);
    return [...refs];
  }, [timeline.edges]);
  const primarySeam = seamRefs.length ? seams[seamRefs[0]] : undefined;

  // dominant plane = most linked (fallback: most in-window)
  const dominant = useMemo(() => {
    const by = c.attached_by_modality && Object.values(c.attached_by_modality).some((v) => v > 0)
      ? c.attached_by_modality : c.by_modality;
    return Object.entries(by ?? {}).sort((a, b) => b[1] - a[1])[0]?.[0] ?? "active_probe";
  }, [c.attached_by_modality, c.by_modality]);

  // which planes are absent but required by some candidate signature → orange
  const requiredModalities = useMemo(() => {
    const s = new Set<string>();
    for (const mi of missing) for (const k of mi.needs) s.add(kindMeta(k).modality);
    return s;
  }, [missing]);

  // ---- the plain-English RCA sentence ---------------------------------------
  const narrative = useMemo(() => {
    const domLabel = modalityLabel(dominant).toLowerCase();
    const story = timeline.top_hypothesis !== "undetermined"
      ? signatureName(timeline.top_hypothesis)
      : primarySeam
        ? `${primarySeam.control_plane_owner.toUpperCase()}/${primarySeam.seam_type ?? "seam"}-seam ${domLabel} degradation`
        : `${domLabel} degradation`;
    const seamPhrase = primarySeam
      ? `a ${primarySeam.visibility} ${primarySeam.control_plane_owner.toUpperCase()} ${primarySeam.seam_type ?? "seam"} boundary`
      : grounded
        ? `${Object.keys(c.by_grounding ?? {}).join("/")} topology`
        : "no grounded boundary";
    const missingPlanes = MODALITY_ORDER
      .filter((m) => (c.attached_by_modality?.[m] ?? 0) === 0)
      .map((m) => modalityLabel(m).toLowerCase());
    const tail = signatureMatch
      ? "and independent cross-plane evidence corroborates it."
      : missingPlanes.length
        ? `but found no ${missingPlanes.slice(0, 3).join(", ")} evidence required to confirm root cause.`
        : "but the evidence has not yet cleared the confirmation bar.";
    return `This appears to be a ${quality.replace("/noisy", "")} ${story} candidate. `
      + `The engine linked ${c.attached} ${domLabel} signal${c.attached === 1 ? "" : "s"} across ${seamPhrase}, ${tail}`;
  }, [quality, timeline.top_hypothesis, primarySeam, grounded, dominant, c, signatureMatch]);

  const card: React.CSSProperties = {
    border: "1px solid var(--border,#2a2f3a)", borderRadius: 8, padding: "12px 14px",
    background: "var(--panel,#11151c)", display: "flex", flexDirection: "column", gap: 12,
  };
  const title: React.CSSProperties = { fontWeight: 600, fontSize: 12 };

  return (
    <div style={card}>
      {/* clean header — no repeated 'undetermined' */}
      <div style={{ display: "flex", gap: 10, alignItems: "baseline", flexWrap: "wrap" }}>
        <span style={{ fontSize: 15, fontWeight: 700 }}>
          RCA Candidate: <span className={`badge ${QUALITY_CLASS[quality]}`}>{quality === "weak/noisy" ? "Weak" : quality.charAt(0).toUpperCase() + quality.slice(1)}</span>
        </span>
        <span style={{ fontSize: 13 }}>Verdict: <b style={{ textTransform: "capitalize" }}>{timeline.verdict_tier}</b></span>
        <span style={{ ...muted, fontSize: 12 }}>
          Status: {state === "open" ? "Open" : "Closed"} · Version {version} · {nodeCount} node{nodeCount === 1 ? "" : "s"} · {timeline.edges.length} grounded edge{timeline.edges.length === 1 ? "" : "s"}
        </span>
      </div>

      {/* the plain-English story sentence */}
      <div style={{ fontSize: 13.5, lineHeight: 1.5 }}>{narrative}</div>

      {/* mini seam-graph preview — above the fold */}
      {grounded && (
        <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
          {seamRefs.length > 0 ? timeline.edges.filter((e) => e.grounding_kind === "seam").slice(0, 3).map((e, i) => {
            const s = seams[e.grounding_ref];
            return (
              <div key={i} style={{ display: "flex", alignItems: "center", gap: 6, fontSize: 11, flexWrap: "wrap" }}>
                <span style={{ ...mono(), background: "var(--bg,#0d1117)", padding: "1px 6px", borderRadius: 4 }}>{episodeEntity(e.from_node)}</span>
                <span style={muted}>──</span>
                <span style={{
                  background: "#f0a02022", border: "1px solid #f0a02066", borderRadius: 4, padding: "1px 6px",
                  color: "#f0a020", fontWeight: 600,
                }} title={e.grounding_ref}>
                  ◆ {s ? `${s.control_plane_owner.toUpperCase()} · ${s.visibility}` : e.grounding_ref}
                </span>
                <span style={muted}>──</span>
                <span style={{ ...mono(), background: "var(--bg,#0d1117)", padding: "1px 6px", borderRadius: 4 }}>{episodeEntity(e.to_node)}</span>
              </div>
            );
          }) : (
            <div style={{ ...muted, fontSize: 11 }}>{timeline.edges.length} grounded topology edge{timeline.edges.length === 1 ? "" : "s"} (no ownership seam) — see the full graph below.</div>
          )}
        </div>
      )}

      {/* per-plane diagnostic coverage */}
      <div>
        <div style={title}>Evidence coverage by plane</div>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(150px,1fr))", gap: 8, marginTop: 6 }}>
          {MODALITY_ORDER.map((key) => {
            const total = c.by_modality?.[key] ?? 0;
            const att = c.attached_by_modality?.[key] ?? 0;
            const isDom = key === dominant && att > 0;
            const sev = att > 0 ? COV.linked
              : total > 0 ? COV.present
              : requiredModalities.has(key) ? COV.required
              : COV.absent;
            const statusText = att > 0 ? (isDom ? "Dominant evidence" : "Linked evidence")
              : total > 0 ? "Present, not linked"
              : requiredModalities.has(key) ? "Missing — required"
              : "Absent";
            return (
              <div key={key} style={{
                border: `1px solid ${sev.color}66`, background: sev.bg, borderRadius: 6, padding: "6px 8px",
              }}>
                <div style={{ fontSize: 11, display: "flex", alignItems: "center", gap: 6 }}>
                  <span style={{ width: 8, height: 8, borderRadius: 2, background: MODALITY_META[key].color, display: "inline-block" }} />
                  {modalityLabel(key)}
                </div>
                <div style={{ fontSize: 13, marginTop: 2 }}>
                  {total > 0
                    ? <><b style={{ color: sev.color }}>{att}</b> <span style={muted}>linked / {total} in window</span></>
                    : <span style={muted}>0 signals</span>}
                </div>
                <div style={{ fontSize: 10.5, color: sev.color, marginTop: 1 }}>{statusText}</div>
              </div>
            );
          })}
        </div>
      </div>

      {/* what would upgrade — human readable */}
      {missing.length > 0 && (
        <div>
          <div style={title}>What would upgrade this verdict</div>
          {missing.map((mi, i) => (
            <div key={i} style={{ marginTop: 5 }}>
              <div style={{ fontSize: 12 }}>
                Possible signature: <b>{signatureName(mi.signature)}</b>
                <span style={{ ...muted, fontSize: 10, marginLeft: 6, fontFamily: "ui-monospace,monospace" }}>{mi.signature}</span>
              </div>
              {mi.needs.length > 0 ? (
                <div style={{ marginTop: 2 }}>
                  {mi.needs.map((kind) => {
                    const present = presentKinds.has(kind);
                    const meta = kindMeta(kind);
                    return (
                      <div key={kind} style={{ fontSize: 11.5, padding: "1px 0", color: present ? "#d29922" : "var(--fg,#e6edf3)" }}>
                        {present ? "⚠" : "○"} {kindLabel(kind)} <span style={muted}>— {modalityLabel(meta.modality).toLowerCase()}</span>
                        {present && <span style={{ color: "#d29922", fontSize: 10 }}> (present, did not qualify)</span>}
                        <span style={{ ...muted, fontSize: 10, marginLeft: 6, fontFamily: "ui-monospace,monospace" }}>{kind}</span>
                      </div>
                    );
                  })}
                </div>
              ) : (
                <div style={{ fontSize: 11.5, ...muted, paddingLeft: 2 }}>{mi.note}</div>
              )}
            </div>
          ))}
        </div>
      )}

      {/* the engine wording — expandable, or always-on in debug view */}
      {view === "operator" && (
        <button onClick={() => setShowWhy((v) => !v)} style={{
          alignSelf: "flex-start", background: "none", border: "none", color: "var(--accent,#4c8dff)",
          fontSize: 12, cursor: "pointer", padding: 0,
        }}>{showWhy ? "Hide engine detail ▲" : "Why? (engine detail) ▼"}</button>
      )}
      {(view === "debug" || showWhy) && (
        <div style={{ ...muted, fontSize: 11, borderTop: "1px solid var(--border,#2a2f3a)", paddingTop: 8, display: "flex", flexDirection: "column", gap: 4 }}>
          <div>
            {grounded
              ? `Engine grounded ${timeline.edges.length} causal edge${timeline.edges.length === 1 ? "" : "s"} across ${attachedModalities} plane${attachedModalities === 1 ? "" : "s"}; ${c.attached} of ${c.total} window signals linked into the graph.`
              : `Singleton — opened on a single high-severity episode; no grounded cross-evidence.`}
          </div>
          <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
            {Object.entries(c.by_status ?? {}).sort().map(([k, v]) => (
              <span key={k} style={{ border: "1px solid var(--border,#2a2f3a)", borderRadius: 4, padding: "0 6px" }}>
                <b style={{ color: "var(--fg,#e6edf3)" }}>{v}</b> {k}
              </span>
            ))}
            <span>{observers} distinct observer{observers === 1 ? "" : "s"} on linked evidence</span>
            {grounded && <span>grounding: {Object.entries(c.by_grounding ?? {}).map(([k, v]) => `${v} ${k}`).join(" · ")}</span>}
          </div>
          {seamRefs.map((ref) => {
            const s = seams[ref];
            return (
              <div key={ref} style={{ fontFamily: "ui-monospace,monospace" }}>
                ◆ {ref}{s ? ` — owner ${s.control_plane_owner} · visibility ${s.visibility}${s.display_name ? ` · ${s.display_name}` : ""}` : " — seam metadata unavailable (file backend)"}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

function mono(): React.CSSProperties {
  return { fontFamily: "ui-monospace, monospace", fontSize: 11 };
}

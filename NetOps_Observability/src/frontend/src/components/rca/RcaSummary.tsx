import { useMemo } from "react";
import { CorrTimeline, Seam } from "../../services/api";

// RcaSummary — the top RCA card that explains the engine's reasoning, not just
// the data. It answers, in order: how strong is this object, what's the verdict
// and WHY did it stay undetermined, how is evidence covered across planes, what
// grounded the causal links, and exactly what additional evidence would upgrade
// it. Everything is derived from engine-recorded fields — it never re-decides.

const MODALITIES: { key: string; label: string; color: string }[] = [
  { key: "device_telemetry", label: "Device telemetry", color: "#4c8dff" },
  { key: "control_plane", label: "Control plane", color: "#f0a020" },
  { key: "passive_flow", label: "Flows", color: "#1bc5bd" },
  { key: "active_probe", label: "Probes", color: "#3fb950" },
];

// kind → (modality, expected source) so the missing-evidence checklist can say
// where each required signal would come from. Heuristic fallback covers kinds
// not enumerated here.
const KIND_META: Record<string, { modality: string; source: string }> = {
  probe_rtt_anomaly: { modality: "active_probe", source: "STAMP / synthetic probes" },
  probe_latency_departure: { modality: "active_probe", source: "STAMP / synthetic probes" },
  probe_loss: { modality: "active_probe", source: "STAMP / synthetic probes" },
  dns_latency_high: { modality: "active_probe", source: "DNS probes" },
  dns_failure_rate: { modality: "active_probe", source: "DNS probes" },
  bgp_state_anomaly: { modality: "control_plane", source: "gNMI / SNMP BGP-MIB" },
  bgp_adjacency_change: { modality: "control_plane", source: "syslog (%BGP ADJCHANGE)" },
  ospf_adjacency_change: { modality: "control_plane", source: "syslog (%OSPF ADJCHANGE)" },
  link_state_change: { modality: "control_plane", source: "syslog (%LINK/%LINEPROTO)" },
  lldp_neighbor_change: { modality: "control_plane", source: "syslog / LLDP" },
  device_resource_anomaly: { modality: "device_telemetry", source: "SNMP / gNMI host metrics" },
  if_metric_anomaly: { modality: "device_telemetry", source: "SNMP / gNMI interface counters" },
  metric_anomaly: { modality: "device_telemetry", source: "SNMP / gNMI metrics" },
  lb_5xx: { modality: "passive_flow", source: "LB / app telemetry" },
  cloud_gw_anomaly: { modality: "passive_flow", source: "cloud gateway telemetry" },
  cloud_health_event: { modality: "passive_flow", source: "cloud health feed" },
  flow_volume_anomaly: { modality: "passive_flow", source: "NetFlow / IPFIX / sFlow" },
};

function kindMeta(kind: string): { modality: string; source: string } {
  if (KIND_META[kind]) return KIND_META[kind];
  if (/^probe_|_rtt|loss|latency/.test(kind)) return { modality: "active_probe", source: "synthetic probes" };
  if (/dns_/.test(kind)) return { modality: "active_probe", source: "DNS probes" };
  if (/bgp|ospf|isis|link|lldp|adjacency|_state_/.test(kind)) return { modality: "control_plane", source: "syslog / routing telemetry" };
  if (/flow|^cloud|lb_/.test(kind)) return { modality: "passive_flow", source: "flow / cloud telemetry" };
  return { modality: "device_telemetry", source: "device metrics" };
}

type MissingItem = { signature: string; needs: string[] };

// evidence_missing is a JSON array of "signature: needs a|b|c" lines. Parse into
// a structured checklist keyed by signature.
function parseMissing(raw: string): MissingItem[] {
  let lines: string[] = [];
  try { lines = JSON.parse(raw || "[]"); } catch { lines = []; }
  return lines.map((line) => {
    const [sig, rest] = line.split(/:\s*/, 2);
    const m = (rest ?? "").match(/needs\s+(.+)$/);
    const needs = m ? m[1].split("|").map((s) => s.trim()).filter(Boolean) : [];
    return { signature: sig?.trim() ?? line, needs };
  });
}

type Quality = "strong" | "candidate" | "weak/noisy";
const QUALITY_CLASS: Record<Quality, string> = {
  strong: "sev-critical",
  candidate: "sev-warning",
  "weak/noisy": "",
};
const QUALITY_WHY: Record<Quality, string> = {
  strong: "≥2 planes of attached evidence, ≥2 observers, grounded, signature matched",
  candidate: "grounded multi-plane object, but no signature has matched yet",
  "weak/noisy": "thin: single-plane / probe-only / no grounded cross-evidence",
};

export default function RcaSummary({
  timeline,
  seams,
}: {
  timeline: CorrTimeline;
  seams: Record<string, Seam>;
}) {
  const c = timeline.counts;
  const muted: React.CSSProperties = { color: "var(--muted)" };

  // distinct non-clear kinds present in the window — for "present but didn't qualify"
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
  // probe-only: the only plane carrying signal is active_probe (the synthetic
  // self-probe lane that currently floods the spine) — caps quality at weak/noisy.
  const probeOnly = useMemo(() => {
    const present = Object.entries(c.by_modality ?? {}).filter(([, v]) => v > 0).map(([k]) => k);
    return present.length > 0 && present.every((k) => k === "active_probe");
  }, [c.by_modality]);

  const quality: Quality =
    signatureMatch && grounded && attachedModalities >= 2 && observers >= 2 ? "strong"
    : !grounded || c.attached <= 1 || attachedModalities <= 1 || probeOnly ? "weak/noisy"
    : "candidate";

  const missing = useMemo(() => parseMissing(timeline.evidence_missing), [timeline.evidence_missing]);

  // grounding rollup + seams actually used
  const seamRefs = useMemo(() => {
    const refs = new Set<string>();
    for (const e of timeline.edges) if (e.grounding_kind === "seam") refs.add(e.grounding_ref);
    return [...refs];
  }, [timeline.edges]);

  const card: React.CSSProperties = {
    border: "1px solid var(--border,#2a2f3a)", borderRadius: 8, padding: "10px 12px",
    background: "var(--panel,#11151c)", display: "flex", flexDirection: "column", gap: 10,
  };
  const title: React.CSSProperties = { fontWeight: 600, fontSize: 12 };

  return (
    <div style={card}>
      {/* headline: quality + verdict + why */}
      <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
        <span className={`badge ${QUALITY_CLASS[quality]}`} title={QUALITY_WHY[quality]}>
          {quality.toUpperCase()}
        </span>
        <span className={`badge ${signatureMatch ? "sev-warning" : ""}`}>{timeline.verdict_tier}</span>
        <span style={{ fontFamily: "ui-monospace,monospace", fontSize: 12 }}>{timeline.top_hypothesis}</span>
        {timeline.top_hypothesis !== "undetermined" && (
          <span style={{ ...muted, fontSize: 12 }}>rank {timeline.top_confidence.toFixed(2)}</span>
        )}
        <span style={{ ...muted, fontSize: 11, marginLeft: "auto" }}>{QUALITY_WHY[quality]}</span>
      </div>

      {/* why undetermined */}
      {timeline.verdict_tier === "undetermined" && (
        <div style={{ fontSize: 12 }}>
          <b>Why undetermined:</b>{" "}
          {grounded
            ? `the engine grounded ${timeline.edges.length} causal edge${timeline.edges.length === 1 ? "" : "s"} across ${attachedModalities} plane${attachedModalities === 1 ? "" : "s"}, but no signature template's required evidence was satisfied (a confirmed verdict needs ≥2 modality classes × ≥2 observers matching a signature). It reports what it linked and what's missing rather than guessing.`
            : "a single grounded episode opened this object on severity alone — there is no cross-evidence to correlate, so no signature can match."}
        </div>
      )}

      {/* coverage by modality */}
      <div>
        <div style={title}>Evidence coverage by plane</div>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(140px,1fr))", gap: 8, marginTop: 6 }}>
          {MODALITIES.map((m) => {
            const total = c.by_modality?.[m.key] ?? 0;
            const att = c.attached_by_modality?.[m.key] ?? 0;
            const has = total > 0;
            return (
              <div key={m.key} style={{
                border: `1px solid ${has ? m.color + "66" : "var(--border,#23272f)"}`, borderRadius: 6,
                padding: "6px 8px", opacity: has ? 1 : 0.5,
              }}>
                <div style={{ fontSize: 11, display: "flex", alignItems: "center", gap: 6 }}>
                  <span style={{ width: 8, height: 8, borderRadius: 2, background: m.color, display: "inline-block" }} />
                  {m.label}
                </div>
                <div style={{ fontSize: 13, marginTop: 2 }}>
                  {has ? <><b style={{ color: m.color }}>{att}</b> <span style={muted}>linked / {total} in window</span></>
                       : <span style={muted}>no signal</span>}
                </div>
              </div>
            );
          })}
        </div>
        <div style={{ ...muted, fontSize: 11, marginTop: 6, display: "flex", gap: 8, flexWrap: "wrap" }}>
          {Object.entries(c.by_status ?? {}).sort().map(([k, v]) => (
            <span key={k} style={{ border: "1px solid var(--border,#2a2f3a)", borderRadius: 4, padding: "0 6px" }}>
              <b style={{ color: "var(--fg,#e6edf3)" }}>{v}</b> {k}
            </span>
          ))}
          <span>{observers} distinct observer{observers === 1 ? "" : "s"} on linked evidence</span>
          {grounded && <span>grounding: {Object.entries(c.by_grounding ?? {}).map(([k, v]) => `${v} ${k}`).join(" · ")}</span>}
        </div>
      </div>

      {/* seams that grounded the causal path */}
      {seamRefs.length > 0 && (
        <div>
          <div style={title}>Ownership boundaries on the causal path</div>
          {seamRefs.map((ref) => {
            const s = seams[ref];
            return (
              <div key={ref} style={{ fontSize: 12, fontFamily: "ui-monospace,monospace", padding: "1px 0" }}>
                ◆ {ref}{s ? <span style={muted}> — owner <b style={{ color: "var(--fg,#e6edf3)" }}>{s.control_plane_owner}</b> · visibility <b>{s.visibility}</b>{s.display_name ? ` · ${s.display_name}` : ""}</span>
                       : <span style={muted}> — seam metadata unavailable (file backend)</span>}
              </div>
            );
          })}
        </div>
      )}

      {/* actionable missing-evidence checklist */}
      {missing.length > 0 && (
        <div>
          <div style={title}>What would upgrade this verdict</div>
          <div style={{ ...muted, fontSize: 11, marginBottom: 4 }}>
            Each signature below was evaluated and fell short. ⚠ = a candidate signal was present in the window but did not qualify; ○ = absent entirely.
          </div>
          {missing.map((mi, i) => (
            <div key={i} style={{ marginBottom: 6 }}>
              <div style={{ fontSize: 12, fontFamily: "ui-monospace,monospace" }}>{mi.signature}</div>
              <div style={{ display: "flex", flexWrap: "wrap", gap: 6, marginTop: 3 }}>
                {mi.needs.map((kind) => {
                  const present = presentKinds.has(kind);
                  const meta = kindMeta(kind);
                  return (
                    <span key={kind} title={`${meta.modality} · ${meta.source}`} style={{
                      fontSize: 11, fontFamily: "ui-monospace,monospace",
                      border: `1px solid ${present ? "#f0a02088" : "var(--border,#2a2f3a)"}`,
                      background: present ? "#f0a02018" : "transparent",
                      borderRadius: 4, padding: "1px 6px",
                    }}>
                      {present ? "⚠ " : "○ "}{kind}
                      <span style={{ ...muted, marginLeft: 4 }}>· {meta.modality}</span>
                    </span>
                  );
                })}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

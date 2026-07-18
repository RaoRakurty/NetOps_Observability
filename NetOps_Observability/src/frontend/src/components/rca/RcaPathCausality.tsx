import { useMemo } from "react";
import type { RcaPathAttribution, RcaTypedSegment, RcaPathKeyDevice } from "../../services/api";
import {
  segmentLabel, segmentMeta, isOpaqueSegment, roleLabel, roleAbbr, roleCloudFamily,
  tierLabel, tierTone, confidenceLabel, kindLabel,
} from "./labels";

// RcaPathCausality — the PATH-FIRST render of the discovered SRC→DST typed path
// (path-causality RCA, design §5/§5a; reworked per the owner directive
// 2026-07-18: "the path, drawn correctly with perfect broken links, will talk a
// million words"). It consumes the `path_attribution` render contract exactly as
// the engine decoded it (rca_path_attribution.go) — the engine already made the
// causal decision and applied the honesty caps; this view NEVER re-decides:
//
//  · ONE clean left-to-right chain — DNS head, then every known device as a
//    small node + label. Healthy hops carry NO state chips, no confidence
//    footers, no "observed" boxes: a hop that isn't implicated just IS.
//  · the RED break is the hero — the attributed device carries the break glyph
//    and "Possible break here" (or "Break here" when the verdict is confirmed).
//  · unknown/opaque spans collapse to a dotted "· · · N hops" connector; the
//    classification reason moves into its tooltip — absence drawn as absence,
//    never a grey box lecturing about telemetry.
//  · per-hop evidence (role, address, classification, confidence) lives behind
//    hover (title) / click (cloud devices deep-link into Cloud Logs).
//  · honesty unchanged — a capped verdict shows its cap reason; discounted
//    off-path faults are listed as ruled-out; and when no break is attributable
//    the chain draws WITHOUT a break plus one clean sentence saying so. No hop
//    and no break is ever invented.
//
// Customer-facing labels only (no schema kinds / backend names). Renders inside
// the RcaWorkspace light report surface; tokens carry dark-safe fallbacks.

type DeviceMark = "cause" | "downstream" | undefined;

// Build the Cloud Logs deep-link for a cloud service device on the path (the
// drill opens the family-tagged Cloud Logs, filtered to this device). Only cloud
// devices with a log family are linkable; everything else is a static node.
function cloudLogsHref(role: string, provider: string, resourceId: string): string {
  const family = roleCloudFamily(role);
  if (!family) return "";
  const p = new URLSearchParams({ family });
  if (provider) p.set("provider", provider.toLowerCase());
  if (resourceId) p.set("resource_id", resourceId);
  return `#/logs/cloud?${p.toString()}`;
}

// Everything an operator may want per hop, behind hover — never on the chain.
function devTooltip(dev: RcaPathKeyDevice, seg: RcaTypedSegment, causeKind?: string): string {
  const parts = [roleLabel(dev.role)];
  if (dev.label) parts.push(dev.label);
  if (dev.address && dev.address !== dev.label) parts.push(dev.address);
  parts.push(`${segmentLabel(seg.segment_type)} segment${seg.provider ? ` · ${seg.provider.toUpperCase()}` : ""}`);
  if (seg.confidence) parts.push(`classified · ${confidenceLabel(seg.confidence).toLowerCase()}`);
  if (causeKind) parts.push(`evidence: ${kindLabel(causeKind)}`);
  return parts.join(" — ");
}

// One node on the chain: small abbr + label. The attributed cause is the RED
// hero with the break glyph; an explained-away victim gets a muted tag; every
// other hop is minimal — no state chip, no footer.
function DeviceNode({
  dev, seg, mark, breakText, causeKind,
}: { dev: RcaPathKeyDevice; seg: RcaTypedSegment; mark: DeviceMark; breakText: string; causeKind?: string }) {
  const resource = dev.label || dev.address || "";
  const href = seg.segment_type === "cloud" ? cloudLogsHref(dev.role, seg.provider || "", resource) : "";
  const cls = `rpc-dev${mark === "cause" ? " cause" : mark === "downstream" ? " downstream" : ""}`;
  const inner = (
    <>
      <span className="rpc-dev-abbr" aria-hidden="true">{mark === "cause" ? "✕" : roleAbbr(dev.role)}</span>
      <span className="rpc-dev-body">
        <span className="rpc-dev-role">{roleLabel(dev.role)}</span>
        {dev.label && <span className="rpc-dev-name">{dev.label}</span>}
        {mark === "cause" && <span className="rpc-dev-tag cause">{breakText}</span>}
        {mark === "downstream" && <span className="rpc-dev-tag down">Downstream</span>}
      </span>
    </>
  );
  const aria = `${roleLabel(dev.role)}${dev.label ? ` ${dev.label}` : ""}${mark === "cause" ? `, ${breakText.toLowerCase()}` : mark === "downstream" ? ", downstream" : ""}`;
  if (href) {
    return (
      <a className={cls} href={href} title={`${devTooltip(dev, seg, causeKind)} — open logs`}
        aria-label={`${aria} — open logs`}>
        {inner}
      </a>
    );
  }
  return <div className={cls} title={devTooltip(dev, seg, causeKind)} aria-label={aria}>{inner}</div>;
}

// Stable identity for a key device within a segment, to match the attributed cause
// and explained-away victims against the drawn path devices.
function devKey(segIndex: number, d: { address?: string; label?: string; role?: string }): string {
  return `${segIndex}|${(d.address || "").toLowerCase()}|${(d.label || "").toLowerCase()}|${(d.role || "").toLowerCase()}`;
}

// A collapsed unknown/opaque span: dotted connector + count. The reason lives in
// the tooltip — absence drawn as absence, never a fabricated device and never a
// grey box (owner 2026-07-18). Count comes only from what the engine measured.
function GapConnector({ seg }: { seg: RcaTypedSegment }) {
  const n = seg.unknown_hops?.length ?? 0;
  const reason = seg.reason || "This span could not be classified from the available telemetry — shown as a gap, not guessed.";
  return (
    <span className="rpc-gap" role="listitem"
      title={reason}
      aria-label={`${n > 0 ? `${n} unclassified hops` : "unclassified span"} — ${reason}`}>
      <span className="rpc-gap-dots" aria-hidden="true">· · ·</span>
      <span className="rpc-gap-count">{n > 0 ? `${n} hop${n === 1 ? "" : "s"}` : "unknown span"}</span>
    </span>
  );
}

export default function RcaPathCausality({ data }: { data: RcaPathAttribution | null | undefined }) {
  const cause = data?.attributed ?? null;

  const causeKey = useMemo(
    () => (cause ? devKey(cause.device.segment_index, cause.device) : ""),
    [cause],
  );
  const downstreamKeys = useMemo(() => {
    const s = new Set<string>();
    for (const e of data?.explained_away ?? []) s.add(devKey(e.device.segment_index, e.device));
    return s;
  }, [data]);

  const path = data?.path ?? null;
  const segments = path?.segments ?? [];

  // Honest empty state — nothing to draw at all. One clean sentence, never a
  // fabricated path.
  if (!data || (!cause && segments.length === 0)) {
    return (
      <div className="rpc rpc-empty" role="note">
        <style>{RPC_CSS}</style>
        <span className="rpc-empty-mark" aria-hidden="true">↳</span>
        No discovered path for this incident — the evidence did not place an on-path
        device between a source and a destination, so no path-causality attribution is drawn.
      </div>
    );
  }

  const head = path?.head ?? null;
  const dstName = head?.query_name || "application";
  const verdict = data.verdict_tier;
  const baseline = data.baseline_verdict_tier;
  const lifted = data.confidence_lifted && baseline && baseline !== verdict;
  const breakText = verdict === "confirmed" ? "Break here" : "Possible break here";

  return (
    <div className="rpc">
      <style>{RPC_CSS}</style>

      {/* honesty cap — a partial/opaque span keeps the verdict at suspected */}
      {data.capped && data.cap_reason && (
        <div className="rpc-cap" role="note">
          <b>Verdict capped:</b> {data.cap_reason} — the path is partly opaque, so this reads as suspected, not confirmed.
        </div>
      )}

      {/* path-causality headline + verdict lift */}
      <div className="rpc-headline">
        <div className="rpc-verdict">
          <span className={`rpc-pill ${tierTone(verdict)}`}>{tierLabel(verdict)}</span>
          {lifted && (
            <span className="rpc-lift" title="On-path evidence lifted the verdict above the symptom-only baseline">
              <span className={`rpc-pill ${tierTone(baseline)} ghost`}>{tierLabel(baseline)}</span>
              <span className="rpc-lift-arrow" aria-hidden="true">↑</span>
              <span className="rpc-lift-note">lifted by on-path evidence</span>
            </span>
          )}
        </div>
        {cause ? (
          <div className="rpc-claim">
            <b>Client → {dstName}</b> broke at <span className="rpc-claim-seg">{segmentLabel(cause.device.segment_type)}</span>
            {" · "}<b className="rpc-claim-dev">{roleLabel(cause.device.role)}{(cause.device.label || cause.device.address) ? ` ${cause.device.label || cause.device.address}` : ""}</b>
          </div>
        ) : (
          <div className="rpc-claim">
            <b>Client → {dstName}</b> — no break point is attributable on this path
            from the current evidence, so no device is blamed.
          </div>
        )}
      </div>

      {/* ONE clean left-to-right chain. Known devices are small nodes; unknown
          spans are dotted gaps; the attributed cause is the red hero. */}
      {segments.length > 0 ? (
        <div className="rpc-ribbon-wrap">
          <div className="rpc-ribbon" role="list" aria-label="Discovered path, source to destination">
            {head && (head.query_name || head.resolved_address) && (
              <>
                <div className="rpc-dev" role="listitem" title={`DNS resolution — ${head.query_name || ""}${head.resolved_address ? ` → ${head.resolved_address}` : ""}`}
                  aria-label={`DNS: ${head.query_name || head.resolved_address}`}>
                  <span className="rpc-dev-abbr" aria-hidden="true">DNS</span>
                  <span className="rpc-dev-body">
                    <span className="rpc-dev-role">DNS</span>
                    <span className="rpc-dev-name">{head.query_name || head.resolved_address}</span>
                  </span>
                </div>
                <span className="rpc-arrow" aria-hidden="true">→</span>
              </>
            )}
            {segments.map((seg, i) => {
              const opaque = (isOpaqueSegment(seg.segment_type) || !!seg.reason) && !(seg.key_devices?.length);
              const meta = segmentMeta(seg.segment_type);
              return (
                <div className="rpc-seg-wrap" key={`${seg.index ?? "s"}-${i}`}>
                  {opaque ? (
                    <GapConnector seg={seg} />
                  ) : (
                    <div className={`rpc-seg${(seg.key_devices ?? []).some((d) => devKey(seg.index, d) === causeKey) ? " has-cause" : ""}`}
                      style={{ ["--seg-color" as string]: meta.color }} role="listitem"
                      aria-label={`${segmentLabel(seg.segment_type)} segment`}>
                      <div className="rpc-seg-cap" title={seg.confidence ? `Classified · ${confidenceLabel(seg.confidence)}` : undefined}>
                        <span className="rpc-seg-tick" aria-hidden="true" />
                        <span className="rpc-seg-name">{segmentLabel(seg.segment_type)}</span>
                        {seg.provider && <span className="rpc-seg-provider">{seg.provider.toUpperCase()}</span>}
                        {seg.ambiguous && <span className="rpc-seg-flag" title="Multiple equal-cost paths (ECMP) — the exact hop is ambiguous">ECMP</span>}
                      </div>
                      <div className="rpc-seg-devs">
                        {(seg.key_devices ?? []).map((d, j) => {
                          const k = devKey(seg.index, d);
                          return (
                            <DeviceNode key={j} dev={d} seg={seg}
                              mark={k === causeKey ? "cause" : downstreamKeys.has(k) ? "downstream" : undefined}
                              breakText={breakText}
                              causeKind={k === causeKey ? cause?.kind : undefined} />
                          );
                        })}
                        {(!seg.key_devices || seg.key_devices.length === 0) && (
                          <span className="rpc-seg-empty" title={seg.reason || undefined}>no device identified</span>
                        )}
                        {seg.unknown_hops && seg.unknown_hops.length > 0 && <GapConnector seg={{ ...seg, reason: seg.reason || `${seg.unknown_hops.length} hop(s) inside this segment did not respond — not visible from here.` }} />}
                      </div>
                    </div>
                  )}
                  {i < segments.length - 1 && <span className="rpc-arrow" aria-hidden="true">→</span>}
                </div>
              );
            })}
          </div>
          {path?.ambiguous && (
            <div className="rpc-path-note">
              This path has ambiguous hops (ECMP / failover) — the segment sequence is the stable essence; exact hops vary per flow.
            </div>
          )}
          {(path?.notes ?? []).map((n, i) => <div key={i} className="rpc-path-note">{n}</div>)}
        </div>
      ) : (
        <div className="rpc-path-note">
          The named cause is placed, but the full typed path is not available for this incident.
        </div>
      )}

      {/* off-path faults the engine ruled out — severity is not causality */}
      {data.discounted && data.discounted.length > 0 && (
        <div className="rpc-discounted">
          <span className="rpc-discounted-label">Ruled out (off-path):</span>{" "}
          {data.discounted.map((d, i) => (
            <span key={i} className="rpc-discounted-item" title={d.reason}>{roleLabel(d.kind)}{i < data.discounted!.length - 1 ? " · " : ""}</span>
          ))}
          <div className="rpc-discounted-note">These changed in the same window but are not on the affected source→destination path, so they are not the cause.</div>
        </div>
      )}
    </div>
  );
}

// Scoped styles. Uses the rw-* report tokens (this renders inside RcaWorkspace's
// light document surface) with dark-safe fallbacks. The break is the ONLY loud
// element; healthy hops are quiet nodes; unknown spans are dotted absence.
const RPC_CSS = `
.rpc { font-size: 13px; color: var(--rw-text, var(--fg, #172033)); }
.rpc-empty { display: flex; gap: 8px; align-items: baseline; color: var(--rw-muted, var(--muted, #6a7384));
  border: 1px dashed var(--rw-line, var(--border, #dce3ee)); border-radius: 10px; padding: 12px 14px; font-size: 13px; }
.rpc-empty-mark { color: var(--rw-muted2, #8a94a6); font-weight: 700; }

.rpc-cap { border: 1px solid var(--rw-orange, #d66a00); background: var(--rw-orange2, #fff4e8);
  color: var(--rw-orange, #b45309); border-radius: 9px; padding: 9px 12px; font-size: 12.5px; margin-bottom: 12px; }
.rpc-cap b { color: inherit; }

.rpc-headline { display: flex; flex-direction: column; gap: 7px; margin-bottom: 12px; }
.rpc-verdict { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
.rpc-lift { display: inline-flex; align-items: center; gap: 6px; }
.rpc-lift-arrow { color: var(--rw-green, #0f9f4f); font-weight: 800; }
.rpc-lift-note { font-size: 11.5px; color: var(--rw-muted, #6a7384); }
.rpc-claim { font-size: 15px; line-height: 1.45; color: var(--rw-text, var(--fg, #172033)); }
.rpc-claim b { color: var(--rw-text, var(--fg, #172033)); }
.rpc-claim-seg { font-weight: 800; }
.rpc-claim-dev { color: var(--rw-red, #dc2626); }

.rpc-pill { display: inline-flex; align-items: center; border-radius: 7px; padding: 2px 9px;
  font-size: 11.5px; font-weight: 800; letter-spacing: .02em; border: 1px solid transparent; text-transform: uppercase; }
.rpc-pill.red { background: var(--rw-red2, #fff0ee); color: var(--rw-red, #dc2626); border-color: #ffd0cc; }
.rpc-pill.orange { background: var(--rw-orange2, #fff4e8); color: var(--rw-orange, #d66a00); border-color: #ffd3a9; }
.rpc-pill.blue { background: var(--rw-blue2, #eef4ff); color: var(--rw-blue, #2563eb); border-color: #c9dbff; }
.rpc-pill.green { background: var(--rw-green2, #eafaf1); color: var(--rw-green, #0f9f4f); border-color: #bfeccf; }
.rpc-pill.gray { background: #eef1f6; color: #667085; border-color: #d8dee8; }
.rpc-pill.purple { background: var(--rw-purple2, #f3f1ff); color: var(--rw-purple, #6d5dfc); border-color: #ddd7ff; }
.rpc-pill.ghost { opacity: .62; }

.rpc-ribbon-wrap { overflow-x: auto; padding-bottom: 4px; }
.rpc-ribbon { display: flex; align-items: flex-end; gap: 6px; min-width: min-content; padding-top: 2px; }
.rpc-seg-wrap { display: flex; align-items: flex-end; gap: 6px; }
.rpc-arrow { align-self: center; color: var(--rw-muted2, #8a94a6); font-size: 15px; padding: 0 1px; }

/* a classified segment: a quiet cap (identity only) over a row of small nodes */
.rpc-seg { display: flex; flex-direction: column; gap: 4px; }
.rpc-seg-cap { display: flex; align-items: center; gap: 6px; font-size: 10px; color: var(--rw-muted, #6a7384); }
.rpc-seg-tick { width: 14px; height: 3px; border-radius: 2px; background: var(--seg-color, #8a94a6); }
.rpc-seg-name { font-weight: 800; letter-spacing: .04em; text-transform: uppercase; }
.rpc-seg-provider { font-weight: 700; border: 1px solid var(--rw-line, #dce3ee); border-radius: 5px; padding: 0 4px; }
.rpc-seg-flag { font-weight: 700; border: 1px solid var(--rw-line, #dce3ee); border-radius: 5px; padding: 0 4px; }
.rpc-seg-devs { display: flex; align-items: stretch; gap: 6px; }
.rpc-seg-empty { font-size: 11px; color: var(--rw-muted2, #8a94a6); font-style: italic; align-self: center; }

/* device node — small, quiet; the cause is the only loud one */
.rpc-dev { display: flex; align-items: center; gap: 7px; text-decoration: none; color: inherit;
  border: 1px solid var(--rw-line, var(--border, #dce3ee)); border-radius: 8px; padding: 5px 8px;
  background: var(--rw-panel, var(--surface, #fff)); }
a.rpc-dev { cursor: pointer; }
a.rpc-dev:hover { border-color: var(--rw-blue, #2563eb); background: var(--rw-blue2, #eef4ff); }
a.rpc-dev:focus-visible { outline: 2px solid var(--rw-blue, #2563eb); outline-offset: 1px; }
.rpc-dev.cause { border: 2px solid var(--rw-red, #dc2626); background: var(--rw-red2, #fff0ee);
  box-shadow: 0 0 0 3px color-mix(in srgb, var(--rw-red, #dc2626) 18%, transparent); }
.rpc-dev.downstream { opacity: .8; }
.rpc-dev-abbr { flex: none; min-width: 26px; text-align: center; font-size: 9.5px; font-weight: 800;
  letter-spacing: .03em; color: var(--rw-muted, #6a7384); background: var(--rw-soft, #edf2f8);
  border-radius: 5px; padding: 3px 4px; }
.rpc-dev.cause .rpc-dev-abbr { color: #fff; background: var(--rw-red, #dc2626); font-size: 12px; }
.rpc-dev-body { display: flex; flex-direction: column; min-width: 0; line-height: 1.25; }
.rpc-dev-role { font-weight: 700; font-size: 11.5px; }
.rpc-dev-name { font-size: 10.5px; color: var(--rw-muted, #6a7384); font-family: var(--rw-mono, ui-monospace, monospace);
  overflow: hidden; text-overflow: ellipsis; max-width: 140px; white-space: nowrap; }
.rpc-dev-tag { align-self: flex-start; margin-top: 2px; font-size: 9.5px; font-weight: 800; border-radius: 5px; padding: 1px 5px; }
.rpc-dev-tag.cause { color: #fff; background: var(--rw-red, #dc2626); }
.rpc-dev-tag.down { color: var(--rw-muted, #6a7384); border: 1px solid var(--rw-line, #dce3ee); }

/* collapsed unknown span — dotted absence with a count, detail on hover */
.rpc-gap { display: inline-flex; flex-direction: column; align-items: center; justify-content: center;
  gap: 1px; align-self: center; padding: 4px 10px; border-bottom: 2px dotted var(--rw-muted2, #8a94a6);
  color: var(--rw-muted2, #8a94a6); cursor: help; }
.rpc-gap-dots { font-weight: 800; letter-spacing: 3px; line-height: 1; }
.rpc-gap-count { font-size: 10px; white-space: nowrap; }

.rpc-path-note { margin-top: 9px; font-size: 11.5px; color: var(--rw-muted, #6a7384); }
.rpc-discounted { margin-top: 12px; padding-top: 10px; border-top: 1px solid var(--rw-line, var(--border, #dce3ee)); font-size: 12px; }
.rpc-discounted-label { font-weight: 700; color: var(--rw-blue, #2563eb); }
.rpc-discounted-item { color: var(--rw-muted, #6a7384); }
.rpc-discounted-note { font-size: 11px; color: var(--rw-muted2, #8a94a6); margin-top: 3px; }
`;

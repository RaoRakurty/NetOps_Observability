import { useMemo } from "react";
import type { RcaPathAttribution, RcaTypedSegment, RcaPathKeyDevice } from "../../services/api";
import {
  segmentLabel, segmentMeta, isOpaqueSegment, roleLabel, roleAbbr, roleCloudFamily,
  tierLabel, tierTone, confidenceLabel,
} from "./labels";

// RcaPathCausality — the PATH-FIRST render of the discovered SRC→DST typed path
// with the broken link highlighted and the named cause (path-causality RCA, design
// §5/§5a). It consumes the `path_attribution` render contract exactly as the engine
// decoded it (rca_path_attribution.go) — the engine already made the causal decision
// and applied the honesty caps; this view NEVER re-decides, it only draws:
//
//  · typed segments  — distinct visual per CLOUD / LAN / DC / WAN / WAN-seam /
//    internet, each with its role-labeled key devices (DNS · WAF · LB · Firewall ·
//    app for cloud; client · leaf · spine · edge for LAN; NVA · tunnel for WAN).
//  · broken-link      — the attributed cause device/segment is called out as where
//    causality snaps; explained_away devices are secondary (downstream victims);
//    discounted off-path faults are listed as ruled-out, never as the cause.
//  · honest opacity   — an unknown/opaque segment renders greyed WITH its reason
//    (never a fabricated device); ambiguous/ECMP is marked; a capped verdict shows
//    its cap_reason so the UI never over-claims.
//  · path causality   — the headline reads "client→app broke at CLOUD · Web
//    Application Firewall", with verdict vs baseline shown as the lift.
//  · device drill     — a cloud device on the path deep-links to the family-tagged
//    Cloud Logs (#/logs/cloud) filtered to that device; it doesn't reproduce logs.
//
// Customer-facing labels only (no schema kinds / backend names). Renders inside the
// RcaWorkspace light report surface; tokens carry dark-safe fallbacks so it degrades
// gracefully if reused elsewhere. Honest empty: data null → a small "no discovered
// path" note, never a fabricated path.

type DeviceMark = "cause" | "downstream" | undefined;

// Build the Cloud Logs deep-link for a cloud service device on the path (design §5:
// the drill opens the family-tagged Cloud Logs, filtered to this device). Only cloud
// devices with a log family are linkable; everything else is a static chip.
function cloudLogsHref(role: string, provider: string, resourceId: string): string {
  const family = roleCloudFamily(role);
  if (!family) return "";
  const p = new URLSearchParams({ family });
  if (provider) p.set("provider", provider.toLowerCase());
  if (resourceId) p.set("resource_id", resourceId);
  return `#/logs/cloud?${p.toString()}`;
}

// A single role-labeled key device on a segment. The attributed cause carries the
// broken-link treatment; explained_away carries the secondary "downstream" tag.
function DeviceChip({
  dev, segmentType, provider, mark,
}: { dev: RcaPathKeyDevice; segmentType: string; provider: string; mark: DeviceMark }) {
  const resource = dev.label || dev.address || "";
  const href = segmentType === "cloud" ? cloudLogsHref(dev.role, provider, resource) : "";
  const cls = `rpc-dev${mark === "cause" ? " cause" : mark === "downstream" ? " downstream" : ""}`;
  const inner = (
    <>
      <span className="rpc-dev-abbr" aria-hidden="true">{roleAbbr(dev.role)}</span>
      <span className="rpc-dev-body">
        <span className="rpc-dev-role">{roleLabel(dev.role)}</span>
        {dev.label && <span className="rpc-dev-name" title={dev.label}>{dev.label}</span>}
      </span>
      {mark === "cause" && <span className="rpc-dev-tag cause">Broke here</span>}
      {mark === "downstream" && <span className="rpc-dev-tag down">Downstream</span>}
    </>
  );
  if (href) {
    return (
      <a className={cls} href={href}
        title={`Open ${roleLabel(dev.role)} logs in Cloud Logs`}
        aria-label={`${roleLabel(dev.role)}${dev.label ? ` ${dev.label}` : ""}${mark === "cause" ? ", broke here" : mark === "downstream" ? ", downstream" : ""} — open logs`}>
        {inner}
        <span className="rpc-dev-open" aria-hidden="true">›</span>
      </a>
    );
  }
  return (
    <div className={cls}
      aria-label={`${roleLabel(dev.role)}${dev.label ? ` ${dev.label}` : ""}${mark === "cause" ? ", broke here" : ""}`}>
      {inner}
    </div>
  );
}

function Segment({
  seg, causeDeviceKey, downstreamKeys,
}: { seg: RcaTypedSegment; causeDeviceKey: string; downstreamKeys: Set<string> }) {
  const meta = segmentMeta(seg.segment_type);
  const opaque = isOpaqueSegment(seg.segment_type) || !!seg.reason;
  const holdsCause = (seg.key_devices ?? []).some((d) => devKey(seg.index, d) === causeDeviceKey);
  const devKeyMark = (d: RcaPathKeyDevice): DeviceMark => {
    const k = devKey(seg.index, d);
    if (k === causeDeviceKey) return "cause";
    if (downstreamKeys.has(k)) return "downstream";
    return undefined;
  };
  return (
    <div className={`rpc-seg${opaque ? " opaque" : ""}${holdsCause ? " has-cause" : ""}`}
      style={{ ["--seg-color" as string]: meta.color }}
      role="listitem"
      aria-label={`${segmentLabel(seg.segment_type)} segment${holdsCause ? ", contains the attributed cause" : ""}${opaque ? ", not classifiable" : ""}`}>
      <div className="rpc-seg-head">
        <span className="rpc-seg-badge">{meta.short}</span>
        <span className="rpc-seg-name">{segmentLabel(seg.segment_type)}</span>
        {seg.provider && <span className="rpc-seg-provider">{seg.provider.toUpperCase()}</span>}
        {seg.ambiguous && <span className="rpc-seg-flag" title="Multiple equal-cost paths (ECMP) — the exact hop is ambiguous">ECMP</span>}
        {holdsCause && <span className="rpc-seg-flag cause">Break</span>}
      </div>
      {opaque ? (
        <div className="rpc-seg-opaque">
          <span className="rpc-seg-opaque-mark" aria-hidden="true">▨</span>
          <span>{seg.reason || "This segment could not be classified from the available telemetry — it is shown as opaque, not guessed."}</span>
        </div>
      ) : (seg.key_devices && seg.key_devices.length > 0) ? (
        <div className="rpc-seg-devs">
          {seg.key_devices.map((d, i) => (
            <DeviceChip key={i} dev={d} segmentType={seg.segment_type} provider={seg.provider || ""} mark={devKeyMark(d)} />
          ))}
        </div>
      ) : (
        <div className="rpc-seg-empty">No key device identified on this segment.</div>
      )}
      {seg.confidence && !opaque && (
        <div className="rpc-seg-conf">Classified · {confidenceLabel(seg.confidence)}</div>
      )}
      {seg.unknown_hops && seg.unknown_hops.length > 0 && (
        <div className="rpc-seg-unknown">
          {seg.unknown_hops.length} opaque hop{seg.unknown_hops.length === 1 ? "" : "s"} inside this segment — not visible from here.
        </div>
      )}
    </div>
  );
}

// Stable identity for a key device within a segment, to match the attributed cause
// and explained-away victims against the drawn path devices (address first, then
// label — the same fields the engine stamps).
function devKey(segIndex: number, d: { address?: string; label?: string; role?: string }): string {
  return `${segIndex}|${(d.address || "").toLowerCase()}|${(d.label || "").toLowerCase()}|${(d.role || "").toLowerCase()}`;
}

export default function RcaPathCausality({ data }: { data: RcaPathAttribution | null | undefined }) {
  // Honest empty state — no discoverable path / no on-path fault for this incident.
  // The report renders as it does today; this is just a small, truthful note.
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

  if (!data || !cause) {
    return (
      <div className="rpc rpc-empty" role="note">
        <style>{RPC_CSS}</style>
        <span className="rpc-empty-mark" aria-hidden="true">↳</span>
        No discovered path for this incident — the evidence did not place an on-path
        device between a source and a destination, so no path-causality attribution is drawn.
      </div>
    );
  }

  const path = data.path ?? null;
  const segments = path?.segments ?? [];
  const head = path?.head ?? null;

  // Headline reads as path causality: "client → app broke at CLOUD · Web
  // Application Firewall <device>". src is the user side; dst prefers the resolved
  // query name (friendly) over the raw address.
  const dstName = head?.query_name || "application";
  const causeSegLabel = segmentLabel(cause.device.segment_type);
  const causeRole = roleLabel(cause.device.role);
  const causeDevice = cause.device.label || cause.device.address || "";

  const verdict = data.verdict_tier;
  const baseline = data.baseline_verdict_tier;
  const lifted = data.confidence_lifted && baseline && baseline !== verdict;

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
        <div className="rpc-claim">
          <b>Client → {dstName}</b> broke at <span className="rpc-claim-seg">{causeSegLabel}</span>
          {" · "}<b className="rpc-claim-dev">{causeRole}{causeDevice ? ` ${causeDevice}` : ""}</b>
        </div>
      </div>

      {/* the discovered typed path, DNS head first, broken link highlighted */}
      {segments.length > 0 ? (
        <div className="rpc-ribbon-wrap">
          <div className="rpc-ribbon" role="list" aria-label="Discovered path, source to destination">
            {head && (head.query_name || head.resolved_address) && (
              <>
                <div className="rpc-head-chip" role="listitem"
                  aria-label={`DNS: ${head.query_name || head.resolved_address}`}>
                  <span className="rpc-dev-abbr" aria-hidden="true">DNS</span>
                  <span className="rpc-dev-body">
                    <span className="rpc-dev-role">DNS</span>
                    <span className="rpc-dev-name" title={head.query_name || head.resolved_address}>
                      {head.query_name || head.resolved_address}
                    </span>
                  </span>
                </div>
                <span className="rpc-arrow" aria-hidden="true">→</span>
              </>
            )}
            {segments.map((seg, i) => (
              <div className="rpc-seg-wrap" key={seg.index ?? i}>
                <Segment seg={seg} causeDeviceKey={causeKey} downstreamKeys={downstreamKeys} />
                {i < segments.length - 1 && <span className="rpc-arrow" aria-hidden="true">→</span>}
              </div>
            ))}
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
// light document surface) with dark-safe fallbacks so it degrades if reused. Every
// severity color is paired with a label/glyph — never color alone (colorblind-safe).
const RPC_CSS = `
.rpc { font-size: 13px; color: var(--rw-text, var(--fg, #172033)); }
.rpc-empty { display: flex; gap: 8px; align-items: baseline; color: var(--rw-muted, var(--muted, #6a7384));
  border: 1px dashed var(--rw-line, var(--border, #dce3ee)); border-radius: 10px; padding: 12px 14px; font-size: 13px; }
.rpc-empty-mark { color: var(--rw-muted2, #8a94a6); font-weight: 700; }

.rpc-cap { border: 1px solid var(--rw-orange, #d66a00); background: var(--rw-orange2, #fff4e8);
  color: var(--rw-orange, #b45309); border-radius: 9px; padding: 9px 12px; font-size: 12.5px; margin-bottom: 12px; }
.rpc-cap b { color: inherit; }

.rpc-headline { display: flex; flex-direction: column; gap: 7px; margin-bottom: 14px; }
.rpc-verdict { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
.rpc-lift { display: inline-flex; align-items: center; gap: 6px; }
.rpc-lift-arrow { color: var(--rw-green, #0f9f4f); font-weight: 800; }
.rpc-lift-note { font-size: 11.5px; color: var(--rw-muted, #6a7384); }
.rpc-claim { font-size: 15px; line-height: 1.45; color: var(--rw-text, var(--fg, #172033)); }
.rpc-claim b { color: var(--rw-text, var(--fg, #172033)); }
.rpc-claim-seg { font-weight: 800; }
.rpc-claim-dev { color: var(--rw-red, #d92d20); }

.rpc-pill { display: inline-flex; align-items: center; border-radius: 7px; padding: 2px 9px;
  font-size: 11.5px; font-weight: 800; letter-spacing: .02em; border: 1px solid transparent; text-transform: uppercase; }
.rpc-pill.red { background: var(--rw-red2, #fff0ee); color: var(--rw-red, #d92d20); border-color: #ffd0cc; }
.rpc-pill.orange { background: var(--rw-orange2, #fff4e8); color: var(--rw-orange, #d66a00); border-color: #ffd3a9; }
.rpc-pill.blue { background: var(--rw-blue2, #eef4ff); color: var(--rw-blue, #2563eb); border-color: #c9dbff; }
.rpc-pill.green { background: var(--rw-green2, #eafaf1); color: var(--rw-green, #0f9f4f); border-color: #bfeccf; }
.rpc-pill.gray { background: #eef1f6; color: #667085; border-color: #d8dee8; }
.rpc-pill.purple { background: var(--rw-purple2, #f3f1ff); color: var(--rw-purple, #6d5dfc); border-color: #ddd7ff; }
.rpc-pill.ghost { opacity: .62; }

.rpc-ribbon-wrap { overflow-x: auto; padding-bottom: 4px; }
.rpc-ribbon { display: flex; align-items: stretch; gap: 4px; min-width: min-content; }
.rpc-seg-wrap { display: flex; align-items: stretch; gap: 4px; }
.rpc-arrow { align-self: center; color: var(--rw-muted2, #8a94a6); font-size: 16px; padding: 0 2px; }

.rpc-head-chip { display: flex; align-items: center; gap: 8px; align-self: center;
  border: 1px solid var(--rw-line, var(--border, #dce3ee)); border-radius: 10px; padding: 8px 10px;
  background: var(--rw-panel2, var(--surface-2, #f9fafc)); }

.rpc-seg { border: 1.5px solid var(--seg-color, #8a94a6); border-radius: 11px; padding: 8px 10px 9px;
  min-width: 150px; background: color-mix(in srgb, var(--seg-color, #8a94a6) 7%, var(--rw-panel, #fff));
  display: flex; flex-direction: column; gap: 6px; }
.rpc-seg.opaque { border-style: dashed; border-color: var(--rw-line, #cdd4e0);
  background: repeating-linear-gradient(135deg, rgba(138,148,166,.07) 0 6px, transparent 6px 12px); }
.rpc-seg.has-cause { box-shadow: 0 0 0 3px color-mix(in srgb, var(--rw-red, #d92d20) 24%, transparent); border-color: var(--rw-red, #d92d20); }
.rpc-seg-head { display: flex; align-items: center; gap: 6px; flex-wrap: wrap; }
.rpc-seg-badge { font-size: 10px; font-weight: 800; letter-spacing: .04em; color: #fff;
  background: var(--seg-color, #8a94a6); border-radius: 5px; padding: 1px 6px; }
.rpc-seg.opaque .rpc-seg-badge { background: var(--rw-muted2, #8a94a6); }
.rpc-seg-name { font-weight: 800; font-size: 12.5px; }
.rpc-seg-provider { font-size: 10px; font-weight: 700; color: var(--rw-muted, #6a7384);
  border: 1px solid var(--rw-line, #dce3ee); border-radius: 5px; padding: 0 5px; }
.rpc-seg-flag { font-size: 10px; font-weight: 700; color: var(--rw-muted, #6a7384);
  border: 1px solid var(--rw-line, #dce3ee); border-radius: 5px; padding: 0 5px; }
.rpc-seg-flag.cause { color: #fff; background: var(--rw-red, #d92d20); border-color: var(--rw-red, #d92d20); }

.rpc-seg-devs { display: flex; flex-direction: column; gap: 5px; }
.rpc-dev { display: flex; align-items: center; gap: 8px; text-decoration: none; color: inherit;
  border: 1px solid var(--rw-line, var(--border, #dce3ee)); border-radius: 8px; padding: 5px 7px;
  background: var(--rw-panel, var(--surface, #fff)); }
a.rpc-dev { cursor: pointer; }
a.rpc-dev:hover { border-color: var(--rw-blue, #2563eb); background: var(--rw-blue2, #eef4ff); }
a.rpc-dev:focus-visible { outline: 2px solid var(--rw-blue, #2563eb); outline-offset: 1px; }
.rpc-dev.cause { border-color: var(--rw-red, #d92d20); background: var(--rw-red2, #fff0ee); }
.rpc-dev.downstream { opacity: .82; }
.rpc-dev-abbr { flex: none; min-width: 30px; text-align: center; font-size: 9.5px; font-weight: 800;
  letter-spacing: .03em; color: var(--rw-muted, #6a7384); background: var(--rw-soft, #edf2f8);
  border-radius: 5px; padding: 3px 4px; }
.rpc-dev.cause .rpc-dev-abbr { color: var(--rw-red, #d92d20); background: #ffe2de; }
.rpc-dev-body { display: flex; flex-direction: column; min-width: 0; line-height: 1.25; }
.rpc-dev-role { font-weight: 700; font-size: 12px; }
.rpc-dev-name { font-size: 10.5px; color: var(--rw-muted, #6a7384); font-family: var(--rw-mono, ui-monospace, monospace);
  overflow: hidden; text-overflow: ellipsis; max-width: 150px; white-space: nowrap; }
.rpc-dev-tag { flex: none; margin-left: auto; font-size: 9.5px; font-weight: 800; border-radius: 5px; padding: 1px 5px; }
.rpc-dev-tag.cause { color: #fff; background: var(--rw-red, #d92d20); }
.rpc-dev-tag.down { color: var(--rw-muted, #6a7384); border: 1px solid var(--rw-line, #dce3ee); }
.rpc-dev-open { flex: none; color: var(--rw-muted2, #8a94a6); font-weight: 800; }

.rpc-seg-opaque { display: flex; gap: 7px; align-items: baseline; font-size: 11.5px;
  color: var(--rw-muted, #6a7384); font-style: italic; }
.rpc-seg-opaque-mark { color: var(--rw-muted2, #8a94a6); font-style: normal; }
.rpc-seg-empty { font-size: 11.5px; color: var(--rw-muted, #6a7384); font-style: italic; }
.rpc-seg-conf { font-size: 10.5px; color: var(--rw-muted2, #8a94a6); }
.rpc-seg-unknown { font-size: 10.5px; color: var(--rw-orange, #d66a00); }

.rpc-path-note { margin-top: 9px; font-size: 11.5px; color: var(--rw-muted, #6a7384); }
.rpc-discounted { margin-top: 12px; padding-top: 10px; border-top: 1px solid var(--rw-line, var(--border, #dce3ee)); font-size: 12px; }
.rpc-discounted-label { font-weight: 700; color: var(--rw-blue, #2563eb); }
.rpc-discounted-item { color: var(--rw-muted, #6a7384); }
.rpc-discounted-note { font-size: 11px; color: var(--rw-muted2, #8a94a6); margin-top: 3px; }
`;

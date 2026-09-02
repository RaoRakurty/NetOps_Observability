// vrfInterfacesModel — the pure model behind the device page's "Interfaces by
// routing instance" tab (frontend-wave item 4).
//
// Everything that decides WHAT an operator sees lives here as pure functions so
// it is unit-testable without a DOM: the honest panel state, the coverage
// sentence, the dialect-aware group heading and the per-row tone.
//
// STATE CONTRACT — the same five states the Troubleshooting investigation lanes
// use (src/pages/troubleshoot/investigationModel.ts is the contract of record;
// the vocabulary is restated here rather than imported so this device-page
// module does not depend on a page module):
//
//   loading        — the fetch is in flight
//   error          — the API said no (its message is shown verbatim)
//   not_connected  — the DATA SOURCE was never wired for this device: no
//                    collector emits interface state for it. A product state,
//                    not a failure.
//   empty          — the source IS collected and reported nothing to group.
//   ready          — there are rows.
//
// "not_connected" and "empty" are never collapsed: the first means "we cannot
// see", the second means "we looked and there was nothing".

import type {
  VrfCoverage,
  VrfDialect,
  VrfInterface,
  VrfInterfaceGroup,
  VrfInterfacesResponse,
} from "../../services/api";

export type PanelState = "loading" | "error" | "not_connected" | "empty" | "ready";

export interface PanelResult {
  state: PanelState;
  /** The honest one-line explanation shown when state is not "ready". */
  note: string;
}

/** The API this panel reads, named on the card so an operator can go verify it. */
export const PANEL_SOURCE = "/api/devices/{id}/interfaces/by-vrf";

/**
 * panelState derives the honest state from the three things a fetch can produce.
 *
 * The distinction that matters: a device with NO interface state series is
 * `not_connected` ("nothing collects it"), not `empty` — and a failed request is
 * `error`, never a reassuring blank.
 */
export function panelState(
  loading: boolean,
  error: string | null,
  data: VrfInterfacesResponse | null,
): PanelResult {
  if (loading) return { state: "loading", note: "Loading…" };
  if (error) return { state: "error", note: error };
  if (!data) return { state: "error", note: "No response was received." };
  if (data.coverage.interfaces === 0) {
    return {
      state: "not_connected",
      note:
        data.coverage.notes[0] ??
        "No interface state series exists for this device — nothing is collecting it.",
    };
  }
  // `groups` is defensively coalesced: a Go nil slice serializes as JSON null,
  // and a crash here would take the whole device page down over an empty list.
  if ((data.groups ?? []).length === 0) {
    return { state: "empty", note: "Interface state is collected, but no interfaces were returned in this window." };
  }
  return { state: "ready", note: "" };
}

/**
 * coverageHeadline is the one sentence at the top of the panel. It states the
 * ONE fact an operator must have before reading the tables: whether the routing
 * instance a given interface belongs to is actually collected here.
 */
export function coverageHeadline(coverage: VrfCoverage, dialect: VrfDialect): string {
  const term = dialect.term;
  if (coverage.interfaces === 0) {
    return `No interface telemetry is collected for this device, so there is nothing to group by ${term}.`;
  }
  if (!coverage.vrf_labels) {
    return `${term} membership is not collected on this transport — the ${coverage.interfaces} interface${coverage.interfaces === 1 ? "" : "s"} below are shown ungrouped, not as members of a default ${term}.`;
  }
  if (coverage.ungrouped > 0) {
    return `${coverage.in_groups} of ${coverage.interfaces} interfaces carry a ${term} label; the remaining ${coverage.ungrouped} are listed separately rather than folded into an instance.`;
  }
  return `All ${coverage.interfaces} interface${coverage.interfaces === 1 ? "" : "s"} carry a ${term} label.`;
}

/**
 * transportLabel renders the collector lane, and says when the answer is an
 * INFERENCE rather than something the telemetry stamped. The SNMP lane stamps
 * no transport label today, so "SNMP" there is a deployment convention.
 */
export function transportLabel(coverage: VrfCoverage): string {
  switch (coverage.transport) {
    case "none":
      return "No transport";
    case "gnmi":
      return "gNMI";
    case "mixed":
      return "Mixed transports";
    case "snmp":
      return coverage.transport_inferred ? "SNMP (inferred — the series carry no transport label)" : "SNMP";
    default:
      return "Unknown transport";
  }
}

/** groupHeading is the section title, in the device's own dialect. */
export function groupHeading(group: VrfInterfaceGroup, dialect: VrfDialect): string {
  if (group.membership === "not_collected") return group.label;
  return `${dialect.term} ${group.vrf}`;
}

/** panelTitle titles the whole tab in the device's dialect. */
export function panelTitle(dialect: VrfDialect): string {
  return `Interfaces by ${dialect.term}`;
}

/** dialectFootnote is shown only when no vendor profile claimed the device, so
 *  the operator knows the word is a default and not an identification. */
export function dialectFootnote(dialect: VrfDialect): string | null {
  if (dialect.vendor_known) return null;
  return `No vendor profile matched ${dialect.vendor ? `"${dialect.vendor}"` : "this device"}, so the industry-majority term "${dialect.term}" is shown. The device's own word may differ.`;
}

/** groupSummary is the per-group count line. `unknown` is surfaced rather than
 *  folded into "down": an interface whose state we never read is not down. */
export function groupSummary(group: VrfInterfaceGroup): string {
  const parts = [`${group.count} interface${group.count === 1 ? "" : "s"}`, `${group.up} up`, `${group.down} down`];
  if (group.unknown > 0) parts.push(`${group.unknown} state unknown`);
  return parts.join(" · ");
}

/**
 * rowTone colours one row. An interface with no state series has NO tone: it is
 * not green and it is not red, because nothing was measured.
 */
export function rowTone(iface: VrfInterface): "good" | "bad" | "warn" | "" {
  if (iface.oper_value === null) return "";
  if (iface.oper_value === 1) {
    const errs = (iface.in_errors_per_s ?? 0) + (iface.out_errors_per_s ?? 0);
    const util = Math.max(iface.in_util_pct ?? 0, iface.out_util_pct ?? 0);
    return errs > 0 || util >= 80 ? "warn" : "good";
  }
  // Administratively down is an intended state, not a fault.
  if (iface.admin_value === 2) return "";
  return "bad";
}

/** fmtRate renders bits/second. null renders as an em dash, NEVER as 0. */
export function fmtRate(bps: number | null): string {
  if (bps === null || !Number.isFinite(bps)) return "—";
  const units = ["bps", "Kbps", "Mbps", "Gbps", "Tbps"];
  let v = bps;
  let i = 0;
  while (Math.abs(v) >= 1000 && i < units.length - 1) {
    v /= 1000;
    i++;
  }
  return `${v >= 100 || i === 0 ? Math.round(v) : v.toFixed(1)} ${units[i]}`;
}

/** fmtPct renders a utilisation percentage. null renders as an em dash. */
export function fmtPct(pct: number | null): string {
  if (pct === null || !Number.isFinite(pct)) return "—";
  return `${pct >= 10 ? Math.round(pct) : pct.toFixed(1)}%`;
}

/** fmtErrRate renders an error rate. A measured ZERO is a fact and renders as
 *  "0/s"; a missing series renders as an em dash. The two must never look the
 *  same — that is the whole difference between "clean" and "not measured". */
export function fmtErrRate(perSec: number | null): string {
  if (perSec === null || !Number.isFinite(perSec)) return "—";
  if (perSec === 0) return "0/s";
  return `${perSec >= 10 ? Math.round(perSec) : perSec.toFixed(2)}/s`;
}

/** totalInterfaces counts what is actually rendered, across every group. */
export function totalInterfaces(groups: VrfInterfaceGroup[]): number {
  return groups.reduce((n, g) => n + g.members.length, 0);
}

/**
 * initiallyOpen decides which groups start expanded. Observed instances always
 * open (that is the answer the operator came for); a single ungrouped bucket
 * opens too, because collapsing the only content there is would render an empty
 * panel. Additional buckets in a many-group view start closed.
 */
export function initiallyOpen(groups: VrfInterfaceGroup[]): Record<string, boolean> {
  const open: Record<string, boolean> = {};
  groups.forEach((g, i) => {
    open[groupKey(g, i)] = g.membership === "observed" || groups.length === 1;
  });
  return open;
}

/** groupKey is a stable React key: the ungrouped bucket has no name. */
export function groupKey(group: VrfInterfaceGroup, index: number): string {
  return group.vrf !== "" ? `vrf:${group.vrf}` : `ungrouped:${index}`;
}

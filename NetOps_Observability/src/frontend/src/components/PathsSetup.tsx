// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

import { useEffect, useMemo, useState } from "react";
import StepFlow, { type FlowStep } from "./admin/StepFlow";
import { api, type ProbeTargetSuggestion, type ProbeTargetSuggestions } from "../services/api";
import { operatorError } from "../lib/errors";

// PathsSetup — the Measured paths empty state as numbered steps (Paths
// redesign P3). It replaces a one-line hint with what an operator actually has
// to do, in order:
//   1. Path discovery is switched on (Platform › Features — a platform
//      administrator's switch; this page only reports it),
//   2. pick what to trace — the workspace's own branch edges, suggested by site
//      and pre-ticked; saving adds them to the Digital Experience target list
//      (POST /api/dem/targets) with trace_path set — one list, not a second one,
//   3. the first trace appears within a minute.
// Every number here comes from /api/probe/targets/suggested, which is scoped to
// the caller's own workspace.

export const FEATURES_HREF = "#/platform/features";
export const TARGETS_HREF = "#/operations/digital-experience/synthetics";

/** The suggestions not already traced, keyed by address. */
export function freshSuggestions(s: ProbeTargetSuggestion[]): ProbeTargetSuggestion[] {
  const seen = new Set<string>();
  return s.filter((x) => {
    if (x.traced || seen.has(x.address)) return false;
    seen.add(x.address);
    return true;
  });
}

export default function PathsSetup() {
  const [data, setData] = useState<ProbeTargetSuggestions | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [picked, setPicked] = useState<Record<string, boolean>>({});
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState<{ ok: number; failed: number } | null>(null);

  const load = () =>
    api.probeTargetSuggestions()
      .then((d) => {
        setData(d);
        setErr(null);
        // Pre-tick every suggestion not already traced.
        const next: Record<string, boolean> = {};
        for (const s of freshSuggestions(d.suggestions ?? [])) next[s.address] = true;
        setPicked(next);
      })
      .catch((e) => setErr(operatorError(e, "Path discovery setup could not be loaded.")));

  useEffect(() => { load(); }, []);

  const fresh = useMemo(() => freshSuggestions(data?.suggestions ?? []), [data]);
  const chosen = fresh.filter((s) => picked[s.address]);

  const save = async () => {
    setSaving(true);
    let ok = 0;
    let failed = 0;
    for (const s of chosen) {
      try {
        await api.createDemTarget({
          name: `Path to ${s.name}`, kind: "icmp", host: s.address, site: s.site ?? "",
          interval_sec: 60, trace_path: true,
        });
        ok++;
      } catch {
        failed++;
      }
    }
    setSaved({ ok, failed });
    setSaving(false);
    load();
  };

  if (err) return <div className="board-empty-hint" role="alert">{err}</div>;
  if (!data) return <div className="board-empty-hint">Checking path discovery…</div>;

  const tracing = data.tracing ?? 0;
  const steps: FlowStep[] = [
    {
      id: "switch",
      title: "Switch on",
      done: !!data.path_discovery,
      status: data.path_discovery ? "On" : "Off",
      render: () => data.path_discovery ? (
        <p className="paths-step-text">Path discovery is on for this installation.</p>
      ) : (
        <p className="paths-step-text">
          A platform administrator turns on <b>Path discovery</b> under{" "}
          <a href={FEATURES_HREF}>Platform › Configuration › Features</a>, in the Active measurement section.
        </p>
      ),
    },
    {
      id: "targets",
      title: "Pick targets",
      done: tracing > 0,
      // Shown even while path discovery is off: a workspace can pick its
      // targets before a platform administrator switches discovery on.
      hasData: tracing > 0 || fresh.length > 0,
      status: tracing > 0 ? `${tracing} traced` : undefined,
      render: () => (
        <div className="paths-step-text">
          {fresh.length === 0 ? (
            <p>
              {tracing > 0
                ? "Every suggested edge is already traced. "
                : "No branch edges with an address were found in your inventory yet; they appear here once discovered. "}
              Traced targets are listed under <a href={TARGETS_HREF}>Digital Experience › Synthetics</a>.
            </p>
          ) : (
            <>
              <p>Your branch edges, by site. Ticked ones are traced every minute.</p>
              <ul className="paths-pick" data-testid="paths-suggestions">
                {fresh.map((s) => (
                  <li key={s.address}>
                    <label>
                      <input
                        type="checkbox"
                        checked={!!picked[s.address]}
                        onChange={(e) => setPicked((p) => ({ ...p, [s.address]: e.target.checked }))}
                      />{" "}
                      <span>{s.name}</span> <span className="mono">{s.address}</span>
                      {s.site ? <span className="paths-pick-site"> · {s.site}</span> : null}
                    </label>
                  </li>
                ))}
              </ul>
              <button className="btn primary" disabled={saving || chosen.length === 0} onClick={save} data-testid="paths-trace-selected">
                {saving ? "Adding…" : `Trace ${chosen.length} selected`}
              </button>
            </>
          )}
          {saved && (
            <p role="status" data-testid="paths-added">
              {saved.ok} added{saved.failed ? `, ${saved.failed} could not be added` : ""}.
            </p>
          )}
        </div>
      ),
    },
    {
      id: "first",
      title: "First trace",
      done: false,
      render: () => <p className="paths-step-text">The first trace shows here within a minute.</p>,
    },
  ];
  return <StepFlow steps={steps} label="Set up path discovery" />;
}

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// AboutData — the "About this data" drawer of Explore → Flows: which flow
// sources are arriving, what the sampling sentence says, how much of the
// window the records cover, the platform-traffic toggle, and how to load the
// country and network datasets when they are not loaded. Read once when the
// drawer opens (it is not on the page's refresh clock).
//
// It also carries the two things the old Flows page showed that belong
// elsewhere: device health (Device Monitoring) and TCP flags (Security).

import { useEffect } from "react";
import { api } from "../../services/api";
import { operatorError } from "../../lib/errors";
import AskIris from "../../components/AskIris";
import Icon from "../../components/Icon";
import { fmtNum } from "../../components/board/panels";
import { PlatformTrafficToggle, samplingNote, fetchCoverage } from "../flowEmpty";
import { useTicked } from "./useTicked";

type ByTypeRow = { flow_type: string; flows: number; exporters: number };

export default function AboutData({ open, onClose, since, includePlatform, onIncludePlatform }: {
  open: boolean;
  onClose: () => void;
  since: number;
  includePlatform: boolean;
  onIncludePlatform: (v: boolean) => void;
}) {
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => { if (e.key === "Escape") onClose(); };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open, onClose]);

  const filters = includePlatform ? { traffic: "all" } : {};
  const byType = useTicked(() => api.flowsByType(since), [since, open], open);
  const cov = useTicked(() => fetchCoverage(since, "", filters), [since, includePlatform, open], open);
  const geo = useTicked(() => api.flowsGeo("src", since), [since, open], open);
  const q = { since, ftype: "", filters, fkey: JSON.stringify(filters) };
  const types = (byType.data?.data as ByTypeRow[] | undefined) ?? [];
  const c = cov.data;
  const geoOn = !!geo.data && geo.data.geo_enabled !== false;
  const asOn = !!c && (c.flows_with_as > 0 || c.asn_dataset_loaded);

  return (
    <>
      <div className={`help-scrim${open ? " open" : ""}`} onClick={onClose} aria-hidden="true" />
      <aside className={`help-panel tr-about${open ? " open" : ""}`} aria-hidden={!open} role="dialog" aria-modal="false" aria-label="About this data">
        <header className="help-head">
          <span className="help-title"><Icon name="info" size={16} />About this data</span>
          <div className="help-actions">
            <AskIris topic="flows.about-data" label="About this data" />
            <button className="help-close" type="button" onClick={onClose} aria-label="Close About this data" title="Close (Esc)">
              <Icon name="close" size={16} />
            </button>
          </div>
        </header>
        {open && (
          <div className="tr-about-body">
            <section>
              <h3>Sources arriving</h3>
              {byType.error ? (
                <p className="tr-error">{operatorError(byType.error, "Flow sources could not be read.")}</p>
              ) : types.length === 0 ? (
                <p className="tr-fact">{byType.loading ? "Reading…" : "No flow records in this window."}</p>
              ) : (
                <ul className="tr-sources">
                  {types.map((t) => (
                    <li key={t.flow_type}>
                      <span className="badge accent-badge">{String(t.flow_type).toUpperCase()}</span>{" "}
                      {fmtNum(Number(t.flows))} flows from {fmtNum(Number(t.exporters))} {Number(t.exporters) === 1 ? "device" : "devices"}
                    </li>
                  ))}
                </ul>
              )}
            </section>

            <section>
              <h3>Sampling</h3>
              <p className="tr-fact" data-testid="about-sampling">{samplingNote(c ?? null)}</p>
            </section>

            <section>
              <h3>Coverage</h3>
              {c ? (
                <ul className="tr-facts">
                  <li>{fmtNum(c.flows)} flow records from {fmtNum(c.exporters)} exporting devices</li>
                  <li>{fmtNum(c.flows_sampling_reported)} report a sampling rate</li>
                  <li>{fmtNum(c.tcp_flows)} are TCP; {fmtNum(c.flows_with_as)} carry a network number</li>
                </ul>
              ) : (
                <p className="tr-fact">{cov.loading ? "Reading…" : "Coverage could not be read."}</p>
              )}
            </section>

            <section>
              <h3>How the numbers are made</h3>
              <ul className="tr-facts" data-testid="about-method">
                <li>Flow totals are scaled by the sampling rate a router reports, and by nothing else. A router that samples without saying so reads low.</li>
                <li>A link's traffic comes from the router's own records: "in" entered the device on that interface, "out" left on it. A figure marked ≈ reads low because some records name no interface.</li>
                <li>"Change" and "What changed" compare the window with the one just before it, of the same length. Flow records are kept for 7 days by default, so a longer look back has no comparison.</li>
                <li>Capacity uses the interface counters, kept for 30 days: the 95th percentile and peak of five-minute rates, and a straight line through each day's 95th percentile for "reaches 90%" (14 days of history and a steady trend needed).</li>
              </ul>
            </section>

            <section>
              <h3>Correlix's own traffic</h3>
              <PlatformTrafficToggle q={q} included={includePlatform} onChange={onIncludePlatform} />
            </section>

            <section>
              <h3>Optional datasets</h3>
              <ul className="tr-facts">
                <li data-testid="dataset-geo">
                  Countries: {geoOn ? "loaded" : <>not loaded · run <code>scripts/geoip-prepare.py</code> with a country file</>}
                </li>
                <li data-testid="dataset-asn">
                  Networks: {asOn ? "available" : <>not loaded · run <code>scripts/asn-prepare.py</code></>}
                </li>
              </ul>
            </section>

            <section>
              <h3>Elsewhere</h3>
              <ul className="tr-facts">
                <li><a href="#/analytics/device-monitoring">Device health → Device Monitoring</a></li>
                <li><a href="#/security/threat/behavior">TCP flags and scans → Security</a></li>
              </ul>
            </section>
          </div>
        )}
      </aside>
    </>
  );
}

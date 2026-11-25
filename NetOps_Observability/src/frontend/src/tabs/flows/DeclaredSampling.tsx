// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// DeclaredSampling — tracker 401 (c), inside "About this data". A router that
// samples but reports no rate reads low; whoever knows its configuration
// ("1 in 1000") records the rate here, and the link figures then multiply ONLY
// that router's records that carried no rate by it, marked "declared". A rate
// the router reports always wins. The server decides who may save (a workspace
// writer, for a router the workspace owns) and says so plainly when refused.

import { useEffect, useState } from "react";
import { api, type FlowSamplingExporter } from "../../services/api";
import { operatorError } from "../../lib/errors";
import { fmtNum } from "../../components/board/panels";
import { listOf } from "./flowsModel";

export default function DeclaredSampling() {
  const [rows, setRows] = useState<FlowSamplingExporter[] | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [draft, setDraft] = useState<Record<string, string>>({});
  const [busy, setBusy] = useState<string | null>(null);
  const [msg, setMsg] = useState<string | null>(null);

  const load = () => {
    api.flowsSampling()
      .then((r) => { setRows(listOf(r?.exporters)); setErr(null); })
      .catch((e) => setErr(operatorError(e, "Declared rates could not be read.")));
  };
  useEffect(load, []);

  const unreported = (rows ?? []).filter((r) => r.flows_rate_reported < r.flows || (r.declared_rate ?? 0) > 1);

  const save = (r: FlowSamplingExporter) => {
    const n = Number((draft[r.exporter] ?? "").trim());
    if (!Number.isInteger(n) || n < 2) {
      setMsg("Enter a whole number of 2 or more.");
      return;
    }
    setBusy(r.exporter);
    setMsg(null);
    api.setFlowSampling(r.exporter, n)
      .then(() => { setMsg(`Saved: ${r.device_name || r.exporter} counts 1 in ${fmtNum(n)}.`); load(); })
      .catch((e) => setMsg(operatorError(e, "The rate could not be saved.")))
      .finally(() => setBusy(null));
  };

  const remove = (r: FlowSamplingExporter) => {
    setBusy(r.exporter);
    setMsg(null);
    api.removeFlowSampling(r.exporter)
      .then(() => { setMsg(`Removed the declared rate for ${r.device_name || r.exporter}.`); load(); })
      .catch((e) => setMsg(operatorError(e, "The rate could not be removed.")))
      .finally(() => setBusy(null));
  };

  return (
    <section data-testid="declared-sampling">
      <h3>Declared sampling</h3>
      <ol className="tr-facts">
        <li>Find a router that reports no rate.</li>
        <li>Enter its sampling rate as 1 in N.</li>
        <li>Save. Its totals are marked declared.</li>
      </ol>
      {err ? (
        <p className="tr-error">{err}</p>
      ) : rows === null ? (
        <p className="tr-fact">Reading…</p>
      ) : unreported.length === 0 ? (
        <p className="tr-fact">Every router here reports its rate.</p>
      ) : (
        <table className="tr-table" aria-label="Declared sampling rates">
          <thead>
            <tr><th scope="col">Router</th><th scope="col">Records without a rate</th><th scope="col">1 in N</th><th scope="col"><span className="sr-only">Actions</span></th></tr>
          </thead>
          <tbody>
            {unreported.map((r) => (
              <tr key={`${r.tenant_id ?? ""}|${r.exporter}`}>
                <td>{r.device_name || r.exporter}</td>
                <td>{fmtNum(r.flows > r.flows_rate_reported ? r.flows - r.flows_rate_reported : 0)} of {fmtNum(r.flows)}</td>
                <td>
                  {r.can_declare ? (
                    <input
                      type="number" min={2} step={1} inputMode="numeric"
                      aria-label={`Sampling rate for ${r.device_name || r.exporter}, 1 in N`}
                      placeholder={r.declared_rate ? String(r.declared_rate) : "1000"}
                      value={draft[r.exporter] ?? ""}
                      onChange={(e) => setDraft({ ...draft, [r.exporter]: e.target.value })}
                    />
                  ) : (
                    <span>{r.declared_rate ? fmtNum(r.declared_rate) : "—"}</span>
                  )}
                </td>
                <td>
                  {r.can_declare && (
                    <>
                      <button type="button" className="btn btn-sm" disabled={busy === r.exporter} onClick={() => save(r)}>Save</button>
                      {(r.declared_rate ?? 0) > 1 && (
                        <button type="button" className="btn btn-sm btn-ghost" disabled={busy === r.exporter} onClick={() => remove(r)}>Remove</button>
                      )}
                    </>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {msg && <p className="tr-fact" role="status">{msg}</p>}
    </section>
  );
}

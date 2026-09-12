// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// CostContext (Wave 5 #18 slice 3) — the "cost context" block on the cloud
// investigation drawer: what the affected account's services COST around the
// incident (onset ± 7 days), read from /api/cloud/costs (tenant-scoped).
//
// HONESTY RULES (rendered, not just intended):
//   * labeled "service cost context — not a measured business impact";
//   * every figure is a provider-billed amount summed with plain arithmetic —
//     no fabricated "downtime cost" multiplication, ever;
//   * scope is the accounts recorded on THIS investigation's changes; when
//     none is derivable, or when no cost data landed, the empty state says
//     exactly what to connect.

import { useEffect, useState } from "react";
import { loadInvestigationChanges } from "./api";
import {
  costScope, costWindow, fmtAmount, loadCloudCosts, summarizeCosts,
  type CostRow, type CostScopeAccount, type ServiceCost,
} from "./costContext";

type Basis =
  | "loading"
  | "error"
  | "onset_unknown"
  | "no_accounts"
  | "no_cost_data"
  | "ok";

interface State {
  basis: Basis;
  services: ServiceCost[];
  accounts: CostScopeAccount[];
  from: string;
  to: string;
}

const INITIAL: State = { basis: "loading", services: [], accounts: [], from: "", to: "" };

export default function CostContext({ id }: { id: string }) {
  const [st, setSt] = useState<State>(INITIAL);

  useEffect(() => {
    let alive = true;
    setSt(INITIAL);
    (async () => {
      const inv = await loadInvestigationChanges(id);
      const win = costWindow(inv.onset, new Date());
      if (!win) {
        if (alive) setSt({ ...INITIAL, basis: "onset_unknown" });
        return;
      }
      const accounts = costScope(inv.changes);
      if (accounts.length === 0) {
        if (alive) setSt({ ...INITIAL, basis: "no_accounts" });
        return;
      }
      const results = await Promise.all(accounts.map((a) =>
        loadCloudCosts({ provider: a.provider, account: a.account, from: win.from, to: win.to })));
      const rows: CostRow[] = results.flatMap((r) => r.costs ?? []);
      const services = summarizeCosts(rows, win.from, win.onsetDay);
      if (alive) {
        setSt({
          basis: rows.length === 0 ? "no_cost_data" : "ok",
          services, accounts, from: win.from, to: win.to,
        });
      }
    })().catch(() => { if (alive) setSt({ ...INITIAL, basis: "error" }); });
    return () => { alive = false; };
  }, [id]);

  return (
    <div className="inv-costctx" data-testid="cost-context">
      <div className="inv-costctx-h">
        Service cost context
        <span className="inv-costctx-meta">
          provider-billed cost, onset ± 7d — not a measured business impact
        </span>
      </div>
      {st.basis === "loading" ? (
        <span className="ao-muted">checking recorded costs…</span>
      ) : st.basis === "error" ? (
        <span className="ao-muted">cost context unavailable</span>
      ) : st.basis === "onset_unknown" ? (
        <span className="ao-muted">
          the investigation&apos;s onset time is unknown — no cost window can be anchored
        </span>
      ) : st.basis === "no_accounts" ? (
        <span className="ao-muted">
          no cloud account is recorded on this investigation&apos;s changes — cost context cannot be scoped honestly
        </span>
      ) : st.basis === "no_cost_data" ? (
        <span className="ao-muted">
          no cost data recorded for {st.accounts.map((a) => a.account).join(", ")} — connect
          billing access (AWS Cost Explorer / Azure Cost Management Reader) to see cost context
        </span>
      ) : (
        <>
          {st.services.map((s) => (
            <div className="inv-costctx-row" key={`${s.service}|${s.provider}|${s.currency}`}>
              <span className="inv-costctx-svc">{s.service}</span>
              <span>{fmtAmount(s.total, s.currency)} in window</span>
              {s.baselineDaily !== null && (
                <span className="ao-muted">· baseline {fmtAmount(s.baselineDaily, s.currency)}/day</span>
              )}
              <span className="ao-muted">
                · onset day {s.onsetDayAmount !== null
                  ? fmtAmount(s.onsetDayAmount, s.currency)
                  : "not yet billed"}
              </span>
            </div>
          ))}
          <div className="inv-costctx-foot ao-muted">
            {st.from} → {st.to} · account{st.accounts.length > 1 ? "s" : ""}{" "}
            {st.accounts.map((a) => a.account).join(", ")}
          </div>
        </>
      )}
    </div>
  );
}

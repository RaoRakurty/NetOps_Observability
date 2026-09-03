import { useCallback, useEffect, useMemo, useState } from "react";
import "./Security.css";
import {
  api, SecCompliance, SecFinding, SecFrameworkCatalog, SecFrameworkToggle,
} from "../../services/api";
import ComplianceMonitoring from "../ComplianceMonitoring";
import { Group, Panel } from "../../components/board/panels";
import { Segmented } from "../../components/ui";
import ComplianceFrameworks from "./ComplianceFrameworks";
import { unassessedReasons } from "./model";
import { operatorError } from "../../lib/errors";
// Compliance — two sub-views:
//
//  · Frameworks — WHICH frameworks this tenant is assessed against, and the
//    score for each. Compliance is scoped per customer (owner, 2026-09-03):
//    the tenant runs the NIST 800-53 base plus CIS Controls by default and adds
//    NIST CSF / HIPAA / PCI DSS deliberately. Scores are computed server-side by
//    projecting a finding's canonical 800-53 control onto each enabled
//    framework's requirements — a framework is never a TAG on a finding, which
//    is why HIPAA can report at all and why the page no longer lists invented
//    CIS benchmark sections as frameworks. Beneath it, the §5g panel naming WHY
//    each unassessed control reached no verdict.
//  · Drift & baselines — the existing Compliance Monitoring board (source-of-
//    truth drift + management-plane baselines), reused as a sub-view.
//
// THE TWO LOADS ARE INDEPENDENT ON PURPOSE. A failure to fetch the unassessed
// reasons must never blank the scorecards, and must never render as "nothing
// was unassessed" — that empty state is a false clear.
//
// Tenant isolation (§3a): every call is server-scoped by the token; the client
// never names a tenant.

type SubView = "frameworks" | "drift";

/** The statuses that mean "no verdict": Unknown, NotApplicable, Error. */
const UNASSESSED_STATUSES = "unknown,not_applicable,error";

export default function SecurityCompliance() {
  const [tab, setTab] = useState<SubView>("frameworks");
  const [catalog, setCatalog] = useState<SecFrameworkCatalog | null>(null);
  const [compliance, setCompliance] = useState<SecCompliance | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [loaded, setLoaded] = useState(false);
  const [saving, setSaving] = useState(false);
  const [saveErr, setSaveErr] = useState<string | null>(null);
  const [saveNote, setSaveNote] = useState<string | null>(null);
  // The selection write is admin-gated server-side. The picker stays editable
  // and a refusal is reported as an honest message rather than a silently
  // reverted toggle — the operator must know the change did not take.
  const [canEdit, setCanEdit] = useState(true);

  const [unassessed, setUnassessed] = useState<SecFinding[] | null>(null);
  const [unassessedErr, setUnassessedErr] = useState<string | null>(null);

  useEffect(() => {
    let alive = true;
    Promise.all([api.securityFrameworks(), api.securityCompliance()])
      .then(([cat, cmp]) => {
        if (!alive) return;
        setCatalog(cat);
        setCompliance(cmp);
        setErr(null);
      })
      .catch((e: unknown) => {
        if (alive) setErr(operatorError(e, "Compliance status could not be loaded."));
      })
      .finally(() => { if (alive) setLoaded(true); });
    return () => { alive = false; };
  }, []);

  useEffect(() => {
    let alive = true;
    api.securityFindings({ current: true, status: UNASSESSED_STATUSES })
      .then((page) => {
        if (!alive) return;
        setUnassessed(Array.isArray(page?.items) ? page.items : []);
        setUnassessedErr(null);
      })
      .catch((e: unknown) => {
        if (!alive) return;
        // Never fall back to the empty state: "we could not ask" and "nothing
        // was unassessed" are opposite facts.
        setUnassessed(null);
        setUnassessedErr(operatorError(e, "The unassessed controls could not be loaded."));
      });
    return () => { alive = false; };
  }, []);

  const reasons = useMemo(() => unassessedReasons(unassessed ?? []), [unassessed]);

  const save = useCallback(async (updates: SecFrameworkToggle[]) => {
    if (updates.length === 0) return;
    setSaving(true); setSaveErr(null); setSaveNote(null);
    try {
      const cat = await api.securityFrameworksUpdate(updates);
      setCatalog(cat);
      setCompliance(await api.securityCompliance());
      setSaveNote(`${updates.length} framework${updates.length === 1 ? "" : "s"} updated.`);
    } catch (e) {
      setSaveErr(operatorError(e, "The framework selection was not saved."));
      const status = (e as { status?: number })?.status;
      if (status === 401 || status === 403) setCanEdit(false);
    } finally {
      setSaving(false);
    }
  }, []);

  return (
    <div className="sec dm-board">
      <div className="sec-toolbar">
        <Segmented
          value={tab}
          onChange={setTab}
          options={[
            { value: "frameworks" as SubView, label: "Frameworks" },
            { value: "drift" as SubView, label: "Drift & baselines" },
          ]}
          ariaLabel="Compliance view"
        />
      </div>

      {tab === "drift" ? (
        <ComplianceMonitoring />
      ) : err ? (
        <div className="empty" role="alert" style={{ color: "var(--bad)" }}>{err}</div>
      ) : !loaded ? (
        <div className="empty" role="status">Loading…</div>
      ) : (
        <>
          <ComplianceFrameworks
            catalog={catalog}
            compliance={compliance}
            onSave={canEdit ? save : undefined}
            saving={saving}
            saveError={saveErr}
            saveNote={saveNote}
          />

          <Group title="Controls that reached no verdict, and why" hue="#8b5cf6">
            <Panel title="Unassessed controls">
              {unassessedErr ? (
                <div className="empty" role="alert" style={{ color: "var(--bad)" }}>{unassessedErr}</div>
              ) : reasons.length === 0 ? (
                <div className="empty" role="status">
                  No control reached this scan without a verdict.
                </div>
              ) : (
                <>
                  <ul
                    aria-label="Unassessed controls by reason"
                    style={{ listStyle: "none", margin: 0, padding: 0, display: "flex", flexDirection: "column", gap: 8 }}
                  >
                    {reasons.map((r) => (
                      <li key={r.reason} className="sec-row" style={{ display: "flex", gap: 10, alignItems: "flex-start" }}>
                        <span className={`sec-stripe ${r.recorded ? "" : "t-warn"}`} aria-hidden="true" />
                        <div className="main">
                          <b>{r.reason}</b>
                          <div className="sub">
                            {r.count.toLocaleString()} control{r.count === 1 ? "" : "s"}
                          </div>
                        </div>
                      </li>
                    ))}
                  </ul>
                  <p className="mini-meta" style={{ marginBottom: 0 }} role="status">
                    These are counted in no passing share: an unassessed control is UNKNOWN, not compliant.
                  </p>
                </>
              )}
            </Panel>
          </Group>
        </>
      )}
    </div>
  );
}

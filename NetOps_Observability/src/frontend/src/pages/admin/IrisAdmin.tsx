// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// IrisAdmin — Administration → Iris, ONE page with tabs (owner decision
// 2026-11-19, "consolidate"). Everything an administrator configures about
// Iris, in one place:
//
//   AI models        — the model connection, per-workspace access and limits,
//                      Iris in Slack and Teams (was: the Iris drawer's inline
//                      "AI models" panel; the guided Connect-a-model step that
//                      sat on Platform → Features).
//   Knowledge        — network context, the names your team uses, runbooks
//                      (was: Network Context and Runbooks leaves; steps 1–3 of
//                      the drawer's Iris vocabulary).
//   Learning & review — learning proposals, recent questions, how Iris decided,
//                      what Iris could not answer.
//   Investigations   — investigations on their own, actions Iris proposes.
//
// Moved, never removed: every section is the component that rendered it before,
// making the same calls under the same permissions and approval rules. A
// section the caller cannot use says so; nothing is hidden on an error.
// Deep links: #/admin/iris/<tab>. The old leaves (#/admin/network-context,
// #/admin/iris-runbooks, #/admin/iris-learning) are aliases in nav.tsx.

import { useCallback, useEffect, useState, type ReactNode } from "react";
import {
  api,
  type AIModelsState,
  type AITenantConfig,
  type AITenantRow,
  type CopilotConfig,
} from "../../services/api";
import { hasAIEntitlement } from "../../lib/aiEntitlements";
import AdminPageHeader from "../../components/admin/AdminPageHeader";
import IrisModelSettings from "../../iris/IrisModelSettings";
import ConnectModelStep from "../../iris/ConnectModelStep";
import IrisVocabulary from "../../components/IrisVocabulary";
import NetworkContext from "./NetworkContext";
import TenantRunbooks from "./TenantRunbooks";
import IrisLearning from "./IrisLearning";
import ErrorBoundary from "../../components/ErrorBoundary";

export const IRIS_ADMIN_TABS = [
  { id: "ai-models", label: "AI models" },
  { id: "knowledge", label: "Knowledge" },
  { id: "review", label: "Learning & review" },
  { id: "investigations", label: "Investigations" },
] as const;

export type IrisAdminTab = (typeof IRIS_ADMIN_TABS)[number]["id"];

export const IRIS_ADMIN_ROUTE = "#/admin/iris";

/** The tab a hash names (#/admin/iris/<tab>); an unknown or missing one is the first tab. */
export function irisAdminTab(hash: string): IrisAdminTab {
  const sub = hash.replace(/^#\/?/, "").split("?")[0].split("/")[2] ?? "";
  return (IRIS_ADMIN_TABS.find((t) => t.id === sub)?.id ?? "ai-models") as IrisAdminTab;
}

/** The hash that opens one tab. */
export function irisAdminHref(tab: IrisAdminTab): string {
  return `${IRIS_ADMIN_ROUTE}/${tab}`;
}

/** What the page read once, shared by every tab. */
type IrisAdminState = {
  cfg: CopilotConfig | null;
  tcfg: AITenantConfig | null;
  tenantRows: AITenantRow[] | null;
  mcpFeature: boolean;
  probesFeature: boolean;
  aiModels: AIModelsState | undefined;
  nlqEntitled: boolean;
  loaded: boolean;
};

// Each section keeps its own error boundary (as DiscoveryHub does): a section
// that fails shows its own report and the rest of the page keeps working. The
// failure is shown, never hidden.
function Section({ tab, label, children }: { tab: IrisAdminTab; label: string; children: ReactNode }) {
  return (
    <ErrorBoundary label={`Iris · ${label}`} route={irisAdminHref(tab)} resetKey={tab}>
      {children}
    </ErrorBoundary>
  );
}

export default function IrisAdmin() {
  const [tab, setTab] = useState<IrisAdminTab>(() => irisAdminTab(window.location.hash));
  useEffect(() => {
    const read = () => setTab(irisAdminTab(window.location.hash));
    window.addEventListener("hashchange", read);
    return () => window.removeEventListener("hashchange", read);
  }, []);
  const open = (t: IrisAdminTab) => {
    setTab(t);
    if (window.location.hash !== irisAdminHref(t)) window.location.hash = irisAdminHref(t);
  };

  const [cfg, setCfg] = useState<CopilotConfig | null>(null);
  const [tcfg, setTcfg] = useState<AITenantConfig | null>(null);
  const [tenantRows, setTenantRows] = useState<AITenantRow[] | null>(null);
  const [st, setSt] = useState<Omit<IrisAdminState, "cfg" | "tcfg" | "tenantRows">>({
    mcpFeature: false, probesFeature: false, aiModels: undefined, nlqEntitled: false, loaded: false,
  });
  // The guided step replaces the model form until a key is saved or the
  // administrator chooses "Not now".
  const [stepDismissed, setStepDismissed] = useState(false);

  // The same reads the drawer made: the platform owner gets the platform
  // settings and the per-workspace list, a tenant administrator its own
  // workspace settings. A call the caller is not allowed simply stays null.
  const load = useCallback(() => {
    void Promise.allSettled([
      api.features().then((c) => setSt((s) => ({ ...s, aiModels: c?.ai_models, nlqEntitled: hasAIEntitlement(c, "ai.nlquery") }))),
      api.copilotConfig().then((c) => {
        setCfg(c);
        return api.aiTenants().then((r) => {
          setTenantRows(r.tenants ?? []);
          setSt((s) => ({ ...s, mcpFeature: !!r.mcp_feature, probesFeature: Boolean(r.probes_feature) }));
        }).catch(() => setTenantRows(null));
      }).catch(() => setCfg(null)),
      api.aiTenantConfig().then(setTcfg).catch(() => setTcfg(null)),
    ]).then(() => setSt((s) => ({ ...s, loaded: true })));
  }, []);
  useEffect(load, [load]);

  // The workspace-scoped Iris tools (names, recent questions, how Iris
  // decided, Slack and Teams, investigations, actions) are what the drawer
  // showed a workspace administrator with the assistant on. Same condition.
  const workspaceTools = !!tcfg && tcfg.assistant_enabled && st.nlqEntitled;
  const workspaceNote = !st.loaded
    ? "Loading…"
    : !tcfg
      ? "These are per workspace. Open a workspace to see them."
      : !tcfg.assistant_enabled
        ? "Iris is turned off for this workspace."
        : "Iris's query tools are not in this licence.";

  const showStep = !!cfg && !cfg.key_present && !stepDismissed;

  return (
    <div className="adm iris-admin">
      <AdminPageHeader icon="copilot" title="Iris" sub="Models, knowledge and review." topic="admin.iris" />

      <nav className="iris-admin-tabs" role="tablist" aria-label="Iris settings">
        {IRIS_ADMIN_TABS.map((t) => (
          <button key={t.id} type="button" role="tab" id={`iris-tab-${t.id}`}
            aria-selected={tab === t.id} aria-controls="iris-admin-panel"
            className="iris-admin-tab" data-testid={`iris-tab-${t.id}`} onClick={() => open(t.id)}>
            {t.label}
          </button>
        ))}
      </nav>

      <div id="iris-admin-panel" role="tabpanel" aria-labelledby={`iris-tab-${tab}`} data-tab={tab}
        style={{ fontSize: 14, marginTop: 12 }}>
        {tab === "ai-models" && (
          <>
            <Section tab="ai-models" label="AI models">
              <section className="card disc-card" style={{ marginBottom: 16 }}>
                <div className="disc-head"><h2 className="disc-title">AI models</h2></div>
                {showStep && (
                  <ConnectModelStep onSaved={load} onDismiss={() => setStepDismissed(true)} />
                )}
                {st.loaded && (
                  <IrisModelSettings
                    cfg={cfg} setCfg={setCfg} tcfg={tcfg} setTcfg={setTcfg}
                    tenantRows={tenantRows} setTenantRows={setTenantRows}
                    mcpFeature={st.mcpFeature} probesFeature={st.probesFeature} aiModels={st.aiModels}
                    onReload={load} hideModelForm={showStep} />
                )}
              </section>
            </Section>
            <Section tab="ai-models" label="Slack and Teams">
              <section className="card disc-card" style={{ marginBottom: 16 }}>
                <div className="disc-head"><h2 className="disc-title">Slack and Teams</h2></div>
                {workspaceTools ? <IrisVocabulary part="chat" /> : <p className="disc-desc">{workspaceNote}</p>}
              </section>
            </Section>
          </>
        )}

        {tab === "knowledge" && (
          <>
            <Section tab="knowledge" label="Network context"><NetworkContext /></Section>
            <Section tab="knowledge" label="Names and questions">
              <section className="card disc-card" style={{ marginBottom: 16 }}>
                <div className="disc-head"><h2 className="disc-title">Names and questions</h2></div>
                {workspaceTools ? <IrisVocabulary part="knowledge" /> : <p className="disc-desc">{workspaceNote}</p>}
              </section>
            </Section>
            <Section tab="knowledge" label="Runbooks"><TenantRunbooks /></Section>
          </>
        )}

        {tab === "review" && (
          <>
            <Section tab="review" label="Learning"><IrisLearning /></Section>
            <Section tab="review" label="Questions and decisions">
              <section className="card disc-card" style={{ marginBottom: 16 }}>
                <div className="disc-head"><h2 className="disc-title">Questions and decisions</h2></div>
                {workspaceTools ? <IrisVocabulary part="review" /> : <p className="disc-desc">{workspaceNote}</p>}
              </section>
            </Section>
          </>
        )}

        {tab === "investigations" && (
          <Section tab="investigations" label="Investigations">
            <section className="card disc-card" style={{ marginBottom: 16 }}>
              <div className="disc-head"><h2 className="disc-title">Investigations</h2></div>
              {workspaceTools ? <IrisVocabulary part="investigations" /> : <p className="disc-desc">{workspaceNote}</p>}
            </section>
          </Section>
        )}
      </div>
    </div>
  );
}

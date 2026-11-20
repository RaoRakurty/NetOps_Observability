// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// IrisModelSettings — Iris's AI models: the platform model connection
// (provider, key, default/quick/deep models, Test connection), the
// per-workspace access list (Assistant / Investigations / MCP / Active probes,
// and the per-workspace guardrails), and a tenant administrator's own
// workspace model. Moved, unchanged in behaviour, out of the Iris drawer's
// inline "AI models" panel into Administration → Iris → AI models (owner
// decision 2026-11-19, "consolidate"). Every call is the one the drawer made:
// copilotConfig / setCopilotConfig / testCopilotConfig (platform owner),
// aiTenants / setAITenantAccess (platform owner), aiTenantConfig /
// setAITenantConfig / testAITenantConfig (tenant administrator). Whichever the
// caller is not allowed simply stays null on the page, and this form says so.

import { useState, type CSSProperties, type Dispatch, type SetStateAction } from "react";
import {
  api,
  type AIModelsState,
  type AITenantConfig,
  type AITenantRow,
  type CopilotConfig,
  type ProviderTestResult,
} from "../services/api";
import { announceModelsChanged, applyRecommended, saveWarnings, testResultText, tierTestLines, GEMINI_FREE_TIER_WARNING } from "./connectModel";
import { investigationsHint } from "./aiModelsBanner";
import { operatorError } from "../lib/errors";
import Icon from "../components/Icon";

// Provider tiles — the vendor name and the model family each one runs. Stated
// facts about the provider, kept out of the JSX so one list is the authority.
const PROVIDER_VENDOR: Record<string, string> = {
  anthropic: "Anthropic",
  openai: "OpenAI",
  gemini: "Google",
};
// Each provider tile carries one of the platform's module accents (the colours
// the rail uses), so the models view reads in the same palette as every other
// section. Theme tokens, not vendor brand colours.
const PROVIDER_TINT: Record<string, string> = {
  anthropic: "var(--mod-copilot)",
  openai: "var(--mod-fleet)",
  gemini: "var(--mod-network)",
};
const PROVIDER_MODEL: Record<string, string> = {
  anthropic: "Claude",
  openai: "GPT",
  gemini: "Gemini",
};


// The plain risk statement for Iris's active probes (N-I3), shown wherever the
// opt-in can be changed and repeated in the confirmation before it turns on.
export const PROBE_RISK =
  "Iris's troubleshooting methods may send a short test from this Correlix server — 3 pings, one traceroute, one DNS lookup or one web request — to this workspace's own devices and declared probes. Nothing is sent from a customer device, and never to an address the workspace does not own.";

export type IrisModelSettingsProps = {
  cfg: CopilotConfig | null;
  setCfg: Dispatch<SetStateAction<CopilotConfig | null>>;
  tcfg: AITenantConfig | null;
  setTcfg: Dispatch<SetStateAction<AITenantConfig | null>>;
  tenantRows: AITenantRow[] | null;
  setTenantRows: Dispatch<SetStateAction<AITenantRow[] | null>>;
  mcpFeature: boolean;
  probesFeature: boolean;
  aiModels: AIModelsState | undefined;
  /** Re-read the stored settings (Discard changes). */
  onReload: () => void;
  /** The platform model form is replaced by the guided Connect-a-model step. */
  hideModelForm?: boolean;
};

export default function IrisModelSettings({
  cfg, setCfg, tcfg, setTcfg, tenantRows, setTenantRows, mcpFeature, probesFeature, aiModels, onReload, hideModelForm = false,
}: IrisModelSettingsProps) {
  const [keyDraft, setKeyDraft] = useState("");
  const [tKeyDraft, setTKeyDraft] = useState("");
  const [savingCfg, setSavingCfg] = useState(false);
  // C3: the latest "Test connection" verdict shown under the settings form.
  const [cfgTest, setCfgTest] = useState<ProviderTestResult | null>(null);
  const [testingCfg, setTestingCfg] = useState(false);
  // Warn-before-save (never block): tier models that failed the latest test.
  const [saveWarn, setSaveWarn] = useState<string[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [savedNote, setSavedNote] = useState<string | null>(null);

  const discard = () => {
    setKeyDraft(""); setTKeyDraft(""); setCfgTest(null); setSaveWarn([]); setError(null); setSavedNote(null);
    onReload();
  };

  const modelChoices = cfg?.model_suggestions?.[cfg.provider] ?? [];

  const saveCfg = async (anyway = false) => {
    if (!cfg) return;
    setSavedNote(null);
    // A model that failed its last test is saved only after a second click:
    // the operator is told, never stopped (owner 2026-11-12).
    const warn = saveWarnings(cfgTest, { provider: cfg.provider, model: cfg.model, model_fast: cfg.model_fast ?? "", model_strong: cfg.model_strong ?? "" }, cfg.recommended);
    if (!anyway && warn.length > 0) {
      setSaveWarn(warn);
      return;
    }
    setSaveWarn([]);
    setSavingCfg(true);
    setError(null);
    try {
      const saved = await api.setCopilotConfig({
        provider: cfg.provider,
        model: cfg.model,
        model_fast: cfg.model_fast ?? "",
        model_strong: cfg.model_strong ?? "",
        ...(keyDraft.trim() ? { key: keyDraft.trim() } : {}),
      });
      setCfg((c) => ({ ...(c ?? saved), ...saved }));
      setKeyDraft("");
      setSavedNote("Saved.");
      announceModelsChanged();
    } catch (e) {
      setError(operatorError(e, "The settings could not be saved."));
    } finally {
      setSavingCfg(false);
    }
  };

  // C3 "Test connection": the platform admin tests the platform key (or the
  // pasted draft); a workspace admin tests their own workspace key only. The
  // server never stores the key from a test and returns only a verdict.
  const testCfg = async (scope: "platform" | "workspace") => {
    setTestingCfg(true);
    setError(null);
    try {
      if (scope === "platform" && cfg) {
        // Every tier model of the form is tested (a blank one as its
        // recommended model), each with its own verdict and latency.
        setCfgTest(await api.testCopilotConfig({
          provider: cfg.provider, key: keyDraft.trim() || undefined,
          model: cfg.model.trim(), model_fast: (cfg.model_fast ?? "").trim(), model_strong: (cfg.model_strong ?? "").trim(),
        }));
        setSaveWarn([]);
      } else if (tcfg) {
        setCfgTest(await api.testAITenantConfig({
          provider: tcfg.provider || undefined, key: tKeyDraft.trim() || undefined,
          model: (tcfg.model || "").trim(), model_fast: (tcfg.model_fast ?? "").trim(), model_strong: (tcfg.model_strong ?? "").trim(),
        }));
      }
    } catch (e) {
      setCfgTest(null);
      setError(operatorError(e, "The connection test could not run."));
    } finally {
      setTestingCfg(false);
    }
  };

  // Save the tenant admin's own workspace settings (key is write-only: a blank
  // draft leaves the stored key untouched).
  const saveTCfg = async () => {
    if (!tcfg) return;
    setSavedNote(null);
    setSavingCfg(true);
    setError(null);
    try {
      const saved = await api.setAITenantConfig({
        provider: tcfg.provider,
        model: tcfg.model,
        model_fast: tcfg.model_fast ?? "",
        model_strong: tcfg.model_strong ?? "",
        no_platform_key: tcfg.no_platform_key,
        ...(tKeyDraft.trim() ? { key: tKeyDraft.trim() } : {}),
      });
      setTcfg(saved);
      setTKeyDraft("");
      setSavedNote("Saved.");
      announceModelsChanged();
    } catch (e) {
      setError(operatorError(e, "The settings could not be saved."));
    } finally {
      setSavingCfg(false);
    }
  };

  // Flip one workspace's AI access / guardrails (platform owner) — optimistic row update.
  const setAccess = async (row: AITenantRow, patch: Partial<Pick<AITenantRow, "assistant_enabled" | "investigations_enabled" | "mcp_enabled" | "max_calls" | "daily_tokens" | "probes_enabled">>) => {
    // Turning active probes on is a deliberate act: the risk is stated and confirmed first.
    if (patch.probes_enabled && !window.confirm(PROBE_RISK + "\n\nTurn active probes on for " + (row.name || row.tenant_id) + "?")) return;
    const next = { ...row, ...patch };
    setTenantRows((rows) => (rows ?? []).map((r) => (r.tenant_id === row.tenant_id ? next : r)));
    try {
      await api.setAITenantAccess(row.tenant_id, {
        assistant_enabled: next.assistant_enabled,
        investigations_enabled: next.investigations_enabled,
        // Sent only when this edit touched it, so a row loaded from an older
        // server never switches MCP off by omission.
        ...("mcp_enabled" in patch ? { mcp_enabled: !!next.mcp_enabled } : {}),
        max_calls: next.max_calls || 0,
        daily_tokens: next.daily_tokens || 0,
        ...(patch.probes_enabled !== undefined
          ? { probes_enabled: patch.probes_enabled, probes_acknowledged: patch.probes_enabled }
          : {}),
      });
    } catch (e) {
      setTenantRows((rows) => (rows ?? []).map((r) => (r.tenant_id === row.tenant_id ? row : r)));
      setError(operatorError(e, "That workspace's access could not be changed."));
    }
  };

  if (!cfg && !tcfg) {
    return (
      <p className="disc-desc" data-testid="iris-models-none" style={{ fontSize: 14 }}>
        Only an administrator can change Iris&apos;s AI models. Ask your administrator if Iris should use a model for this workspace.
      </p>
    );
  }

  return (
    <div className="iris-models" data-testid="iris-model-settings">
      {error && <p role="alert" style={{ color: "var(--bad)", fontSize: 14, margin: "0 0 8px" }}>{error}</p>}
      {savedNote && <p role="status" style={{ color: "var(--good)", fontSize: 14, margin: "0 0 8px" }}>{savedNote}</p>}
      {cfg && (
        <div className="op-settings">
          {!hideModelForm && (
          <>
          <p style={{ color: "var(--muted)", fontSize: 14, margin: "0 0 10px" }}>
            Pick a provider and paste its API key. The key is encrypted at rest and never shown again.
          </p>
          <label className="op-field">
            <span>
              {cfg.provider === "openai" ? "OpenAI" : cfg.provider === "gemini" ? "Gemini" : "Anthropic"} API key{" "}
              {cfg.key_present
                ? <span className="badge good" style={{ fontSize: 14 }}>{cfg.key_source === "env" ? "set by installer" : "saved"}</span>
                : <span className="badge warn" style={{ fontSize: 14 }}>not set</span>}
            </span>
            <input
              type="password"
              value={keyDraft}
              onChange={(e) => setKeyDraft(e.target.value)}
              placeholder={cfg.key_present ? "Saved — leave blank to keep" : "Paste API key"}
              autoComplete="off"
              disabled={cfg.key_source === "env"}
            />
            {cfg.key_source === "env" && (
              <span style={{ color: "var(--muted)", fontSize: 14 }}>Managed by your installation.</span>
            )}
          </label>
          <div className="op-field">
            <span>Provider</span>
            <div className="op-tiles">
              {(cfg.providers ?? ["anthropic", "openai", "gemini"]).map((pv) => (
                <button type="button" key={pv}
                  className={`op-tile${cfg.provider === pv ? " on" : ""}`}
                  onClick={() => { setCfg({ ...cfg, ...applyRecommended(pv, cfg.recommended, cfg) }); setCfgTest(null); }}>
                  <span className="op-tile-icon" style={{ "--tile": PROVIDER_TINT[pv] ?? "var(--accent)" } as CSSProperties}>
                    <Icon name="model" size={16} />
                  </span>
                  <span className="op-tile-text">
                    <span className="op-tile-name">{PROVIDER_VENDOR[pv] ?? pv}</span>
                    <span className="op-tile-sub">{PROVIDER_MODEL[pv] ?? ""}</span>
                  </span>
                </button>
              ))}
            </div>
          </div>
          {cfg.provider === "gemini" && <p className="connect-warn" role="note">{GEMINI_FREE_TIER_WARNING}</p>}
          <details className="op-advanced">
          <summary>Advanced: choose the models</summary>
          <div className="op-field">
            <span>Model</span>
            <input className="op-modelinput" list="copilot-models" value={cfg.model} onChange={(e) => setCfg({ ...cfg, model: e.target.value })} placeholder="Default model" />
            <datalist id="copilot-models">{modelChoices.map((m) => <option key={m} value={m} />)}</datalist>
            {modelChoices.length > 0 && (
              <div className="op-modelchips">
                {modelChoices.slice(0, 4).map((m) => (
                  <button type="button" key={m} className={`op-modelchip${cfg.model === m ? " on" : ""}`} onClick={() => setCfg({ ...cfg, model: m })}>{m}</button>
                ))}
              </div>
            )}
          </div>
          <TierModelFields
            fast={cfg.model_fast ?? ""} strong={cfg.model_strong ?? ""}
            onChange={(t) => setCfg({ ...cfg, model_fast: t.fast, model_strong: t.strong })} />
          </details>
          <div style={{ display: "flex", gap: 8, marginTop: 4 }}>
            <button className="dash-btn accent" onClick={() => { void saveCfg(saveWarn.length > 0); }} disabled={savingCfg}>
              {savingCfg ? "Saving…" : saveWarn.length > 0 ? "Save anyway" : "Save"}
            </button>
            <button className="dash-btn" onClick={() => testCfg("platform")} disabled={testingCfg || (!cfg.key_present && !keyDraft.trim())}>
              {testingCfg ? "Testing…" : "Test connection"}
            </button>
            <button className="dash-btn" onClick={discard} disabled={savingCfg}>Discard changes</button>
          </div>
          {saveWarn.length > 0 && (
            <div className="op-save-warn" role="alert" data-testid="iris-save-warn">
              {saveWarn.map((w) => <p key={w} style={{ margin: 0 }}>{w}</p>)}
              <p style={{ margin: 0 }}>Iris falls back to the evidence answer when a model fails. Save anyway, or pick a model that passed.</p>
            </div>
          )}
          <ConnectionTestLine result={cfgTest ?? cfg.last_test ?? null} />

          </>
          )}

          {/* Per-workspace access (platform owner): which customer workspaces get
              the assistant, and which may run AI Investigations (tool lookups). */}
          {tenantRows && tenantRows.length > 0 && (
            <div style={{ marginTop: 14, borderTop: "1px solid var(--line)", paddingTop: 10 }}>
              <div style={{ fontSize: 14, fontWeight: 500, marginBottom: 2 }}>Workspace access</div>
              <p style={{ color: "var(--muted)", fontSize: 14, margin: "0 0 8px" }}>
                Assistant answers are always scoped to each workspace&apos;s own data. Investigations
                let the AI run governed, read-only lookups before answering.
              </p>
              <p data-testid="iris-probes-risk" style={{ color: "var(--muted)", fontSize: 14, margin: "0 0 8px" }}>
                Active probes: {PROBE_RISK}{" "}
                {probesFeature ? "Each workspace is off until it is turned on here." : "They are off for every workspace until a platform administrator turns on “Iris active probes” on the Features page."}
              </p>
              {investigationsHint(aiModels) && (
                <p data-testid="iris-investigations-hint" style={{ color: "var(--warn)", fontSize: 14, margin: "0 0 8px" }}>
                  {investigationsHint(aiModels)}
                </p>
              )}
              {tenantRows.map((row) => (
                <div key={row.tenant_id} style={{ display: "flex", alignItems: "center", gap: 10, padding: "4px 0", fontSize: 14 }}>
                  <span style={{ flex: 1, minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }} title={row.tenant_id}>
                    {row.name || row.tenant_id}
                    {row.key_present && <span className="badge good" style={{ fontSize: 14, marginLeft: 6 }}>own key</span>}
                    {row.no_platform_key && !row.key_present && <span className="badge warn" style={{ fontSize: 14, marginLeft: 6 }}>own key required</span>}
                  </span>
                  <label style={{ display: "inline-flex", alignItems: "center", gap: 4, color: "var(--muted)" }}>
                    <input type="checkbox" checked={row.assistant_enabled}
                      onChange={(e) => setAccess(row, { assistant_enabled: e.target.checked })} /> Assistant
                  </label>
                  <label style={{ display: "inline-flex", alignItems: "center", gap: 4, color: "var(--muted)" }}>
                    <input type="checkbox" checked={row.investigations_enabled} disabled={!row.assistant_enabled}
                      onChange={(e) => setAccess(row, { investigations_enabled: e.target.checked })} /> Investigations
                  </label>
                  {/* Read-only MCP (N-I5): an outside AI assistant may use Iris's lookups with a workspace API key. */}
                  <label style={{ display: "inline-flex", alignItems: "center", gap: 4, color: "var(--muted)" }}
                    title={mcpFeature ? "Let an outside AI assistant use Iris's read-only lookups with an API key that has the iris:mcp scope" : "Turn on Iris over MCP under Platform → Features first"}>
                    <input type="checkbox" data-testid="iris-mcp-toggle" checked={!!row.mcp_enabled} disabled={!mcpFeature}
                      onChange={(e) => setAccess(row, { mcp_enabled: e.target.checked })} /> MCP
                  </label>
                  <label style={{ display: "inline-flex", alignItems: "center", gap: 4, color: "var(--muted)" }}
                    title={probesFeature ? "Let Iris's methods send a short test from Correlix to this workspace's own targets" : "Turn on “Iris active probes” on the Features page first"}>
                    <input type="checkbox" data-testid="iris-probes-toggle" checked={Boolean(row.probes_enabled)}
                      disabled={!probesFeature || !row.investigations_enabled}
                      onChange={(e) => setAccess(row, { probes_enabled: e.target.checked })} /> Active probes
                  </label>
                  {/* Per-workspace spend guardrails — blank = platform default. */}
                  <input type="number" min={0} max={8} value={row.max_calls || ""}
                    title="Lookups per question (empty = platform default)"
                    placeholder="4" disabled={!row.investigations_enabled}
                    style={{ width: 44, fontSize: 14 }}
                    onChange={(e) => setAccess(row, { max_calls: Math.max(0, Math.min(8, Number(e.target.value) || 0)) })} />
                  <input type="number" min={0} step={50000} value={row.daily_tokens || ""}
                    title="AI tokens per day (empty = platform default)"
                    placeholder="250000" disabled={!row.assistant_enabled}
                    style={{ width: 84, fontSize: 14 }}
                    onChange={(e) => setAccess(row, { daily_tokens: Math.max(0, Number(e.target.value) || 0) })} />
                </div>
              ))}
              <div style={{ fontSize: 14, color: "var(--muted)", marginTop: 4 }}>
                Guardrails per workspace: lookups per question · AI tokens per day. Blank = platform defaults.
              </div>
            </div>
          )}
        </div>
      )}

      {/* Workspace settings — tenant admins manage their own AI service here:
          bring their own provider key (write-only, encrypted at rest) or ride the
          platform AI service when it's available. */}
      {!cfg && tcfg && (
        <div className="op-settings">
          <p style={{ color: "var(--muted)", fontSize: 14, margin: "0 0 10px" }}>
            {tcfg.assistant_enabled
              ? "Your workspace's AI. Keys are encrypted and never shown again."
              : "AI is turned off for this workspace — ask your administrator."}
          </p>
          <label className="op-field">
            <span>
              {tcfg.provider === "openai" ? "OpenAI" : tcfg.provider === "gemini" ? "Gemini" : "Anthropic"} API key{" "}
              {tcfg.key_present
                ? <span className="badge good" style={{ fontSize: 14 }}>configured</span>
                : <span className="badge warn" style={{ fontSize: 14 }}>not set</span>}
            </span>
            <input
              type="password"
              value={tKeyDraft}
              onChange={(e) => setTKeyDraft(e.target.value)}
              placeholder={tcfg.key_present ? "Saved — leave blank to keep" : "Paste API key"}
              autoComplete="off"
            />
          </label>
          <div className="op-field">
            <span>Provider</span>
            <div className="op-tiles">
              {(tcfg.providers ?? ["anthropic", "openai", "gemini"]).map((pv) => (
                <button type="button" key={pv}
                  className={`op-tile${tcfg.provider === pv || (!tcfg.provider && pv === "gemini") ? " on" : ""}`}
                  onClick={() => { setTcfg({ ...tcfg, ...applyRecommended(pv, tcfg.recommended, tcfg) }); setCfgTest(null); }}>
                  <span className="op-tile-icon" style={{ "--tile": PROVIDER_TINT[pv] ?? "var(--accent)" } as CSSProperties}>
                    <Icon name="model" size={16} />
                  </span>
                  <span className="op-tile-text">
                    <span className="op-tile-name">{PROVIDER_VENDOR[pv] ?? pv}</span>
                    <span className="op-tile-sub">{PROVIDER_MODEL[pv] ?? ""}</span>
                  </span>
                </button>
              ))}
            </div>
          </div>
          {tcfg.provider === "gemini" && <p className="connect-warn" role="note">{GEMINI_FREE_TIER_WARNING}</p>}
          <details className="op-advanced">
          <summary>Advanced: choose the models</summary>
          <div className="op-field">
            <span>Model</span>
            <input className="op-modelinput" value={tcfg.model}
              onChange={(e) => setTcfg({ ...tcfg, model: e.target.value })}
              placeholder="Default model" />
          </div>
          <TierModelFields
            fast={tcfg.model_fast ?? ""} strong={tcfg.model_strong ?? ""}
            onChange={(t) => setTcfg({ ...tcfg, model_fast: t.fast, model_strong: t.strong })} />
          </details>
          {tcfg.platform_key_available && (
            <label style={{ display: "flex", alignItems: "center", gap: 6, fontSize: 14, color: "var(--muted)", margin: "2px 0 8px" }}>
              <input type="checkbox" checked={!tcfg.no_platform_key}
                onChange={(e) => setTcfg({ ...tcfg, no_platform_key: !e.target.checked })} />
              Use the platform AI service when no key is set
            </label>
          )}
          {/* N-I3: this workspace's own opt-in to active probes. */}
          {tcfg.investigations_enabled && (
            <div className="op-field" data-testid="iris-tenant-probes">
              <label style={{ display: "flex", alignItems: "center", gap: 6, fontSize: 14 }}>
                <input type="checkbox" checked={Boolean(tcfg.probes_enabled)} disabled={savingCfg || !tcfg.probes_available}
                  onChange={async (e) => {
                    const on = e.target.checked;
                    if (on && !window.confirm(PROBE_RISK + "\n\nTurn active probes on for this workspace?")) return;
                    setSavingCfg(true);
                    try {
                      setTcfg(await api.setAITenantConfig({ provider: tcfg.provider, model: tcfg.model, model_fast: tcfg.model_fast, model_strong: tcfg.model_strong,
                        no_platform_key: tcfg.no_platform_key, probes_enabled: on, probes_acknowledged: on }));
                    } catch (err) { setError(operatorError(err, "The active-probe setting could not be changed.")); }
                    finally { setSavingCfg(false); }
                  }} />
                Active probes
              </label>
              <p style={{ color: "var(--muted)", fontSize: 14, margin: "4px 0 0" }}>
                {tcfg.probes_available ? PROBE_RISK : "Not available yet: a platform administrator must turn on “Iris active probes” on the Features page."}
              </p>
            </div>
          )}
          <div style={{ display: "flex", gap: 8, marginTop: 4 }}>
            <button className="dash-btn accent" onClick={saveTCfg} disabled={savingCfg}>{savingCfg ? "Saving…" : "Save"}</button>
            {tcfg.key_present && (
              <button className="dash-btn" disabled={savingCfg}
                onClick={async () => {
                  setSavingCfg(true);
                  try { setTcfg(await api.setAITenantConfig({ provider: tcfg.provider, model: tcfg.model, no_platform_key: tcfg.no_platform_key, clear_key: true })); setTKeyDraft(""); }
                  catch (e) { setError(operatorError(e, "The key could not be removed.")); }
                  finally { setSavingCfg(false); }
                }}>Remove key</button>
            )}
            <button className="dash-btn" onClick={() => testCfg("workspace")} disabled={testingCfg || (!tcfg.key_present && !tKeyDraft.trim())}>
              {testingCfg ? "Testing…" : "Test connection"}
            </button>
            <button className="dash-btn" onClick={discard} disabled={savingCfg}>Discard changes</button>
          </div>
          <ConnectionTestLine result={cfgTest} />
        </div>
      )}
    </div>
  );
}


// TierModelFields — the optional model-router overrides. Iris answers quick
// look-ups with the "fast" model and multi-step investigations with the
// "strong" one; blank means "use the model above for everything", which is the
// behaviour of every install that never sets them.
// ConnectionTestLine — the latest "Test connection" verdict (C3/C6 "last
// tested"), in plain words; never the provider's own message.
export function ConnectionTestLine({ result }: { result: ProviderTestResult | null }) {
  if (!result) return null;
  return (
    <div className={`op-conn-test ${(result.tiers?.length ? result.tiers.every((t) => t.ok) : result.ok) ? "ok" : "bad"}`} role="status" data-testid="connection-test">
      {result.tiers?.length ? (result.tiers.every((t) => t.ok) ? "Every model answered." : "A model did not answer.") : testResultText(result)}
      {result.tested_at && <span className="op-conn-when"> Tested {result.tested_at.replace("T", " ").replace(/\.\d+Z$|Z$/, " UTC")}.</span>}
      {result.tiers?.length ? (
        <ul className="op-conn-tiers" data-testid="connection-test-tiers">
          {tierTestLines(result).map((l) => <li key={l.tier} className={l.ok ? "ok" : "bad"}>{l.text}</li>)}
        </ul>
      ) : null}
    </div>
  );
}

function TierModelFields({ fast, strong, onChange }: {
  fast: string;
  strong: string;
  onChange: (t: { fast: string; strong: string }) => void;
}) {
  return (
    <div className="op-field">
      <span>Model for quick answers <span style={{ color: "var(--muted)" }}>(optional)</span></span>
      <input className="op-modelinput" value={fast} aria-label="Model for quick answers"
        onChange={(e) => onChange({ fast: e.target.value, strong })}
        placeholder="Same as default model" />
      <span>Model for deep investigations <span style={{ color: "var(--muted)" }}>(optional)</span></span>
      <input className="op-modelinput" value={strong} aria-label="Model for deep investigations"
        onChange={(e) => onChange({ fast, strong: e.target.value })}
        placeholder="Same as default model" />
    </div>
  );
}

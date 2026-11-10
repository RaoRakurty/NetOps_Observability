// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// ConnectModelStep — the "Connect a model" setup step (tracker 337 plan C4,
// owner D5/D6). It lives in the product, not the installer: the key is sealed
// by the running API and the test needs the API's own egress path.
//
// Numbered steps in plain words (NOC-admin UI standard): pick a provider
// (Gemini pre-selected, with the free-tier data-use warning), paste the key,
// test it, save. The recommended models are filled in; "Advanced" lets an
// administrator change them. Shown to the platform administrator only — the
// config call is 403 for everyone else and the step renders nothing.

import { useEffect, useState } from "react";
import { api, type CopilotConfig, type ProviderTestResult } from "../services/api";
import { ConnectModelBanner } from "../components/ConnectModelBanner";
import {
  PROVIDER_ORDER,
  GEMINI_FREE_TIER_WARNING,
  applyRecommended,
  providerLabel,
  testResultText,
  writeDismissed,
  type ModelFields,
} from "./connectModel";

export default function ConnectModelStep() {
  const [cfg, setCfg] = useState<CopilotConfig | null>(null);
  const [fields, setFields] = useState<ModelFields | null>(null);
  const [key, setKey] = useState("");
  const [testing, setTesting] = useState(false);
  const [saving, setSaving] = useState(false);
  const [result, setResult] = useState<ProviderTestResult | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const [hidden, setHidden] = useState(false);

  useEffect(() => {
    let live = true;
    api.copilotConfig()
      .then((c) => {
        if (!live) return;
        setCfg(c);
        // D6: gemini pre-selected when nothing is configured yet.
        const provider = c.key_present && c.provider ? c.provider : "gemini";
        setFields(c.key_present && c.model
          ? { provider, model: c.model, model_fast: c.model_fast ?? "", model_strong: c.model_strong ?? "" }
          : applyRecommended(provider, c.recommended));
      })
      .catch(() => { if (live) setCfg(null); });
    return () => { live = false; };
  }, []);

  if (!cfg || !fields || hidden) return null;
  // Configured: only the budget notice (if any) remains.
  if (cfg.key_present) return <ConnectModelBanner platform={cfg} />;

  const pick = (p: string) => {
    setFields(applyRecommended(p, cfg.recommended, fields));
    setResult(null);
  };

  const test = async () => {
    setTesting(true);
    setMessage(null);
    try {
      setResult(await api.testCopilotConfig({ provider: fields.provider, key: key.trim() || undefined, model: fields.model_fast || fields.model || undefined }));
    } catch (e) {
      setResult(null);
      setMessage(e instanceof Error ? e.message : "The test could not run.");
    } finally {
      setTesting(false);
    }
  };

  const save = async () => {
    setSaving(true);
    setMessage(null);
    try {
      const saved = await api.setCopilotConfig({ ...fields, ...(key.trim() ? { key: key.trim() } : {}) });
      setCfg((c) => ({ ...(c ?? saved), ...saved }));
      setKey("");
      setMessage(saved.key_present ? "Saved. Iris now uses this model." : "Saved, but no key is stored yet.");
    } catch (e) {
      setMessage(e instanceof Error ? e.message : "Not saved.");
    } finally {
      setSaving(false);
    }
  };

  return (
    <section className="cc-panel connect-step" aria-labelledby="connect-step-h" data-testid="connect-model-step"
      style={{ padding: "14px 16px", marginBottom: 16, fontSize: 14 }}>
      <h3 id="connect-step-h" style={{ margin: "0 0 4px", fontSize: 16 }}>Connect a model</h3>
      <p style={{ margin: "0 0 10px", color: "var(--muted)" }}>
        Iris answers from your Correlix data with or without a model. A model adds full language understanding.
      </p>
      <ol style={{ margin: 0, paddingLeft: 20, lineHeight: 1.7 }}>
        <li>
          <span>Pick a provider.</span>
          <div className="op-tiles" role="radiogroup" aria-label="Provider" style={{ marginTop: 6 }}>
            {PROVIDER_ORDER.map((p) => (
              <button key={p} type="button" role="radio" aria-checked={fields.provider === p}
                className={`op-tile${fields.provider === p ? " on" : ""}`} onClick={() => pick(p)}>
                <span className="op-tile-text"><span className="op-tile-name">{providerLabel(p)}</span></span>
              </button>
            ))}
          </div>
          {fields.provider === "gemini" && (
            <p className="connect-warn" role="note" style={{ margin: "6px 0 0", color: "var(--warn)" }}>{GEMINI_FREE_TIER_WARNING}</p>
          )}
        </li>
        <li>
          <label className="op-field" style={{ display: "block" }}>
            <span>Paste the {providerLabel(fields.provider)} API key.</span>
            <input type="password" value={key} onChange={(e) => setKey(e.target.value)} autoComplete="off"
              placeholder="API key" aria-label="API key" style={{ display: "block", width: "100%", maxWidth: 420, marginTop: 4 }} />
          </label>
        </li>
        <li>
          <span>Test the connection. </span>
          <button type="button" className="dash-btn" onClick={test} disabled={testing || !key.trim()}>
            {testing ? "Testing…" : "Test connection"}
          </button>
          {result && (
            <p role="status" style={{ margin: "6px 0 0", color: result.ok ? "var(--good)" : "var(--bad)" }}>{testResultText(result)}</p>
          )}
        </li>
        <li>
          <span>Save. </span>
          <button type="button" className="dash-btn accent" onClick={save} disabled={saving || !key.trim()}>
            {saving ? "Saving…" : "Save"}
          </button>
        </li>
      </ol>
      <details style={{ marginTop: 10 }}>
        <summary>Advanced: choose the models</summary>
        <p style={{ margin: "6px 0", color: "var(--muted)" }}>Recommended models are filled in. Change them only if you need to.</p>
        {(["model", "model_fast", "model_strong"] as const).map((k) => (
          <label key={k} className="op-field" style={{ display: "block", marginBottom: 6 }}>
            <span>{k === "model" ? "Default model" : k === "model_fast" ? "Quick answers" : "Detailed answers"}</span>
            <input value={fields[k]} onChange={(e) => setFields({ ...fields, [k]: e.target.value })}
              aria-label={k === "model" ? "Default model" : k === "model_fast" ? "Quick answers model" : "Detailed answers model"}
              style={{ display: "block", width: "100%", maxWidth: 420 }} />
          </label>
        ))}
      </details>
      {message && <p role="alert" style={{ margin: "8px 0 0" }}>{message}</p>}
      <div style={{ marginTop: 10 }}>
        <button type="button" className="dash-btn" onClick={() => { writeDismissed(); setHidden(true); }}>Not now</button>
      </div>
    </section>
  );
}

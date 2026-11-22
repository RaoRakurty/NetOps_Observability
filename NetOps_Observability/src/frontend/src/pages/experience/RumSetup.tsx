// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// RumSetup.tsx — Digital Experience › Data Health › "Real-user setup".
//
// The owner's question was "how does a customer with hundreds of apps add the
// tag, and who does it?" The answer this page gives: the customer's engineer
// adds ONE tag at a shared layer (load balancer, reverse proxy, CDN edge or tag
// manager); Correlix hands them the exact rule and then shows, app by app,
// whether data is arriving. Correlix never applies a rule itself — it does not
// write to customer systems.
//
// Four numbered steps: get a key, the tag, inject it once, is it working.

import { useMemo, useState } from "react";
import { api } from "../../services/api";
import type { DemRumSourcesResponse } from "../../services/api";
import { fmtDateTime } from "../../lib/time";
import { httpFailure, operatorError } from "../../lib/errors";
import { Loading, LoadError, Panel } from "./honest";
import { useDemRead } from "./state";
import {
  applianceOrigin, cspLines, injectionRules, labelledBy, snippetTag, sourcesSummary,
} from "./rumSetup.model";

function copy(text: string): void {
  try {
    void navigator.clipboard?.writeText(text);
  } catch {
    /* no clipboard (an old browser, an insecure origin): the text stays selectable */
  }
}

function Code({ text, label }: { text: string; label: string }) {
  return (
    <div className="dx-code">
      <pre aria-label={label}><code>{text}</code></pre>
      <button type="button" className="btn-ghost" onClick={() => copy(text)}>Copy</button>
    </div>
  );
}

export default function RumSetup() {
  const origin = useMemo(() => applianceOrigin(window.location.href), []);
  const [key, setKey] = useState("");
  const [keyBusy, setKeyBusy] = useState(false);
  const [keyErr, setKeyErr] = useState("");
  const rules = useMemo(() => injectionRules(origin, key), [origin, key]);
  const [ruleId, setRuleId] = useState(rules[0].id);
  const rule = rules.find((r) => r.id === ruleId) ?? rules[0];
  // Started inside a promise: a failure of any kind, even a synchronous one,
  // is this step's error state and never breaks the Data Health tab around it.
  const sources = useDemRead<DemRumSourcesResponse>(() => Promise.resolve().then(() => api.demRumSources()), []);

  async function generate() {
    setKeyBusy(true);
    setKeyErr("");
    try {
      const res = await api.createApiKey({ label: "Real-user monitoring", scopes: ["ingest:experience"] });
      setKey(res.secret);
    } catch (e) {
      const f = httpFailure(e);
      setKeyErr(f && f.status === 403
        ? "Only an administrator can create keys. Ask one, or use Administration › API Access › Generate key (Ingest)."
        : operatorError(e, "The key could not be created."));
    } finally {
      setKeyBusy(false);
    }
  }

  return (
    <section className="dx-section" aria-label="Real-user monitoring setup" data-testid="rum-setup">
      <Panel title="Real-user setup" label="Real-user monitoring setup">
        <p>
          See what people experience in their browsers, app by app. Your team adds one tag in front
          of your apps; Correlix never changes your systems.
        </p>
        <ol className="dx-setup-steps">
          <li data-step="key">
            <h4>Get a key</h4>
            <p>The key can only send data. It cannot read anything, so it is safe inside a web page.</p>
            {key ? (
              <>
                <p role="status"><b>Copy it now: it is shown once.</b></p>
                <Code text={key} label="Ingest key" />
              </>
            ) : (
              <button type="button" className="btn" onClick={() => void generate()} disabled={keyBusy}>
                {keyBusy ? "Creating…" : "Generate a key"}
              </button>
            )}
            {keyErr && <p className="dx-error" role="alert">{keyErr}</p>}
          </li>

          <li data-step="tag">
            <h4>The tag</h4>
            <p>
              Without an app name, each page is named by its web address, so one tag covers every app.
            </p>
            <Code text={snippetTag(origin, key)} label="Real-user tag" />
          </li>

          <li data-step="inject">
            <h4>Add it once</h4>
            <p>Give your proxy or web team the rule for the layer in front of your apps.</p>
            <div className="dx-tabs" role="tablist" aria-label="Where to add the tag">
              {rules.map((r) => (
                <button key={r.id} type="button" role="tab" aria-selected={r.id === rule.id}
                  className={r.id === rule.id ? "dx-tab active" : "dx-tab"} onClick={() => setRuleId(r.id)}>
                  {r.label}
                </button>
              ))}
            </div>
            <p>{rule.where}</p>
            <Code text={rule.code} label={`${rule.label} rule`} />
            <p>
              Starting points: test in staging first. Apps with a strict content security policy also
              need these two lines:
            </p>
            <Code text={cspLines(origin).join(";\n") + ";"} label="Content security policy additions" />
            <p>
              Your Correlix administrator must also allow each app's web address to send data (the
              cross-origin allowlist). Until it does, browsers block the data.
            </p>
          </li>

          <li data-step="check">
            <h4>Is it working?</h4>
            {sources.status === "loading" && <Loading what="the real-user feeds" />}
            {sources.status === "error" && (
              <LoadError what="The real-user feeds" error={sources.error} onRetry={sources.reload} />
            )}
            {sources.status === "ready" && sources.data && (
              <RumSources data={sources.data} />
            )}
          </li>
        </ol>
      </Panel>
    </section>
  );
}

function RumSources({ data }: { data: DemRumSourcesResponse }) {
  return (
    <>
      <p role="status" data-testid="rum-summary">{sourcesSummary(data)}</p>
      {data.sources.length > 0 && (
        <table className="dx-table" aria-label="Apps sending real-user data">
          <thead>
            <tr><th>App</th><th>State</th><th>Last 24 hours</th><th>Last seen</th><th>Named</th></tr>
          </thead>
          <tbody>
            {data.sources.map((s) => (
              <tr key={s.app} data-state={s.state}>
                <td>{s.app}</td>
                <td>{s.state === "reporting" ? "Sending" : "Went quiet"}</td>
                <td>{s.events_24h} events · {s.page_views_24h} page views · {s.errors_24h} errors</td>
                <td>{fmtDateTime(s.last_seen)}</td>
                <td>{labelledBy(s.app_source)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </>
  );
}

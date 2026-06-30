import { useEffect, useRef, useState } from "react";
import {
  api,
  CopilotMessage,
  CopilotChatResponse,
  AnthropicChatResponse,
  OpenAIChatResponse,
  CopilotConfig,
  AiAnswer,
} from "../services/api";
import Icon from "../components/Icon";

// Opsis Ai — the in-app assistant chat. Posts to /api/copilot/chat (provider
// fallback chain server-side). Rendered inside the right-side drawer.
//
// Context is never pulled automatically: the "+ Logs" action attaches the most
// recent 50 log lines to the next turn. Assistant output is rendered as ESCAPED
// React text only (OWASP LLM02 — never dangerouslySetInnerHTML).

const SUGGESTIONS = [
  "Why might my edge router be dropping BGP sessions?",
  "How do I set up SNMP device discovery?",
  "How do I connect Okta SSO (OIDC)?",
  "Summarize the most recent critical alerts",
];

export default function Opsis() {
  const [enabled, setEnabled] = useState<boolean | null>(null);
  const [history, setHistory] = useState<CopilotMessage[]>([]);
  const [draft, setDraft] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const endRef = useRef<HTMLDivElement | null>(null);
  const taRef = useRef<HTMLTextAreaElement | null>(null);

  const [cfg, setCfg] = useState<CopilotConfig | null>(null);
  const [showSettings, setShowSettings] = useState(false);
  const [savingCfg, setSavingCfg] = useState(false);
  const [keyDraft, setKeyDraft] = useState("");

  useEffect(() => {
    api.credentials().then((c) => setEnabled(Boolean(c?.copilot))).catch(() => setEnabled(false));
    api.copilotConfig().then(setCfg).catch(() => setCfg(null));
  }, []);

  useEffect(() => {
    endRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [history.length, busy]);

  const modelChoices = cfg?.model_suggestions?.[cfg.provider] ?? [];

  const saveCfg = async () => {
    if (!cfg) return;
    setSavingCfg(true);
    setError(null);
    try {
      const saved = await api.setCopilotConfig({
        provider: cfg.provider,
        model: cfg.model,
        system: cfg.system,
        ...(keyDraft.trim() ? { key: keyDraft.trim() } : {}),
      });
      setCfg((c) => ({ ...(c ?? saved), ...saved }));
      setKeyDraft("");
      setShowSettings(false);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setSavingCfg(false);
    }
  };

  const send = async (text?: string) => {
    const content = (text ?? draft).trim();
    if (!content || busy) return;
    const newHistory = [...history, { role: "user", content } as CopilotMessage];
    setHistory(newHistory);
    setDraft("");
    setBusy(true);
    setError(null);
    try {
      const r = await api.copilotChat(newHistory);
      setHistory([...newHistory, { role: "assistant", content: extractAssistantText(r) }]);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  // Grounded "what's going on right now" — routes through the evidence-grounded
  // /api/ai/ask orchestrator (NOT the free-form proxy), so it works even before a
  // provider key is set (deterministic, tenant-scoped, cited). Rendered inline as
  // an ordinary assistant turn so the chat stays a single clean surface.
  const askGrounded = async () => {
    if (busy) return;
    const newHistory = [...history, { role: "user", content: "What's going on right now?" } as CopilotMessage];
    setHistory(newHistory);
    setBusy(true);
    setError(null);
    try {
      const ans = await api.aiAsk("What is going on right now? What should the NOC focus on first?");
      setHistory([...newHistory, { role: "assistant", content: groundedToText(ans) }]);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const addRecentLogContext = async () => {
    if (busy) return;
    setBusy(true);
    setError(null);
    try {
      const r = await api.searchLogs({ query: "*", size: 50, signal: "" });
      const hits = (r?.hits?.hits ?? []).map((h) => {
        const src = h._source || {};
        return `[${src["@timestamp"] ?? ""}] ${src.message ?? src.msg ?? JSON.stringify(src)}`;
      });
      setHistory((h) => [
        ...h,
        { role: "user", content: "Context — last 50 log lines:\n```\n" + hits.join("\n") + "\n```\nUse these when answering my next question." },
      ]);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  if (enabled === false) {
    return (
      <div className="op-chat" style={{ padding: 20 }}>
        <p style={{ color: "var(--muted)", fontSize: 13 }}>
          Correlix AI is turned off. Set <code>FEATURE_COPILOT=true</code> in{" "}
          <code>deployment/docker/.env</code> and restart the API.
        </p>
      </div>
    );
  }

  const ready = !!cfg?.feature_enabled && !!cfg?.key_present;

  return (
    <div className="op-chat">
      {/* Slim status toolbar (the drawer header already carries the title). */}
      <div className="op-toolbar">
        {cfg && (
          <span className="op-status" title={cfg.key_present ? "Connected" : "No API key — add one in settings"}>
            <span className={`op-dot ${ready ? "ok" : "warn"}`} />
            {cfg.provider === "anthropic" ? "Claude" : cfg.provider} · {cfg.model}
          </span>
        )}
        <span style={{ flex: 1 }} />
        <button className="op-iconbtn" title="Clear conversation" onClick={() => setHistory([])} disabled={busy || history.length === 0}>
          <Icon name="refresh" size={15} />
        </button>
        <button className="op-iconbtn" title="Assistant settings" onClick={() => setShowSettings((v) => !v)}>
          <Icon name="settings" size={15} />
        </button>
      </div>

      {showSettings && cfg && (
        <div className="op-settings">
          <p style={{ color: "var(--muted)", fontSize: 12, margin: "0 0 10px" }}>
            Runs on Claude by default. The API key is encrypted at rest and never shown again.
          </p>
          <label className="op-field">
            <span>
              {cfg.provider === "openai" ? "OpenAI" : "Anthropic"} API key{" "}
              {cfg.key_present
                ? <span className="badge good" style={{ fontSize: 10 }}>{cfg.key_source === "env" ? "via environment" : "configured"}</span>
                : <span className="badge warn" style={{ fontSize: 10 }}>not set</span>}
            </span>
            <input
              type="password"
              value={keyDraft}
              onChange={(e) => setKeyDraft(e.target.value)}
              placeholder={cfg.key_present ? "•••••••• (stored — leave blank to keep)" : "paste an API key (e.g. sk-…)"}
              autoComplete="off"
              disabled={cfg.key_source === "env"}
            />
            {cfg.key_source === "env" && (
              <span style={{ color: "var(--muted)", fontSize: 11 }}>Set via environment; clear it from <code>.env</code> to manage it here.</span>
            )}
          </label>
          <label className="op-field">
            <span>Provider</span>
            <select value={cfg.provider} onChange={(e) => { const provider = e.target.value; const s = cfg.model_suggestions?.[provider] ?? []; setCfg({ ...cfg, provider, model: s[0] ?? cfg.model }); }}>
              {(cfg.providers ?? ["anthropic", "openai"]).map((p) => <option key={p} value={p}>{p === "anthropic" ? "Anthropic (Claude)" : p}</option>)}
            </select>
          </label>
          <label className="op-field">
            <span>Model</span>
            <input list="copilot-models" value={cfg.model} onChange={(e) => setCfg({ ...cfg, model: e.target.value })} placeholder="model id" />
            <datalist id="copilot-models">{modelChoices.map((m) => <option key={m} value={m} />)}</datalist>
          </label>
          <div style={{ display: "flex", gap: 8, marginTop: 4 }}>
            <button className="dash-btn accent" onClick={saveCfg} disabled={savingCfg}>{savingCfg ? "Saving…" : "Save"}</button>
            <button className="dash-btn" onClick={() => setShowSettings(false)} disabled={savingCfg}>Cancel</button>
          </div>
        </div>
      )}

      {/* Conversation */}
      <div className="op-msgs">
        {history.length === 0 && !showSettings && (
          <div className="op-welcome">
            <div className="op-welcome-icon"><Icon name="copilot" size={26} /></div>
            <div className="op-welcome-title">How can I help?</div>
            <div className="op-welcome-sub">Ask about your network, troubleshoot an issue, or get setup help.</div>
            {/* Grounded NOC summary — works without a provider key (evidence-only
                fallback), so it's always offered as the first action. */}
            <div className="op-chips">
              <button className="op-chip op-chip-primary" onClick={askGrounded}>
                <Icon name="copilot" size={14} /> What&apos;s going on right now?
              </button>
            </div>
            {cfg && !cfg.key_present ? (
              <div className="op-nokey">
                <Icon name="key" size={15} /> Connect a provider key for free-form chat.
                <button className="dash-btn accent" style={{ marginLeft: 6 }} onClick={() => setShowSettings(true)}>Add API key</button>
              </div>
            ) : (
              <div className="op-chips">
                {SUGGESTIONS.map((s) => (
                  <button key={s} className="op-chip" onClick={() => send(s)}>{s}</button>
                ))}
              </div>
            )}
          </div>
        )}

        {history.map((m, i) => (
          <div key={i} className={`op-row ${m.role}`}>
            {m.role === "assistant" && <span className="op-avatar"><Icon name="copilot" size={14} /></span>}
            <div className={`op-bubble ${m.role}`}>{renderContent(m.content)}</div>
          </div>
        ))}

        {busy && (
          <div className="op-row assistant">
            <span className="op-avatar"><Icon name="copilot" size={14} /></span>
            <div className="op-bubble assistant op-typing"><span /><span /><span /></div>
          </div>
        )}
        <div ref={endRef} />
      </div>

      {error && <div className="op-error">{error}</div>}

      {/* Composer */}
      <form className="op-composer" onSubmit={(e) => { e.preventDefault(); send(); }}>
        <textarea
          ref={taRef}
          className="op-input"
          value={draft}
          onChange={(e) => setDraft(e.target.value)}
          placeholder="Ask Correlix AI…  (⏎ to send, ⇧⏎ for newline)"
          rows={1}
          onKeyDown={(e) => {
            if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); send(); }
          }}
        />
        <div className="op-composer-actions">
          <button type="button" className="op-iconbtn" title="Attach the last 50 log lines" onClick={addRecentLogContext} disabled={busy}>
            <Icon name="explore" size={15} /> Logs
          </button>
          <button type="submit" className="op-send" disabled={busy || !draft.trim()} title="Send">
            <Icon name="chevron" size={16} />
          </button>
        </div>
      </form>
    </div>
  );
}

// renderContent renders assistant/user text safely: fenced ``` blocks become
// <pre> (monospace, scrollable), everything else is plain pre-wrapped text. No
// HTML is ever interpreted (OWASP LLM02).
function renderContent(text: string) {
  const parts = text.split("```");
  return parts.map((p, i) =>
    i % 2 === 1
      ? <pre key={i} className="op-code">{p.replace(/^[a-zA-Z0-9_-]*\n/, "")}</pre>
      : <span key={i} className="op-text">{p}</span>,
  );
}

// groundedToText flattens a grounded AiAnswer into a clean chat bubble: the
// model (or evidence-only) narrative, then a compact, deterministic state line.
function groundedToText(ans: AiAnswer): string {
  let t = (ans.text || "").trim();
  const cs = ans.current_state;
  if (cs) {
    const lines = [`Confirmed ${cs.confirmed} · Suspected ${cs.suspected} · Undetermined ${cs.undetermined}`];
    if (cs.impacted_entities?.length) lines.push(`Most impacted: ${cs.impacted_entities.slice(0, 6).join(", ")}`);
    if (cs.recommended_focus?.length) lines.push(`Focus first: ${cs.recommended_focus[0]}`);
    t += (t ? "\n\n" : "") + lines.join("\n");
  }
  if (ans.provider === "none") t += "\n\n(Evidence-only summary — no AI provider configured.)";
  return t || "No active correlations right now — the fleet is quiet.";
}

function extractAssistantText(r: CopilotChatResponse): string {
  if (typeof (r as { text?: unknown }).text === "string") return (r as { text: string }).text;
  if ((r as AnthropicChatResponse).content) {
    return (r as AnthropicChatResponse).content.filter((c) => c.type === "text").map((c) => c.text).join("");
  }
  if ((r as OpenAIChatResponse).choices) return (r as OpenAIChatResponse).choices[0]?.message?.content ?? "";
  return JSON.stringify(r);
}

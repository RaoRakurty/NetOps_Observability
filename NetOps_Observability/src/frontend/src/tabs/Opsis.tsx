import { useEffect, useRef, useState } from "react";
import {
  api,
  CopilotMessage,
  CopilotChatResponse,
  AnthropicChatResponse,
  OpenAIChatResponse,
  CopilotConfig,
  AiAnswer,
  AiCitation,
} from "../services/api";
import Icon from "../components/Icon";
import { friendlyProblemId } from "../components/rca/labels";
import { useShell } from "../context/shell";

// Opsis Ai — the in-app assistant chat. Posts to /api/copilot/chat (provider
// fallback chain server-side); key-free questions fall through to the grounded
// /api/ai/ask engine. Rendered inside the right-side drawer. Assistant output is
// rendered as ESCAPED React text only (OWASP LLM02 — never dangerouslySetInnerHTML).

const SUGGESTIONS = [
  "Why might my edge router be dropping BGP sessions?",
  "How do I set up SNMP device discovery?",
  "How do I connect Okta SSO (OIDC)?",
  "Summarize the most recent critical alerts",
];

export default function Opsis() {
  const { setCopilotOpen } = useShell();
  const [enabled, setEnabled] = useState<boolean | null>(null);
  const [history, setHistory] = useState<CopilotMessage[]>([]);
  // Grounded answers (from /api/ai/ask) keyed by their assistant-message index in
  // `history`, so those turns render the rich, cited card instead of plain text.
  // History only ever grows by append (or full clear), so the index stays stable.
  const [grounded, setGrounded] = useState<Record<number, AiAnswer>>({});
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
    const idx = newHistory.length; // index the assistant reply will land at
    setHistory(newHistory);
    setDraft("");
    setBusy(true);
    setError(null);
    try {
      if (ready) {
        // Free-form LLM chat — a provider key is configured.
        const r = await api.copilotChat(newHistory);
        setHistory([...newHistory, { role: "assistant", content: extractAssistantText(r) }]);
      } else {
        // No provider key: answer from the grounded engine instead of erroring, so
        // any typed question still gets a tenant-scoped, evidence-cited answer.
        const ans = await api.aiAsk(content);
        setHistory([...newHistory, { role: "assistant", content: groundedToText(ans) }]);
        setGrounded((g) => ({ ...g, [idx]: ans }));
      }
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
    const idx = newHistory.length;
    setHistory(newHistory);
    setBusy(true);
    setError(null);
    try {
      const ans = await api.aiAsk("What is going on right now? What should the NOC focus on first?");
      setHistory([...newHistory, { role: "assistant", content: groundedToText(ans) }]);
      setGrounded((g) => ({ ...g, [idx]: ans }));
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  // Grounded deep-dive on the highest-priority active incident: get the current
  // state, resolve its recommended-focus problem id, then ask the engine to
  // explain that specific correlation. Works key-free (evidence-only fallback).
  const askTopIncident = async () => {
    if (busy) return;
    const newHistory = [...history, { role: "user", content: "Explain the top incident" } as CopilotMessage];
    const idx = newHistory.length;
    setHistory(newHistory);
    setBusy(true);
    setError(null);
    try {
      const state = await api.aiAsk("What is going on right now?");
      const id = topProblemId(state);
      if (!id) {
        setHistory([...newHistory, { role: "assistant", content: "No active correlations right now — there's no incident to explain." }]);
        return;
      }
      const ans = await api.aiAsk("Explain this incident: the likely root cause and the recommended next action.", { correlation_id: id });
      setHistory([...newHistory, { role: "assistant", content: groundedToText(ans) }]);
      setGrounded((g) => ({ ...g, [idx]: ans }));
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
        <button className="op-iconbtn" title="Clear conversation" onClick={() => { setHistory([]); setGrounded({}); }} disabled={busy || history.length === 0}>
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
              <button className="op-chip op-chip-primary" onClick={askTopIncident}>
                <Icon name="alerts" size={14} /> Explain the top incident
              </button>
            </div>
            {/* Module-aware example questions (P4) — grounded + key-free, so they
                showcase what Correlix AI can read across modules. */}
            <div className="op-examplerow">
              {["Show me the top talkers", "Any metric anomalies right now?"].map((s) => (
                <button key={s} className="op-example" onClick={() => send(s)}>{s}</button>
              ))}
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
            <div className={`op-bubble ${m.role}${m.role === "assistant" && grounded[i] ? " op-bubble-grounded" : ""}`}>
              {m.role === "assistant" && grounded[i]
                ? <GroundedAnswer ans={grounded[i]} onCite={() => setCopilotOpen(false)} onClose={() => setCopilotOpen(false)} />
                : renderContent(m.content)}
            </div>
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
          <span className="op-composer-hint">
            <span className="op-composer-dot" /> Grounded · tenant-scoped · cited
          </span>
          <button type="submit" className="op-send" disabled={busy || !draft.trim()} title="Send (⏎)">
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

// topProblemId resolves the highest-priority active problem's id from a
// current-state answer: prefer the recommended-focus line (matched to its full
// citation id), else the first cited problem. Returns "" when nothing is active.
export function topProblemId(ans: AiAnswer): string {
  const cs = ans.current_state;
  const focus = (cs?.recommended_focus?.[0] || cs?.active_incidents?.[0] || "").trim();
  const short = focus.split(/[\s—-]+/)[0]; // leading short id, e.g. "614896e5"
  const cites = ans.citations || [];
  if (short) {
    const byFocus = cites.find((c) => c.id.startsWith("problem:") && c.id.slice(8).startsWith(short));
    if (byFocus) return byFocus.id.slice(8);
  }
  const first = cites.find((c) => c.id.startsWith("problem:"));
  return first ? first.id.slice(8) : "";
}

// GroundedAnswer renders an evidence-grounded answer (from /api/ai/ask) as a
// formatted card inside the chat: the narrative, per-mode structured facts, and
// clickable citations that deep-link into the source view. Model text is escaped
// React text (OWASP LLM02) — never HTML.
function GroundedAnswer({ ans, onCite, onClose }: { ans: AiAnswer; onCite: () => void; onClose: () => void }) {
  const cs = ans.current_state;
  const pr = ans.problem;
  const mod = ans.module;
  // A short, human label for the answer kind — a quiet futuristic header chip.
  const kind =
    pr ? "RCA" : cs ? "Live state" : mod ? (mod.display_name || "Module") : ans.mode === "unavailable" ? "Notice" : "Answer";
  return (
    <div className="op-grounded">
      <div className="op-ans-head">
        <span className="op-ans-kind">{kind}</span>
        {pr && <span className="op-ans-id" title={pr.problem_id}>{friendlyProblemId(pr.problem_id)}</span>}
        <span className="op-ans-spacer" />
        <button type="button" className="op-ans-x" title="Close Correlix AI" aria-label="Close" onClick={onClose}>
          <Icon name="close" size={13} />
        </button>
      </div>

      {ans.text && <div className="op-text">{ans.text}</div>}

      {cs && (
        <div className="op-facts">
          <span className="op-fact op-fact-ok"><b>{cs.confirmed}</b> confirmed</span>
          <span className="op-fact op-fact-warn"><b>{cs.suspected}</b> suspected</span>
          <span className="op-fact"><b>{cs.undetermined}</b> undetermined</span>
        </div>
      )}
      {cs?.impacted_entities && cs.impacted_entities.length > 0 && (
        <div className="op-kv"><span className="op-kv-k">Most impacted</span> {cs.impacted_entities.slice(0, 8).join(", ")}</div>
      )}
      {cs?.recommended_focus && cs.recommended_focus.length > 0 && (
        <div className="op-kv"><span className="op-kv-k">Focus first</span> {cs.recommended_focus[0]}</div>
      )}

      {pr && (
        <div className="op-facts">
          <span className={`op-fact verdict-${pr.verdict.toLowerCase()}`}>{pr.verdict}</span>
          <span className="op-fact"><b>{pr.confidence}</b> confidence</span>
          {pr.recommended_owner && <span className="op-fact">owner: {pr.recommended_owner}</span>}
        </div>
      )}
      {pr?.missing_evidence && pr.missing_evidence.length > 0 && (
        <div className="op-kv"><span className="op-kv-k">Missing evidence</span> {pr.missing_evidence.join(", ")}</div>
      )}

      {/* P4 module-aware answer — a focused read of one module's tools. */}
      {mod && mod.items && mod.items.length > 0 && (
        <ul className="op-modlist">
          {mod.items.slice(0, 8).map((it, i) => (
            <li key={i} className="op-moditem">{it}</li>
          ))}
        </ul>
      )}
      {mod?.notes && mod.notes.length > 0 && (
        <div className="op-kv"><span className="op-kv-k">Note</span> {mod.notes.join(" ")}</div>
      )}

      {ans.citations && ans.citations.length > 0 && (
        <div className="op-cites">
          {ans.citations.slice(0, 12).map((c: AiCitation) => (
            <a key={c.id} className="op-cite" href={c.href} title={c.label} onClick={onCite}>
              <Icon name="external" size={11} /> {c.label || c.id}
            </a>
          ))}
        </div>
      )}

      {ans.disclaimers && ans.disclaimers.length > 0 && (
        <div className="op-disc">{ans.disclaimers.join(" ")}</div>
      )}
      {ans.provider === "none" && (
        <div className="op-disc">Evidence-only summary — no AI provider configured.</div>
      )}
    </div>
  );
}

// groundedToText flattens a grounded AiAnswer into a clean chat bubble: the
// model (or evidence-only) narrative, then a compact, deterministic state line.
export function groundedToText(ans: AiAnswer): string {
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

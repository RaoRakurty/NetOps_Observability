import { useEffect, useRef, useState } from "react";
import {
  api,
  CopilotMessage,
  CopilotChatResponse,
  AnthropicChatResponse,
  OpenAIChatResponse,
} from "../services/api";
import { BRAND } from "../brand";

// AI Copilot — chat pane. Posts to /api/copilot/chat. The backend
// dispatches to Anthropic or OpenAI based on COPILOT_PROVIDER.
//
// We don't pull context automatically. If the user wants the model to
// see specific logs / metrics / findings, they paste it in or use the
// "Add context" button (which fetches the most recent 50 lines from
// OpenSearch and tacks them onto the next message).

export default function Copilot() {
  const [enabled, setEnabled] = useState<boolean | null>(null);
  const [history, setHistory] = useState<CopilotMessage[]>([]);
  const [draft, setDraft] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const endRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    api
      .credentials()
      .then((c) => setEnabled(Boolean(c?.copilot)))
      .catch(() => setEnabled(false));
  }, []);

  useEffect(() => {
    endRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [history.length, busy]);

  const send = async () => {
    if (!draft.trim()) return;
    const userMsg: CopilotMessage = { role: "user", content: draft.trim() };
    const newHistory = [...history, userMsg];
    setHistory(newHistory);
    setDraft("");
    setBusy(true);
    setError(null);
    try {
      const r = await api.copilotChat(newHistory);
      const text = extractAssistantText(r);
      setHistory([...newHistory, { role: "assistant", content: text }]);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const addRecentLogContext = async () => {
    setBusy(true);
    try {
      const r = await api.searchLogs({ query: "*", size: 50, signal: "" });
      const hits = (r?.hits?.hits ?? []).map((h) => {
        const src = h._source || {};
        return `[${src["@timestamp"] ?? ""}] ${src.message ?? src.msg ?? JSON.stringify(src)}`;
      });
      const ctx: CopilotMessage = {
        role: "user",
        content:
          "Context — last 50 log lines:\n```\n" +
          hits.join("\n") +
          "\n```\nUse these when answering my next question.",
      };
      setHistory((h) => [...h, ctx]);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  if (enabled === false) {
    return (
      <div className="card">
        <h2>AI Copilot</h2>
        <p style={{ color: "var(--muted)" }}>
          Copilot is disabled. Set <code>FEATURE_COPILOT=true</code> and{" "}
          <code>COPILOT_API_KEY=...</code> in <code>deployment/docker/.env</code>, then{" "}
          <code>docker compose up -d</code>.
        </p>
      </div>
    );
  }

  return (
    <>
      <div className="card" style={{ display: "flex", flexDirection: "column", height: "65vh" }}>
        <h2>{BRAND} Copilot</h2>
        <div
          style={{
            flex: 1,
            overflowY: "auto",
            padding: 8,
            background: "var(--bg)",
            border: "1px solid var(--panel-border)",
            borderRadius: 8,
          }}
        >
          {history.length === 0 && (
            <div className="empty" style={{ paddingTop: 60 }}>
              Ask anything. Try: "Why might my edge router be dropping BGP sessions?"
            </div>
          )}
          {history.map((m, i) => (
            <div
              key={i}
              style={{
                margin: "10px 0",
                padding: 10,
                borderRadius: 8,
                background: m.role === "user" ? "rgba(79,70,229,0.07)" : "var(--bg)",
                border:
                  "1px solid " +
                  (m.role === "user" ? "rgba(79,70,229,0.22)" : "var(--panel-border)"),
                whiteSpace: "pre-wrap",
                fontSize: 13,
              }}
            >
              <div style={{ color: "var(--muted)", fontSize: 11, marginBottom: 4 }}>
                {m.role.toUpperCase()}
              </div>
              {m.content}
            </div>
          ))}
          {busy && <div className="empty">Thinking…</div>}
          <div ref={endRef} />
        </div>

        {error && <p style={{ color: "var(--bad)", marginTop: 8 }}>{error}</p>}

        <form
          style={{ display: "flex", gap: 8, marginTop: 12 }}
          onSubmit={(e) => {
            e.preventDefault();
            send();
          }}
        >
          <textarea
            value={draft}
            onChange={(e) => setDraft(e.target.value)}
            placeholder="Ask the copilot…"
            rows={3}
            style={{ flex: 1, resize: "vertical", fontFamily: "inherit", fontSize: 13 }}
            onKeyDown={(e) => {
              if (e.key === "Enter" && (e.metaKey || e.ctrlKey)) {
                e.preventDefault();
                send();
              }
            }}
          />
          <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
            <button disabled={busy} type="submit">
              Send
            </button>
            <button type="button" onClick={addRecentLogContext} disabled={busy}>
              + Context
            </button>
            <button
              type="button"
              onClick={() => setHistory([])}
              disabled={busy || history.length === 0}
            >
              Clear
            </button>
          </div>
        </form>
        <p style={{ color: "var(--muted)", fontSize: 11, marginTop: 6 }}>
          ⌘/Ctrl+Enter to send. "+ Context" adds the last 50 log lines as context.
        </p>
      </div>
    </>
  );
}

function extractAssistantText(r: CopilotChatResponse): string {
  // Anthropic
  if ((r as AnthropicChatResponse).content) {
    return (r as AnthropicChatResponse).content
      .filter((c) => c.type === "text")
      .map((c) => c.text)
      .join("");
  }
  // OpenAI
  if ((r as OpenAIChatResponse).choices) {
    return (r as OpenAIChatResponse).choices[0]?.message?.content ?? "";
  }
  return JSON.stringify(r);
}

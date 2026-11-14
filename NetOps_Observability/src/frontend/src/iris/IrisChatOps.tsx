// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// IrisChatOps — Iris in Slack and Microsoft Teams (tracker 337 N-I6).
//
// Two parts:
//   1. Everyone: link my chat account — enter the code Iris gave you in the
//      chat; see and revoke your links.
//   2. Workspace admins: connect the workspace's own Slack app or Teams bot,
//      and approve or revoke each linked account (never your own).
//
// Secrets are write-only: the page shows whether one is set, never its value.
// Every server string renders as escaped React text.

import { useCallback, useEffect, useState } from "react";
import {
  api,
  type ChatConnection,
  type ChatConnectionInput,
  type ChatLink,
  type ChatPlatform,
} from "../services/api";
import { httpFailure, operatorError } from "../lib/errors";

const text14 = { fontSize: 14 } as const;
const muted = { color: "var(--muted)", fontSize: 14 } as const;
const field = { fontSize: 14, padding: "4px 6px", minWidth: 260 } as const;
const row = { display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" as const, margin: "4px 0" };

const PLATFORM_LABEL: Record<ChatPlatform, string> = { slack: "Slack", teams: "Microsoft Teams" };
const STATUS_LABEL: Record<ChatLink["status"], string> = {
  pending: "Waiting for approval",
  approved: "Approved",
  revoked: "Revoked",
};

export default function IrisChatOps() {
  return (
    <div data-testid="iris-chatops" style={text14}>
      <MyChatLinks />
      <ChatAdmin />
    </div>
  );
}

// ── 1. my chat account ──────────────────────────────────────────────────────

function MyChatLinks() {
  const [links, setLinks] = useState<ChatLink[] | null>(null);
  const [code, setCode] = useState("");
  const [note, setNote] = useState("");
  const [err, setErr] = useState("");
  const [loadErr, setLoadErr] = useState("");
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    try {
      setLinks((await api.myChatLinks()).links ?? []);
      setLoadErr("");
    } catch (e) {
      // A read failure is a status line, not an alert: only what the person
      // just did raises one.
      setLoadErr(operatorError(e, "Your chat links could not be loaded."));
    }
  }, []);
  useEffect(() => { void load(); }, [load]);

  const redeem = async () => {
    setBusy(true);
    setErr("");
    setNote("");
    try {
      await api.redeemChatCode(code.trim());
      setCode("");
      setNote("Linked. A workspace admin now approves it; until then Iris answers in the chat with a reminder.");
      await load();
    } catch (e) {
      setErr(operatorError(e, "That code did not work — ask Iris in the chat for a new one."));
    } finally {
      setBusy(false);
    }
  };

  const revoke = async (id: string) => {
    try {
      await api.revokeMyChatLink(id);
      await load();
    } catch (e) {
      setErr(operatorError(e, "The link could not be revoked."));
    }
  };

  return (
    <div data-testid="chat-my-links">
      <div><strong>Link my chat account</strong></div>
      <p style={{ ...muted, margin: "2px 0 6px" }}>
        Ask Iris anything in Slack or Teams; it replies with a code. Enter it here.
      </p>
      <div style={row}>
        <input
          aria-label="Code from Iris"
          style={{ ...field, minWidth: 140 }}
          value={code}
          maxLength={16}
          placeholder="ABCD-EFGH"
          onChange={(e) => setCode(e.target.value)}
        />
        <button type="button" disabled={busy || code.trim().length < 8} onClick={() => void redeem()}>Link</button>
      </div>
      {note && <p style={muted} role="status">{note}</p>}
      {err && <p role="alert" style={text14}>{err}</p>}
      {loadErr && <p style={muted}>{loadErr}</p>}
      {links && links.length > 0 && (
        <ul style={{ margin: "4px 0 0", paddingLeft: 18 }}>
          {links.map((l) => (
            <li key={l.id} style={text14}>
              {PLATFORM_LABEL[l.platform]} · {l.chat_name || l.chat_user_id} — {STATUS_LABEL[l.status]}
              {l.status !== "revoked" && (
                <button type="button" style={{ marginLeft: 8 }} onClick={() => void revoke(l.id)}>Revoke</button>
              )}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

// ── 2. workspace admin ──────────────────────────────────────────────────────

function ChatAdmin() {
  const [conns, setConns] = useState<ChatConnection[] | null>(null);
  const [switchOn, setSwitchOn] = useState(false);
  const [links, setLinks] = useState<ChatLink[]>([]);
  const [denied, setDenied] = useState(false);
  const [err, setErr] = useState("");
  const [loadErr, setLoadErr] = useState("");

  const load = useCallback(async () => {
    try {
      const c = await api.chatConnections();
      setConns(c.connections ?? []);
      setSwitchOn(c.switch_on);
      setLinks((await api.chatLinks()).links ?? []);
      setLoadErr("");
    } catch (e) {
      if (httpFailure(e)?.status === 403) {
        setDenied(true);
        return;
      }
      setLoadErr(operatorError(e, "The chat connections could not be loaded."));
    }
  }, []);
  useEffect(() => { void load(); }, [load]);

  if (denied) return <p style={{ ...muted, marginTop: 10 }}>Workspace admins connect chat apps and approve linked accounts.</p>;
  if (loadErr) return <p style={muted}>{loadErr}</p>;
  if (!conns) return <p style={muted}>Loading…</p>;

  const decide = async (id: string, approve: boolean) => {
    try {
      await api.decideChatLink(id, approve);
      await load();
    } catch (e) {
      setErr(operatorError(e, "The link could not be updated."));
    }
  };

  const pending = links.filter((l) => l.status === "pending");
  const approved = links.filter((l) => l.status === "approved");
  return (
    <div data-testid="chat-admin" style={{ marginTop: 12 }}>
      {!switchOn && (
        <p style={muted} data-testid="chat-switch-off">
          Off for this installation: a platform administrator turns on “Iris in Slack and Teams” on the Features page.
        </p>
      )}
      <ConnectionForm platform="slack" current={conns.find((c) => c.platform === "slack")} onSaved={load} />
      <ConnectionForm platform="teams" current={conns.find((c) => c.platform === "teams")} onSaved={load} />
      <div style={{ marginTop: 10 }}><strong>Linked accounts</strong></div>
      {pending.length === 0 && approved.length === 0 && <p style={muted}>Nobody has linked a chat account yet.</p>}
      <ul style={{ margin: "4px 0 0", paddingLeft: 18 }} data-testid="chat-links">
        {[...pending, ...approved].map((l) => (
          <li key={l.id} style={text14}>
            {PLATFORM_LABEL[l.platform]} {l.chat_name || l.chat_user_id} → Correlix user {l.user_id} — {STATUS_LABEL[l.status]}
            {l.status === "pending" && (
              <button type="button" style={{ marginLeft: 8 }} onClick={() => void decide(l.id, true)}>Approve</button>
            )}
            <button type="button" style={{ marginLeft: 8 }} onClick={() => void decide(l.id, false)}>Revoke</button>
          </li>
        ))}
      </ul>
      <p style={muted}>Check the chat name matches the person before approving. Nobody approves their own link.</p>
      {err && <p role="alert" style={text14}>{err}</p>}
    </div>
  );
}

function ConnectionForm({ platform, current, onSaved }: { platform: ChatPlatform; current?: ChatConnection; onSaved: () => Promise<void> }) {
  const slack = platform === "slack";
  const [f, setF] = useState<ChatConnectionInput>({
    workspace_id: current?.workspace_id ?? "",
    app_id: current?.app_id ?? "",
    app_tenant: current?.app_tenant ?? "",
    public_url: current?.public_url ?? "",
    channel_replies: current?.channel_replies ?? "private",
    enabled: current?.enabled ?? false,
  });
  const [err, setErr] = useState("");
  const [saved, setSaved] = useState("");
  const set = (k: keyof ChatConnectionInput, v: string | boolean) => setF((p) => ({ ...p, [k]: v }));

  const save = async (rotate = false) => {
    setErr("");
    setSaved("");
    try {
      await api.saveChatConnection(platform, { ...f, rotate_token: rotate });
      setF((p) => ({ ...p, signing_secret: "", bot_token: "", app_password: "" }));
      setSaved("Saved.");
      await onSaved();
    } catch (e) {
      setErr(operatorError(e, "The connection could not be saved."));
    }
  };
  const remove = async () => {
    try {
      await api.removeChatConnection(platform);
      await onSaved();
    } catch (e) {
      setErr(operatorError(e, "The connection could not be removed."));
    }
  };

  return (
    <fieldset data-testid={`chat-conn-${platform}`} style={{ border: "1px solid var(--border)", padding: 8, margin: "8px 0" }}>
      <legend style={text14}><strong>{PLATFORM_LABEL[platform]}</strong>{current ? (current.enabled ? " — on" : " — off") : " — not connected"}</legend>
      <ol style={{ ...text14, paddingLeft: 20, margin: 0 }}>
        <li style={row}>
          <label style={text14}>
            {slack ? "Workspace ID (T…)" : "Microsoft tenant ID"}{" "}
            <input style={field} value={f.workspace_id} onChange={(e) => set("workspace_id", e.target.value)} />
          </label>
        </li>
        <li style={row}>
          <label style={text14}>
            {slack ? "App ID (optional)" : "Bot app ID"}{" "}
            <input style={field} value={f.app_id ?? ""} onChange={(e) => set("app_id", e.target.value)} />
          </label>
        </li>
        {slack ? (
          <>
            <li style={row}>
              <label style={text14}>
                Signing secret{current?.has_signing_secret ? " (set — leave blank to keep)" : ""}{" "}
                <input style={field} type="password" autoComplete="off" value={f.signing_secret ?? ""} onChange={(e) => set("signing_secret", e.target.value)} />
              </label>
            </li>
            <li style={row}>
              <label style={text14}>
                Bot token (xoxb-…){current?.has_bot_token ? " (set — leave blank to keep)" : ""}{" "}
                <input style={field} type="password" autoComplete="off" value={f.bot_token ?? ""} onChange={(e) => set("bot_token", e.target.value)} />
              </label>
            </li>
          </>
        ) : (
          <li style={row}>
            <label style={text14}>
              App password{current?.has_app_password ? " (set — leave blank to keep)" : ""}{" "}
              <input style={field} type="password" autoComplete="off" value={f.app_password ?? ""} onChange={(e) => set("app_password", e.target.value)} />
            </label>
          </li>
        )}
        <li style={row}>
          <label style={text14}>
            Correlix address for links{" "}
            <input style={field} placeholder="https://correlix.example.com" value={f.public_url ?? ""} onChange={(e) => set("public_url", e.target.value)} />
          </label>
        </li>
        <li style={row}>
          <label style={text14}>
            Answers asked in a channel{" "}
            <select style={text14} value={f.channel_replies} onChange={(e) => set("channel_replies", e.target.value)}>
              <option value="private">Only the person who asked sees them</option>
              <option value="public">Everyone in the channel sees them</option>
            </select>
          </label>
        </li>
        <li style={row}>
          <label style={text14}>
            <input type="checkbox" checked={f.enabled} onChange={(e) => set("enabled", e.target.checked)} /> Answer in {PLATFORM_LABEL[platform]}
          </label>
        </li>
      </ol>
      <div style={row}>
        <button type="button" onClick={() => void save()}>Save</button>
        {current && <button type="button" onClick={() => void save(true)}>New inbound address</button>}
        {current && <button type="button" onClick={() => void remove()}>Disconnect</button>}
      </div>
      {current && (
        <p style={muted}>
          {slack ? "Event Subscriptions and slash command URL" : "Messaging endpoint"}: <code>{current.webhook_url}</code> on this Correlix address.
        </p>
      )}
      {saved && <p style={muted} role="status">{saved}</p>}
      {err && <p role="alert" style={text14}>{err}</p>}
    </fieldset>
  );
}

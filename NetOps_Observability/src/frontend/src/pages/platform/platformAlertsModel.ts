// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// platformAlertsModel — pure helpers for Platform → Platform alerts. No React,
// no IO, so every rule here is unit-tested directly.
//
// The server (internal/platformalert) is the authority on validation; the
// checks here only catch the obvious mistakes before a round trip and use the
// same plain sentences.

import type { PlatformAlertRoute, PlatformAlertRouteUpdate, PlatformAlertTiers, PlatformAlertVerdict } from "../../services/api";

export type Draft = {
  ntfy: { enabled: boolean; server: string; topic: string; token: string; clearToken: boolean; tiers: PlatformAlertTiers };
  sms: {
    enabled: boolean;
    accountSid: string;
    authToken: string;
    clearAuthToken: boolean;
    from: string;
    /** Numbers as typed: one per line or separated by commas. */
    toText: string;
    tiers: PlatformAlertTiers;
    maxPerHour: string;
  };
  replaceUnreadable: boolean;
};

export const MAX_SMS_RECIPIENTS = 5;
export const MIN_SMS_PER_HOUR = 1;
export const MAX_SMS_PER_HOUR = 60;

/** The form, filled from what the server holds. Secret fields start empty. */
export function draftFrom(r: PlatformAlertRoute): Draft {
  return {
    ntfy: { enabled: r.ntfy.enabled, server: r.ntfy.server, topic: r.ntfy.topic, token: "", clearToken: false, tiers: { ...r.ntfy.tiers } },
    sms: {
      enabled: r.sms.enabled,
      accountSid: r.sms.account_sid,
      authToken: "",
      clearAuthToken: false,
      from: r.sms.from,
      toText: r.sms.to.join("\n"),
      tiers: { ...r.sms.tiers },
      maxPerHour: String(r.sms.max_per_hour || 10),
    },
    replaceUnreadable: false,
  };
}

export function parseNumbers(text: string): string[] {
  return text
    .split(/[\s,;]+/)
    .map((s) => s.trim())
    .filter(Boolean);
}

const E164 = /^\+[1-9][0-9]{6,14}$/;
export const isE164 = (n: string) => E164.test(n);

const TOPIC = /^[A-Za-z0-9_-]{1,64}$/;

/** The first problem with the form, as the sentence to show, or null. */
export function validateDraft(d: Draft, saved: PlatformAlertRoute): string | null {
  const n = d.ntfy;
  if (!/^https:\/\/[^\s/?#@]+/i.test(n.server.trim())) return "The ntfy server must be an https:// address, for example https://ntfy.sh.";
  if (n.topic.trim() && !TOPIC.test(n.topic.trim())) return "The ntfy topic may use only letters, digits, - and _ (at most 64).";
  if (n.enabled && !n.topic.trim()) return "To turn on ntfy, enter a topic.";
  if (n.enabled && !n.tiers.page && !n.tiers.warning) return "A channel that is turned on must receive pages, the warning summary, or both.";

  const s = d.sms;
  const to = parseNumbers(s.toText);
  if (s.accountSid.trim() && !/^AC[0-9a-fA-F]{32}$/.test(s.accountSid.trim()))
    return "The Twilio Account SID starts with AC followed by 32 letters and digits.";
  if (s.from.trim() && !isE164(s.from.trim())) return "Phone numbers must be in international format, for example +14155550100.";
  if (to.some((x) => !isE164(x))) return "Phone numbers must be in international format, for example +14155550100.";
  if (to.length > MAX_SMS_RECIPIENTS || new Set(to).size !== to.length)
    return `Enter between 1 and ${MAX_SMS_RECIPIENTS} phone numbers to text, without repeats.`;
  const cap = Number(s.maxPerHour);
  if (!Number.isInteger(cap) || cap < MIN_SMS_PER_HOUR || cap > MAX_SMS_PER_HOUR)
    return `The text-message limit must be between ${MIN_SMS_PER_HOUR} and ${MAX_SMS_PER_HOUR} an hour.`;
  if (s.enabled) {
    const tokenWillBeSet = s.authToken.trim() !== "" || (saved.sms.auth_token_set && !s.clearAuthToken);
    if (!s.accountSid.trim() || !tokenWillBeSet || !s.from.trim() || to.length === 0)
      return "To turn on text messages, enter the Account SID, auth token, the number to send from and at least one number to text.";
    if (!s.tiers.page && !s.tiers.warning) return "A channel that is turned on must receive pages, the warning summary, or both.";
  }
  return null;
}

/** The PUT body. An empty secret keeps the saved one. */
export function toUpdate(d: Draft): PlatformAlertRouteUpdate {
  return {
    ntfy: {
      enabled: d.ntfy.enabled,
      server: d.ntfy.server.trim(),
      topic: d.ntfy.topic.trim(),
      token: d.ntfy.clearToken ? "" : d.ntfy.token.trim(),
      clear_token: d.ntfy.clearToken,
      tiers: d.ntfy.tiers,
    },
    sms: {
      enabled: d.sms.enabled,
      account_sid: d.sms.accountSid.trim(),
      auth_token: d.sms.clearAuthToken ? "" : d.sms.authToken.trim(),
      clear_auth_token: d.sms.clearAuthToken,
      from: d.sms.from.trim(),
      to: parseNumbers(d.sms.toText),
      tiers: d.sms.tiers,
      max_per_hour: Number(d.sms.maxPerHour),
    },
    replace_unreadable: d.replaceUnreadable,
  };
}

/** True when the form differs from what is saved (tests use saved settings). */
export function isDirty(d: Draft, saved: PlatformAlertRoute): boolean {
  return JSON.stringify(toUpdate({ ...d, replaceUnreadable: false })) !== JSON.stringify(toUpdate(draftFrom(saved)));
}

/** The banner over the page, or null when pages reach someone. */
export function routeBanner(r: PlatformAlertRoute): string | null {
  if (r.store_status === "unreadable")
    return "The saved platform alert settings could not be read. Platform alerts reach nobody until they are read or replaced.";
  if (!r.page_routed) return "Platform alerts reach nobody. Turn on at least one channel that receives pages.";
  return null;
}

export function verdictTone(v: PlatformAlertVerdict): "good" | "warn" | "bad" {
  if (v === "ok") return "good";
  if (v === "rate_limited" || v === "not_configured") return "warn";
  return "bad";
}

/** One line under each channel saying what it receives. */
export function receivesLine(t: PlatformAlertTiers): string {
  if (t.page && t.warning) return "Receives pages and the warning summary.";
  if (t.page) return "Receives pages only.";
  if (t.warning) return "Receives the warning summary only.";
  return "Receives nothing.";
}

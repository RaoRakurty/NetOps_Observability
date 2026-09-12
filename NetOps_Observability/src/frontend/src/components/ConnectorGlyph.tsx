// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// ConnectorGlyph.tsx — how Correlix identifies a THIRD-PARTY SERVICE CONNECTOR.
//
// TRACKER 239 (2026-09-05). Until this file existed, six connectors were drawn
// with the vendors' OWN marks: ServiceNow's circular "Now" symbol in brand
// green, the Atlassian Jira mark in its blue gradient, the Slack four-colour
// lozenge, the Twilio red roundel, the PagerDuty green mark and the Microsoft
// Teams two-tone purple tile — verbatim brand path data, in brand colours,
// minified into the shipped SPA with no usage terms recorded anywhere. That is
// the SAME class of exposure licence decision D5 (2026-09-04) resolved for the
// AWS / Azure / Google Cloud marks, and it is resolved here the SAME way:
//
//   connector identity = a GENERIC FUNCTIONAL GLYPH + the vendor's name as
//                        plain, factual text.
//
// The glyph says what the connector DOES — open a ticket, move a work item,
// post to a channel, send a message, page someone, collaborate. The text says
// who it talks to. Naming a vendor to describe interoperability is ordinary
// nominative use; reproducing the vendor's artwork is not, so we do the first
// and never the second.
//
// RULES that keep this file clean (the same four that keep assets/cloud clean):
//
//   • NEVER a vendor silhouette. Do not trace, simplify, recolour, strip text
//     from or otherwise approximate an official mark. A glyph here must be
//     recognisable as ITS FUNCTION and unrecognisable as anyone's brand.
//   • NEVER a vendor colour. Every glyph is `currentColor` from components/
//     Icon.tsx, so it inherits the theme in light AND dark and carries no
//     brand hue. Connector chips use design tokens (`.conn-logo` in
//     styles.css), never a brand tint.
//   • NEVER identity by glyph alone. The same glyph deliberately serves
//     several vendors (ServiceNow and any other ITSM desk both get `ticket`).
//     The visible NAME is what distinguishes them, so a screen reader and a
//     monochrome display lose nothing.
//   • ALWAYS an honest fallback. An unknown connector renders the generic
//     integration plug — never a broken image, never another vendor's glyph.
//
// Adding a connector is ONE ENTRY in CONNECTOR_REGISTRY below. Adding an
// official third-party mark instead requires an explicit owner review with the
// usage terms recorded in scripts/license-data.json first — see
// docs/design/UI_CONNECTOR_MARKS.md.

import type { CSSProperties } from "react";
import Icon from "./Icon";

/**
 * The functional taxonomy. A connector is presented by WHAT IT DOES, which is
 * why one category legitimately covers many vendors.
 */
export type ConnectorCategory =
  | "ITSM"
  | "Issue tracking"
  | "Chat"
  | "Messaging"
  | "Incident response"
  | "Collaboration"
  | "Email"
  | "Push"
  | "Webhook"
  | "Integration";

export type ConnectorPresentation = {
  /** Canonical connector id (lower-case, as used by the API). */
  id: string;
  /** The vendor / product name, shown as plain text. Never a wordmark. */
  displayName: string;
  /** Functional category — the second line of a connector card. */
  category: ConnectorCategory;
  /** Glyph name in components/Icon.tsx. Functional, never vendor-shaped. */
  icon: string;
  /** One-line statement of the capability, safe to show as a tooltip. */
  capability: string;
};

/**
 * The single source of truth for connector presentation. No component may
 * branch on a connector id to draw its own artwork — it asks here.
 */
export const CONNECTOR_REGISTRY: Record<string, Omit<ConnectorPresentation, "id">> = {
  servicenow: {
    displayName: "ServiceNow",
    category: "ITSM",
    icon: "ticket",
    capability: "Opens and resolves incidents in an ITSM service desk.",
  },
  jira: {
    displayName: "Jira",
    category: "Issue tracking",
    icon: "board",
    capability: "Creates and transitions issues in a work-item tracker.",
  },
  slack: {
    displayName: "Slack",
    category: "Chat",
    icon: "chat",
    capability: "Posts alerts into a team chat channel.",
  },
  teams: {
    displayName: "Microsoft Teams",
    category: "Collaboration",
    icon: "users",
    capability: "Posts alerts into a collaboration workspace channel.",
  },
  twilio: {
    displayName: "Twilio",
    category: "Messaging",
    icon: "phone",
    capability: "Delivers alerts as SMS to on-call phone numbers.",
  },
  pagerduty: {
    displayName: "PagerDuty",
    category: "Incident response",
    icon: "incident",
    capability: "Raises and resolves on-call pages.",
  },
  ntfy: {
    displayName: "ntfy",
    category: "Push",
    icon: "bell",
    capability: "Sends free push notifications to a phone topic.",
  },
  email: {
    displayName: "Email",
    category: "Email",
    icon: "mail",
    capability: "Relays alert email through an SMTP server.",
  },
  webhook: {
    displayName: "Webhook",
    category: "Webhook",
    icon: "webhook",
    capability: "POSTs alerts to an HTTP endpoint you control.",
  },
};

/**
 * What an unrecognised connector renders. Deliberately a plug: it reads as
 * "some integration", claims nothing, and can never be mistaken for a vendor.
 */
export const GENERIC_CONNECTOR: ConnectorPresentation = {
  id: "generic",
  displayName: "Integration",
  category: "Integration",
  icon: "plug",
  capability: "A third-party integration.",
};

/** Presentation for a connector id — the generic plug for anything unknown. */
export function connectorPresentation(connector?: string | null): ConnectorPresentation {
  const id = (connector ?? "").trim().toLowerCase();
  const hit = id ? CONNECTOR_REGISTRY[id] : undefined;
  return hit ? { id, ...hit } : GENERIC_CONNECTOR;
}

/** The functional glyph name for a connector id. */
export function connectorIcon(connector?: string | null): string {
  return connectorPresentation(connector).icon;
}

/**
 * The connector's glyph. Decorative by default — connector surfaces always
 * print the name beside it, so the glyph is hidden from assistive tech unless
 * a caller passes an explicit `label`.
 */
export default function ConnectorGlyph({
  connector,
  size = 24,
  label,
  className,
  style,
}: {
  connector?: string | null;
  size?: number;
  label?: string;
  className?: string;
  style?: CSSProperties;
}) {
  return (
    <Icon
      name={connectorPresentation(connector).icon}
      size={size}
      label={label}
      className={className}
      style={style}
    />
  );
}

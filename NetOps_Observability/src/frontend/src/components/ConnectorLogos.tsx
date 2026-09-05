// ConnectorLogos.tsx — the cloud-provider marks for the Integrations gallery.
//
// NOTHING IN THIS FILE IS A VENDOR'S ARTWORK, and nothing in it may become
// one. Two licence decisions emptied it:
//
//   D5 (owner, 2026-09-04) — the official AWS Smile, the Azure gradient
//   chevron and the Google Cloud four-colour "G" were deleted. The three cloud
//   tiles now draw ORIGINAL Correlix artwork from components/CloudGlyph.tsx:
//   one cloud silhouette carrying a plain letter tag.
//
//   Tracker 239 (2026-09-05) — the six ITSM / chat / comms marks that used to
//   live here (ServiceNow's circular "Now" symbol, the Atlassian Jira mark,
//   the Slack four-colour lozenge, the Twilio roundel, the PagerDuty mark and
//   the Microsoft Teams tile — verbatim brand path data in brand colours, with
//   no usage terms recorded anywhere) were deleted for the same reason and
//   replaced the same way. Connectors are now identified by a generic
//   FUNCTIONAL glyph plus the vendor's name as plain text; the registry lives
//   in components/ConnectorGlyph.tsx.
//
// So: no brand hex, no gradient ramp, no vendor path data, in this file or in
// anything it imports. ConnectorLogos.test.tsx reads this SOURCE and fails the
// build if any comes back — a render-only guard would miss a mark re-inlined
// behind a flag.

import CloudGlyph from "./CloudGlyph";

type LogoProps = { size?: number; className?: string };

// ── Cloud provider marks (onboarding wizard) ────────────────────────
// ORIGINAL Correlix artwork — NOT the providers' marks. What renders is the
// cloud-glyph family (components/CloudGlyph.tsx) — ONE silhouette in the
// product's own icon style, with a plain letter tag as the only difference.
//
// The cloud PROVIDER names (AWS / Azure / GCP) remain fine to show — the "no
// backend vendor names" rule is about OUR stack, not the clouds we observe —
// and the tag is exactly that: a nominative textual reference, never a wordmark,
// never a claim of endorsement.
//
// These keep the `*Logo` names and the LogoProps signature so no call site
// churns. They render the TAGGED variant: the connector gallery shows the three
// tiles side by side at 44px (ConnectorWizard) and the SNS channel card at 30px
// (admin), where the glyph is the tile's primary identifier and an untagged
// cloud on all three would make the gallery unreadable at a glance. That is the
// opposite call from pages/appobs/badges.tsx, where the mark is 14px with the
// provider name printed immediately beside it and a tag would only repeat it.

export function AwsLogo({ size = 40, className }: LogoProps) {
  return <CloudGlyph provider="aws" size={size} className={className} />;
}

export function AzureLogo({ size = 40, className }: LogoProps) {
  return <CloudGlyph provider="azure" size={size} className={className} />;
}

export function GcpLogo({ size = 40, className }: LogoProps) {
  return <CloudGlyph provider="gcp" size={size} className={className} />;
}

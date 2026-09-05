// Marks for the Integrations connector gallery, inlined as SVG so they render
// crisply at any size and carry no asset-pipeline / runtime dependency.
//
// TWO DIFFERENT KINDS OF MARK LIVE IN THIS FILE — do not confuse them:
//
// 1. The SIX ITSM / notification marks (ServiceNow, Jira, Slack, Twilio,
//    PagerDuty, Microsoft Teams) ARE the official vendor brand marks: vector
//    data and brand palette reproduced as published.
//      • ServiceNow — the circular "Now" symbol (brand green-teal #81b5a1).
//      • Jira       — the Atlassian Jira mark (brand blue gradient #0052cc→#2684ff).
//    `useId` namespaces the Jira gradient ids so multiple instances on a page
//    (tile + modal header) never collide.
//
// 2. The THREE CLOUD-PROVIDER marks (AWS, Azure, GCP) are NOT vendor artwork.
//    Licence audit D5 (2026-09-04) removed the official AWS/Azure/Google marks
//    from this file; those tiles now draw ORIGINAL Correlix artwork from
//    components/CloudGlyph.tsx — one cloud silhouette carrying a plain letter
//    tag. No cloud-provider brand colour or logo path data remains here, and
//    ConnectorLogos.test.tsx fails the build if any comes back.

import { useId } from "react";
import CloudGlyph from "./CloudGlyph";

type LogoProps = { size?: number; className?: string };

export function ServiceNowLogo({ size = 40, className }: LogoProps) {
  return (
    <svg width={size} height={size} viewBox="0 0 64 64" className={className} aria-hidden="true" role="img">
      <path
        fillRule="evenodd"
        fill="#81b5a1"
        d="M32.195 3.312A32.267 32.267 0 0 0 9.949 58.883a6.346 6.346 0 0 0 8.264.43 23.035 23.035 0 0 1 27.445 0 6.364 6.364 0 0 0 8.389-.43A32.267 32.267 0 0 0 32.195 3.312m-.18 48.275a15.632 15.632 0 0 1-16.133-16.026 16.044 16.044 0 1 1 32.07 0 15.614 15.614 0 0 1-16.026 16.026"
      />
    </svg>
  );
}

export function JiraLogo({ size = 40, className }: LogoProps) {
  const id = useId().replace(/:/g, "");
  const a = `${id}-a`, b = `${id}-b`, c = `${id}-c`;
  return (
    <svg width={size} height={size} viewBox="0 0 64 64" className={className} aria-hidden="true" role="img">
      <defs>
        <linearGradient id={a} gradientUnits="userSpaceOnUse">
          <stop offset=".18" stopColor="#0052cc" />
          <stop offset="1" stopColor="#2684ff" />
        </linearGradient>
        <linearGradient id={b} x1="42.023" y1="35.232" x2="44.133" y2="33.122" xlinkHref={`#${a}`} />
        <linearGradient id={c} x1="41.464" y1="29.159" x2="39.35" y2="31.273" xlinkHref={`#${a}`} />
      </defs>
      <g transform="matrix(6.249587 0 0 6.249587 -228.82126 -169.26286)">
        <path
          fill="#2684ff"
          d="M46.568 31.918l-4.834-4.834-4.834 4.834a.406.406 0 0 0 0 .573l4.834 4.834 4.834-4.834a.406.406 0 0 0 0-.573zm-4.834 1.8l-1.514-1.514 1.514-1.514 1.514 1.514z"
        />
        <path fill={`url(#${c})`} d="M41.734 30.7a2.549 2.549 0 0 1-.011-3.594L38.4 30.408l1.803 1.803z" />
        <path fill={`url(#${b})`} d="M43.252 32.2l-1.518 1.518a2.549 2.549 0 0 1 0 3.606l3.32-3.32z" />
      </g>
    </svg>
  );
}

// Slack — the official four-colour mark.
export function SlackLogo({ size = 40, className }: LogoProps) {
  return (
    <svg width={size} height={size} viewBox="0 0 128 128" className={className} aria-hidden="true" role="img">
      <path fill="#de1c59" d="M27.255 80.719c0 7.33-5.978 13.317-13.309 13.317C6.616 94.036.63 88.049.63 80.719s5.987-13.317 13.317-13.317h13.309zm6.709 0c0-7.33 5.987-13.317 13.317-13.317s13.317 5.986 13.317 13.317v33.335c0 7.33-5.986 13.317-13.317 13.317-7.33 0-13.317-5.987-13.317-13.317zm0 0" />
      <path fill="#35c5f0" d="M47.281 27.255c-7.33 0-13.317-5.978-13.317-13.309C33.964 6.616 39.951.63 47.281.63s13.317 5.987 13.317 13.317v13.309zm0 6.709c7.33 0 13.317 5.987 13.317 13.317s-5.986 13.317-13.317 13.317H13.946C6.616 60.598.63 54.612.63 47.281c0-7.33 5.987-13.317 13.317-13.317zm0 0" />
      <path fill="#2eb57d" d="M100.745 47.281c0-7.33 5.978-13.317 13.309-13.317 7.33 0 13.317 5.987 13.317 13.317s-5.987 13.317-13.317 13.317h-13.309zm-6.709 0c0 7.33-5.987 13.317-13.317 13.317s-13.317-5.986-13.317-13.317V13.946C67.402 6.616 73.388.63 80.719.63c7.33 0 13.317 5.987 13.317 13.317zm0 0" />
      <path fill="#ebb02e" d="M80.719 100.745c7.33 0 13.317 5.978 13.317 13.309 0 7.33-5.987 13.317-13.317 13.317s-13.317-5.987-13.317-13.317v-13.309zm0-6.709c-7.33 0-13.317-5.987-13.317-13.317s5.986-13.317 13.317-13.317h33.335c7.33 0 13.317 5.986 13.317 13.317 0 7.33-5.987 13.317-13.317 13.317zm0 0" />
    </svg>
  );
}

// Twilio — the official red roundel.
export function TwilioLogo({ size = 40, className }: LogoProps) {
  return (
    <svg width={size} height={size} viewBox="0 0 128 128" className={className} aria-hidden="true" role="img">
      <path fill="#f22f46" d="M48 92.309c16.41 0 16.41-24.618 0-24.618S31.59 92.31 48 92.31Zm0-32c16.41 0 16.41-24.618 0-24.618S31.59 60.31 48 60.31Zm32 32c16.41 0 16.41-24.618 0-24.618S63.59 92.31 80 92.31Zm0-32c16.41 0 16.41-24.618 0-24.618S63.59 60.31 80 60.31ZM64 0c34.664 0 64 29.336 64 64s-29.336 64-64 64S0 98.664 0 64 29.336 0 64 0Zm0 17.23c-25.758 0-46.77 20.286-46.77 45.91 0 25.626 21.012 47.63 46.77 47.63 25.758 0 46.77-22.004 46.77-47.63 0-25.624-21.012-45.91-46.77-45.91Zm0 0" />
    </svg>
  );
}

// ── Cloud provider marks (onboarding wizard) ────────────────────────
// ORIGINAL Correlix artwork — NOT the providers' marks. The official AWS Smile,
// the Azure gradient chevron and the Google Cloud four-colour "G" were deleted
// by licence audit D5 (2026-09-04): they were trademark vector data with only a
// terms-of-use posture, bundled into the shipped SPA. What renders now is the
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

// PagerDuty — the official green mark.
export function PagerDutyLogo({ size = 40, className }: LogoProps) {
  return (
    <svg width={size} height={size} viewBox="0 0 64 64" className={className} aria-hidden="true" role="img">
      <path fill="#25c151" d="M6.704 59.217H0v-33.65c0-3.455 1.418-5.544 2.604-6.704 2.63-2.58 6.2-2.656 6.782-2.656h10.546c3.765 0 5.93 1.52 7.117 2.8 2.346 2.553 2.372 5.853 2.32 6.73v12.687c0 3.662-1.496 5.828-2.733 6.988-2.553 2.398-5.93 2.45-6.73 2.424H6.704zm13.46-18.102c.36 0 1.367-.103 1.908-.62.413-.387.62-1.083.62-2.1v-13.02c0-.36-.077-1.315-.593-1.857-.5-.516-1.444-.62-2.166-.62h-10.6c-2.63 0-2.63 1.985-2.63 2.656v15.55zM57.296 4.783H64V38.46c0 3.455-1.418 5.544-2.604 6.704-2.63 2.58-6.2 2.656-6.782 2.656H44.068c-3.765 0-5.93-1.52-7.117-2.8-2.346-2.553-2.372-5.853-2.32-6.73V25.62c0-3.662 1.496-5.828 2.733-6.988 2.553-2.398 5.93-2.45 6.73-2.424h13.202zM43.836 22.9c-.36 0-1.367.103-1.908.62-.413.387-.62 1.083-.62 2.1v13.02c0 .36.077 1.315.593 1.857.5.516 1.444.62 2.166.62h10.598c2.656-.026 2.656-2 2.656-2.682V22.9z" />
    </svg>
  );
}

// Microsoft Teams — the official two-tone purple mark: the "T" tile in front of
// the two collaborator silhouettes.
export function TeamsLogo({ size = 40, className }: LogoProps) {
  return (
    <svg width={size} height={size} viewBox="0 0 64 64" className={className} aria-hidden="true" role="img">
      <circle cx="49.5" cy="15" r="6.5" fill="#5059c9" />
      <path fill="#5059c9" d="M44 24h14a2 2 0 0 1 2 2v13a9 9 0 0 1-9 9h-.5A9.5 9.5 0 0 1 41 38.5V27a3 3 0 0 1 3-3z" />
      <circle cx="33" cy="14" r="8" fill="#7b83eb" />
      <path fill="#7b83eb" d="M23 24h20a2 2 0 0 1 2 2v15a12 12 0 0 1-12 12 12 12 0 0 1-12-12V26a2 2 0 0 1 2-2z" />
      <rect x="4" y="16" width="32" height="32" rx="3" fill="#5059c9" />
      <path fill="#fff" d="M11 22h18v4.2h-6.8V42h-4.4V26.2H11z" />
    </svg>
  );
}

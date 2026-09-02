// Real vendor brand logos for the Integrations connector gallery, inlined as
// SVG so they render crisply at any size and carry no asset-pipeline / runtime
// dependency. Vector data is the official brand mark for each product:
//   • ServiceNow — the circular "Now" symbol (brand green-teal #81b5a1).
//   • Jira       — the Atlassian Jira mark (brand blue gradient #0052cc→#2684ff).
// `useId` namespaces the Jira gradient ids so multiple instances on a page
// (tile + modal header) never collide.

import { useId } from "react";

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

// ── Cloud provider marks (onboarding wizard) ─────────────────────────────────
// Provider brand marks for the connector catalog tiles. The cloud PROVIDER names
// (AWS / Azure / GCP) are the customer's own vocabulary and are fine to show — the
// "no backend vendor names" rule is about OUR stack, not the clouds we observe.

// AWS — the Smile arrow mark in Amazon orange.
export function AwsLogo({ size = 40, className }: LogoProps) {
  return (
    <svg width={size} height={size} viewBox="0 0 64 64" className={className} aria-hidden="true" role="img">
      <path fill="#ff9900" d="M18.4 27.9c0 .8.1 1.4.2 1.9.2.5.4 1 .7 1.6.1.2.2.4.2.5 0 .2-.1.4-.4.6l-1.3.9c-.2.1-.4.2-.5.2-.2 0-.4-.1-.6-.3-.3-.3-.5-.6-.7-1-.2-.4-.4-.8-.6-1.3-1.5 1.8-3.4 2.7-5.7 2.7-1.6 0-2.9-.5-3.9-1.4s-1.4-2.2-1.4-3.7c0-1.7.6-3 1.8-4s2.8-1.5 4.8-1.5c.7 0 1.4.1 2.1.2s1.5.3 2.3.5v-1.4c0-1.4-.3-2.4-.9-3-.6-.6-1.6-.9-3-.9-.7 0-1.3.1-2 .2-.7.2-1.3.4-2 .6-.3.1-.5.2-.6.2-.1 0-.2.1-.3.1-.3 0-.4-.2-.4-.6v-1c0-.3 0-.5.1-.7.1-.1.3-.3.5-.4.7-.3 1.5-.6 2.4-.9 1-.3 2-.4 3.1-.4 2.4 0 4.1.5 5.2 1.6s1.6 2.7 1.6 5v6.6zm-7.9 3c.6 0 1.3-.1 2-.3.7-.2 1.3-.7 1.9-1.3.3-.4.6-.8.7-1.3.1-.5.2-1.1.2-1.7v-.8c-.6-.1-1.2-.3-1.8-.3-.6-.1-1.2-.1-1.8-.1-1.3 0-2.2.3-2.9.8-.6.5-.9 1.2-.9 2.2 0 .9.2 1.6.7 2 .4.6 1.1.8 1.9.8zm15.7 2.1c-.4 0-.6-.1-.8-.2-.2-.1-.3-.4-.5-.8L20.3 15c-.1-.4-.2-.7-.2-.8 0-.3.2-.5.5-.5h2c.4 0 .7.1.8.2.2.1.3.4.4.8l3.2 12.9 3-12.9c.1-.4.2-.7.4-.8s.5-.2.8-.2h1.7c.4 0 .7.1.8.2.2.1.3.4.4.8l3 13 3.3-13c.1-.4.3-.7.4-.8.2-.1.5-.2.8-.2h1.9c.3 0 .5.2.5.5 0 .1 0 .2-.1.3 0 .1-.1.3-.2.5l-4.6 14.9c-.1.4-.3.7-.5.8-.2.1-.4.2-.8.2h-1.9c-.4 0-.7-.1-.8-.2-.2-.2-.3-.4-.4-.8l-3-12.6-3 12.5c-.1.4-.2.7-.4.8-.2.2-.5.2-.8.2h-1.9zm25.1.6c-1 0-2-.1-3-.4-1-.2-1.7-.5-2.2-.8-.3-.2-.5-.4-.6-.5-.1-.2-.1-.4-.1-.5v-1c0-.4.2-.6.5-.6.1 0 .2 0 .4.1.1 0 .3.1.5.2.6.3 1.3.5 2 .6.7.1 1.4.2 2.2.2 1.1 0 2-.2 2.6-.6.6-.4.9-1 .9-1.7 0-.5-.2-.9-.5-1.2-.3-.3-.9-.6-1.8-.9l-2.6-.8c-1.3-.4-2.3-1-2.9-1.8-.6-.8-.9-1.6-.9-2.6 0-.7.2-1.4.5-2 .3-.6.7-1.1 1.3-1.5.5-.4 1.2-.7 1.9-.9.7-.2 1.5-.3 2.3-.3.4 0 .8 0 1.3.1.4.1.8.1 1.2.2.4.1.7.2 1 .3.3.1.6.2.7.4.2.1.3.2.4.4.1.1.1.3.1.5v.9c0 .4-.2.6-.5.6-.2 0-.4-.1-.8-.2-1.1-.5-2.3-.7-3.7-.7-1 0-1.8.2-2.4.5-.5.3-.8.8-.8 1.5 0 .5.2.9.5 1.2.4.3 1 .6 1.9.9l2.5.8c1.3.4 2.2 1 2.8 1.7.6.7.9 1.5.9 2.5 0 .8-.2 1.5-.5 2.1-.3.6-.8 1.2-1.3 1.6-.6.4-1.3.8-2.1 1-.8.3-1.7.4-2.7.4z" />
      <path fill="#ff9900" d="M55.8 43.4c-6.4 4.7-15.7 7.2-23.7 7.2-11.2 0-21.3-4.1-28.9-11-.6-.5-.1-1.3.7-.9 8.2 4.8 18.4 7.7 28.9 7.7 7.1 0 15-1.5 22.2-4.5 1-.5 1.9.7.8 1.5z" />
      <path fill="#ff9900" d="M58.5 40.3c-.8-1.1-5.4-.5-7.5-.3-.6.1-.7-.5-.1-.9 3.7-2.6 9.7-1.8 10.4-1 .7.9-.2 6.9-3.6 9.8-.5.4-1 .2-.8-.4.7-1.9 2.3-6.1 1.6-7.2z" />
    </svg>
  );
}

// Azure — the official gradient "A" chevron.
export function AzureLogo({ size = 40, className }: LogoProps) {
  const id = useId().replace(/:/g, "");
  return (
    <svg width={size} height={size} viewBox="0 0 64 64" className={className} aria-hidden="true" role="img">
      <defs>
        <linearGradient id={`${id}-a`} x1="30" y1="8" x2="18" y2="43" gradientUnits="userSpaceOnUse">
          <stop offset="0" stopColor="#114a8b" />
          <stop offset="1" stopColor="#0669bc" />
        </linearGradient>
        <linearGradient id={`${id}-b`} x1="38" y1="35" x2="35" y2="36" gradientUnits="userSpaceOnUse">
          <stop offset="0" stopColor="#000" stopOpacity=".3" />
          <stop offset="1" stopColor="#000" stopOpacity="0" />
        </linearGradient>
        <linearGradient id={`${id}-c`} x1="34" y1="7" x2="47" y2="42" gradientUnits="userSpaceOnUse">
          <stop offset="0" stopColor="#3ccbf4" />
          <stop offset="1" stopColor="#2892df" />
        </linearGradient>
      </defs>
      <path fill={`url(#${id}-a)`} d="M23.7 9h11l-11.4 33.8a1.8 1.8 0 0 1-1.7 1.2H12.9a1.8 1.8 0 0 1-1.7-2.4L22 10.2A1.8 1.8 0 0 1 23.7 9z" />
      <path fill="#0078d4" d="M39.6 32.8H22.1a.8.8 0 0 0-.6 1.4l11.2 10.5a1.8 1.8 0 0 0 1.2.5H44z" />
      <path fill={`url(#${id}-b)`} d="M23.7 9a1.8 1.8 0 0 0-1.7 1.2L11.3 41.5a1.8 1.8 0 0 0 1.7 2.4h8.9a1.9 1.9 0 0 0 1.5-1.3l2.1-6.3 7.6 7.1a1.8 1.8 0 0 0 1.1.4H44l-4.4-11.2-12.8 0L34.8 9z" />
      <path fill={`url(#${id}-c)`} d="M42 10.2A1.8 1.8 0 0 0 40.3 9H23.8a1.8 1.8 0 0 1 1.7 1.2l10.8 31.6a1.8 1.8 0 0 1-1.7 2.4h16.5a1.8 1.8 0 0 0 1.7-2.4z" />
    </svg>
  );
}

// Google Cloud — the four-colour hexagon "G".
export function GcpLogo({ size = 40, className }: LogoProps) {
  return (
    <svg width={size} height={size} viewBox="0 0 64 64" className={className} aria-hidden="true" role="img">
      <path fill="#ea4335" d="M40.3 22.5h1.9l5.4-5.4.3-2.3A24.3 24.3 0 0 0 9.4 26.6a2.9 2.9 0 0 1 1.9-.1l10.8-1.8s.5-.9.8-.9a13.5 13.5 0 0 1 17.6-1.4z" />
      <path fill="#4285f4" d="M55.4 26.6a24.3 24.3 0 0 0-7.3-11.8l-7.6 7.6a13.5 13.5 0 0 1 5 10.7v1.3a6.7 6.7 0 0 1 0 13.5H37l-1.3 1.4v8.1l1.3 1.3h13.4A17.6 17.6 0 0 0 55.4 26.6z" />
      <path fill="#34a853" d="M23.6 57.4h13.4v-10.8H23.6a6.7 6.7 0 0 1-2.8-.6l-1.9.6-5.4 5.4-.5 1.9a17.5 17.5 0 0 0 10.6 3.5z" />
      <path fill="#fbbc05" d="M23.6 22.3A17.6 17.6 0 0 0 13 53.9l7.8-7.8a6.7 6.7 0 1 1 8.9-8.9l7.8-7.8a17.5 17.5 0 0 0-13.9-7.1z" />
    </svg>
  );
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

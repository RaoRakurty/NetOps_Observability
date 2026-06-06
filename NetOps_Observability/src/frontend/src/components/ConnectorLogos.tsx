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

# Premium NOC Glassmorphism Visual System (Correlix)

Owner directive (2026-06-17). A premium, **serious, NOC-grade** glassmorphism system —
dark graphite / midnight navy foundation, frosted-glass elevated panels, restrained
shadows, disciplined status color. **Not** bright, playful, neon, or
consumer-analytics. Feel: a premium NOC command center vs Datadog / Dynatrace /
ThousandEyes / Cisco-grade tooling.

## Palette (→ CSS design tokens; single source)
| Token | Value | Use |
|---|---|---|
| `--bg-app` | `#070B14` | app background (radial premium, not flat) |
| `--bg-chrome` | `#0B1020` | sidebar / header |
| `--glass` | `rgba(17,25,40,0.72)` | glass panel |
| `--glass-strong` | `rgba(20,28,46,0.88)` | strong glass panel |
| `--glass-border` | `rgba(148,163,184,0.16)` | glass border |
| `--glass-border-strong` | `rgba(148,163,184,0.28)` | strong border |
| `--text` | `#F8FAFC` | primary text |
| `--text-2` | `#CBD5E1` | secondary text |
| `--text-muted` | `#94A3B8` | muted text |
| `--accent-teal` | `#2DD4BF` | live telemetry, active diagnostics, verified evidence |
| `--accent-cyan` | `#38BDF8` | live telemetry (alt) |
| `--accent-blue` | `#3B82F6` | neutral accent / links |
| `--accent-ai` | `#A78BFA` | AI / copilot / evidence reasoning ONLY |
| `--crit` | `#F43F5E` | confirmed critical impact ONLY |
| `--suspected` | `#F97316` | suspected RCA + carrier/ISP fault domain |
| `--warn` | `#FBBF24` | warning |
| `--ok` | `#10B981` | confirmed healthy / available telemetry ONLY |
| `--unknown` | `#64748B` | unknown |

## Rules
- Glass ONLY for elevated surfaces: command bar, RCA hero banner, topology inspector,
  AI assistant panel, major cards. Tables/dense lists stay highly readable (no blur).
- Color communicates ONLY: severity, confidence, ownership, telemetry freshness.
- Glow = very subtle status aura for critical/suspected only. No colorful gradients
  everywhere. No flashy animations. Light hover/focus states (no bounce).
- Avoid low-contrast text on glass; meet WCAG contrast. Verify with the `scan` skill.

## Specific upgrades
1. Main content bg: flat white → dark graphite/radial premium.
2. Major cards → frosted glass (blur + subtle border + restrained shadow).
3. Suspected-RCA banner → premium glass hero, amber/orange severity.
4. Critical health-score card → restrained red/pink critical styling.
5. Teal/cyan for live telemetry/active diagnostics/verified evidence.
6. Purple for AI/copilot/evidence reasoning.
7. Amber/orange for suspected RCA + carrier/ISP fault domain.
8. Red for confirmed critical impact only.
9. Green for confirmed healthy/available telemetry only.
10. All colors as CSS variables/tokens (consistent theme).
11. Light hover + focus states, no flash.
12. Accessibility + readable contrast.

## Critique focus (Operations Overview / FrontPage — strict, VP-of-NetOps lens)
Visual hierarchy · enterprise polish · NOC decision clarity · RCA credibility ·
density without clutter · typography · spacing · color discipline · operator wording ·
demo readiness. Fix: weak KPI cards, generic empty states, raw event lists, ambiguous
dashes, lowercase protocol/provider names (→ BGP, OSPF, ISP, AWS…), weak owner/
fault-domain prominence, and any panel that doesn't answer **what happened, why, who
owns it, what to do next**.

## Scope / sequencing
Tracked as task. Sequenced AFTER the RCA PDF↔screen topology-parity refactor (owner's
choice). Apply with the `frontend-design` / `ui-ux-pro-max` skills; verify contrast
with `scan`. See [[netops-defense-security-and-premium-noc-ui]] (standing premium bar).

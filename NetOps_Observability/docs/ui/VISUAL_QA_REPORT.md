# Visual QA report

One entry per crawl (see FRONTEND_UI_AUDIT.md, "How it is measured").
Screenshots are kept outside the repo; the numbers here are the record.

## 2026-10-19 — baseline + C1 (phone width)

- Stack: lab, main @ 38b3df36, platform workspace, 68 routes × 3 viewports
  (dark/light 1440×900, dark 390×844). Page errors: **0**.
- Phone width, before C1: **68/68** routes scrolled sideways.
- Phone width, after C1 (preview build of this change against the same lab):
  **67/68** fit; `security/overview` open (U3).
- Desktop: no horizontal scroll on any route, either theme.
- Type: 12.5px is the most common text size (≈4,100 elements), then 12px
  (≈2,200); 14px third (≈1,650). Tracked as U1.

# Iris panel — window interaction design (owner, 2026-10-05)

**Status:** design of record for the Iris panel/window. Owner-supplied 2026-10-05.
**Scope:** only how the Iris panel looks, opens, docks, expands, resizes and animates.
The Iris conversation/content model (`docs/design/IRIS_AI_DESIGN.md`, the plan of record
`docs/architecture/iris-natural-language-platform.md`) is **unchanged** by this document.
**Tracker:** rows 338–342 (`docs/TRACKER.md`), under the umbrella of row 337.

## Relationship to the existing Iris design

- `IRIS_AI_DESIGN.md` and the NL platform plan specify what goes **inside** an answer:
  presentation renderer, statement classes, hypotheses trace, chips, evidence. They never
  specified the window, which is why the 2026-10-04 lab deploy showed no visible Iris change.
  This document is that missing piece. The contents keep their current components.
- **Supersedes** the same-day "floating assistant" direction: a round bottom-right launcher that
  popped up a chat window. That was built on `iris/floating-assistant` (PR #18, closed unmerged)
  and is explicitly ruled out below: "Do not use a large bottom-right chatbot bubble." Reusable
  parts of that branch (one mounted container, focus trap, Esc handling, conversation id surviving
  close/reopen, the vitest/e2e harness) may be carried over. Its launcher and bottom-right anchoring
  may not.
- **Unchanged constraints from earlier owner decisions:**
  - The topbar BLOGO5 wordmark is the shell's only brand mark. The `✦ Iris` control uses the Iris
    sparkle icon, never the standalone eye.
  - Theme is chosen at login only; no theme toggle here.
  - The NOC-admin UI standard applies: plain language, fonts ≥ 14 px.

## Mapping to the codebase (verified 2026-10-05)

| Concern | Today | This design |
|---|---|---|
| Container | `tabs/Opsis.tsx` header and body, opened via the shell's `copilotOpen` | One Iris container with a mode state machine. `Opsis.tsx` content is kept |
| Entry points | icon-rail "Iris AI" item, command palette, investigation page, `(i)` AskIris buttons | `✦ Iris` header control (upper right) is primary; the others open the same panel |
| Conversation | server conversation id in sessionStorage (`iris.conversation`) | unchanged; never reset across modes |
| Page context | AskIris topic + investigation page (N-E4 partial) | shown as minimal chips; no new backend AI |

---

## The design (owner's specification, verbatim)

Redesign only the **Iris AI panel/window interaction** in the existing Correlix network observability UI.

Do not redesign the overall application, navigation, dashboards, topology views, or Iris conversation/content model.

The task is specifically to improve:

- how Iris looks when closed and open
- how Iris opens
- floating vs docked behavior
- expand/collapse behavior
- resizing
- transitions
- subtle interaction feedback
- contextual visual cues
- the overall feeling of Iris as a modern, intelligent observability copilot

The result should feel comparable in quality to the best AI assistants in modern observability and developer platforms, while remaining appropriate for a serious enterprise network operations product.

### Core UX model

Use these Iris states: `closed`, `floating`, `docked`, `expanded`. Optionally support a lightweight contextual state: `peek`.

The transitions should feel continuous: `closed → floating → docked → expanded` and, where contextual invocation exists, `peek → floating/docked`.

Never recreate the Iris conversation or reset state when moving between these modes.

### 1. Iris entry point

Place a compact Iris control in the **upper-right area of the global application header**. Preferred treatment: `✦ Iris`, or use the existing Iris icon if one already exists.

Do not use a large bottom-right chatbot bubble. The control should feel native to an observability platform, not like a customer-support widget.

When Iris has no activity, keep it visually quiet. When Iris is actively analyzing something, allow a very subtle ambient state on the icon, such as a soft pulse, a tiny animated ring, or a slight accent-color breathing effect. This should never be neon, flashy, rainbow-colored, or distracting. Respect `prefers-reduced-motion`.

### 2. Default open behavior — Floating mode

When the user clicks Iris, open it from the **right side as a floating panel**. Floating panel behavior:

- slide in from the right
- approximately 440–460px wide
- approximately 12–16px gap from top, right, and bottom application edges
- overlay the current workspace
- do not resize the center content while floating
- approximately 10–12px border radius
- thin neutral border
- subtle restrained shadow
- dark surface matching the existing Correlix theme
- clean enterprise typography
- no excessive gradients
- no glassmorphism unless already part of the design system
- no glowing borders
- no generic chatbot visual language

Use a smooth transition around 180–220ms. Prefer transform-based animation to avoid layout jank. The opening motion should feel deliberate and polished: a slight horizontal slide and a small opacity fade, with no bouncing or exaggerated overshoot.

### 3. Iris header

Use a minimal header similar to: `✦ Iris                     [Dock] [Expand] [Close]`

Use icon buttons with tooltips. All controls must have accessible labels, for example Dock / Undock, Expand, Close.

Avoid draggable free-floating desktop-window behavior. Iris should feel integrated into the application shell, not like an operating-system window.

### 4. Dock behavior

When the user clicks Dock:

- snap Iris to the right edge
- remove the floating gap
- remove or greatly reduce the floating shadow
- flatten the corner radius where the panel meets the application shell
- reflow the Correlix workspace so Iris no longer overlaps the center content
- keep Iris fixed on the right
- preserve the left navigation and center workspace

Maintain the spatial model: Left = navigation, Center = observability workspace, Right = Iris intelligence. Do not support left docking or bottom docking.

Default dock width: `480px`. Resizable range: `380px` minimum, `650px` maximum. Add a draggable vertical splitter. During resize:

- show the `ew-resize` cursor
- subtly highlight the splitter
- update width in real time
- throttle expensive resize-related work
- avoid re-rendering the whole application unnecessarily

Allow keyboard resizing of the splitter if practical. Persist the last docked width.

### 5. Make docking feel satisfying

The transition from floating to docked should not look like Iris closes and reopens. Make it feel like Iris physically joins the workspace. Use a subtle "snap into place" interaction:

1. the floating panel moves toward the edge
2. the outer gap reduces
3. the shadow fades
4. the workspace begins reflowing
5. the panel settles into its docked position

Total motion should still be around 180–220ms. No exaggerated spring animation; a very small settle effect is acceptable if it feels premium.

### 6. Undock behavior

When the user clicks Undock: the center content expands back to normal width, Iris detaches from the application edge, the floating gap returns, the floating shadow and radius return, and conversation and component state remain untouched. Animate this as the reverse of docking. Do not remount Iris.

### 7. Expanded mode

Expand turns Iris into a near-full-screen or large investigation workspace. For this task, do not redesign the expanded workspace itself; only implement the transition behavior. Supported transitions: `floating → expanded`, `docked → expanded`, `expanded → previous state`. Remember the previous mode: if the user entered Expanded from Docked, collapse back to Docked; if they entered from Floating, collapse back to Floating.

### 8. Close behavior

Close hides Iris completely. When Iris is reopened, restore the user's previous preferred mode (last state Docked → reopen Docked; last state Floating → reopen Floating). Preserve the conversation, current context, panel width, mode preference, and scroll position where practical.

Keyboard behavior for `Esc`: Expanded → previous state; Floating/Docked → Closed. Return keyboard focus to the Iris header button after closing.

### 9. Add a subtle contextual Peek interaction

If the existing Correlix UI already supports contextual AI actions, add a lightweight **Peek** mode. For example, when a user clicks something like `Ask Iris` on a chart, interface, alert, topology object, tunnel, service, or device, briefly show a compact contextual Iris card near that object, roughly `320–360px` wide. The card should:

- visually connect to the selected object
- show a short Iris response or acknowledgement
- provide a clear action such as `Open in Iris`
- smoothly promote into the main floating or docked Iris panel

Animation: about 150ms, a small fade plus 4–8px positional movement. Do not open Peek cards on simple hover alone; require an intentional click or action so the UI does not feel noisy. If no contextual integration exists today, structure the panel code so this state could be supported later without rewriting the component.

### 10. Give Iris a tasteful sense of personality

Iris should feel intelligent and responsive, but never playful in a childish way. Add small micro-interactions:

- **Iris icon press:** on click, scale very slightly (around `0.96–0.98`) and return immediately, over about 80–120ms. This should feel tactile.
- **Thinking state:** when Iris is actively performing an analysis, show a subtle pulse around the Iris icon or header mark, using only the existing Iris accent color at low opacity, slow and calm, around 700–900ms per cycle. Do not animate continuously when nothing is happening.
- **Dock control:** when Dock is clicked, briefly highlight the target edge or splitter, then snap Iris into position. This helps the user understand what just happened.
- **Resize limits:** when the user reaches min or max width, add a very small resistance or visual stop, with no elastic cartoon bounce.
- **Hover behavior:** all header actions get subtle hover feedback: a low-opacity surface highlight with a 120–160ms transition.
- **Context arrival:** if Iris receives new page context, animate the context indicator/chip in with a small fade plus translate, over about 150–200ms. Do not repeatedly animate stable context.

### 11. Ambient intelligence cue

Give Iris a small, useful closed-state cue without making it intrusive. For example, when Iris detects something relevant in the current page context, the `✦ Iris` control may briefly show a tiny dot, a restrained pulse, or a short accent line. Do not display unsolicited popups, do not auto-open Iris, and do not interrupt the user. The cue should simply communicate "Iris noticed something." The user remains in control.

### 12. Context awareness in the shell

Without redesigning Iris content, allow the panel shell/header to visually show that Iris understands the current page. Example header subtext: `Current context: WAN Health`, or compact chips like `Branch-42`, `Last 30m`, `WAN Health`. Keep this minimal. Do not expose sensitive context without user permission. Use existing context APIs if they already exist. Do not build new backend AI behavior for this task.

### 13. Accessibility requirements

- The Iris launcher includes `aria-expanded` and `aria-controls`.
- The Iris container uses an appropriate semantic role such as `role="complementary"`, or dialog semantics if the current application architecture makes that more appropriate.
- All icon controls need `aria-label`, keyboard focus states, and tooltips.
- Keyboard: Tab through controls; Enter/Space activates buttons; Esc collapses or closes appropriately; focus returns to the launcher after close.
- Respect `prefers-reduced-motion`. Do not remove visible focus indicators. Ensure sufficient contrast in dark mode.

### 14. Performance

Do not load heavy Iris UI unnecessarily:

- lazy-initialize heavy Iris content on first open
- preserve component state afterward
- avoid unnecessary remounts
- use CSS transforms for motion
- debounce/throttle splitter resize work
- prevent layout thrashing
- preserve the conversation without keeping unnecessarily huge DOM trees rendered

If the codebase already has state-management or persistence utilities, use them. Do not introduce a new global state library just for this feature.

### 15. Persistence

Persist the last Iris mode, the last docked width, whether Iris was pinned, and the previous mode before Expand. Use the project's existing persistence approach; if none exists, prefer lightweight local/session storage. Do not persist sensitive AI conversation content unless the existing architecture already does so.

### 16. Responsive behavior

Desktop is the primary design target. For narrower viewports: if there is insufficient room for a docked panel, automatically use overlay/floating behavior; do not squeeze the observability workspace into an unusable width; on very narrow layouts, Iris may use a near-full-screen overlay. Do not create additional left or bottom dock modes.

### 17. Visual direction

Target the quality bar of modern enterprise observability and developer interfaces. The feeling should be calm, intelligent, responsive, polished, premium, technical, focused and deeply integrated. Avoid chat-bubble UI, neon AI aesthetics, colorful gradients, constant motion, excessive glass effects, oversized assistant branding, cartoon-like animation, unnecessary shadows, and modal-heavy behavior. Iris should feel like a native intelligence pane inside Correlix.

### 18. Implementation approach

Before changing code:

1. inspect the existing Correlix layout components
2. locate the application header
3. locate any current Iris component
4. identify existing drawer/panel primitives
5. identify design tokens for spacing, radius, elevation, border, motion, and color
6. identify the existing state/persistence pattern
7. reuse these wherever possible

Do not introduce a parallel design system. Do not change unrelated files. Use the smallest reasonable implementation footprint. Maintain one logical Iris component across state transitions.

### Acceptance criteria

The implementation is complete when:

- clicking Iris opens a polished right-side floating panel
- the floating panel does not resize the workspace
- Dock smoothly integrates Iris into the right side
- docked Iris causes the center workspace to reflow
- the dock width is resizable and remembered
- Undock restores the floating state
- Expand returns to the correct previous state
- close/reopen preserves the preferred mode
- conversation and component state are preserved through transitions
- animations are smooth and restrained
- keyboard and focus behavior works
- reduced-motion users are respected
- no bottom-right chatbot bubble is introduced
- no left/bottom docking is introduced
- no major unrelated UI changes are made

Most importantly, the finished experience should make Iris feel like a **living, context-aware intelligence surface inside a network observability platform**, while remaining professional enough for an engineer to leave open all day.

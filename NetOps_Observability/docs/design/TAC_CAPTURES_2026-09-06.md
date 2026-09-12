# TAC escalation — the Captures model (owner decision, 2026-09-06)

Supersedes the plan → review → collect presentation in
`TAC_ESCALATION_2026-09-05.md` §5. The engine (classify, command plan, bindings,
citations, redaction, bundle) is unchanged; what the customer sees is not.

## What the customer sees

1. **Nothing to review.** Classification, command extraction and the default
   capture for the device's vendor happen silently. No plan table, no intent
   ids, no citation links, no verification chips in the escalation step.
2. **Captures.** A capture is a named list of commands. Correlix supplies the
   vendor default. The customer may upload their own — `txt` (one command per
   line, `#` comments), `csv` (`command[,note]`), `json` (`{"name","commands":[…]}`),
   `yaml` (same shape), `docx` (one command per paragraph or table row). Every
   line is validated against the output-only policy (`forbidden.yaml`,
   ping/traceroute bounds) before the capture is accepted; a refused line names
   the rule. An uploaded capture replaces the vendor default for that
   escalation and can be saved as a tenant template.
3. **Commands collapsed.** A capture row shows name · command count · status.
   An expand control reveals the commands; nothing expands by default.
4. **Progress, not output.** While collecting, the status column is a coloured
   bar: queued (grey) · running (blue) · done (green) · partial (amber) ·
   failed (red). Only commands that FAILED are listed under the row, in the
   error colour, each with its reason (timeout · refused by device · not on
   this platform · gateway unavailable). Successful output goes to the bundle
   and is never rendered.
5. **Behind the scenes, on demand.** One collapsible control ("What Correlix is
   doing") shows the class chosen, the commands with their sources and
   verification state, and the collection log — the material the panel used
   to show inline.
6. **Unchanged claims.** "Passwords, keys and community strings are masked" and
   "Correlix never opens a case on its own" stay, one line each.

## Data

- Capture = `{id, tenant_id, name, source: vendor-default|uploaded|template,
  dialect, commands[], created_by, created_at}` in the existing template store
  (RLS, tenant from the token). Upload parsing is server-side, stdlib only
  (`archive/zip` + `encoding/xml` for docx), bounded (1 MiB, 500 commands).
- Collection status per capture and per command already exists in the collect
  state machine; the UI reads it, it does not add a lane.

## Guard

Escalation-step tests assert: no intent id text, no citation links, no
research paragraph, commands hidden until expanded, only failed commands
rendered after a partial collection, upload of each format round-trips, a
forbidden line is refused by name.

# Adding a new slash command

Slash commands are a **guided front door to the same intent system** as natural
language — they must not create a second answer path. A command maps to a
*canonical natural-language phrasing* that `Classify` already routes.

## Steps

1. Add an entry to `commands` in `src/backend/ai/commands.go`:

   ```go
   {Command: "/flows", Aliases: []string{"/talkers", "/traffic"}, Label: "Flow analytics",
       Description: "Top talkers and busiest services in the recent window.",
       Intent: "flow_analytics_summary", RiskLevel: "read_only",
       canonical: "show me top talkers and busiest services"},
   ```

   - `canonical` must be a phrasing that `Classify` already routes to the intended
     intent (verify with a convergence test). Trailing user text after the command
     is appended (e.g. `/playbook bgp flap` → `how do I troubleshoot bgp flap`).
   - `RiskLevel`: `read_only`, or `draft` for write-ish commands (drafts only — no
     send/close/assign in v1).
   - `/help` is special (handled in the gateway, lists commands).

2. **Test** (`go test ./ai/`): add a case to `TestSlashAndNaturalLanguageConverge`
   asserting the command and its natural-language equivalent yield the SAME intent.

3. Nothing else — `GET /api/ai/commands` and `/commands/suggestions` serve the
   registry to the UI automatically, and `handleAIAsk` resolves the command before
   `Classify`.

## Rules

- One intent system: never branch a command to a bespoke handler that NL can't
  reach.
- Draft-only for anything write-ish; the model never sends/closes/assigns.
- If the target intent isn't built yet, that's fine — the command degrades to the
  same honest "not available yet" disclosure as the NL path.

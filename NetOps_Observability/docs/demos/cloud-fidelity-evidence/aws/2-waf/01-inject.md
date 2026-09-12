# AWS — WAF misfire  (scenario `DAWS2`)

Fill during the live capture window. Exact commands: **`../../RUNBOOK.md`**
→ "Scenario 2 — WAF misfire" (AWS block).
## What changed
<!-- one line: the component + rule/record/host and how it was altered -->

## Exact command / console step

```bash
# INJECT (paste the actual command you ran, from RUNBOOK.md):

```

```bash
# REVERT (paste the actual revert command):

```

## Timestamps (UTC)

| Event | Time |
|-------|------|
| Inject applied | |
| Signal seen in Correlix | |
| Revert applied | |
| Recovery confirmed | |

## Expected Correlix evidence

- **Lane / kind:** cloud_waf_log (BLOCK) + cloud_change
- **Log Search query:** `cloud_waf_log AND action:BLOCK`
- **RCA must attribute to:** <!-- the real component, not a neighbour -->

## Observed result

<!-- what actually rendered; note client-side generator corroboration
     (2xx/4xx/5xx/fail counts). If a lane was absent/blocked, record it as a
     GAP here with the reason — do NOT fabricate. -->

## Shots captured

- [ ] `02-provider-log.png` — provider console / CLI log
- [ ] `03-correlix-signal.png` — `./capture-scenario.sh aws 2-waf signal` (or log-lane zoom)
- [ ] `04-correlix-rca.png` — `./capture-scenario.sh aws 2-waf rca`
- [ ] `05-recovery.png` — `./capture-scenario.sh aws 2-waf recovery` (post-revert + soak)

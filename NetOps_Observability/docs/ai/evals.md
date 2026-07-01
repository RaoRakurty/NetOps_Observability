# Correlix AI — Evals

The eval suite (`src/backend/ai/evals_test.go`) encodes the design's
**definition-of-done** (§16) as runnable assertions over the orchestrator, so a
change that regresses a core guarantee fails CI. It runs entirely on the mock
provider — no credentials, offline.

## What each eval asserts

| Eval | Guarantee |
|------|-----------|
| StatusPrioritizesActionable | `/status` focuses a suspected classified incident over undetermined 0% noise |
| ZeroConfidenceWording | 0% → "Confidence not established"; no bare 0% in the body |
| UnclassifiedWording | verdict-only correlations read as "low-evidence", not raw |
| MissingEvidenceCleanWording | `needs ospf_adjacency_change` → humanized, not raw keys |
| OwnerInference | a routing incident infers a network/routing owner |
| ProviderUnavailableEvidenceOnly | provider down → polished evidence-only answer; provider state is a badge, not body text |
| PromptInjectionTreatedAsData | the server-owned system prompt fences evidence as data |
| SlashNLConvergence | a slash command and its NL equivalent share one intent |
| NavigationIncludesLocation | a navigation answer carries a UI deep link |
| CrossTenantDenied | a caller can't explain another tenant's incident |

Plus the verifier evals (`verify_test.go`): fabricated citations are stripped and
the answer is badged **Verified**.

## Running

```bash
cd src/backend && go test ./ai/ -run TestEval    # the DoD evals
go test ./ai/                                     # full ai package (evals + unit)
```

## Golden examples

`docs/ai/golden-examples/` holds representative answer shapes (the `/status`
briefing, an RCA explanation with an evidence gap, the KB playbook answer). They
document the expected structure of each answer-mode card; the evals enforce the
invariants behind them.

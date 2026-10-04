# Iris AI quality alerts

Warning-tier alerts from the `iris-ai-quality` group in
`src/config/rules-scale-slo.yaml` (tracker 337 N-A3). None wakes anyone; each
says the Iris scorecard's numbers have stopped meaning what they say. The
metrics are defined in `src/backend/internal/aiscore/metrics.go`.

## Unsupported-claim rate

`IrisUnsupportedClaimRateHigh` — more than 20 % of answers in the last hour had
a deterministic grounding guard remove content (≥ 20 answers in the window).

1. Which guard? `sum by (guard) (increase(netops_ai_grounding_guard_total[1h]))`.
   `fabricated_citation` = the model cited evidence it was not given;
   `uncertain_claim` = it stated a cause as confirmed when the engine had not.
2. Did the model change? Check the model tiers in **Iris settings** (platform and
   per-workspace `model_fast` / `model_strong`). A tier change is the usual cause.
3. Operators still got clean answers — the guard removed the text. Nothing to roll
   back in data; revert the model choice if the rate followed a change.

## Provider usage invisible

`IrisProviderUsageInvisible` — more than half of model calls returned no token
accounting (≥ 20 calls in the window). Iris never estimates tokens, so that spend
is unseen by the cost KPIs and by every tenant's daily-token budget.

1. `sum by (usage_reported) (increase(netops_ai_provider_calls_total[1h]))`.
2. Check which provider/model the affected workspaces use; a model whose response
   carries no usage block is the common cause.
3. Check the api logs for provider errors (`component":"ai"`): failed calls also
   report no usage.

## Scorecard not sampling

`IrisScorecardNotSampling` — the correlation-store sample has not completed for
30 minutes (`netops_ai_scorecard_sample_age_seconds` > 1800), or never (-1).

1. api logs: `ai-scorecard` errors.
2. ClickHouse reachable? Over its worker query budget
   (`docs/runbooks/clickhouse-query-budget.md`)?
3. Until it recovers, read correlation-derived scorecard KPIs as stale.

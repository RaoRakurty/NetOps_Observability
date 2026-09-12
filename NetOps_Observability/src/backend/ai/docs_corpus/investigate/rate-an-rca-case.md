---
title: Review and rate an RCA verdict
description: Review a verdict, record whether the engine was right, name which claim was wrong, and read the 30-day feedback tile.
page_type: task
sidebar_position: 4
---

# Review and rate an RCA verdict

The engine's confidence tier is its opinion of itself. The operator verdict you
record here is the only external measure of whether Correlix was right, and it
is what the 30-day feedback tile reports.

## Before you begin

- **Reading** recorded verdicts needs the same permission as the case itself
  (`infrastructure:read`). **Recording** one needs the incident-action
  permission `alerts:write`, the gate that acknowledging and assigning use.
- An RCA case you have actually worked. Rate the verdict against what you found,
  not against how the case reads.
- Verdicts are scoped to your tenant. A case from another tenant answers 404,
  identically to a case that does not exist.

## Steps

1. Open the case from **Investigate → RCA**.
2. Read the case header and the panels, as in
   [Read an RCA case](/investigate/read-an-rca-case).
3. Under the header, find **Was this verdict right?** and select one of
   **Correct**, **Partially** or **Wrong**. **Correct** is recorded
   immediately.
4. For **Partially** or **Wrong**, select which of the five claims the case makes
   was wrong. The vocabulary is closed, in the order the case asserts them:
   **Cause**, **Owner**, **Affected**, **Evidence**, **Recovery**. A verdict
   without a named part is refused with `Choose which part was wrong.`
5. Optionally describe what it got wrong, up to 500 characters. The counter
   under the box shows the budget. The text is operator prose and is deliberately
   not copied into the audit detail.
6. Select **Record verdict**.

## Result

Nothing is shown as recorded until the server has stored it and the page has
read it back, so what you see is what was persisted. The stored line reads:

```text
Operator verdict: Wrong — owner — 'ISP was not at fault' — alice, Sep 02, 10:14:00 UTC
```

Verdicts are append-only. Changing your mind adds a row; earlier verdicts stay
under **earlier verdicts** rather than being overwritten. The object version you
judged is submitted with the verdict, so a later re-render of the case cannot
silently reassign your judgement.

Read the recorded verdicts back for one case:

```bash
curl -s -H "Authorization: Bearer $TOKEN" \
  http://localhost:8000/api/correlations/7b32f8ef-496a-5ccd-82d5-bb3cfae66b27/feedback
```

```json
{"correlation_id":"7b32f8ef-496a-5ccd-82d5-bb3cfae66b27","count":0,"feedback":[]}
```

### The 30-day tile

**Analytics → Recovery Scorecard** carries **Verdict feedback (30 d)**, which
asks whether operators agreed with the engine. On an empty sample the
false-positive rate is `null` on the wire and renders as **Not enough feedback
yet**. It is never rendered as `0 %`, which would read as "the engine is never
wrong":

```bash
curl -s -H "Authorization: Bearer $TOKEN" \
  http://localhost:8000/api/correlations/feedback/summary
```

```json
{
  "by_template": [],
  "counts": {"correct": 0, "partial": 0, "wrong": 0},
  "days": 30,
  "false_positive_rate": null,
  "n": 0,
  "since": "2026-08-04T04:12:54Z"
}
```

The tile shows the correct / partially / wrong split beside the rate, so a
one-of-one sample cannot pass for a trend. A failed read says so and does not
render zeros.

## Related

- [Read an RCA case](/investigate/read-an-rca-case)
- [How root-cause analysis works](/investigate/rca-explained)
- [Investigation memory](/iris-ai/memory)
- [API reference](/reference/api)

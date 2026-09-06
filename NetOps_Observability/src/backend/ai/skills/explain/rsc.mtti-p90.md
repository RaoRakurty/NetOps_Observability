---
topic: rsc.mtti-p90
question: What does the P90 isolation time tell me?
keywords: p90, long tail isolation, percentile, worst incidents, mtti p90
---
P90 is long-tail isolation: 90% of incidents in this window were isolated
faster than this, 10% were slower. It exists beside the median because it
exposes the NOC pain that medians hide — a good P50 with a terrible P90 means
most incidents are routine and a handful burn an afternoon. Those are the ones
that cost overtime, escalations and customer credibility, so the gap between
P50 and P90 is usually the more useful number to work on.

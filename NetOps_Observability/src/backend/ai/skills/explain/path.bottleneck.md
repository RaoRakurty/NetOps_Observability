---
topic: path.bottleneck
question: How is the bottleneck hop chosen?
keywords: bottleneck, busiest link on the path, likely bottleneck, worst segment
---
A down or degraded link on the path is the bottleneck. If every link is up, the
busiest measured one is flagged once it passes a high utilization mark. It is
named "likely" because utilization is a symptom: a link can be saturated
because it is the problem, or because it is carrying traffic that a failure
elsewhere pushed onto it. Links with no measurement are never chosen — an
unmeasured link cannot be ranked.

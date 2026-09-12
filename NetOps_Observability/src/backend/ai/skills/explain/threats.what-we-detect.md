---
topic: threats.what-we-detect
question: What does threat detection look at?
keywords: what we detect, threat detection, device log detections, network behavior
---
Two kinds of evidence answer one question: is something acting on this estate.
Detections are rule-engine verdicts over device logs, each one a normalized
finding with the same detail as any other exposure. Network Behavior is derived
from flow records already collected — scan fan-out and traffic to high-risk
service ports — so it adds no new collection. Neither is a verdict on its own.
Both are triage starting points that ground into the correlation engine and
surface as exposure stories. The Detection Rules page lists which rules are
enabled; a disabled rule detects nothing.

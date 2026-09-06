---
topic: kpi.correlated-incidents
question: What does the Correlated incidents number count?
keywords: correlated incidents, correlation group, grouped alerts
---
On the Command Center this is the count of correlation groups, not of raw
alerts. The engine groups signals that share a cause, a time window and a
blast radius into one incident, so ten interface traps from one failed uplink
count as one. Working the queue therefore means working causes, not messages.
Selecting the number clears every filter and shows the whole queue below it.

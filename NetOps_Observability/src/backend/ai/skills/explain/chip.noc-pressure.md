---
topic: chip.noc-pressure
question: How is NOC pressure worked out?
keywords: noc pressure, pressure chip, watch chip, severe chip
---
The Command Center header chip grades how hard the queue is pushing right now.
Severe means three or more critical incidents are open, Elevated means at least
one, Watch means none are critical but something is suspected, and Nominal
means neither. It is derived from the same queue you see below, so it can never
disagree with the rows. It is a workload signal, not a service-level breach.

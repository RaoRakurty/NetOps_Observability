---
topic: rsc.time-loss-driver
question: What is the top time-loss driver?
keywords: time loss driver, lifecycle phase, where time is lost, delay driver
---
The lifecycle phase that accumulated the most operational delay across this
window — detection, correlation, isolation, evidence gathering, recovery or
closure. It is the answer to "if we could only fix one part of how incidents
run here, which part?" The Owner domains table shows the same driver per owner,
which usually differs: the phase that hurts on ISP-owned incidents is rarely the
phase that hurts on LAN-owned ones.

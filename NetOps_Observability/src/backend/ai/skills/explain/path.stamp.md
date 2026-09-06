---
topic: path.stamp
question: What is a STAMP probe?
keywords: stamp probe, active probe, one-way delay, owd, jitter pdv, rfc 8762
---
STAMP is a two-way active measurement protocol: a sender times stamped packets
against a reflector, so both directions are measured separately. That is why it
can report one-way delay and packet delay variation — jitter — which traceroute
cannot, because a traceroute only ever sees a round trip. Where both measured a
hop, STAMP is preferred, and each number carries the method that produced it.
One-way delay and jitter are never derived from a round-trip figure.

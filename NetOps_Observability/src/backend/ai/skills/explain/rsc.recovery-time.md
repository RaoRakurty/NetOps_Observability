---
topic: rsc.recovery-time
question: How is the median recovery time measured?
keywords: recovery time, service recovered, engine inferred recovery, ttr recovery
---
The median time until service health recovered. Where an ITSM recovery signal
is linked, that signal is the measurement. Where none is linked, recovery is
engine-inferred — the incident window closed with no further symptoms — and is
shown as an approximation, never as a measurement. The card reads "Not
measured" only when the window carries neither: no linked recovery signal and
no inferable close. That is deliberate on the NOC Recovery Scorecard. A
fabricated MTTR is worse than an honest blank, because a number nobody can
trace becomes a target somebody is held to.

---
topic: dem.step-coverage-gap
question: What happens to a step nothing measures?
keywords: step coverage gap, unmeasured step, no target
---
A journey step with no check attached is reported as a coverage gap, never as
a success. Counting an unmeasured step as passing would let a journey read
green because nobody was watching part of it. Attach a synthetic check or a
real-user measurement to the step and it starts contributing to the journey's
score.

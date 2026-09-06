---
topic: dem.journey-steps
question: How do journey steps have to be arranged?
keywords: journey steps, success terminal, step graph
---
A step may branch to several others and may point back at an earlier one — a
retry loop is legal. The one rule is that the journey must be able to end
well: at least one step has to be a success terminal, or there is no
definition of success and therefore no success rate to report.

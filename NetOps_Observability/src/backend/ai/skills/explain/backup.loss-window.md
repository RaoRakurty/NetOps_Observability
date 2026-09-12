---
topic: backup.loss-window
question: What does "Would lose" mean?
keywords: would lose, loss window, how much data lost, recovery point reality
---
How much work an outage starting right now would destroy: the time between the
last good copy and this moment, taken from the WORST store, and named. It is
measured, not a target — the schedule you asked for and the objective you
declared are shown separately, further down. It reads "up to" when every store
reported the age of its last copy, and "at least" when one or more did not:
a floor is not a maximum, and a number that quietly ignored a store that never
answered would be the same lie in a smaller font.

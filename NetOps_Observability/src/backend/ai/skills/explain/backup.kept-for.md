---
topic: backup.kept-for
question: How long are copies kept?
keywords: kept for, retention, how many copies, prune, keep newest
---
Two bounds, and a store may use either or both. A COUNT keeps the newest N
copies and deletes the rest as new ones arrive; an AGE deletes anything older
than N days whatever the count. Where both are set, whichever bites first wins.
Retention is the ceiling on how far back you can recover: lowering the count
frees disk and shortens your reach in the same move. A store showing "not
measured" here reported no rule at all, which is not the same as keeping
everything for ever — read the reason beside it.

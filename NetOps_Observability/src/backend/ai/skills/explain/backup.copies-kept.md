---
topic: backup.copies-kept
question: What does copies kept do?
keywords: copies kept, retain count, backup retention, how many backups are kept, pruning
---
Copies kept is how many system-bundle artifacts the host keeps. After each run
the oldest are deleted until that many remain, so it is the control that
decides how far back you can restore — and the only one on this page that
deletes data. Zero means pruning is off: every copy is kept until the volume
fills. Leaving it unset is not zero; it means nobody has chosen, and the host
keeps seven. Clearing the box does not undo a choice already saved, because a
partial save must never silently drop a retention somebody set.

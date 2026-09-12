---
topic: backup.recoverable
question: What decides whether this is recoverable?
keywords: recoverable, can we recover, recovery verdict, yes not yet unknown
---
Three answers, never two. **Yes** means every store the platform protects has a
recent copy AND at least one restore has actually been proved by a drill. **Not
yet** means a specific condition blocks that, and the line beneath names it — a
store nothing copies, a copy store that failed its check, a schedule that is
off, or copies nobody has ever restored. **Unknown** means the facts could not
be read; it is deliberately not green, because the absence of bad news is not
good news. Fix the named condition and re-read. The verdict moves only when the
condition does.

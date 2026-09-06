---
topic: monitor.preview
question: What does the monitor preview tell me?
keywords: would fire, monitor preview, quiet right now, dry run alert
---
The preview evaluates the condition against live data as it stands now, and
lists what it currently matches. "Would fire" means the condition is already
true for those series, which usually means the threshold is too tight rather
than that you have found an incident. Quiet means nothing matches at this
moment — the monitor will fire when the condition starts holding. It is a dry
run: nothing is created and nobody is notified.

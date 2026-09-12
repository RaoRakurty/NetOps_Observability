---
topic: pipedebug.saved-runs
question: What is kept in a saved run?
keywords: saved runs, one file per module, download archive
---
Each run keeps one file per module on the api, readable here and downloadable
as an archive. That is what lets a run be examined after the fact, or handed
to someone else, instead of only being watched live. The same files are
written under `data/debug/` by `correlix-debug` on the host, so a run started
from the command line lands in the same place.

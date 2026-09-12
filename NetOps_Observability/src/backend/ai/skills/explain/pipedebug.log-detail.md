---
topic: pipedebug.log-detail
question: What does raising log detail do?
keywords: log level, raise to debug, bounded window, returns on its own
---
It turns one module's logging up to debug for a bounded window, and the raise
returns to normal on its own inside the module that was raised — there is no
way to leave it on by forgetting. A raise affects every tenant's service,
which is why the whole page is platform-operator only. The countdown beside a
raised module is what it asked for, not a reading back from the module.

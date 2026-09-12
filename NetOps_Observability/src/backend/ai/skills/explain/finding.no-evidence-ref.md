---
topic: finding.no-evidence-ref
question: What is an evidence pointer?
keywords: evidence pointer, evidence ref, locator, replay a verdict
---
An evidence pointer is the by-reference locator of the raw artifact a verdict
was read from — the config, the log document or the scan output, plus the
ruleset version and a digest. With one, the verdict can be replayed against the
original later and shown to an auditor. A verdict that carries none is still a
verdict, but nobody can re-derive it: treat it as weaker evidence and ask the
producer to emit a pointer.

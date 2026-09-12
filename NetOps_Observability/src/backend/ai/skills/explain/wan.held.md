---
topic: wan.held
question: What does a held path mean?
keywords: held path, in the registry not measured, path disabled, not measuring
---
The path exists in the registry and nothing is probing it. It is a known far
end with measurement switched off, so its latency, loss and jitter columns stay
empty on purpose. A held path is not a failed one: no measurement was
attempted, so nothing failed. Enable it to start measuring, or leave it held
where the far end should not be probed.

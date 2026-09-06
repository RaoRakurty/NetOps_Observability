---
topic: seal.key-rotation
question: What happens when I rotate the sealing key?
keywords: sealing key rotation, rotate dek, key version, sealed fields key, re-encrypt sealed values
---
Rotation issues your tenant a new sealing key version. Everything sealed from
that moment names the new version; everything already stored keeps naming the
version that sealed it, and keeps opening. Nothing is re-encrypted, because
sealed values live in immutable log storage across the whole retention window —
rewriting them is not a thing that can be done, and a scheme that required it
would fail the first time it was needed. One delay is worth knowing: the edge
router resolves its secrets when it loads its config, so new values seal under
the new version only after it reloads. Rotate on exposure, when someone with
access leaves, or on your policy's schedule. The runbook is
docs/runbooks/sealing-key-rotation.md.

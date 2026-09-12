---
topic: backup.posture
question: What decides the protection verdict?
keywords: protection health, posture verdict, backup posture, one verdict
---
The verdict is decided by the single worst condition the platform can prove,
and the line beside it names that condition — an engine with no copy, a
repository that failed verification, a disabled policy, or a copy nobody has
ever restored. It is deliberately one verdict for the whole stack, because a
green tile per engine hides the one engine that is not protected. Fix the named
condition and re-read; the verdict moves only when the condition does.

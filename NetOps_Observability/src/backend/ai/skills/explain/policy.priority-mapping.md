---
topic: policy.priority-mapping
question: How is ticket priority decided?
keywords: ticket priority, impact urgency, automatic mapping
---
The ticketing system derives Priority from Impact multiplied by Urgency, so
the platform sets those two rather than a priority directly. Zero means
automatic: a confirmed critical fault files at 1 / 1, the highest priority; a
confirmed fault raises Urgency to High; a suspected fault uses the default
impact and urgency on the policy. Set a non-zero value to override any of
those.

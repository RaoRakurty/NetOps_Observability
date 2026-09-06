---
topic: nms.controller-state
question: What is controller state on an NMS integration?
keywords: controller state, nms integration, tracked state, controller belief, flaps, entity state
---
This table is what the controller told us at the last poll — its own view of
each entity it manages, not a reading taken from the device. It can disagree
with the device: the controller may be stale, may have lost its session, or may
never have been told about a change made outside it. That disagreement is
useful, which is why the state is tracked, along with the previous value, how
many times it has flapped and when it was last seen. Treat it as one source of
evidence, not as ground truth.

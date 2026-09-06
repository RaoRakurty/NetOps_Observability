---
topic: path.behaviour
question: How is path behaviour judged?
keywords: path behaviour, adaptive baseline, path health, likely owner
---
Each path is compared against its own recent behaviour rather than a fixed
threshold, so a path that is normally slow is not permanently in alarm and a
fast path that doubles is. The verdict carries a confidence and a likely owner
— the party whose network the change sits in — and the worst paths sort first.
A path with too little history to baseline says so instead of being scored.

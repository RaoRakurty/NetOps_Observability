---
topic: backup.measured-bytes
question: What does measured bytes on disk mean?
keywords: bytes on disk, measured not derived, storage reading, taken at
---
Every storage number elsewhere in the platform is derived — a row rate times an
assumed size per row. These figures are the other kind: each was read back from
the store that owns the bytes, and each row names the query it came from and
the moment it was taken, so a stale number reads as stale rather than as
current. A store nobody could weigh keeps the same rule as the rest of the
page: the reason, in words, never a zero.

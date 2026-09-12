---
topic: quarantine.hashed-identity
question: What is the hashed identity?
keywords: hashed identity, sender claimed, raw hostname never stored
---
It is what the sender claimed to be — a hostname or an exporter address —
hashed on the way in. The raw value is never stored outside the sealed
envelope, so this page can show you that two events came from the same unknown
sender without revealing who that is. To match it, assign the device in the
inventory; the quarantine runbook names the exact identity strings that are
hashed.

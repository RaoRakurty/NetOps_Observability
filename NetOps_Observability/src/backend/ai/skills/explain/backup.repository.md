---
topic: backup.repository
question: What is the repository state?
keywords: repository, registered and verified, not verified, repository headroom
---
The repository is the store the restore points live in. Registered and verified
means the platform registered it and read it back successfully. Not verified
means it is registered but has not been proved readable; failed verification
and could not be read are both faults that make every copy in it doubtful until
resolved. Headroom — how much space is left on the repository volume — is not
something the platform reports yet, so it is named as unreported rather than
guessed.

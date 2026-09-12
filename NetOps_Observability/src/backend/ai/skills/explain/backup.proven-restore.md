---
topic: backup.proven-restore
question: What is a proven restorable copy?
keywords: proven restore, last verified restore, restore drill, proved restorable
---
A copy nobody has restored is a copy nobody knows is good. A restore drill
restores the smallest index of the newest good copy under a temporary name,
compares document counts against the live source, and records the result. This
figure is the age of the last copy that passed that test — not the age of the
last backup taken. If it says never, no restore has ever been proved on this
deployment, whatever the backup schedule reports.

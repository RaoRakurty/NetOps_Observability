---
topic: lane.errors-unassessed
question: Why did checks report unassessed?
keywords: checks unassessed, lane errors, reported unassessed not clear
---
These checks ran and could not reach a verdict — unreachable device, refused
credentials, an unparseable response. The lane records them as unassessed
rather than clear, because a check that failed to look proves nothing about
what it did not see. Fix the reason listed beside each one (reachability,
credential profile, or the response the device gave) and the next run turns
them into real verdicts.

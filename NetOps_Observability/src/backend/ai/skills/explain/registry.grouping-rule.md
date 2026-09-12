---
topic: registry.grouping-rule
question: How does a grouping rule work?
keywords: grouping rule, selector, versioned, destination ports prefixes protocols
---
It says which traffic belongs to this service. The engine acts on destination
ports, destination prefixes and protocol numbers — anything else in the rule
is carried but not acted on, and the page says so. Rules are versioned: a save
adds a new version rather than editing one, the newest is the one in force,
and earlier versions stay on the record so past attribution keeps its meaning.

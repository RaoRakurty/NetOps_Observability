---
topic: policy.bgp-canonical
question: What happens when I save the BGP alert rules?
keywords: save bgp rules, canonical form, normalize policy, duplicates dropped, prefix rewritten
---
Saving tidies what you typed into one canonical form: duplicates dropped, AS
numbers sorted ascending, AS0 removed, and every prefix key rewritten to its
network address, so 193.0.0.1/21 becomes 193.0.0.0/21. The panel then re-renders
from what is actually stored rather than from what was typed. That is
deliberate: showing your text back would claim an intent the evaluator is not
holding. What you read after a save is always the rule the checks are using.

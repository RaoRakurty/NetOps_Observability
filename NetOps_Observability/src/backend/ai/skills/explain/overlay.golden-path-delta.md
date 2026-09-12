---
topic: overlay.golden-path-delta
question: What is a golden-path delta?
keywords: golden path, approved path, path delta, live path versus golden
---
A golden path is the route traffic is supposed to take, recorded in advance.
This overlay compares the observed path against it and highlights where the two
differ. A delta is not automatically a fault: a network that reroutes correctly
around a failure is off its golden path on purpose. It is a prompt to ask why
the path moved, and the change overlay usually holds the answer.

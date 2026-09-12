---
topic: views.saved-view
question: What does a saved view store?
keywords: saved view, stores a filter, re-runs under your scope
---
A saved view stores a filter, never rows. Opening one re-runs the query under
your own token, so it always shows current data and can never widen what its
owner may see or carry another tenant's data with it. Share a view freely: two
people opening the same view each see only what they are entitled to.

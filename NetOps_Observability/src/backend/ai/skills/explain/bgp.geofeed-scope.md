---
topic: bgp.geofeed-scope
question: Which geofeed rows are shown here?
keywords: geofeed rows, rows kept, malformed rows, geofeed scope, dropped never repaired
---
Only rows about address space inside the resource you looked up are kept, and
the filtering happens on the server. That is what stops a published list from
making claims about somebody else's prefixes through this view. Rows whose
prefix or ISO-3166 country will not parse are dropped, never repaired, and the
count of dropped rows is shown so you can see how much of the published file was
unusable. A long list is capped, and the page says when it was.

---
topic: apikeys.ingest-scope
question: What is an ingest key?
keywords: ingest scope, ingest experience, rum snippet key, write-only api key
---
An ingest key sends data and does nothing else. `ingest:experience` accepts
the first-party browser snippet's experience beacons and business events;
`ingest:cloud` is the cloud-ingest poller's service credential. A key holding
only ingest scopes reads nothing at all — no devices, no flows, no alerts —
because a snippet served inside a public page must have its key assumed
public. Experience events are stamped with the tenant the key is bound to, so
that key must belong to a concrete tenant; a platform-realm one is refused.
Revoking the key stops it at the next request.

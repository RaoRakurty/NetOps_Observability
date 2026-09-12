---
topic: itsm.inbound-webhook
question: What is the inbound webhook?
keywords: inbound webhook, hmac signed, register with provider, callback
---
A URL you register with the provider so it can push state changes back to the
platform. Every callback is verified against a shared secret using HMAC, so an
unsigned or badly signed request is rejected rather than trusted. It requires
bidirectional mode and a stored signing secret; the secret is write-only and
is never shown back.

---
topic: verify.active-verification
question: What is active verification?
keywords: active verification, sign in to device, check what a case claims, read only
---
Instead of inferring a fault from telemetry alone, the platform signs in to
the device and checks what the case claims. It uses a read-only sign-in you
store here — a user with no configuration rights is enough — and it runs only
against this tenant's own devices. The credential is sealed on save and never
shown again. With verification off, cases are still produced; they simply
carry no on-device confirmation.

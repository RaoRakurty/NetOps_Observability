# Per-Interface Packet Capture — module design (2026-08-25)

Owner request: every interface in device inventory gets a **Wireshark icon** to
capture traffic; captures stored in a **secure place**, with an option to store
them **remotely**.

Packet capture is more sensitive than config backup — it touches the DATA PLANE
and the files contain real payload (PII, credentials, application data). This
design leads with guardrails. It is its own opt-in module
(`FEATURE_PACKET_CAPTURE`, dormant by default — same class as
`FEATURE_DEVICE_SSH` / `FEATURE_TRACEROUTE`) and reuses the secure-store
pattern from the config-backup module.

## The honest mechanism (this is not laptop Wireshark)

Capturing on a production router/switch is a deliberate, BOUNDED, privileged,
on-device action — never an open firehose. Two mechanisms:

1. **On-device Embedded Packet Capture (PRIMARY).** Cisco IOS-XE
   `monitor capture`, Junos packet capture, Arista, etc. — configure a capture
   point on the interface, capture to a bounded on-device buffer, export the
   `.pcap`, then TEAR DOWN the capture point. Vendor-specific (dialect-aware via
   netconcepts, item 4). This is what the per-interface icon triggers.
2. **SPAN/ERSPAN → collector (ALTERNATIVE).** Mirror the interface to a
   Correlix collector for high-volume or sustained capture where on-device
   buffers are too small. Heavier; needs a capture target; a later tier.

Bounded is non-negotiable: every capture has a HARD time limit, max packet
count, AND max buffer size — whichever hits first stops and tears down. An
unbounded capture can exhaust a router's CPU/memory and take down the box. The
UI cannot offer "capture forever."

## Guardrails (lead with these — capturing customer traffic is high-privilege)

- **Opt-in feature flag**, dormant by default.
- **RBAC-gated** — packet capture is a distinct high privilege (reveals
  customer payload), not bundled with read access. A separate `packet_capture`
  permission, platform/admin-tier by default.
- **Ticketed + audited** — reuse the `device_ssh` ticketed-session model: each
  capture is a time-boxed, revocable, fully-audited action (who, which
  interface, when, filter, duration). No capture is anonymous.
- **Privacy / sensitive-data class** — a PCAP IS payload. Treat every capture
  as sensitive data (the Sealed Fields class, #129): access-logged reveal,
  who-downloaded-what audit, a legal caption on the UI ("captures may contain
  personal data / credentials; capture only with authorization"). Capture may
  be regulated (wiretap/GDPR) — this is opt-in and the customer's
  responsibility, surfaced explicitly.
- **Bounded device impact** — pre-flight the device (skip/warn if CPU already
  high); default filters narrow (a BPF/ACL filter encouraged, not "all
  traffic"); small default duration (e.g. 30s / 10 MB).
- **Least-privilege capture command set** — the EPC config/exec commands are a
  controlled, vendor-keyed allowlist through the SSH gateway (like the verify
  engine), never a general shell.

## Secure storage (reuse the config-backup secure-store pattern)

Same rules as config backup — a PCAP is even more sensitive:
- **Encryption at rest** under the tenant DEK (sealing/) — local or remote
  alike. A capture blob at rest is ciphertext.
- **Secure transport only for remote** — SFTP / SCP / HTTPS / S3-with-TLS.
  **FTP/TFTP refused** (the protocols §5e flags as insecure). Remote creds
  vault-sealed, write-only.
- **Backends per-tenant configurable:** local (encrypted volume, default) or
  remote (S3-TLS / SFTP). "Option to store remotely" = this config knob.
- **§3a tenant isolation** — a capture belongs to one tenant; store keys/filters
  by tenant, per-tenant DEK on the blob. No cross-tenant "list all captures".
- **Size/retention caps matter MORE than config** — PCAPs are MB-GB, not KB.
  Hard per-capture size cap + tenant storage quota + retention (auto-expire
  old captures). This ties directly to the storage/retention BILLING lever
  (capacity-and-pricing model) — capture volume is a real cost driver, so
  storage is metered and priced, and a quota protects the platform disk (the
  soak taught us disk is the binding resource).

## UI

- **Wireshark icon per interface** on the interface/port surfaces
  (PortsWorkbench / InterfacePerformance / the device's interface list). Click →
  a **bounded-capture dialog**: duration, max size, optional BPF/ACL filter,
  confirm the privacy caption.
- Runs as a ticketed job with live status; on completion the sealed `.pcap`
  lands in the capture store with a card (interface, time, size, filter,
  capturer).
- Download (access-logged) and/or open in an in-browser analyzer later; never
  auto-download to arbitrary users (RBAC + audit on every reveal).

## Where it sits & modularity

- **Nav:** the icon lives on the existing interface surfaces (Infrastructure);
  a "Captures" library page lists/searches stored PCAPs. Feature-flagged.
- **Module boundary:** a producer of capture artifacts. Removing the module
  removes the icon + store; nothing else depends on it. A capture CAN feed the
  correlation/security lane as evidence (e.g. attach a PCAP to an exposure
  story / RCA object) but only by reference — the engine never requires it.

## Build order (when green-lit — goes to Opus)

1. Secure capture store (reuse the config-backup sealed store; PCAP size/quota
   caps) + local backend.
2. On-device EPC orchestration for ONE vendor first (Cisco IOS-XE
   `monitor capture`) via the SSH gateway, bounded + ticketed + audited; the
   per-interface icon + bounded-capture dialog.
3. Sensitive-data reveal/audit on download; the Captures library page.
4. Remote backends (S3-TLS / SFTP) + retention/quota + the storage billing tie.
5. Additional vendors (Junos/Arista) via netconcepts dialect mapping.
6. (Later) SPAN/ERSPAN-to-collector tier for sustained/high-volume capture.

## Risks

- **Device impact** is the top operational risk — bounded capture (time+size+
  count) with pre-flight is mandatory; an unbounded capture can crash a router.
- **Privacy/legal** — PCAPs are payload; opt-in, RBAC, audit, legal caption,
  encryption at rest are all non-negotiable. Capture is the customer's
  authorized action, surfaced explicitly.
- **Storage cost/disk** — PCAPs are large; hard caps + quota + retention +
  metered pricing, or the platform disk is the casualty (soak lesson: disk is
  the binding resource).
- **Privileged device access** — least-privilege EPC command allowlist through
  the audited gateway, never a general shell.

---
topic: path.synthetics
question: What do the service checks measure?
keywords: synthetics, service check, http timing, ttfb, tcp connect, certificate expiry
---
Service checks are active tests run from the platform against a target you
name. The HTTP check reports the total time and each phase inside it — name
resolution, connect, TLS handshake and time to first byte — so a slow page can
be attributed. The ICMP check reports reachability and round trip; the TCP
check reports connect time to one port. Certificate days-to-expiry comes from
the same HTTPS handshake. They measure a service, not a path.

# Verification Cheat-Sheet

Useful SR-OS commands grouped by what you're trying to confirm.

## ISIS underlay

```
show router isis adjacency
show router isis routes
show router isis database detail
show router route-table protocol isis
```

Expect every P/PE/RR pair across a physical link to show `Up` adjacency in
`level-2`.

## LDP / MPLS

```
show router ldp session
show router ldp bindings
show router mpls lsp
show router tunnel-table protocol ldp
```

Each PE should see an LDP session to every directly-connected P, and a
tunnel-table entry (label) for every other PE/RR loopback.

## MP-iBGP (control plane)

```
show router bgp summary
show router bgp neighbor <RR-loopback>
show router bgp routes vpn-ipv4
show router bgp routes vpn-ipv4 hunt rd 65000:100
```

On a PE you should see two iBGP sessions in `Established` state
(one per RR), with VPNv4/VPNv6 families enabled.

## VPRN (per-VRF state)

```
show service service-using
show router 100 interface
show router 100 bgp summary
show router 100 route-table
show router 100 bgp routes
```

Where `100` is the service-id (= the VRF). Replace with `200`/`300`.

## CE end-to-end test

From a CE:

```
ping router 100 172.17.1.1 source 172.16.1.1
ping router 200 172.17.2.1 source 172.16.2.1
ping router 300 172.17.3.1 source 172.16.3.1
```

VRF-A reaches CE2's VRF-A loopback, VRF-B reaches B, VRF-C reaches C — and
none of them reach the others (proving VRF isolation).

## Quick fault-finding

| Symptom                                        | First thing to check                             |
|-----------------------------------------------|--------------------------------------------------|
| `bgp summary` shows neighbor `Connect`         | underlay LSP missing → check ISIS / LDP first    |
| LDP session up but no labels for PE loopback   | PE loopback not advertised into ISIS as `passive`|
| VPRN routes present on PE2 but no traffic      | RT mismatch — re-check `vrf-target`              |
| CE eBGP neighbor `Active`                      | SAP encap mismatch (dot1q vs null)               |

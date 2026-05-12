# Architecture

## Goals

1. **Single source of truth** — every IP, ASN, VRF, RD/RT and adjacency lives
   in YAML under `inventory/`. Templates contain only structure.
2. **Role-based composition** — each device type is rendered by a wrapper
   template that `{% include %}`s small protocol partials. Switching a
   protocol affects one file.
3. **Topology-agnostic** — the playbooks/templates work for any number of
   P/PE/RR/CE devices. Add a host_vars entry and re-run.
4. **Two-mode operation** — you can render configs offline (`build_configs.yml`)
   or render-and-push to live SR-OS routers (`deploy_configs.yml -e deploy=true`).

## Underlay design

| Layer        | Choice                | Why                                          |
|--------------|-----------------------|----------------------------------------------|
| IGP          | ISIS, single L2 area  | Flat hierarchy, simplest convergence story   |
| Label distr. | LDP                   | Lowest-friction MPLS LSPs; matches user req  |
| MTU          | 9000 in core, 9212 to CE | Allow 1500 + MPLS labels + dot1q overhead |
| Auth         | ISIS message-digest   | Best practice for SP cores                   |
| BFD          | Enabled for iBGP      | Sub-second VPNv4 convergence                 |

## Control-plane design

```
                           ┌──────────┐
                           │   RR1    │   cluster-id 1.1.1.1
                           └─────┬────┘
                  iBGP  /        │       \  iBGP
                       /         │        \
                ┌────────┐ ┌────────┐ ┌────────┐ ┌────────┐
                │  PE1   │ │  PE2   │ │  PE3   │ │  PE4   │
                └────────┘ └────────┘ └────────┘ └────────┘
                       \         │        /
                        \        │       /
                           ┌─────┴────┐
                           │   RR2    │
                           └──────────┘
```

* RRs reflect both **VPN-IPv4** and **VPN-IPv6**.
* RRs run a **non-client** session to each other so a PE-only RR loss is
  survivable.
* Every PE peers ONLY with the two RRs — no full mesh. Adding a PE adds two
  new sessions, period.

## Data-plane (CE attachment)

Each CE-PE physical port carries one **dot1q sub-interface per VRF**:

```
+--------+ 1/1/2 (dot1q hybrid)
|  PE1   |───────────┬───── VLAN 100  →  VPRN 100 (VRF-A)
|        |           ├───── VLAN 200  →  VPRN 200 (VRF-B)
+--------+           └───── VLAN 300  →  VPRN 300 (VRF-C)
```

The CE side mirrors this as three VPRNs, each with its own loopback so we can
prove end-to-end with a single ping.

## Variable hierarchy

```
inventory/group_vars/all.yml         # global: AS, ISIS knobs, RR list, VRFs
inventory/group_vars/<role>.yml      # per-role flags (runs_isis, runs_bgp…)
inventory/host_vars/<device>.yml     # device-unique data (loopback, IPs…)
```

Ansible merges these in the order shown, so a more specific file always wins.
That means you can re-define `isis.hello_interval` for a single router by adding
it to that router's host_vars without touching anything else.

## Why per-device host_vars?

* Inspectable — a network engineer can read `pe1.yml` and immediately see
  what links and VRFs that PE has.
* Diff-friendly — re-IPing a single link is a one-line change with a clean
  git diff.
* Tooling-friendly — easy to generate from NetBox or another source-of-truth
  by writing one file per host instead of mutating a giant YAML.

## Idempotency

The Jinja templates emit pure SR-OS classic-CLI commands. SR-OS treats most
config blocks as a desired state, so re-running `deploy_configs.yml` is safe
once the device is in steady state. For destructive changes (re-IPing a link)
prefer `admin save` then a manual rollback if needed.

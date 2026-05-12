# Deployment Run-book

This walks you from a fresh clone to a converged MPLS L3VPN fabric.

## 0. Pre-requisites

| Tool                 | Version  | Notes                              |
|----------------------|----------|------------------------------------|
| Python               | ≥ 3.9    |                                    |
| Ansible              | ≥ 2.14   | `pip install ansible`              |
| `nokia.sros` collection | latest | `ansible-galaxy collection install nokia.sros` |
| Containerlab (lab)   | ≥ 0.50   | only if you want to spin up the topology |
| `vrnetlab/vr-sros` image | 23.x | requires a Nokia SR-OS license file |

## 1. Render configs (offline)

```bash
ansible-playbook playbooks/build_configs.yml
```

After it finishes:

```
output/
├── ce1.cfg ce2.cfg
├── p1.cfg p2.cfg p3.cfg p4.cfg p5.cfg p6.cfg p7.cfg p8.cfg
├── pe1.cfg pe2.cfg pe3.cfg pe4.cfg
└── rr1.cfg rr2.cfg
```

Open any file — it is the exact SR-OS classic-CLI script that will be applied.

Useful selective renders:

```bash
ansible-playbook playbooks/build_configs.yml --limit pe_routers
ansible-playbook playbooks/build_configs.yml --limit pe1
```

## 2. Bring up the lab (Containerlab)

```bash
sudo containerlab deploy -t lab/topology.clab.yml
sudo containerlab inspect -t lab/topology.clab.yml
```

Each node gets a management IP from `172.20.20.0/24`. Those IPs match
`inventory/hosts.yml`, so Ansible can reach them straight away.

If you prefer GNS3, see [`lab/GNS3_NOTES.md`](../lab/GNS3_NOTES.md).

## 3. Push configs

```bash
ansible-playbook playbooks/deploy_configs.yml -e deploy=true
```

Use `--limit` and `--tags` for surgical changes:

```bash
# Re-deploy only the VPRN section of every PE
ansible-playbook playbooks/deploy_configs.yml -e deploy=true \
    --limit pe_routers --tags pe
```

## 4. Verify

```bash
ansible-playbook playbooks/verify.yml
```

This collects:

* `show router isis adjacency`
* `show router ldp session`
* `show router mpls lsp`
* `show router bgp summary`
* (CEs) per-VRF `show router <id> bgp summary` and `route-table`

…into per-device `output/<host>.verify.log` files.

## 5. End-to-end ping (the real test)

From CE1 inside VRF-A:

```
A:CE1# ping router 100 172.17.1.1 source 172.16.1.1
PING 172.17.1.1 56 data bytes
64 bytes from 172.17.1.1: icmp_seq=1 ttl=253 time=2.31ms.
```

Repeat with `router 200` (VRF-B → 172.17.2.1) and `router 300` (VRF-C → 172.17.3.1).

## 6. Common operational changes

| Change | What to edit | Re-run |
|--------|--------------|--------|
| New VRF | `inventory/group_vars/all.yml` (vrfs[]) + each PE's `vrf_attachments` | build + deploy |
| New PE | `inventory/hosts.yml` + new `host_vars/peN.yml` | build + deploy |
| Re-IP a core link | both endpoints' `host_vars` | build + deploy on those two hosts |
| Add a CE peer | the relevant PE's `vrf_attachments` + the CE's `uplinks` | build + deploy |

## 7. Rollback

`admin save` is called at the bottom of every rendered config. To roll back:

```
A:device# admin rollback view
A:device# admin rollback revert <id>
```

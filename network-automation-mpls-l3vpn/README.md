# MPLS L3VPN Network Automation (Nokia SR-OS)

> Build the entire configuration of an 8-P / 4-PE / 2-RR / 2-CE service-provider
> fabric — flat ISIS L2 core, LDP-signalled LSPs, MP-iBGP route reflectors and
> three customer VRFs — from a single set of YAML variables and Jinja2 templates,
> driven by Ansible.

---

## Topology

```
                 ┌─── RR1 ───┐                  ┌─── RR2 ───┐
                 │           │                  │           │
       ┌─ PE1 ─ P1 ─ P2 ─ P3 ─ P4 ─ PE3 ─┐
 CE1 ──┤        │    │    │    │         ├── CE2
       └─ PE2 ─ P5 ─ P6 ─ P7 ─ P8 ─ PE4 ─┘

   ── ISIS L2 + LDP underlay ────────────────────
   == eBGP per VRF (CE→PE) ======================
   ▒▒ MP-iBGP VPNv4/VPNv6 (PE↔RR ↔ RR) ▒▒▒▒▒▒
```

See [`lab/diagram.md`](lab/diagram.md) for the rendered Mermaid diagram and the
VRF table (RDs, RTs, end-to-end loopbacks).

| Role | Devices                              | Runs                                      |
|------|--------------------------------------|-------------------------------------------|
| P    | P1–P8                                | ISIS L2, LDP, MPLS                        |
| PE   | PE1, PE2, PE3, PE4                   | ISIS, LDP, MPLS, MP-iBGP→RR, **VPRNs**    |
| RR   | RR1, RR2                             | ISIS, LDP, MPLS, MP-iBGP RR (VPNv4/v6)    |
| CE   | CE1 (multihomed PE1+PE2), CE2 (PE3+PE4) | eBGP per VRF over dot1q sub-interfaces |

VRFs **A / B / C** are stretched end-to-end so that CE1's `172.16.x.1` loopbacks
talk to CE2's `172.17.x.1` loopbacks.

---

## Repo layout

```
network-automation-mpls-l3vpn/
├── ansible.cfg
├── inventory/
│   ├── hosts.yml                      # 16 devices, grouped by role
│   ├── group_vars/
│   │   ├── all.yml                    # AS, ISIS, LDP, BGP, VRFs
│   │   ├── p_routers.yml              # role defaults
│   │   ├── pe_routers.yml
│   │   ├── rr_routers.yml
│   │   └── ce_routers.yml
│   └── host_vars/
│       ├── p1.yml … p8.yml            # per-device interfaces, NET, loopback
│       ├── pe1.yml … pe4.yml          # + VRF attachments / SAPs / EBGP peers
│       ├── rr1.yml, rr2.yml
│       └── ce1.yml, ce2.yml           # + service loopbacks per VRF
├── templates/
│   ├── _header.j2 _ports.j2 _interfaces.j2
│   ├── _isis.j2 _ldp_mpls.j2
│   ├── _bgp_pe.j2 _bgp_rr.j2 _vprn.j2 _ce.j2 _telemetry.j2
│   ├── p_router.j2  pe_router.j2  rr_router.j2  ce_router.j2
├── roles/
│   ├── common/   p_router/   pe_router/   rr_router/   ce_router/
├── playbooks/
│   ├── build_configs.yml              # render only
│   ├── deploy_configs.yml             # render + push (`-e deploy=true`)
│   └── verify.yml                     # show-commands → log files
├── lab/
│   ├── topology.clab.yml              # Containerlab (vr-sros) topology
│   ├── GNS3_NOTES.md                  # link map for GNS3 users
│   └── diagram.md                     # Mermaid diagram + VRF table
├── docs/
│   ├── ARCHITECTURE.md                # design choices in detail
│   ├── DEPLOYMENT.md                  # end-to-end run-book
│   └── VERIFICATION.md                # show-cmd cheat-sheet
└── output/                            # rendered .cfg files (created on first run)
```

---

## Quick start

```bash
# 1. Install pre-requisites
pip install ansible jinja2
ansible-galaxy collection install nokia.sros            # only needed to push

# 2. Render every config locally — no devices required
ansible-playbook playbooks/build_configs.yml

ls output/
# ce1.cfg ce2.cfg p1.cfg … pe4.cfg rr1.cfg rr2.cfg

# 3. Bring up the lab and push
sudo containerlab deploy -t lab/topology.clab.yml
ansible-playbook playbooks/deploy_configs.yml -e deploy=true

# 4. Verify
ansible-playbook playbooks/verify.yml
```

---

## How it's extensible

### Adding a new VRF
Append one entry to the `vrfs:` list in `inventory/group_vars/all.yml`:

```yaml
- name:        VRF-D
  service_id:  400
  rd:          "65000:400"
  rt_import:   "target:65000:400"
  rt_export:   "target:65000:400"
  description: "Customer-D"
```

…and add `vrf_attachments` for it on every PE that should host it. Re-run
`build_configs.yml` and the VPRN, EBGP peering and policies are emitted.

### Adding a new PE
1. Add the device to `inventory/hosts.yml` under `pe_routers`.
2. Create `inventory/host_vars/peN.yml` with its loopback, ISIS NET, core-facing
   interface and any `vrf_attachments`.
3. Re-run `build_configs.yml`. The RR template iterates `groups['pe_routers']`,
   so the new PE is auto-added as an iBGP client.

### Re-IPing the fabric
Every IP comes from the host_vars `interfaces[]`/`vrf_attachments[]`. There are
no addresses hard-coded inside any template.

### Tuning or disabling telemetry
All telemetry (gRPC/gNMI, SNMPv2c, syslog, streaming subscriptions) is driven
by the `telemetry:` block in `inventory/group_vars/all.yml`. Point the
`streaming.collector_ip` at your Telegraf / gNMIc collector, change SNMP
community strings, or set any `*.enabled: false` to opt out of a sub-system.

### Switching to SR-MPLS or BGP-LU
Each protocol partial (`_isis.j2`, `_ldp_mpls.j2`, `_bgp_pe.j2`, etc.) is
included by the per-role wrapper. Drop in a `_sr_mpls.j2`, swap the include in
`pe_router.j2`, and the rest of the pipeline is unchanged.

---

## Contributing

PRs welcome. Please:
* Keep templates idempotent (no random IDs).
* Add a host_vars file for any new device — never put per-device values in the
  template itself.
* Run `ansible-playbook playbooks/build_configs.yml --check` before opening a
  PR to confirm the templates still render.

## License

MIT — see [`LICENSE`](LICENSE).

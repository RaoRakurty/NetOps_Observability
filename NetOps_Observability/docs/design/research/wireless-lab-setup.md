# Wireless lab setup — virtual WLC + 2× AP + client (O7 research)

Researched 2026-07-27 for owner item **O7** (tracker) / #128 Phase 9. Goal: the
smallest lab that lets the Catalyst 9800 connector go `doc_claimed → lab`, runs
the §23 fault battery, and gives the Wireless UI real data: **controller
redundancy, 2 APs (AP-level redundancy), a real client**.

## The one hard constraint (verified, 2026)

**No virtual CAPWAP AP exists — anywhere.** Cisco has never shipped an AP
image. CML 2.10's `wireless-ap` node is Ubuntu + `hostapd` and does not speak
CAPWAP; nothing will ever join a 9800 from inside CML/EVE-NG/GNS3. The same is
true for clients (CML's `wifi-client` is `wpa_supplicant` against that hostapd
node — useful for generic Wi-Fi experiments, useless for a WLC lab).

So every real 9800 lab is a **hybrid**: virtual controller(s), physical APs
bridged in, real client devices. This is a well-trodden, fully supported
pattern — a physical AP CAPWAP-joins a bridged 9800-CL exactly as if both were
physical.

## Recommended build

### Virtual half (runs on the existing lab host — KVM, ESXi, or EVE-NG)

| Piece | Spec | Notes |
|---|---|---|
| 2× Catalyst 9800-CL VM | 4 vCPU / 8 GB each | Free download (CCO login), 90-day eval license, renewable in a lab. 2v/6G "ultra-low" profile only supports FlexConnect; **4v/8G enables local mode** — we want local mode so the data plane crosses the WLC (richer telemetry). |
| HA SSO pair | 3 vNICs per VM | Gig1 mgmt, Gig2 wireless mgmt (VLAN trunk), **Gig3 = dedicated RP link on its own vSwitch/bridge** (same interface number both sides; latency on a shared vSwitch drops HA keepalives). Works on ESXi/KVM/EVE-NG; inside CML's fabric SSO tends to stay "Non-redundant" — avoid CML for the HA half. |
| Bridge to physical | 1 host NIC | EVE-NG: `pnet` cloud object; bare KVM: bridge; ESXi: portgroup (promiscuous/forged-transmits ON for HA). APs plug into this L2 segment. |

EVE-NG works fine for the 9800-CL qcow2, but plain KVM/libvirt on the lab host
is equally good and one less layer — EVE-NG only earns its keep if we also want
switches/routers in the same topology later.

### Physical half (the only money)

| Piece | Choice | Why |
|---|---|---|
| 2× AP | **Catalyst 9105AXI** (safe) or used **Aironet 2802I** (cheap) | 9105: Wi-Fi 6, current-release support, ~$80–150 used each. 2802: ~$40–80 used, Wave-2; support was re-introduced in IOS-XE 17.9.x — if we buy 2802s, pin the 9800-CL to 17.9 LTS. Two APs = the AP-redundancy axis (client roam, one-AP-down while the WLAN stays up). |
| 2× PoE | PoE injectors (~$15 each) or a used PoE switch | A small PoE switch is better: its port shutdowns ARE two §23 battery rows (AP power removal, uplink shutdown) driven from a CLI. |
| Client | any laptop + a phone | Real 802.11. Phone adds the randomized-MAC battery row for free. |

Total new spend: **~$150–350**, one-time.

### Day-0 on the 9800-CL (the parts people trip on)

1. **Self-signed cert on the wireless management trustpoint** (`wireless config
   vwlc-ssc` / day-0 wizard). Hardware 9800s have a manufacturer cert; the CL
   does not — without this, AP DTLS join fails with errors that never say
   "missing cert".
2. Country code + AP regulatory domain must match the APs (-B for US).
3. AP discovery: DHCP option 43 on the AP VLAN, or prime each AP once with
   `capwap ap primary-base <wlc-name> <ip>`.
4. **For the Correlix connector** (RESTCONF-first, HTTP Basic — nms/catalyst9800.go):
   `ip http secure-server` + `restconf` + a priv-15 local user. That is the
   whole integration surface; SNMP optional for the generic pollers.

## What this lab unlocks (mapped to §23)

Runnable the day it's up: **controller member failover** (HA SSO pair),
**RADIUS server stop** (FreeRADIUS container + automate-tester), **AP power
removal** and **uplink port shutdown** (PoE switch port), **forced client
roam** (two APs, walk the client or kill the nearer AP), **DHCP scope
exhaustion** (tiny scope on the client VLAN), duplicate-roam dedup,
randomized-MAC honesty, single-witness caps, controller-unreachable /
partial-response classes — plus the headline item: **live verification of
every doc_claimed Cisco-IOS-XE-wireless-\* leaf spelling** and the
`doc_claimed → lab` fidelity promotion.

Still deferred to first-customer acceptance (as §23 already tags them):
controlled RF interference and DFS radar simulation — those want RF gear no
small lab justifies.

## What NOT to bother with

- **CML wireless nodes / mac80211_hwsim** for this programme: they simulate
  802.11 without CAPWAP, so they exercise none of our connector, sessions, or
  correlation paths. Only worth revisiting as a generic-Wi-Fi testbed for the
  multi-vendor canonical model, and even then fixtures already cover it.
- **A fully-virtual "wireless up in EVE-NG" topology**: it does not exist;
  anyone claiming it is running hostapd, not a WLC.

## Sources

- [CML: Catalyst 9800-CL node (DevNet)](https://developer.cisco.com/docs/modeling-labs/catalyst-9800-cl/)
- [9800-CL in CML — what you can and cannot lab](https://www.pinglabz.com/catalyst-9800-cl-cml-limitations/)
- [9800-CL day-0 configuration](https://www.pinglabz.com/catalyst-9800-cl-day-0-configuration/)
- [Cisco: AP join process with the 9800](https://www.cisco.com/c/en/us/support/docs/wireless/catalyst-9120axe-access-point/221056-understand-the-ap-join-process-with-the.html)
- [Cisco: 9800 HA SSO quick start](https://www.cisco.com/c/en/us/support/docs/wireless/catalyst-9800-series-wireless-controllers/220277-configure-high-availability-sso-on-catal.html)
- [Cisco: 9800-CL deployment guide](https://www.cisco.com/c/en/us/td/docs/wireless/controller/9800/technical-reference/c9800-cl-dg.html)
- [WiFi Ninjas: 9800-CL HA SSO deep dive](https://wifininjas.net/wn-blog-013-cisco-catalyst-9800-cl-redundancy-ha-sso-cli-and-deeper-dive/)
- [Cisco 17.9.x release notes (Wave-2 AP support re-introduced)](https://www.cisco.com/c/en/us/td/docs/wireless/controller/9800/17-9/release-notes/rn-17-9-9800.html)
- [Cisco Switzerland blog: lab with 9800-CL](https://gblogs.cisco.com/ch-tech/setup-your-lab-with-catalyst-9800-cl/)

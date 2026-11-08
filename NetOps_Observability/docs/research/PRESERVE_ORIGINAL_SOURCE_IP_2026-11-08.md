# Preserving Original Source IP for UDP Telemetry Through Docker Restarts

## Executive conclusion

Correlix should **stop relying on Docker-published UDP ports for source-IP-sensitive telemetry and move the UDP receiver containers to host networking on Linux**. For SNMP traps, syslog/UDP, NetFlow, IPFIX, and sFlow, the receiver should bind directly to the appliance host's sockets using `network_mode: host` / `--network host`, with no `-p` mappings at all. Docker documents that host networking shares the host network namespace, performs no port publishing or NAT, and creates no userland proxy for those ports. That removes the failure mechanism rather than trying to repair conntrack after it occurs. citeturn308294search0turn308294search1

For least privilege, the telemetry receiver should run as a non-root application user, drop all Linux capabilities, and add back only `NET_BIND_SERVICE` where it must bind ports below 1024 such as UDP/162 and UDP/514. `NET_RAW` and `NET_ADMIN` should explicitly remain absent. Docker documents that `NET_BIND_SERVICE` is sufficient to bind privileged ports and that capabilities can be independently added or dropped rather than granting `--privileged`. citeturn327434search0turn327434search1

This design is materially stronger than conntrack flushing, disabling Docker's userland proxy, or NOTRACK rules. Those alternatives either retain dependence on Docker/NAT lifecycle correctness, require host-level firewall mutation, introduce compatibility risk, or only change the symptom rather than eliminate the packet path that can lose attribution. Host networking removes DNAT, Docker's per-port conntrack cleanup dependency, and docker-proxy from the inbound path altogether. citeturn308294search0turn173600search3

The current Docker fix situation reinforces that recommendation. Moby issue **#53384**, opened August 16, 2026, documents a regression in Docker 29.5.x and later in which stale UDP conntrack entries are not reliably flushed after a published-port receiver returns; its proposed fix, PR **#53385**, remains open as of the latest retrieved GitHub state. Docker 29.9.2 was released October 20, 2026, but the published 29.x release notes do not list #53385 as shipped. Correlix therefore should not make source attribution depend on a particular Docker version fixing this class of problem. citeturn671064view0turn268469view0turn899230search2

My recommended production architecture is therefore:

> **Host-networked, unprivileged telemetry receiver + explicit startup self-test + runtime source-IP sanity monitoring + fail-closed health status if the host-network guarantee is unavailable.**

This meets the stated appliance constraints without requiring `conntrack`, iptables tooling, Internet access, or a permanently privileged container.

## Why the failure persists

Docker bridge-network port publishing is implemented with host firewall rules that perform NAT/PAT between a host port and the container. Docker's documentation explicitly states that published bridge ports are mapped through firewall/NAT rules; in host networking, by contrast, there is no NAT and no userland proxy. citeturn308294search4turn308294search0

The important property of Linux connection tracking is that NAT is decided when the conntrack state for a flow is created. A long-lived UDP sender using a stable source address and source port can continually refresh that state. Kubernetes documentation similarly notes that UDP conntrack records must time out rather than being torn down by a connection close, and its kube-proxy configuration exposes separate UDP conntrack timeouts for this reason. citeturn173600search5turn173600search6

Moby #53384 describes almost exactly the Correlix observation. During a container outage, an arriving datagram can create a **non-NAT conntrack entry** pointing at the host. Once Docker restores the DNAT rule, later datagrams in the same UDP tuple continue following the already-created conntrack state rather than being reevaluated against the new DNAT rule. When docker-proxy handles the host-side socket and relays the datagram, the container observes the Docker bridge gateway, such as `172.17.0.1` or `172.18.0.1`, instead of the actual remote sender. citeturn671064view0

The issue's reproductions are particularly relevant to Correlix. A sender transmitting every five seconds from a fixed UDP source port was sufficient to preserve the bad entry indefinitely. Docker 29.5.0 was observed to fail even when host and container UDP ports were equal, while 29.5.1 and 29.7.2 recovered correctly for equal ports but remained broken where host and container ports differed. The regression was traced to Docker's conntrack deletion code using the container port instead of the published host port. citeturn671064view0

That explains why your existing **host port = container port** mitigation is useful but is not a formal guarantee. On affected Docker releases it greatly reduces or removes one known bug path, but Moby's own version history shows that conntrack cleanup behavior has changed repeatedly. Docker 29.5.0 introduced two interacting bugs, 29.5.1 fixed one, and the later port-selection bug remained open when #53384 was filed. citeturn671064view0turn899230search2

The broader lesson is that the invariant Correlix actually needs is not “Docker successfully removes stale conntrack state.” It is:

**A telemetry datagram must never traverse an intermediary that terminates and retransmits the UDP packet before Correlix reads the sender address.**

Host networking satisfies that invariant structurally.

## What other telemetry products do

There is no evidence for a universal rule that every observability vendor uses host networking, but the products reviewed show a meaningful pattern: systems that care about receiving device-originated UDP either run directly on the host, use host networking, or accept the operational risks of Docker port publication.

Splunk Connect for Syslog is the clearest example. Splunk's published SC4S launch configuration uses `--network host` for its Podman/Docker container. Its documentation also shows host networking in the configuration example associated with its optional eBPF receive path. citeturn232341search6turn232341search3

New Relic's network monitoring agent, **ktranslate**, provides a useful contrast. Its Docker instructions use published UDP ports—for example `-p 162:1620/udp` for SNMP traps and `-p 514:5143/udp` for syslog. Its Podman syslog instructions, however, use `--net=host`; for low-numbered ports in rootless environments, New Relic documents host-side redirection as necessary. citeturn232341search0turn232341search2 New Relic therefore demonstrates that published UDP ports are a commercially used deployment pattern, but not that they provide a source-IP-preservation guarantee across Docker network lifecycle events.

Kentik, whose ktranslate codebase is also used by the New Relic integration, documents Docker deployments using `-p` mappings for its container examples. Its newer Universal Agent documentation describes the agent itself as a local receiver on the host for flow and syslog traffic, including UDP flow ingestion and UDP/TCP 514 for syslog. citeturn164539search1turn164539search10

LogicMonitor supports a containerized Collector, but its Collector is fundamentally described as software running at a location and listening directly for SNMP traps on UDP/162 and syslog on UDP/514. LogicMonitor's container documentation does not establish that its UDP event receiver uses host networking, and its containerized Collector must currently run its Collector process as root. citeturn625033search0turn625033search1turn625033search2 That does not match Correlix's desired least-privilege model particularly well.

Datadog's SNMP-trap receiver binds directly to a configurable address and port, with its documented default configuration using UDP/9162. For Kubernetes Agent deployments, Datadog explicitly documents `hostNetwork: true` as an option where host ports are not supported, while warning that host networking means the container shares the host network namespace and can create port conflicts. citeturn232341search4turn164539search2

Dynatrace's current syslog implementation is more strongly oriented toward a **host-based Environment ActiveGate** for network-device ingestion: its syslog instructions tell users to deploy an Environment ActiveGate and configure an embedded OpenTelemetry receiver to listen on `0.0.0.0:514`. Dynatrace supports containerized ActiveGate generally, mainly through Kubernetes/OpenShift, but not every ActiveGate module has equivalent support in containerized deployments. citeturn232341search5turn330428search0turn330428search3 Dynatrace's SNMP-trap topology is derived from the sending agent's IP address, underscoring that sender-IP integrity is semantically important to this class of product. citeturn330428search16

The industry evidence therefore does **not** support saying “host networking is mandatory everywhere.” It does support the narrower conclusion that host-level reception is a normal, established architecture for network telemetry, especially where the transport-layer sender is part of the data model. Splunk SC4S is a particularly strong precedent for Correlix because it is itself a high-volume syslog receiver packaged as a container but intentionally attached to the host network. citeturn232341search6

## Lessons from Kubernetes and Docker conntrack cleanup

Kubernetes has spent years dealing with the same conceptual problem: when a UDP backend changes, old conntrack entries can continue sending packets toward a backend that no longer exists. Kubernetes therefore contains explicit conntrack cleanup logic in kube-proxy and exposes UDP conntrack timeout settings. citeturn173600search5

That cleanup is not trivial. Kubernetes 1.32 introduced a reconciler-based cleanup implementation; a later production issue showed that a UDP service scaled to zero endpoints could retain stale conntrack records indefinitely while a continuously transmitting sender refreshed them. The report describes traffic continuing toward a deleted Pod for 13 hours until a valid endpoint returned. citeturn173600search8

The opposite failure mode also occurred: over-aggressive cleanup. A Kubernetes issue against v1.32 reported that UDP endpoint changes could cause kube-proxy to iterate large conntrack tables, with reports of multi-gigabyte transient memory use and significant CPU load. Kubernetes subsequently optimized stale UDP conntrack deletion, with the Kubernetes 1.36 changelog specifically noting a reduction in cleanup complexity. citeturn173600search9turn173600search10

These experiences are highly relevant to Correlix. They demonstrate that “clean conntrack correctly on every lifecycle transition” is itself a substantial networking subsystem, not a simple restart hook. A production-grade implementation has to cover backend addition, backend deletion, zero-backend transitions, IP changes, port changes, races with incoming packets, nftables versus iptables backends, and large conntrack tables. citeturn173600search8turn173600search9

Docker has followed a similar path. Docker 29.5.0 shipped a change intended to make UDP conntrack deletion more precise when multiple containers share ports on different IPs. Docker 29.5.1 then fixed another conntrack filtering defect involving ports bound to unspecified addresses. Moby #53384 shows that the same cleanup refactoring accidentally switched from the published host port to the container port for one deletion path. citeturn173600search1turn899230search2turn671064view0

PR #53385 proposes changing that path back to the host port for NATted bindings and skipping the port-keyed cleanup for routed, non-NAT bindings. The PR had received one approval but remained open in the retrieved state, with no milestone. citeturn268469view0

Consequently, upgrading Docker when a fix eventually ships is worthwhile, but it should be treated as **defense in depth**, not as Correlix's correctness boundary.

## Options and trade-offs

The strongest option is **host networking**. Docker explicitly states that `--network host` shares the host networking namespace, gives the container no separate container IP, ignores port publication, avoids NAT, and does not create a userland proxy. citeturn308294search0 Because the telemetry socket is the host socket, container recreation does not require removing and re-adding a DNAT mapping. A packet that arrives while the receiver is down is simply dropped because nothing is listening; critically, it cannot create a Docker DNAT-versus-no-DNAT ambiguity that later causes packets to be proxied with the wrong source address.

The cost is reduced network-namespace isolation. Ports opened by the process are opened directly on the host, only one listener can own a given address/port tuple, and accidental bindings to additional host interfaces become more consequential. Docker calls out the port-conflict consequence of host networking, and Datadog similarly warns that sharing the host network namespace exposes the container's open ports on the host. citeturn308294search0turn164539search2 That risk is manageable for an appliance with intentionally dedicated well-known receive ports.

Host networking does **not** imply a privileged container. Docker's capability model allows an application to drop all capabilities and add only `NET_BIND_SERVICE` for UDP/162 and UDP/514. `NET_RAW`, which permits raw and packet sockets, can remain dropped; `NET_ADMIN`, which permits network-configuration changes, is not granted by default and should remain absent. citeturn327434search0 A hardened receiver could therefore use semantics such as:

```yaml
network_mode: host
cap_drop:
  - ALL
cap_add:
  - NET_BIND_SERVICE
security_opt:
  - no-new-privileges:true
read_only: true
```

The exact filesystem mounts and writable tmpfs locations would depend on the receiver's implementation, but the security principle is that sharing the network namespace should **not** be accompanied by sharing host PID, IPC, device access, Docker socket access, or administrative network capabilities.

**Disabling Docker's userland proxy** is weaker. Docker exposes `--userland-proxy` as a daemon setting, and Docker's own rootless troubleshooting guidance sometimes recommends setting it to false specifically because userland proxying interferes with source-IP propagation. citeturn173600search3turn173600search4 In the Correlix failure, this could prevent the especially harmful outcome in which docker-proxy successfully delivers the datagram but changes its apparent sender. However, it does not make an already-poisoned conntrack entry point at the correct container; depending on routing and firewall state, the result may simply change from “misattributed packet” to “dropped packet.” It also requires changing daemon-wide Docker behavior, which is intrusive on a customer appliance and applies to unrelated containers.

**Post-start conntrack deletion** is also weaker. Moby #53384 lists targeted `conntrack -D` as a workaround, but this requires the userspace conntrack tool or equivalent netlink code, privileges to manipulate host conntrack state, and perfect coverage of every event that can invalidate Docker's forwarding state. citeturn671064view0 It also reintroduces exactly the operational complexity Kubernetes has struggled with. For Correlix's constraints—offline appliance, no assumed extra packages, non-root installer, least privilege—it is the wrong primary architecture.

**NOTRACK** is technically attractive but operationally worse than host networking here. Netfilter provides `CT --notrack` / `NOTRACK` in the raw table, and nftables provides a corresponding `notrack` statement that must execute before the conntrack lookup. citeturn308294search2turn308294search3 If inbound telemetry packets never enter conntrack, stale conntrack state cannot pin their NAT decision. But Docker's normal bridge-network port publication itself relies on NAT and connection tracking semantics; bypassing conntrack for traffic that still needs Docker DNAT is therefore not a straightforward drop-in solution. A correct design would require custom host firewall plumbing and careful return-path treatment and would couple Correlix to iptables/nftables implementation details. Docker itself cautions against modifying the firewall rules it creates for bridge networking. citeturn308294search1

Docker's **routed bridge gateway mode** can eliminate NAT, but it changes the addressing model: remote devices must be able to route directly to the container network via the host, and Docker says that a host port is not actually used in routed mode. citeturn308294search4 That is inappropriate for an appliance product whose exporters are already configured to send to the appliance's stable host IP.

Accordingly, the options rank as follows for this requirement:

| Design | Source-IP guarantee | Host mutation | Persistent privilege | Works offline | Operational complexity |
|---|---:|---:|---:|---:|---:|
| Host network receiver | **Strongest** | None beyond Docker config | No | Yes | Low |
| Docker bridge + future conntrack fix | Medium | None | No | Yes | Medium; Docker-version dependent |
| Disable userland proxy | Medium/low | Docker daemon config | No | Yes | Medium; daemon-wide |
| Startup conntrack purge | Medium | Conntrack state | Yes or helper privilege | Maybe | High |
| NOTRACK rules | Potentially strong if redesigned | Firewall rules | Setup privilege required | Yes | High |
| Routed Docker bridge | Strong for NAT avoidance | Routing required | No | Yes | High/customer-network dependent |

## Recommended Correlix implementation

The appliance deployment should separate **telemetry ingress** from the rest of the application network architecture. Only containers whose correctness depends on the transport sender address—SNMP trap, UDP syslog, NetFlow/IPFIX, and sFlow listeners—need host networking. Backend APIs, databases, message buses, and normal application services can remain on isolated Docker bridge networks.

The ingress container should bind explicitly to the required UDP ports on the host network. Docker's host driver does not use published ports, so Compose should contain `network_mode: host` and must not contain `ports:` for that service. citeturn308294search0 If different Correlix receiver processes currently occupy separate containers and need overlapping ports, either each should bind a distinct host port or multiple protocols should be consolidated into a single ingress service where appropriate; host networking correctly exposes real socket ownership conflicts instead of hiding them behind container namespaces.

The receiver process should run as an application UID, with `cap_drop: [ALL]` and `cap_add: [NET_BIND_SERVICE]` only when using 162 or 514. Docker documents that this capability permits privileged-port binding without full root privilege. citeturn327434search0turn327434search1 `NET_RAW`, `NET_ADMIN`, `SYS_ADMIN`, Docker socket mounts, host filesystem mounts, and `--privileged` should not be granted.

For a non-root installer, no iptables or sysctl manipulation is necessary. The installer only needs the same Docker access it already requires to create Correlix containers. The Docker daemon performs namespace setup; the application container itself needs no administrative host-network capability. This avoids adding a new dependency on `conntrack`, iptables, nftables userspace packages, systemd manipulation, or Internet access.

The deployment should implement an explicit **source-IP guarantee health check**, rather than assuming that `network_mode: host` was honored. At startup, Correlix should inspect its effective deployment mode through the Docker API or configuration and verify all of the following internally: the telemetry service is using host networking; no published-port mapping exists for the protected UDP ports; the process has successfully bound every configured telemetry port; and the service is not running in an unsupported rootless or non-Linux networking mode whose semantics differ from the validated appliance profile. Docker notes platform-specific differences in host networking, so appliance certification should constrain the supported host environment. citeturn308294search0turn327434search17

That check should feed a first-class status such as **SOURCE_IP_INTEGRITY = GUARANTEED / DEGRADED**. If the receiver starts on a bridge network or observes source addresses belonging to Docker bridge gateway ranges, the appliance should raise a high-severity health alert stating that telemetry attribution is no longer guaranteed. It should not silently downgrade to accepting `172.x` proxy addresses as devices.

The existing runtime masked-source detector should remain. It becomes defense in depth for configuration regressions, customer modifications, or an unexpected platform change. A useful enhancement is to classify suspicious packets using local interface knowledge rather than hard-coding `172.18.0.1`: compare each telemetry sender against the host's Docker bridge addresses, container-network gateway addresses, loopback, and other locally owned addresses. An exporter identified as one of those addresses should trigger the source-integrity alarm unless it is explicitly configured as a legitimate network device.

For Kubernetes, the existing `externalTrafficPolicy: Local` configuration should remain where a Service is required. Kubernetes documents conntrack as a material part of UDP Service forwarding, so avoiding cross-node source-NAT paths and retaining the existing masked-source detector remains appropriate. citeturn173600search5turn173600search8 Where the deployment model permits a node-local telemetry listener, `hostNetwork` is even closer to the appliance architecture and is a known pattern used by observability agents, including Datadog in circumstances requiring direct host port access. citeturn164539search2

A migration can therefore be implemented without host scripts:

```yaml
services:
  correlix-telemetry:
    image: correlix/telemetry:<version>
    network_mode: host

    user: "10001:10001"

    cap_drop:
      - ALL
    cap_add:
      - NET_BIND_SERVICE

    security_opt:
      - no-new-privileges:true

    read_only: true
    tmpfs:
      - /tmp

    restart: unless-stopped

    # No "ports:" section.
```

If the image can avoid low numbered ports—for example, if upstream firewalls or device configurations already target high ports—`NET_BIND_SERVICE` can also be removed. For the current requirement to accept standard UDP/162 and UDP/514 directly, retaining only that capability is the narrowest Docker capability set documented for the task. citeturn327434search0

The validation suite should deliberately reproduce the observed failure class. A test sender should transmit from a constant source IP and constant UDP source port continuously while the receiver is stopped and started, while Docker is restarted, and while the host firewall service is reloaded where applicable. The acceptance criterion is not merely receipt: **every received datagram must carry the external sender's actual address**. The same test should be run against SNMP traps, syslog, and a representative flow exporter because their traffic rates and source-port behavior differ.

Docker bridge/published-port mode can remain as an explicitly **unsupported or degraded fallback** for unusual environments, but Correlix should state that source-IP integrity cannot be guaranteed there. That is preferable to attempting to make correctness conditional on Docker's conntrack cleanup implementation, particularly while Moby #53385 is still unmerged and the current Docker 29.x line has already demonstrated multiple changes to UDP conntrack cleanup behavior. citeturn268469view0turn899230search2

The resulting architecture changes the problem from “detect and repair poisoned UDP NAT state” to “do not create UDP NAT state for telemetry in the first place.” For Correlix's RCA model, where packet source address is part of the evidence identity, that is the cleaner and more defensible boundary.
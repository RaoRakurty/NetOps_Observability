# Lab flow-export configs — clos-multivendor fabric

Purpose: make the fabric devices actually export **NetFlow / IPFIX / sFlow** to the
NetOps stack so the Flows tab shows *real* telemetry. As of 2026-05-31 the
pipeline (goflow2 → vector-router → ClickHouse) works, but **no fabric device was
exporting flows** — the only data in `netops.flows` was a stale synthetic NetFlow
v5 burst (sampler `10.20.0.1` / `172.18.0.1`), never a `172.40.40.x` device.

## Collector target

All exporters point at the stack host **on the fabric mgmt network**:

| What            | Value                |
|-----------------|----------------------|
| Collector IP    | `172.40.40.122`      |
| sFlow port      | `6343/udp`           |
| NetFlow v9 port | `2055/udp`           |
| IPFIX port      | `4739/udp`           |

(`172.40.40.122` is the same address the devices already use for SNMP traps and
syslog — verified in the live Arista/Nokia configs. Do **not** use
`10.70.245.122`; the devices reach the collector via the fabric mgmt subnet.)

## Per-device assignment

| Device   | Vendor / NOS              | mgmt IP        | Export  | File                  | Status (2026-05-31) |
|----------|---------------------------|----------------|---------|-----------------------|---------------------|
| spine1/2 | Nokia SR Linux            | .11 / .12      | sFlow   | `nokia-sflow.txt`     | configured but **not landing** — needs mgmt netinst + source-addr fix |
| leaf1-4  | Arista cEOS 4.36          | .21–.24        | sFlow   | `arista-sflow.cfg`    | **sFlow disabled** — enable it |
| wan-r2   | Arista cEOS 4.36          | .32            | sFlow   | `arista-sflow.cfg`    | **sFlow disabled** — enable it |
| wan-r1   | Juniper vJunos-router     | .31            | IPFIX   | `juniper-ipfix.txt`   | unverified (vrnetlab VM) |
| lan-sw1/2| Cisco Cat8000v IOS-XE     | .51 / .52      | NetFlow | `cisco-netflow.txt`   | unverified (vrnetlab VM) |
| dmz-fw   | FortiGate 6.0             | .41            | NetFlow | `fortigate-netflow.txt` | unverified (vrnetlab VM) |

What's already healthy on the audited devices: SNMP v2c **and** v3, gNMI
(grpc 57400/57401), syslog → 172.40.40.122. Only **flow export** was missing.

## Push (user runs these — the agent does not write device config)

Arista / Nokia are native containers; Juniper / Cisco / Fortinet are vrnetlab VMs
reached over SSH with their device credentials. Example pushes from the lab host
(`10.70.245.120`):

```bash
# Arista cEOS (repeat for leaf1 leaf2 leaf3 leaf4 wan-r2)
sudo docker exec -i clab-clos-multivendor-leaf1 Cli -p 15 <<'EOF'
configure
$(cat arista-sflow.cfg)
end
write memory
EOF

# Nokia SR Linux (spine1 spine2) — set the per-device source-address!
sudo docker exec -i clab-clos-multivendor-spine1 sr_cli <<'EOF'
enter candidate
$(cat nokia-sflow.txt)   # edit source-address to .11 / .12 per node
commit save
EOF
```

For the vrnetlab VMs, SSH into the device mgmt IP (172.40.40.31/.51/.52/.41) and
paste the matching file's contents in config mode.

## Validate (on the stack host, after pushing)

```bash
# packets arriving?
sudo tcpdump -ni any 'udp and (port 6343 or port 2055 or port 4739)' -c 20

# goflow2 decoding them, and from which samplers/types?
docker logs --tail 50 netops-goflow2-1 | grep -oE '"type":"[A-Z0-9_]+"|"sampler_address":"[0-9.]+"' | sort | uniq -c

# rows landing in ClickHouse from real fabric devices?
docker exec netops-clickhouse-1 clickhouse-client -q \
  "SELECT sampler_address, count() FROM netops.flows WHERE ts > now()-INTERVAL 10 MINUTE GROUP BY sampler_address"
```

You want to see samplers in `172.40.40.x`. If packets arrive (tcpdump) but the
sampler shows as the docker gateway (`172.18.0.1`) instead of the device IP, that
is docker's published-port masquerade rewriting the source — see the note in
`nokia-sflow.txt`.

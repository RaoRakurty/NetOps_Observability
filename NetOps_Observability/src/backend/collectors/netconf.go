package collectors

import "time"

// NETCONF reports how many devices expose a live NETCONF-over-SSH endpoint.
//
// Approach (validated against RFC 6241/6022/6242, RFC 4253, and how Nagios /
// Zabbix 7.2 monitor NETCONF without credentials):
//
//   - The authoritative "active session" data is RFC 6022's
//     ietf-netconf-monitoring /netconf-state/sessions subtree (session-id,
//     transport, username, login-time…), advertised by Juniper, Cisco IOS-XE
//     and Nokia. Reading it requires an *authenticated* NETCONF session — SSH
//     transport + the "netconf" subsystem + a <hello>/<get> exchange — which
//     needs a real SSH client (golang.org/x/crypto/ssh). That's outside the
//     backend's stdlib-only budget, so we don't claim a per-session count.
//
//   - What we CAN do with stdlib: confirm a real NETCONF/SSH server is
//     answering on TCP/830 by reading its SSH identification banner
//     ("SSH-2.0-…"), which RFC 4253 has the server send in cleartext before any
//     auth. That distinguishes a live NETCONF transport from a merely-open port.
//
// So this collector counts *NETCONF-capable endpoints currently answering* and
// is labelled honestly in the UI ("NETCONF" with reachable = answering count).
// It probes every device's :830 (not just netconf-preferred devices) because
// most inventories set a richer preferred protocol (snmp/gnmi) yet still expose
// NETCONF — e.g. the Arista fabric runs `management api netconf` alongside SNMP.
func NewNETCONF(targets TargetFunc) Collector {
	return newPoller("netconf", 120*time.Second, 830, sshBannerProbe, targets)
}

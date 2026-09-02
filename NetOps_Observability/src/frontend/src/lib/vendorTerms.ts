// vendorTerms — vendor-dialect display vocabulary (item 4, 2026-08-25).
// Mirrors backend internal/netconcepts: Correlix READS every dialect as one
// canonical concept, but SHOWS each device's own dialect to its operator.
// A Juniper operator sees "routing-instance"; the correlation identity
// underneath is the same dialect-free token either way.

const canon = (s: string) => s.toLowerCase().replace(/[-_. ]/g, "");

/** The device-appropriate word for the L3 VRF concept. */
export function vrfTerm(vendor?: string): string {
  switch (canon(vendor ?? "")) {
    case "juniper": case "junos": case "jnpr":
      return "routing-instance";
    case "nokia": case "sros": case "alcatel": case "alcatellucent": case "srlinux":
      return "VPRN";
    case "huawei": case "vrp":
      return "VPN instance";
    default:
      return "VRF";
  }
}

/** Plural, capitalized for section headers ("Routing instances", "VRFs"). */
export function vrfTermPlural(vendor?: string): string {
  const t = vrfTerm(vendor);
  if (t === "routing-instance") return "Routing instances";
  if (t === "VPN instance") return "VPN instances";
  return `${t}s`;
}

/**
 * An example interface name in the device's own dialect. Used as the placeholder
 * and hint when a device has no discovered interface inventory to pick from, so
 * the operator types the name THE DEVICE uses rather than a normalized one.
 */
export function interfaceExample(vendor?: string): string {
  switch (canon(vendor ?? "")) {
    case "juniper": case "junos": case "jnpr":
      return "ge-0/0/0";
    case "cisco": case "ios": case "iosxe": case "iosxr": case "nxos":
      return "GigabitEthernet0/0/1";
    case "arista": case "eos":
      return "Ethernet1";
    case "nokia": case "sros": case "alcatel": case "alcatellucent":
      return "1/1/1";
    case "srlinux":
      return "ethernet-1/1";
    case "huawei": case "vrp":
      return "GigabitEthernet0/0/1";
    case "mikrotik": case "routeros":
      return "ether1";
    case "paloalto": case "panos":
      return "ethernet1/1";
    case "fortinet": case "fortios":
      return "port1";
    default:
      return "eth0";
  }
}

/** One sentence of guidance for a free-text interface field. */
export function interfaceHint(vendor?: string): string {
  return `Type the interface name exactly as the device reports it — for example ${interfaceExample(vendor)}.`;
}

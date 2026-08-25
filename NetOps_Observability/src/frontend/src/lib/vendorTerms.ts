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

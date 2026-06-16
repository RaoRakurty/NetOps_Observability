// ifname.ts — the platform's interface-name display standard. Long vendor names
// ("GigabitEthernet2", "Ethernet1") are abbreviated to the short forms NOC
// operators actually use, so topology link labels stay compact and don't overlap.
// Already-short vendor forms (Juniper ge-0/0/1, SR Linux ethernet-1/1→e1/1) are
// kept idiomatic. Free-text port descriptions ("to-spine1") pass through unchanged.

// Order matters: hyphenated SR-Linux "ethernet-1/1" before the generic "Ethernet",
// and longer speed prefixes before shorter ones.
const RULES: [RegExp, string][] = [
  [/^ethernet-/i, "e"],            // SR Linux ethernet-1/1 → e1/1
  [/^HundredGigE/i, "Hu"],
  [/^FortyGigE/i, "Fo"],
  [/^TwentyFiveGigE/i, "Twe"],
  [/^TenGigabitEthernet/i, "Te"],
  [/^TenGigE/i, "Te"],
  [/^GigabitEthernet/i, "Gi"],
  [/^FastEthernet/i, "Fa"],
  [/^Ethernet/i, "Et"],            // Arista Ethernet1 → Et1
  [/^Management/i, "Ma"],
  [/^Port-?channel/i, "Po"],
  [/^Loopback/i, "Lo"],
  [/^Vlan/i, "Vl"],
  [/^Tunnel/i, "Tu"],
];

// abbrevIfName returns the compact, operator-facing form of an interface name.
export function abbrevIfName(name: string): string {
  const n = (name ?? "").trim();
  if (!n) return n;
  for (const [re, short] of RULES) {
    if (re.test(n)) return n.replace(re, short);
  }
  return n;
}

// abbrevPortPair formats a link's two endpoints as "Gi2 ↔ e1/1".
export function abbrevPortPair(local?: string, remote?: string): string {
  return [local, remote].filter(Boolean).map((p) => abbrevIfName(p as string)).join(" ↔ ");
}

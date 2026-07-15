// TopologyDomainTabs — the network-DOMAIN tab bar (LAN · SD-WAN · DC · Cloud)
// plus the cross-cutting Carrier overlay toggle. This is the primary "where am I
// looking" control; it sits ABOVE the existing toolbar (the "what task" workflow
// selector). LAN is the default and renders the current canvas unchanged.
//
// See docs/design/topology-cloud-tabs.md.

import { DOMAINS, type NetworkDomain } from "../utils/topologyDomains";

export default function TopologyDomainTabs({
  value,
  onChange,
  carrier,
  onToggleCarrier,
}: {
  value: NetworkDomain;
  onChange: (d: NetworkDomain) => void;
  carrier: boolean;
  onToggleCarrier: (v: boolean) => void;
}) {
  return (
    <div className="topo-domain-tabs" role="tablist" aria-label="Network domain">
      <div className="topo-domain-tabs-eyebrow" aria-hidden="true">
        Network
      </div>
      {DOMAINS.map((d) => {
        const active = d.id === value;
        return (
          <button
            key={d.id}
            type="button"
            role="tab"
            aria-selected={active}
            title={d.blurb}
            className={active ? "on" : ""}
            onClick={() => onChange(d.id)}
          >
            {d.label}
          </button>
        );
      })}
      <span className="topo-domain-tabs-sep" aria-hidden="true" />
      <button
        type="button"
        role="switch"
        aria-checked={carrier}
        aria-label="Carrier / transport overlay"
        title="Overlay the shared carrier / transport network onto this tab — the fabric that ties LAN, SD-WAN, DC and Cloud together."
        className={`topo-domain-carrier${carrier ? " on" : ""}`}
        onClick={() => onToggleCarrier(!carrier)}
      >
        <span className="topo-domain-carrier-dot" aria-hidden="true" />
        Carrier
      </button>
    </div>
  );
}

export type { NetworkDomain };

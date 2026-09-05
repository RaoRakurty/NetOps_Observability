// DigitalExperience.tsx — Digital Experience Monitoring.
//
// HELD ON PURPOSE. The owner ruled (2026-09-05) that DEM gets a full design of
// record — market research across the endpoint, SD-WAN, data-centre and
// LAN/Wi-Fi vendors, a minimal-interference architecture, and a designed
// dashboard — BEFORE any screen is built. So this file is a route stub and
// nothing else: it renders what is true right now and does not fetch, because
// a half-built screen that shows a few real numbers is worse than no screen —
// it teaches an operator to trust a view that is not finished.
//
// The plumbing underneath it IS built and is live: the per-tenant synthetics
// catalogue, the prober's ICMP/TCP/DNS/HTTP checks, the dem_* series, the
// experience score and the experience alert rules. See
// docs/design/DEM_PLUMBING_2026-09-05.md; the product design of record is
// docs/design/DEM_2026-09-05.md.
//
// There is deliberately NO nav entry yet. The intended one, for whoever wires
// it: section Operations, leaf "Digital Experience",
// route #/operations/digital-experience.

import { NocHeader } from "../components/noc";

export default function DigitalExperience() {
  return (
    <div className="dm-board cc-board">
      <NocHeader
        title="Digital Experience"
        subtitle="Availability, latency against budget and path stability for the services people actually use"
      />
      <section className="card" role="region" aria-label="Digital Experience status">
        <div className="empty" role="status">
          <p>
            The design of record is in progress. This screen is not built yet, and it is
            deliberately empty rather than partly built.
          </p>
          <p className="mini-meta">
            Collection is already running: experience targets are declared per tenant, the prober
            measures them (ICMP, TCP, DNS and HTTP), and the availability, latency-against-budget
            and path-stability scores are served over the API. Nothing measured is being lost while
            this screen waits.
          </p>
        </div>
      </section>
    </div>
  );
}

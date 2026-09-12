// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// DigitalExperience.tsx — Digital Experience Monitoring.
//
// The design of record is ratified and the screen is LIVE. This file is the
// route target for #/operations/digital-experience and does nothing but mount
// the surface itself, which lives in pages/experience/: seven tabs (Experience,
// Incidents, Journeys, Service Paths, Synthetics, Changes, Data Health) over
// the /api/dem/* routes.
//
// The plumbing underneath it — the per-tenant check catalogue, the prober's
// ICMP/TCP/DNS/HTTP measurements, the dem_* series, the published experience
// score and the experience alert rules — was already running while the screen
// was held; nothing measured was lost in the interval.
//
// Nav entry: section Operations, leaf "Digital Experience",
// route #/operations/digital-experience/<tab>.

import ExperiencePage from "./experience/ExperiencePage";

export default function DigitalExperience() {
  return <ExperiencePage />;
}

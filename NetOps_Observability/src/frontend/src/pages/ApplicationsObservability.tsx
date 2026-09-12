// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Infrastructure → Applications — the route entry for the application half of
// the old Service View (owner IA, 2026-09-07): Catalog, Application map,
// Registries, Business services.
//
// The shell and every tab body it mounts live in AppObservability.tsx, which is
// also where the Cloud half lives; the two shells therefore SHARE one route
// chunk rather than splitting into two — the same single chunk the one
// "Services" leaf fetched before the split, so nothing got heavier. This file
// exists so nav.tsx addresses each half by the name an operator clicks, and so a
// future body-level split has an obvious seam to grow from.

export { ApplicationsShell as default } from "./AppObservability";

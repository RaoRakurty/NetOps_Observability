// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

/** Who reported a device's site id, in words: the device itself or its
 *  controller. The reported id is shown beside the operator's site, never
 *  instead of it (a manual site wins — owner decision 2026-10-18). */
export function reportedSiteTitle(source?: string): string {
  if (!source || source === "device") return "Site ID reported by the device itself";
  return `Site ID reported by ${source === "vmanage" ? "vManage" : source}`;
}

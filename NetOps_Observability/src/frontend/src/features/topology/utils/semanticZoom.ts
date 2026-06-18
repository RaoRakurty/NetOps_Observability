// semanticZoom.ts — map a React Flow zoom factor to a semantic level of detail.
// Pure. Drives label density and which strata of objects are emphasised as the
// operator zooms (PDF §10 "Semantic zoom" table).
//
// PDF §10 — zoom → semantic level (React Flow zoom ranges ~0.2 .. 2.0):
//   zoom < 0.45   global     — sites / regions only; minimal labels
//   0.45 ≤ z <0.8 site       — sites + fabrics; site labels
//   0.8  ≤ z <1.2 fabric     — fabric / pod detail; group labels
//   1.2  ≤ z <1.7 device     — individual devices; device labels
//   z ≥ 1.7       interface  — interfaces / ports; full labels
//
// Labels get denser the further in you go; "labelDensityForZoom" is the cheap
// boolean a renderer uses to decide whether to show secondary labels.

export type ZoomLevel = "global" | "site" | "fabric" | "device" | "interface";

/** Bucket a React Flow zoom factor into a semantic level (see §10 table above). */
export function zoomLevel(zoom: number): ZoomLevel {
  const z = Number.isFinite(zoom) ? zoom : 1;
  if (z < 0.45) return "global";
  if (z < 0.8) return "site";
  if (z < 1.2) return "fabric";
  if (z < 1.7) return "device";
  return "interface";
}

/**
 * Whether to show the denser/secondary label set. We start surfacing extra labels
 * once the operator is at "fabric" detail or closer (zoom ≥ 0.8).
 */
export function labelDensityForZoom(zoom: number): boolean {
  const level = zoomLevel(zoom);
  return level === "fabric" || level === "device" || level === "interface";
}

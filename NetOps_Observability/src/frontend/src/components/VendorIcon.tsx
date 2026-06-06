import { VENDOR_BRANDS, vendorKey } from "./vendorBrands";

// VendorIcon — renders a vendor's brand mark for HTML contexts (the Topology
// icon editor, device views). Uses the bundled CC0 brand path when available,
// otherwise an elegant monogram tile so every vendor reads as a clean,
// consistent box. (The ECharts map uses brandDataUri() from the same source.)

// Brand-ish tints for common vendors absent from the CC0 set, so their monogram
// still feels on-brand; anything else derives a stable hue from its name.
const FALLBACK_TINT: Record<string, string> = {
  juniper: "#84b135",
  arista: "#1f9bcf",
  aruba: "#ff8300",
};

function hueFromString(s: string): number {
  let h = 0;
  for (const c of s) h = (h * 31 + c.charCodeAt(0)) % 360;
  return h;
}

export default function VendorIcon({
  vendor,
  size = 20,
  title,
}: {
  vendor: string;
  size?: number;
  title?: string;
}) {
  const key = vendorKey(vendor);
  const brand = VENDOR_BRANDS[key];
  const label = title ?? (vendor || "Unknown vendor");

  if (brand) {
    return (
      <svg width={size} height={size} viewBox="0 0 24 24" role="img" aria-label={label}>
        <title>{label}</title>
        <path d={brand.path} fill={brand.hex} />
      </svg>
    );
  }

  const tint = FALLBACK_TINT[key] || `hsl(${hueFromString(key || "x")} 52% 46%)`;
  const initials =
    (vendor || "?").replace(/[^a-zA-Z0-9]/g, "").slice(0, 2).toUpperCase() || "?";
  return (
    <span
      className="vendor-mono"
      style={{ width: size, height: size, fontSize: size * 0.42, ["--tint" as string]: tint } as React.CSSProperties}
      role="img"
      aria-label={label}
      title={label}
    >
      {initials}
    </span>
  );
}

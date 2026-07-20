// text.ts — small display-only string helpers.
//
// capitalize is for the RENDER layer only: it upper-cases the first character
// of a value for human display (e.g. a vendor id "arista" → "Arista"). It must
// never be used to mutate ids/values that feed lookups or API calls — those
// stay verbatim; only what the user reads changes.
export function capitalize(s: string): string {
  return s ? s.charAt(0).toUpperCase() + s.slice(1) : s;
}

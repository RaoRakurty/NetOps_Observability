// investigationUrl — pure helpers for the `inv` hash param that keeps the
// embedded investigation drawer shareable/refresh-safe (#7 Wave 2): the open
// object's id lives in the URL, so a refresh or a pasted link reopens the same
// investigation over the same tab — no context-losing jump to another page.

/** The open investigation id from a hash like `#/operations/services?inv=<id>`. */
export function invFromHash(hash: string): string {
  const q = hash.split("?")[1] ?? "";
  return new URLSearchParams(q).get("inv") ?? "";
}

/** The hash with `inv=<id>` set (other params preserved). */
export function hashWithInv(hash: string, id: string): string {
  const [path, q = ""] = hash.split("?");
  const params = new URLSearchParams(q);
  params.set("inv", id);
  return `${path}?${params.toString()}`;
}

/** The hash with the `inv` param removed (drops the `?` when nothing remains). */
export function hashWithoutInv(hash: string): string {
  const [path, q = ""] = hash.split("?");
  const params = new URLSearchParams(q);
  params.delete("inv");
  const rest = params.toString();
  return rest ? `${path}?${rest}` : path;
}

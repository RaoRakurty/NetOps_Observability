// Minimal X.509 helpers for the SSO admin UI: extract a certificate's NotAfter
// client-side (so the cert-expiry banner works the moment a PEM is pasted or
// uploaded, before any round-trip) and classify how close to expiry it is.
//
// Parsing is a strict, minimal DER walk of the RFC 5280 layout — no dependency:
//   Certificate ::= SEQUENCE {
//     tbsCertificate ::= SEQUENCE {
//       [0] version (optional), serialNumber INTEGER, signature SEQUENCE,
//       issuer SEQUENCE, validity SEQUENCE { notBefore Time, notAfter Time }, … }
//     … }
// Anything that doesn't match that shape returns null (zero-trust: a malformed
// upload must never crash the form or produce a bogus date).

type Tlv = { tag: number; start: number; end: number }; // content [start, end)

function readTlv(buf: Uint8Array, off: number): Tlv | null {
  if (off + 2 > buf.length) return null;
  const tag = buf[off];
  let len = buf[off + 1];
  let head = 2;
  if (len & 0x80) {
    const n = len & 0x7f;
    if (n === 0 || n > 4 || off + 2 + n > buf.length) return null; // indefinite/oversized — not valid DER cert
    len = 0;
    for (let i = 0; i < n; i++) len = len * 256 + buf[off + 2 + i];
    head = 2 + n;
  }
  const start = off + head;
  const end = start + len;
  if (end > buf.length) return null;
  return { tag, start, end };
}

// Decode the first PEM CERTIFICATE block to DER bytes; null when absent/invalid.
function pemToDer(pem: string): Uint8Array | null {
  const m = /-----BEGIN CERTIFICATE-----([\s\S]*?)-----END CERTIFICATE-----/.exec(pem);
  if (!m) return null;
  const b64 = m[1].replace(/[^A-Za-z0-9+/=]/g, "");
  if (!b64) return null;
  try {
    const bin = atob(b64);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  } catch {
    return null;
  }
}

// ASN.1 Time (UTCTime 0x17: YYMMDDHHMMSSZ, RFC 5280 pivot 2050;
// GeneralizedTime 0x18: YYYYMMDDHHMMSSZ) → Date, or null.
function parseAsn1Time(tag: number, s: string): Date | null {
  let m: RegExpExecArray | null;
  if (tag === 0x17 && (m = /^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/.exec(s))) {
    const yy = Number(m[1]);
    const year = yy < 50 ? 2000 + yy : 1900 + yy;
    return new Date(Date.UTC(year, Number(m[2]) - 1, Number(m[3]), Number(m[4]), Number(m[5]), Number(m[6])));
  }
  if (tag === 0x18 && (m = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(?:\.\d+)?Z$/.exec(s))) {
    return new Date(Date.UTC(Number(m[1]), Number(m[2]) - 1, Number(m[3]), Number(m[4]), Number(m[5]), Number(m[6])));
  }
  return null;
}

// parseCertNotAfter — the NotAfter of the first CERTIFICATE block in `pem`,
// or null when the input is not a well-formed certificate.
export function parseCertNotAfter(pem: string): Date | null {
  const der = pemToDer(pem);
  if (!der) return null;

  const cert = readTlv(der, 0); // Certificate SEQUENCE
  if (!cert || cert.tag !== 0x30) return null;
  const tbs = readTlv(der, cert.start); // tbsCertificate SEQUENCE
  if (!tbs || tbs.tag !== 0x30) return null;

  // Walk tbsCertificate field by field up to validity.
  let off = tbs.start;
  let t = readTlv(der, off);
  if (!t) return null;
  if (t.tag === 0xa0) { off = t.end; t = readTlv(der, off); if (!t) return null; } // version
  if (t.tag !== 0x02) return null; // serialNumber
  off = t.end; t = readTlv(der, off);
  if (!t || t.tag !== 0x30) return null; // signature
  off = t.end; t = readTlv(der, off);
  if (!t || t.tag !== 0x30) return null; // issuer
  off = t.end;
  const validity = readTlv(der, off);
  if (!validity || validity.tag !== 0x30) return null;
  const notBefore = readTlv(der, validity.start);
  if (!notBefore || (notBefore.tag !== 0x17 && notBefore.tag !== 0x18)) return null;
  const notAfter = readTlv(der, notBefore.end);
  if (!notAfter || (notAfter.tag !== 0x17 && notAfter.tag !== 0x18) || notAfter.end > validity.end) return null;

  let s = "";
  for (let i = notAfter.start; i < notAfter.end; i++) s += String.fromCharCode(der[i]);
  return parseAsn1Time(notAfter.tag, s);
}

// Cert-expiry banner levels (docs/research/sso-admin-ui-vendor-patterns.md §6,
// following Citrix's 30-day banner): > 30d = none, ≤ 30d = warn, ≤ 7d or
// already expired = crit.
export type CertExpiry = { days: number; level: "ok" | "warn" | "crit"; expired: boolean };

export function certExpiry(notAfter: Date, now: Date = new Date()): CertExpiry {
  const days = Math.floor((notAfter.getTime() - now.getTime()) / 86_400_000);
  const expired = notAfter.getTime() <= now.getTime();
  const level = expired || days <= 7 ? "crit" : days <= 30 ? "warn" : "ok";
  return { days, level, expired };
}

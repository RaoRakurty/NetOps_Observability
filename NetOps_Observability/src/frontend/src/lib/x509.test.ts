// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// x509 helpers — client-side NotAfter extraction (drives the SSO cert-expiry
// banner the moment a PEM is pasted) and the §6 threshold classification
// (>30d none · ≤30d warn · ≤7d/expired crit). Fixture certs generated with
// openssl (self-signed, P-256); their NotAfter values are baked into the DER
// forever, so the parse assertions are stable.

import { describe, it, expect } from "vitest";
import { parseCertNotAfter, certExpiry } from "./x509";

// notAfter=Aug 1 06:27:36 2036 GMT (UTCTime encoding — year < 2050).
const FIXTURE_UTCTIME = `-----BEGIN CERTIFICATE-----
MIIBgTCCASegAwIBAgIUBdiCPbg/FapZfTuc/7pm+t9hWLowCgYIKoZIzj0EAwIw
FjEUMBIGA1UEAwwLc3NvLWZpeHR1cmUwHhcNMjYwODA0MDYyNzM2WhcNMzYwODAx
MDYyNzM2WjAWMRQwEgYDVQQDDAtzc28tZml4dHVyZTBZMBMGByqGSM49AgEGCCqG
SM49AwEHA0IABNdr/xqbhPWmJaDEmNRmS7Z5YnPAi6/lXQTTIetgMNbREx2WmI81
g5pw+ia96+9DNz5fbR2hislNs799mSmQGJijUzBRMB0GA1UdDgQWBBQsP2BzEIjy
nxSVoRWMn3hXGh6VJDAfBgNVHSMEGDAWgBQsP2BzEIjynxSVoRWMn3hXGh6VJDAP
BgNVHRMBAf8EBTADAQH/MAoGCCqGSM49BAMCA0gAMEUCIGc9xQbXM/u54+Kt4/Rd
lMTmKoddjJ5txbPMM9udkh5OAiEAlPkEws8HuPzUhMCWxar3P71pAvZEX3bMYx8N
ZEVQ4rs=
-----END CERTIFICATE-----`;

// notAfter=Dec 19 06:27:48 2053 GMT (GeneralizedTime encoding — year ≥ 2050).
const FIXTURE_GENERALIZEDTIME = `-----BEGIN CERTIFICATE-----
MIIBiTCCAS+gAwIBAgIUWu4cuvsIgOTY6j4iUvKCvnkI/xYwCgYIKoZIzj0EAwIw
GTEXMBUGA1UEAwwOc3NvLWZpeHR1cmUtZ3QwIBcNMjYwODA0MDYyNzQ4WhgPMjA1
MzEyMTkwNjI3NDhaMBkxFzAVBgNVBAMMDnNzby1maXh0dXJlLWd0MFkwEwYHKoZI
zj0CAQYIKoZIzj0DAQcDQgAEtcIv06qfKAHuiQbY0Q7gALkI8nwRfNcsOe1+/sHO
e99Nbh0ItRhlIJ55tZWKuOOmdNP89fTT97WeFmOX24z4dKNTMFEwHQYDVR0OBBYE
FITSyrxFfM46uthdpFmBIj2VyGeUMB8GA1UdIwQYMBaAFITSyrxFfM46uthdpFmB
Ij2VyGeUMA8GA1UdEwEB/wQFMAMBAf8wCgYIKoZIzj0EAwIDSAAwRQIhAPxY3js6
+ONsTiCUbilZf/mvyL6uMZaA9fl2BX8R96D0AiAEM0XjkTbk74U/1HeNnGOa0yyy
boIJ3/xRxJtexsUJrA==
-----END CERTIFICATE-----`;

describe("parseCertNotAfter", () => {
  it("extracts NotAfter from a UTCTime cert", () => {
    const d = parseCertNotAfter(FIXTURE_UTCTIME);
    expect(d?.toISOString()).toBe("2036-08-01T06:27:36.000Z");
  });

  it("extracts NotAfter from a GeneralizedTime cert (year ≥ 2050)", () => {
    const d = parseCertNotAfter(FIXTURE_GENERALIZEDTIME);
    expect(d?.toISOString()).toBe("2053-12-19T06:27:48.000Z");
  });

  it("tolerates surrounding whitespace / extra text around the PEM block", () => {
    const d = parseCertNotAfter(`some header\n${FIXTURE_UTCTIME}\ntrailing`);
    expect(d?.toISOString()).toBe("2036-08-01T06:27:36.000Z");
  });

  it("returns null for garbage, empty, and truncated inputs (never throws)", () => {
    expect(parseCertNotAfter("")).toBeNull();
    expect(parseCertNotAfter("not a pem")).toBeNull();
    expect(parseCertNotAfter("-----BEGIN CERTIFICATE-----\n!!!!\n-----END CERTIFICATE-----")).toBeNull();
    // Structurally valid base64 but not a certificate.
    expect(parseCertNotAfter("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----")).toBeNull();
    // Truncated DER: chop the fixture body in half.
    const body = FIXTURE_UTCTIME.split("\n").slice(1, 4).join("\n");
    expect(parseCertNotAfter(`-----BEGIN CERTIFICATE-----\n${body}\n-----END CERTIFICATE-----`)).toBeNull();
  });
});

describe("certExpiry thresholds (§6: >30d ok, ≤30d warn, ≤7d/expired crit)", () => {
  const now = new Date("2026-08-04T12:00:00Z");
  const plusDays = (n: number) => new Date(now.getTime() + n * 86_400_000);

  it("more than 30 days out → ok", () => {
    expect(certExpiry(plusDays(31), now)).toEqual({ days: 31, level: "ok", expired: false });
    expect(certExpiry(plusDays(365), now).level).toBe("ok");
  });

  it("30 days or less → warn", () => {
    expect(certExpiry(plusDays(30), now)).toEqual({ days: 30, level: "warn", expired: false });
    expect(certExpiry(plusDays(8), now).level).toBe("warn");
  });

  it("7 days or less → crit", () => {
    expect(certExpiry(plusDays(7), now)).toEqual({ days: 7, level: "crit", expired: false });
    expect(certExpiry(plusDays(1), now).level).toBe("crit");
  });

  it("expired → crit with the expired flag", () => {
    const e = certExpiry(plusDays(-2), now);
    expect(e.level).toBe("crit");
    expect(e.expired).toBe(true);
    expect(e.days).toBeLessThan(0);
  });
});

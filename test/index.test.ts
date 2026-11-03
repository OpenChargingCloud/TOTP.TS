// The example token values and rejection cases that used to be duplicated
// here live in the canonical conformance vectors now (test/vectors/, run by
// vectors.test.ts and shared with the C# TOTPGenerator in Vanaheimr Hermod
// via https://github.com/OpenChargingCloud/TOTPConformanceTests). This file
// keeps the structural properties of the frozen token format that hold for
// ALL inputs, beyond the pinned example values.

import { describe, expect, it } from "vitest";

import { generateTOTPs, tlsExporterMaterialOf, TLS_EXPORTER_LABEL, type TLSExporter } from "../src/index.js";

describe("Token format properties", () => {

  it("reads the hash as a ring buffer: a 64 character sha256 token repeats its first 32 characters verbatim", () => {
    expect(generateTOTPs("secure!Charging!", 30, 64, null, 1718611200000, "sha256").current)
      .toBe("akF3c7qY2uiuO4rpyU0SC0W8VFE6nvxz".repeat(2));
  });

  it("does not repeat a 64 character sha512 token, as its hash has 64 bytes", () => {
    const totp = generateTOTPs("secure!Charging!", 30, 64, null, 1718611200000, "sha512").current;
    expect(totp.slice(32)).not.toBe(totp.slice(0, 32));
  });

  it("wraps the previous slot to 2^64 - 1 within the first slot after the Unix epoch, like the unchecked UInt64 arithmetic in C#", () => {
    expect(generateTOTPs("secure!Charging!", 30, 12, null, 0)).toEqual({
      previous:       "SzcwtcR5qcY7",
      current:        "u5CoKdo5HUS1",
      next:           "tVGiyLys7Y1V",
      remainingTime:   30
    });
  });

  it("defaults to HMAC-SHA256", () => {
    expect(generateTOTPs("secure!Charging!", null, null, null, 1718611200000).current)
      .toBe(generateTOTPs("secure!Charging!", null, null, null, 1718611200000, "sha256").current);
  });

  it("overlaps previous/current/next across adjacent slots", () => {
    const timestamp = 1718611200000;
    const next0     = generateTOTPs("secure!Charging!", null, null, null, timestamp).next;
    const current1  = generateTOTPs("secure!Charging!", null, null, null, timestamp + 30_000).current;
    const previous2 = generateTOTPs("secure!Charging!", null, null, null, timestamp + 60_000).previous;
    expect(current1).toBe(next0);
    expect(previous2).toBe(next0);
  });

});

describe("TLS channel binding", () => {

  const material = Uint8Array.from({ length: 32 }, (_, i) => i);

  it("treats empty exporter material as absent, not as an HMAC with an empty key", () => {
    expect(generateTOTPs({ sharedSecret: "secure!Charging!", timestamp: 1718611200000, tlsExporterMaterial: new Uint8Array(0) }))
      .toEqual(generateTOTPs({ sharedSecret: "secure!Charging!", timestamp: 1718611200000 }));
  });

  it("binds every token of the triple", () => {
    const raw   = generateTOTPs("secure!Charging!", null, null, null, 1718611200000);
    const bound = generateTOTPs("secure!Charging!", null, null, null, 1718611200000, null, material);
    expect(bound.previous).not.toBe(raw.previous);
    expect(bound.current). not.toBe(raw.current);
    expect(bound.next).    not.toBe(raw.next);
    expect(bound.remainingTime).toBe(raw.remainingTime);
  });

  it("rejects exporter material that is not a Uint8Array", () => {
    expect(() => generateTOTPs({ sharedSecret: "secure!Charging!", tlsExporterMaterial: "000102" as unknown as Uint8Array }))
      .toThrow("The TLS exporter material must be a Uint8Array!");
  });

  function fakeSocket(protocol: string | null): TLSExporter & { calls: [number, string][] } {
    const calls: [number, string][] = [];
    return {
      calls,
      getProtocol:          (): string | null => protocol,
      exportKeyingMaterial: (length, label): Uint8Array => { calls.push([length, label]); return new Uint8Array(length); }
    };
  }

  it("derives 32 bytes under the specified label, without a context", () => {
    const socket = fakeSocket("TLSv1.3");
    expect(tlsExporterMaterialOf(socket)).toHaveLength(32);
    expect(socket.calls).toEqual([[32, "EXPORTER-Time-Based-One-Time-Password-v1"]]);
    expect(TLS_EXPORTER_LABEL).toBe("EXPORTER-Time-Based-One-Time-Password-v1");
  });

  it("refuses to bind to anything but TLS v1.3", () => {
    for (const protocol of ["TLSv1.2", "TLSv1.1", null]) {
      const socket = fakeSocket(protocol);
      expect(() => tlsExporterMaterialOf(socket)).toThrow("TLS channel binding requires TLS v1.3");
      expect(socket.calls).toEqual([]);
    }
  });

});

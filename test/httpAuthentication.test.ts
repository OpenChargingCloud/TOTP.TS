// The canonical vectors (vectors.test.ts) pin the wire format; this file
// covers the rules of the "Authorization: TOTP" scheme that no vector
// exercises: what the builder refuses, and the edges of Base64 and UTF-8.

import { describe, expect, it } from "vitest";

import { formatTOTPAuthorization, generateTOTPs, parseTOTPAuthorization } from "../src/index.js";

describe("formatTOTPAuthorization", () => {

  it("defaults to a TLS-bound token and therefore omits tlscb", () => {
    expect(formatTOTPAuthorization({ login: "chargingstation-0001", totp: "gAzxPfYtmRgd" }))
      .toBe("TOTP login=\"Y2hhcmdpbmdzdGF0aW9uLTAwMDE=\", totp=\"Z0F6eFBmWXRtUmdk\"");
  });

  it("trims the login, as Hermod does", () => {
    expect(formatTOTPAuthorization({ login: "  chargingstation-0001 ", totp: "CN63y502maVh", tlscb: false }))
      .toBe(formatTOTPAuthorization({ login: "chargingstation-0001",    totp: "CN63y502maVh", tlscb: false }));
  });

  it("refuses an empty login or token", () => {
    expect(() => formatTOTPAuthorization({ login: "   ",       totp: "CN63y502maVh" })).toThrow("The given login must not be null or empty!");
    expect(() => formatTOTPAuthorization({ login: "station-1", totp: ""             })).toThrow("The given TOTP must not be null or empty!");
  });

  it("refuses a tlscb that is not a boolean, rather than reading \"false\" as true", () => {
    expect(() => formatTOTPAuthorization({ login: "station-1", totp: "CN63y502maVh", tlscb: "false" as unknown as boolean }))
      .toThrow("The given tlscb must be a boolean!");
  });

  it("round-trips logins and tokens beyond ASCII, astral characters included", () => {
    for (const credentials of [
      { login: "EVSE:DE*GEF*E1234*1",  totp: "CN63y502maVh", tlscb: false },
      { login: "Ladesäule-Süd-01",     totp: "äöü€",         tlscb: true  },
      { login: "station-🔌",           totp: "⚡⚡⚡⚡",       tlscb: false },
      { login: "a",                    totp: "ab",           tlscb: true  },
      { login: "abc",                  totp: "abcd",         tlscb: false }
    ])
      expect(parseTOTPAuthorization(formatTOTPAuthorization(credentials))).toEqual(credentials);
  });

  it("carries a generated token", () => {
    const totp = generateTOTPs("secure!Charging!", null, null, null, 1718611200000).current;
    expect(parseTOTPAuthorization(formatTOTPAuthorization({ login: "station-1", totp, tlscb: false })).totp).toBe(totp);
  });

});

describe("parseTOTPAuthorization", () => {

  const totp = "totp=\"Q042M3k1MDJtYVZo\"";

  it("matches parameter names case-insensitively, duplicates included", () => {
    expect(parseTOTPAuthorization(`TOTP LOGIN="c3RhdGlvbi0x", ToTp="Q042M3k1MDJtYVZo", TLSCB=false`))
      .toEqual({ login: "station-1", totp: "CN63y502maVh", tlscb: false });
    expect(() => parseTOTPAuthorization(`TOTP login="c3RhdGlvbi0x", Login="c3RhdGlvbi0x", ${totp}`))
      .toThrow("more than once");
  });

  it("accepts unpadded Base64, and rejects padding that does not add up", () => {
    expect(parseTOTPAuthorization(`TOTP login=QQ, ${totp}`).login).toBe("A");
    expect(parseTOTPAuthorization(`TOTP login="QQ==", ${totp}`).login).toBe("A");
    for (const login of ["QQ=", "QUJD==", "Q", "=", "QQ=A", "Q Q", "QQ==="])
      expect(() => parseTOTPAuthorization(`TOTP login="${login}", ${totp}`), login).toThrow("login");
  });

  it("rejects a login that is not UTF-8 instead of repairing it", () => {
    // 0xFF never occurs in UTF-8.
    expect(() => parseTOTPAuthorization(`TOTP login="/w==", ${totp}`)).toThrow("UTF-8");
  });

  it("rejects an empty token", () => {
    expect(() => parseTOTPAuthorization("TOTP login=\"c3RhdGlvbi0x\", totp=\"\"")).toThrow("totp");
  });

  it("unescapes quoted-pairs inside quoted strings", () => {
    expect(parseTOTPAuthorization(`TOTP login="c3Rhd\\Glvbi0x", ${totp}, foo="a \\"quoted\\" value"`).login)
      .toBe("station-1");
  });

  it("accepts tabs as whitespace and surrounding whitespace of the whole value", () => {
    expect(parseTOTPAuthorization(`  TOTP\tlogin="c3RhdGlvbi0x",\t${totp}  `).login).toBe("station-1");
  });

});

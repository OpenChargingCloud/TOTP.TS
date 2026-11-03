/*
 * Smoke test for the PUBLISHED package — run by the engines-floor job in
 * .github/workflows/ci.yml on the oldest Node this package claims to support
 * ("engines": { "node": ">=20.19.0" }). vitest 5 cannot run there (its own
 * floor is 22.12.0), so this file is what keeps that claim tested: plain
 * Node, no test runner, nothing but the package and its runtime dependency.
 *
 * It imports the package by its name, not by a path into dist/: in the CI
 * job the packed tarball is installed into an empty project, so what runs is
 * what npm would publish. In the repository itself the same import resolves
 * through the package's self-reference, so after "npm run build" it also
 * runs from the repository root:
 *
 *     node test/smoke.mjs
 *
 * The values are the conformance vectors the vitest suite pins (an unbound
 * and a TLS-bound token) and the header example of the README — if they ever
 * disagree, trust neither and look at the code.
 */

import { formatTOTPAuthorization,
         generateTOTPs,
         parseTOTPAuthorization } from "@open-charging-cloud/totp";

const checks = [
    {
        name:      "unbound token",
        actual:    generateTOTPs("secure!Charging!", 30, 12, null, 1718611200000),
        expected:  { previous: "QT1cCdKsIb9e", current: "akF3c7qY2uiu", next: "1U70OgaBA48M", remainingTime: 30 }
    },
    {
        name:      "TLS-bound token",
        actual:    generateTOTPs({ sharedSecret:         "secure!Charging!",
                                   timestamp:             1716423785000,
                                   tlsExporterMaterial:   Uint8Array.from({ length: 32 }, (_, i) => i) }),
        expected:  { previous: "a603aFLdBS79", current: "gAzxPfYtmRgd", next: "cwveP1RTF3PN", remainingTime: 25 }
    },
    {
        name:      "Authorization: TOTP header",
        actual:    { header: formatTOTPAuthorization({ login: "chargingstation-0001", totp: "CN63y502maVh", tlscb: false }) },
        expected:  { header: "TOTP login=\"Y2hhcmdpbmdzdGF0aW9uLTAwMDE=\", totp=\"Q042M3k1MDJtYVZo\", tlscb=false" }
    },
    {
        name:      "parsed Authorization: TOTP header",
        actual:    parseTOTPAuthorization("TOTP login=\"Y2hhcmdpbmdzdGF0aW9uLTAwMDE=\", totp=\"Z0F6eFBmWXRtUmdk\""),
        expected:  { login: "chargingstation-0001", totp: "gAzxPfYtmRgd", tlscb: true }
    }
];

for (const { name, actual, expected } of checks)
    for (const key of Object.keys(expected))
        if (actual[key] !== expected[key]) {
            console.error(`Smoke test FAILED on Node ${process.version}: ${name}: ${key} was "${actual[key]}", expected "${expected[key]}"!`);
            process.exit(1);
        }

console.log(`Smoke test passed on Node ${process.version}: ${checks.length} checks.`);

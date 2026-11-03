# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
While the version number is below 1.0.0, breaking changes are released in minor
versions and are always listed first below.

**Token values are never a change.** The token format is frozen at v1.0 and is
verified against the vendored conformance vectors on every run: a release that
moved a single token would break deployed verifiers and printed QR codes, so no
entry below ever will.


## [Unreleased]

### Added

- **TLS v1.3 channel binding** (token format specification, section 6): the
  new optional `tlsExporterMaterial` - in the options object, or as the
  seventh positional argument - HMACs every token once more with exporter
  material of the TLS session, so a captured token is useless on any other
  connection. Empty material means no binding. `tlsExporterMaterialOf(socket)`
  derives the material from a Node `TLSSocket` (label
  `EXPORTER-Time-Based-One-Time-Password-v1`, exported as
  `TLS_EXPORTER_LABEL`; 32 bytes, empty context) and refuses anything but
  TLS v1.3. The three `tlsChannelBinding` conformance vectors run now
  instead of being skipped, byte-identical with the C# `TOTPGenerator`.
  Unbound tokens are unchanged.


## [0.3.1] - 2026-09-05

### Changed

- The repository URLs name `TOTP.TS`, the spelling the repository actually
  has. Metadata only - no code, no token value and no API changed. It needs a
  release of its own because npm serves `repository`, `homepage` and the README
  from the published version and lets no version be edited afterwards, so 0.3.0
  will keep pointing at the old spelling forever.


## [0.3.0] - 2026-09-05

### Breaking

- **`engines.node` is now `>=20.19.0`**, up from `>=18`. Not a change of what
  the library uses - it needs less of Node than before - but of what it depends
  on: `@noble/hashes` sets that floor, and claiming `>=18` would promise an
  installation that cannot resolve.

### Added

- **The library runs wherever the tokens are needed**: Node, browsers, bundler
  output (webpack, Vite, esbuild, Rollup), Cordova, Deno, service workers.
  Two lines used to keep it out of three of those four.

  `node:crypto` was the harder one: webpack refuses the scheme with an
  `UnhandledSchemeError` before `resolve.alias` or `resolve.fallback` ever see
  the request, so a browser consumer could not paper over it from its own
  config - it had to replace the module. The HMAC now comes from
  [`@noble/hashes`](https://github.com/paulmillr/noble-hashes), this package's
  first runtime dependency. That choice is also what keeps `generateTOTPs()`
  **synchronous**: WebCrypto computes the same digest in a browser, but only
  asynchronously, which would turn the function into a promise for every caller
  that exists.

  `Buffer` was the quieter one: present in some bundles, absent in others, so
  depending on it made a consumer's success accidental.
  `Buffer.alloc(8).writeBigUInt64BE()` is now a `DataView` over eight bytes -
  the same big-endian slot number, everywhere - and `Buffer.from(secret)` a
  `TextEncoder`.

  No token value moved: the vendored conformance vectors pass unchanged, and
  spot checks across sha256/sha384/sha512 with custom alphabets and lengths
  produce byte-identical tokens before and after.

- **`test/portability.test.ts`** keeps it that way: it computes with
  `globalThis.Buffer` deleted, asserts that the built `dist/` imports nothing
  only Node has, and pins the API as synchronous.

- **ESLint**, with the same rule set as the other Open Charging Cloud
  TypeScript packages (`npm run lint`, `npm run verify`).

### Changed

- The `exports` map gained a `default` condition and `./package.json`, so
  resolvers that ask for neither `import` nor `require` - some bundlers, Deno,
  tooling that reads the version - find the package rather than failing.
- `tsconfig.json` now covers the tests and config files for the editor and the
  linter, while `tsconfig.build.json` emits `dist/` from `src/` alone. Same
  split as the other packages.
- The development toolchain matches the other packages: TypeScript 6,
  vitest 5, `@types/node` 26.


## [0.2.0] - 2026

### Added

- The conformance test suite runs against the vendored vectors of the
  specification, which now lives in
  [OpenChargingTechnology/Whitepapers](https://github.com/OpenChargingTechnology/Whitepapers)
  and is executed against both this implementation and the C# `TOTPGenerator`
  in Vanaheimr Hermod.
- `sha384` and `sha512` alongside `sha256`.
- The documented quirks of the token format - the modulo bias of the alphabet
  mapping, the hash read as a ring buffer, and the unchecked UInt64 wrap of the
  previous slot within the first slot after the Unix epoch.


## [0.1.0] - 2024

### Added

- `generateTOTPs()`, converted from the earlier JavaScript implementation:
  previous, current and next token plus the remaining time of the current slot,
  from a shared secret, a slot duration, a token length, an alphabet, a
  timestamp and a hash algorithm.

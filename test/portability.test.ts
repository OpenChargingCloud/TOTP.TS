/*
 * Copyright (c) 2024-2026 GraphDefined GmbH <achim.friedland@graphdefined.com>
 * This file is part of TOTP.TS <https://github.com/OpenChargingCloud/TOTP.TS>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// A one-time password is needed wherever a QR code is scanned or an HTTP
// request is signed: in Node, in a browser, inside a bundler's output, in a
// service worker. This library therefore uses nothing that only Node has - no
// "node:crypto", no Buffer - and these tests are what keeps it that way.
//
// The failure they prevent is not subtle: a "node:" import makes webpack
// refuse the build outright, and a Buffer reference makes the bundle throw at
// runtime unless the consumer polyfills it. Both used to be true here, and
// both cost every browser consumer a workaround of its own.

import { readdirSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

import { generateTOTPs } from "../src/index.js";

const projectRoot = fileURLToPath(new URL("..", import.meta.url));

describe("Portability", () => {

  it("computes without any Node global", () => {

    // Buffer is the one Node global a bundle silently inherits in some setups
    // and lacks in others. Nothing here may depend on it being there.
    const buffer = (globalThis as { Buffer?: unknown }).Buffer;

    try
    {
      delete (globalThis as { Buffer?: unknown }).Buffer;

      expect(generateTOTPs("secure!Charging!", 30, 12, null, 1718611200000).current).
        toBe(generateTOTPs("secure!Charging!", 30, 12, null, 1718611200000).current);

      expect(generateTOTPs({ sharedSecret: "secure!Charging!", timestamp: 0 })).toEqual({
        previous:       "SzcwtcR5qcY7",
        current:        "u5CoKdo5HUS1",
        next:           "tVGiyLys7Y1V",
        remainingTime:   30
      });
    }
    finally
    {
      (globalThis as { Buffer?: unknown }).Buffer = buffer;
    }

  });

  it("ships a build that imports nothing only Node has", () => {

    // Every module of the build, not just the entry point: index.js
    // re-exports the others, so each one ends up in a consumer's bundle.
    const modules = readdirSync(join(projectRoot, "dist")).filter(file => file.endsWith(".js"));

    expect(modules).toContain("index.js");

    for (const module of modules) {

      // The comments explain why none of this is used, so they would match
      // every pattern below - it is the code that has to be clean.
      const code = readFileSync(join(projectRoot, "dist", module), "utf8").
                       replace(/\/\*[\s\S]*?\*\//g, "").
                       replace(/^\s*\/\/.*$/gm, "");

      // A "node:" import is what webpack refuses with UnhandledSchemeError, and
      // no resolve.alias or resolve.fallback ever gets to see it: the scheme is
      // rejected before anything is resolved.
      expect(code, module).not.toMatch(/["']node:/);
      expect(code, module).not.toMatch(/\bBuffer\b/);
      expect(code, module).not.toMatch(/\bprocess\./);
      expect(code, module).not.toMatch(/\b__dirname\b/);

    }

  });

  it("keeps its API synchronous", () => {

    // WebCrypto could do the HMAC in a browser, but only asynchronously.
    // Returning a promise would break every caller that exists, so the hash
    // has to come from a synchronous implementation - which is the reason for
    // the @noble/hashes dependency.
    expect(generateTOTPs("secure!Charging!", 30, 12, null, 0)).not.toBeInstanceOf(Promise);

  });

});

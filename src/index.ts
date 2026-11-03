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

import { hmac }                   from "@noble/hashes/hmac.js";
import { sha256, sha384, sha512 } from "@noble/hashes/sha2.js";

// The hash functions by the name the API takes. @noble/hashes rather than
// Node's crypto: this library has to run wherever a one-time password is
// needed - Node, a browser, a bundler's output, a service worker - and
// "node:crypto" is unavailable in three of those four. It is also what keeps
// the API synchronous: WebCrypto could do the HMAC in a browser, but only
// asynchronously, which would turn generateTOTPs() into a promise for every
// caller that ever existed.
const hashFunctions: Record<TOTPHashAlgorithm, Parameters<typeof hmac.create>[0]> = {
    "sha256": sha256,
    "sha384": sha384,
    "sha512": sha512
};

const utf8 = new TextEncoder();

const DEFAULT_VALIDITY_TIME  = 30;
const DEFAULT_TOTP_LENGTH    = 12;
const DEFAULT_ALPHABET       = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DEFAULT_HASH_ALGORITHM = "sha256";

/** The TLS exporter label for TOTP channel binding (RFC 8446 section 7.5). */
export const TLS_EXPORTER_LABEL  = "EXPORTER-Time-Based-One-Time-Password-v1";

/** The RECOMMENDED length of the TLS exporter material, in bytes. */
export const TLS_EXPORTER_LENGTH = 32;

export type TOTPHashAlgorithm = "sha256" | "sha384" | "sha512";

export interface GenerateTOTPOptions {
    sharedSecret:          string;
    validityTime?:         number | null;
    totpLength?:           number | null;
    alphabet?:             string | null;
    timestamp?:            Date   | number | null;
    hashAlgorithm?:        TOTPHashAlgorithm | null;
    tlsExporterMaterial?:  Uint8Array | null;
}

/**
 * The part of a TLS socket that channel binding needs - structurally typed,
 * so that this library stays free of "node:tls". Node's TLSSocket provides
 * both methods.
 */
export interface TLSExporter {
    getProtocol():           string | null;
    exportKeyingMaterial(length: number, label: string): Uint8Array;
}

export interface TOTPResult {
    previous:       string;
    current:        string;
    next:           string;
    remainingTime:  number;
}

function calcTOTPSlot(slotBytes:            Uint8Array,
                      totpLength:           number,
                      alphabet:             string,
                      sharedSecret:         string,
                      hashAlgorithm:        TOTPHashAlgorithm,
                      tlsExporterMaterial:  Uint8Array | null): string {

    let currentHash = hmac(hashFunctions[hashAlgorithm], utf8.encode(sharedSecret), slotBytes);

    // TLS channel binding: a second HMAC over the first digest, keyed with
    // the exporter material, with the same hash algorithm. Empty material
    // means "no binding", never an HMAC with an empty key.
    if (tlsExporterMaterial !== null && tlsExporterMaterial.length > 0)
        currentHash = hmac(hashFunctions[hashAlgorithm], tlsExporterMaterial, currentHash);

    const offset = currentHash[currentHash.length - 1] & 0x0F;

    // Two properties of this loop are frozen parts of the token format — the
    // C# TOTPGenerator in Vanaheimr Hermod produces byte-identical tokens and
    // deployed verifiers depend on them (see README, "Security notes"):
    //
    //  * "% alphabet.length" has a modulo bias: with the default 62-character
    //    alphabet, 256 = 4*62 + 8, so the first eight alphabet characters are
    //    25% more likely than the rest. Do not "fix" this with rejection
    //    sampling — alphabets whose length divides 256 (e.g. the 64-character
    //    base64url set) have no bias at all.
    //
    //  * "% currentHash.length" reads the hash as a ring buffer: position
    //    i + hashLength repeats position i verbatim, so tokens longer than
    //    32/48/64 characters (sha256/sha384/sha512) gain no further entropy.
    let result = "";
    for (let i = 0; i < totpLength; i++)
        result += alphabet[currentHash[(offset + i) % currentHash.length] % alphabet.length];

    return result;

}

// The slot number as the eight big-endian bytes the HMAC is taken over -
// Buffer.alloc(8).writeBigUInt64BE() without Buffer, which exists in Node
// alone. DataView is the same eight bytes, everywhere.
function slotBytesOf(slot: bigint): Uint8Array {

    const bytes = new Uint8Array(8);

    new DataView(bytes.buffer).setBigUint64(0, slot, false);

    return bytes;

}

function normalizeTimestamp(timestamp: Date | number | null | undefined): number {

    if (timestamp === null || timestamp === undefined)
        return Date.now();

    if (timestamp instanceof Date)
        return timestamp.getTime();

    return timestamp;

}

export function generateTOTPs(options:                GenerateTOTPOptions): TOTPResult;

export function generateTOTPs(sharedSecret:           string,
                              validityTime?:          number | null,
                              totpLength?:            number | null,
                              alphabet?:              string | null,
                              timestamp?:             Date   | number | null,
                              hashAlgorithm?:         TOTPHashAlgorithm | null,
                              tlsExporterMaterial?:   Uint8Array | null): TOTPResult;

export function generateTOTPs(sharedSecretOrOptions:  string | GenerateTOTPOptions,
                              validityTime:           number | null = null,
                              totpLength:             number | null = null,
                              alphabet:               string | null = null,
                              timestamp:              Date   | number | null = null,
                              hashAlgorithm:          TOTPHashAlgorithm | null = null,
                              tlsExporterMaterial:    Uint8Array | null = null): TOTPResult {

    const options                 = typeof sharedSecretOrOptions === "string"
                                        ? {
                                              sharedSecret: sharedSecretOrOptions,
                                              validityTime,
                                              totpLength,
                                              alphabet,
                                              timestamp,
                                              hashAlgorithm,
                                              tlsExporterMaterial
                                          }
                                        : sharedSecretOrOptions;

    const normalizedValidityTime  =  options.validityTime ?? DEFAULT_VALIDITY_TIME;
    const normalizedTOTPLength    =  options.totpLength   ?? DEFAULT_TOTP_LENGTH;
    const normalizedTimestamp     =  normalizeTimestamp(options.timestamp);
    const normalizedHashAlgorithm =  options.hashAlgorithm ?? DEFAULT_HASH_ALGORITHM;
    const normalizedTLSMaterial   =  options.tlsExporterMaterial ?? null;

    // The type says string; a JavaScript caller says whatever it likes, and the
    // invalid-input vectors expect this function's own error message rather
    // than a TypeError from .trim(). The optional chain is what keeps that
    // promise, so the rule is answered here rather than obeyed.
    // eslint-disable-next-line @typescript-eslint/no-unnecessary-condition
    const sharedSecret            =  options.sharedSecret?.trim();
    const normalizedAlphabet      = (options.alphabet     ?? DEFAULT_ALPHABET).trim();

    if (!sharedSecret)
        throw new Error("The given shared secret must not be null or empty!");

    if (/\s/.test(sharedSecret))
        throw new Error("The given shared secret must not contain any whitespace characters!");

    if (sharedSecret.length < 16)
        throw new Error("The length of the given shared secret must be at least 16 characters!");

    if (!Number.isInteger(normalizedValidityTime) || normalizedValidityTime <= 0)
        throw new Error("The validity time must be a positive integer number of seconds!");

    if (!Number.isInteger(normalizedTOTPLength) || normalizedTOTPLength < 4 || normalizedTOTPLength > 255)
        throw new Error("The expected length of the TOTP must be between 4 and 255 characters!");

    if (!Number.isFinite(normalizedTimestamp) || normalizedTimestamp < 0)
        throw new Error("The timestamp must be a non-negative Unix timestamp in milliseconds!");

    if (!["sha256", "sha384", "sha512"].includes(normalizedHashAlgorithm))
        throw new Error("The hash algorithm must be one of: sha256, sha384, sha512!");

    if (!normalizedAlphabet)
        throw new Error("The given alphabet must not be null or empty!");

    if (normalizedAlphabet.length < 4)
        throw new Error("The given alphabet must contain at least 4 characters!");

    if (new Set(normalizedAlphabet).size !== normalizedAlphabet.length)
        throw new Error("The given alphabet must not contain duplicate characters!");

    if (/\s/.test(normalizedAlphabet))
        throw new Error("The given alphabet must not contain any whitespace characters!");

    // A JavaScript caller may hand over a hex string or a plain array; either
    // would key the second HMAC with something the peer never derived.
    if (normalizedTLSMaterial !== null && !(normalizedTLSMaterial instanceof Uint8Array))
        throw new Error("The TLS exporter material must be a Uint8Array!");

    const currentUnixTime    = Math.floor(normalizedTimestamp / 1000);
    const currentSlot        = BigInt(Math.floor(currentUnixTime / normalizedValidityTime));
    const remainingTime      = normalizedValidityTime - (currentUnixTime % normalizedValidityTime);

    // BigInt.asUintN mirrors the unchecked UInt64 arithmetic of the C#
    // implementation: within the first slot after the Unix epoch, "previous"
    // wraps to slot 2^64 - 1 instead of throwing on -1n.
    const previousSlotBytes  = slotBytesOf(BigInt.asUintN(64, currentSlot - BigInt(1)));
    const currentSlotBytes   = slotBytesOf(currentSlot);
    const nextSlotBytes      = slotBytesOf(currentSlot + BigInt(1));

    return {
        previous:  calcTOTPSlot(previousSlotBytes, normalizedTOTPLength, normalizedAlphabet, sharedSecret, normalizedHashAlgorithm, normalizedTLSMaterial),
        current:   calcTOTPSlot(currentSlotBytes,  normalizedTOTPLength, normalizedAlphabet, sharedSecret, normalizedHashAlgorithm, normalizedTLSMaterial),
        next:      calcTOTPSlot(nextSlotBytes,     normalizedTOTPLength, normalizedAlphabet, sharedSecret, normalizedHashAlgorithm, normalizedTLSMaterial),
        remainingTime
    };

}

/**
 * Derives the TLS exporter material for channel binding from a TLS socket,
 * e.g. Node's TLSSocket: label TLS_EXPORTER_LABEL, empty context, 32 bytes
 * by default. Both ends of the connection derive the same bytes.
 *
 * Throws unless the connection is TLS v1.3 - earlier versions have no
 * exporter with the properties channel binding relies on, and a verifier
 * that cannot bind MUST reject a bound token rather than verify it as raw.
 */
export function tlsExporterMaterialOf(socket:  TLSExporter,
                                      length:  number = TLS_EXPORTER_LENGTH): Uint8Array {

    const protocol = socket.getProtocol();

    if (protocol !== "TLSv1.3")
        throw new Error(`TLS channel binding requires TLS v1.3, but the connection uses ${protocol ?? "no TLS"}!`);

    if (!Number.isInteger(length) || length <= 0)
        throw new Error("The length of the TLS exporter material must be a positive integer number of bytes!");

    // Omitting the context is the empty context under TLS v1.3 (RFC 8446
    // section 7.5), which is what the specification asks for.
    return socket.exportKeyingMaterial(length, TLS_EXPORTER_LABEL);

}

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

// The "Authorization: TOTP" scheme of the TOTP HTTP authentication
// specification (totp-http-authentication.md, section 5): RFC 9110
// auth-params,
//
//     TOTP login="<b64>", totp="<b64>"[, tlscb=true|false]
//
// Where the specification leaves a detail open, this follows the C#
// HTTPTOTPAuthentication in Vanaheimr Hermod, so that both parsers accept
// and reject the same headers.

/** The credentials of an "Authorization: TOTP" header. */
export interface TOTPCredentials {
    /** The name under which the verifier looks up the TOTP configuration - a role, not necessarily a person. */
    login:  string;
    /** The time-based one-time password. */
    totp:   string;
    /** Whether the token is bound to the TLS session (channel binding). */
    tlscb:  boolean;
}

const BASE64_ALPHABET  = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const utf8Encoder      = new TextEncoder();
// fatal: a login that is not UTF-8 is malformed, not something to repair with
// U+FFFD. ignoreBOM: the bytes are the login, a leading BOM included.
const utf8Decoder      = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

function toBase64(bytes: Uint8Array): string {

    let base64 = "";

    for (let i = 0; i < bytes.length; i += 3) {

        const chunk = (bytes[i] << 16) | ((bytes[i + 1] ?? 0) << 8) | (bytes[i + 2] ?? 0);

        base64 += BASE64_ALPHABET[(chunk >> 18) & 0x3F] +
                  BASE64_ALPHABET[(chunk >> 12) & 0x3F] +
                  (i + 1 < bytes.length ? BASE64_ALPHABET[(chunk >> 6) & 0x3F] : "=") +
                  (i + 2 < bytes.length ? BASE64_ALPHABET[ chunk       & 0x3F] : "=");

    }

    return base64;

}

// RFC 4648 section 4, padded - or unpadded, which the specification makes
// recipients accept for values sent in token form. Empty is not Base64 here:
// neither a login nor a token may be empty.
function fromBase64(base64: string): Uint8Array | null {

    const data = base64.replace(/={1,2}$/, "");

    if (data.length === 0 || data.length % 4 === 1)
        return null;

    if (data.length !== base64.length && base64.length % 4 !== 0)
        return null;

    const bytes  = new Uint8Array(Math.floor(data.length * 3 / 4));
    let   buffer = 0;
    let   bits   = 0;
    let   index  = 0;

    for (const character of data) {

        const value = BASE64_ALPHABET.indexOf(character);

        if (value < 0)
            return null;

        buffer = (buffer << 6) | value;
        bits  += 6;

        if (bits >= 8) {
            bits -= 8;
            bytes[index++] = (buffer >> bits) & 0xFF;
        }

    }

    return bytes;

}

function fromBase64UTF8(base64: string): string | null {

    const bytes = fromBase64(base64);

    if (bytes === null)
        return null;

    try {
        return utf8Decoder.decode(bytes);
    }
    catch {
        return null;
    }

}

function isWhitespace(character: string | undefined): boolean {
    return character === " " || character === "\t";
}

// A comma-separated list of auth-params (RFC 9110 section 11.2): names are
// case-insensitive, values are tokens or quoted strings with quoted-pair
// unescaping. Duplicates are ambiguous and fail closed.
function parseAuthParams(text: string): Map<string, string> {

    const parameters = new Map<string, string>();
    let   i          = 0;

    while (i < text.length) {

        while (isWhitespace(text[i]))
            i++;

        if (i >= text.length)
            break;

        const nameStart = i;

        while (i < text.length && text[i] !== "=" && text[i] !== "," && !isWhitespace(text[i]))
            i++;

        const name = text.slice(nameStart, i);

        if (name.length === 0)
            throw new Error("The TOTP authorization header contains an auth-param without a name!");

        while (isWhitespace(text[i]))
            i++;

        if (text[i] !== "=")
            throw new Error(`The auth-param '${name}' of the TOTP authorization header has no value!`);

        i++;

        while (isWhitespace(text[i]))
            i++;

        let value = "";

        if (text[i] === "\"") {

            i++;
            let closed = false;

            while (i < text.length) {

                const character = text[i++];

                if (character === "\\" && i < text.length)
                    value += text[i++];

                else if (character === "\"") {
                    closed = true;
                    break;
                }

                else
                    value += character;

            }

            if (!closed)
                throw new Error(`The quoted value of the auth-param '${name}' of the TOTP authorization header is not terminated!`);

        }
        else {

            const valueStart = i;

            while (i < text.length && text[i] !== "," && !isWhitespace(text[i]))
                i++;

            value = text.slice(valueStart, i);

            if (value.length === 0)
                throw new Error(`The auth-param '${name}' of the TOTP authorization header has no value!`);

        }

        if (parameters.has(name.toLowerCase()))
            throw new Error(`The TOTP authorization header contains the auth-param '${name}' more than once!`);

        parameters.set(name.toLowerCase(), value);

        while (isWhitespace(text[i]))
            i++;

        if (i < text.length) {

            if (text[i] !== ",")
                throw new Error("The auth-params of the TOTP authorization header must be separated by commas!");

            i++;

        }

    }

    return parameters;

}

/**
 * Builds the canonical value of an "Authorization: TOTP" header: login and
 * token as quoted Base64 strings of their UTF-8 encoding, and tlscb only
 * when it is false - true is the default.
 */
export function formatTOTPAuthorization(credentials: { login: string; totp: string; tlscb?: boolean | null }): string {

    const login = credentials.login.trim();
    const tlscb = credentials.tlscb ?? true;

    if (login.length === 0)
        throw new Error("The given login must not be null or empty!");

    if (credentials.totp.length === 0)
        throw new Error("The given TOTP must not be null or empty!");

    // The type says boolean; a JavaScript caller's "false" would otherwise
    // be truthy and claim a channel binding the token does not have.
    if (typeof tlscb !== "boolean")
        throw new Error("The given tlscb must be a boolean!");

    const header = `TOTP login="${toBase64(utf8Encoder.encode(login))}", totp="${toBase64(utf8Encoder.encode(credentials.totp))}"`;

    return tlscb
               ? header
               : `${header}, tlscb=false`;

}

/**
 * Parses the value of an "Authorization: TOTP" header. Scheme, parameter
 * names and the tlscb value are case-insensitive, parameters are unordered,
 * unknown parameters are ignored, and an absent tlscb means true.
 *
 * Throws on everything the specification calls malformed: another scheme,
 * a missing or empty login or totp, invalid Base64 or UTF-8, duplicate
 * parameters, and a tlscb that is neither true nor false.
 */
export function parseTOTPAuthorization(header: string): TOTPCredentials {

    const text      = header.trim();
    const schemeEnd = text.search(/[ \t]/);

    if (schemeEnd < 0 || text.slice(0, schemeEnd).toLowerCase() !== "totp")
        throw new Error("The given header is not a TOTP authorization header!");

    const parameters = parseAuthParams(text.slice(schemeEnd));

    const loginBase64 = parameters.get("login");
    const totpBase64  = parameters.get("totp");
    const tlscbText   = parameters.get("tlscb");

    if (loginBase64 === undefined)
        throw new Error("The TOTP authorization header has no login!");

    if (totpBase64 === undefined)
        throw new Error("The TOTP authorization header has no totp!");

    const login = fromBase64UTF8(loginBase64)?.trim();
    const totp  = fromBase64UTF8(totpBase64);

    if (login === undefined || login.length === 0)
        throw new Error("The login of the TOTP authorization header is not the Base64 of a non-empty UTF-8 text!");

    if (totp === null)
        throw new Error("The totp of the TOTP authorization header is not the Base64 of a non-empty UTF-8 text!");

    let tlscb = true;

    if (tlscbText !== undefined) {

        if      (tlscbText.toLowerCase() === "true")
            tlscb = true;

        else if (tlscbText.toLowerCase() === "false")
            tlscb = false;

        else
            throw new Error("The tlscb of the TOTP authorization header must be true or false!");

    }

    return { login, totp, tlscb };

}

/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Shared EDV-over-WAS constants: the stored-envelope content types (the portable
 * default and the preferred JOSE marker) and the envelope byte serialization.
 * Kept in one place so `WasTransport` and `EdvCodec` stay in lockstep instead
 * of each declaring their own copy.
 */
import { ENCODER } from '../internal/content.js'

/**
 * The content type used by default: plain JSON, which an unmodified WAS server
 * accepts. The stored envelope is still self-identifying by its `jwe` field.
 */
export const DEFAULT_CONTENT_TYPE = 'application/json'

/**
 * The preferred content type marking a stored EDV-encrypted document: the JWE
 * JSON Serialization media type (`application/jose+json`, RFC 7516), which is
 * the wire format the WAS spec's Encryption Scheme Registry maps the `edv`
 * scheme to. The stored envelope's `jwe` property carries the ciphertext.
 * Requires the server to register an `application/*+json` content-type parser;
 * otherwise use the default `application/json` (see `WasTransport`'s
 * `contentType` option).
 */
export const JOSE_CONTENT_TYPE = 'application/jose+json'

/**
 * Serializes an encrypted envelope to its wire bytes -- the single source of
 * the envelope encoding shared by `EdvCodec` and `WasTransport`.
 *
 * @param envelope {object}   the encrypted EDV document envelope
 * @returns {Uint8Array}
 */
export function envelopeBytes(envelope: object): Uint8Array {
  return ENCODER.encode(JSON.stringify(envelope))
}

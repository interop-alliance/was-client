/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Multibase / multicodec helpers for the EDV subpath's key-epoch machinery:
 * base58btc encode/decode (RFC-draft multibase `z` prefix, Bitcoin alphabet)
 * plus the X25519 public/private multicodec headers, and the unpadded base64url
 * codec JOSE uses. The codecs come from `@scure/base` -- the same library the
 * wider key graph (`@interop/minimal-cipher`, the key suites) encodes with, so
 * output is byte-identical across the stack.
 */
import { base58, base64urlnopad } from '@scure/base'

/**
 * The multicodec varint header for an X25519 public key (`0xec 0x01`).
 */
export const X25519_PUB_HEADER = new Uint8Array([0xec, 0x01])

/**
 * The multicodec varint header for an X25519 private key (`0x82 0x26`).
 */
export const X25519_PRIV_HEADER = new Uint8Array([0x82, 0x26])

/**
 * Encodes bytes as a base58btc string (no multibase prefix).
 *
 * @param bytes {Uint8Array}
 * @returns {string}
 */
export function base58Encode(bytes: Uint8Array): string {
  return base58.encode(bytes)
}

/**
 * Decodes a base58btc string (no multibase prefix) back to bytes.
 *
 * @param text {string}
 * @returns {Uint8Array}
 */
export function base58Decode(text: string): Uint8Array {
  return base58.decode(text)
}

/**
 * Prepends a multicodec header to `bytes` and base58btc-multibase-encodes the
 * result (the leading `z`).
 *
 * @param header {Uint8Array}   the multicodec varint header
 * @param bytes {Uint8Array}    the raw key bytes
 * @returns {string}
 */
export function multibaseEncode(header: Uint8Array, bytes: Uint8Array): string {
  const prefixed = new Uint8Array(header.length + bytes.length)
  prefixed.set(header)
  prefixed.set(bytes, header.length)
  return 'z' + base58Encode(prefixed)
}

/**
 * Decodes a base58btc multibase string (leading `z`), asserts the expected
 * multicodec header, and returns the raw key bytes with the header stripped.
 *
 * @param header {Uint8Array}   the expected multicodec varint header
 * @param text {string}         the multibase string (leading `z`)
 * @returns {Uint8Array}
 */
export function multibaseDecode(header: Uint8Array, text: string): Uint8Array {
  if (text[0] !== 'z') {
    throw new Error(`Expected a base58btc multibase value (leading "z").`)
  }
  const decoded = base58Decode(text.slice(1))
  for (let index = 0; index < header.length; index++) {
    if (decoded[index] !== header[index]) {
      throw new Error('Multibase value does not have the expected header.')
    }
  }
  return decoded.slice(header.length)
}

/**
 * Encodes bytes as unpadded base64url (JOSE form).
 *
 * @param bytes {Uint8Array}
 * @returns {string}
 */
export function base64urlEncode(bytes: Uint8Array): string {
  return base64urlnopad.encode(bytes)
}

/**
 * Decodes an unpadded base64url string (JOSE form) to bytes.
 *
 * @param text {string}
 * @returns {Uint8Array}
 */
export function base64urlDecode(text: string): Uint8Array {
  return base64urlnopad.decode(text)
}

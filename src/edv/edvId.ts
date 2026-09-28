/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * A deterministic EDV document id from 16 caller-supplied bytes, in the same
 * multibase identity layout `EdvDocumentCipher.deriveId` and
 * `EdvClientCore.generateId` use: `'z' + base58btc([0x00, 0x10, ...bytes])`
 * (identity-multihash tag `0x00`, length `0x10`). Unlike `deriveId`, which
 * hashes a JWE's ciphertext, this helper takes the 16 bytes as given, so a
 * caller that already holds a truncated digest (for example, one it derived
 * for its own indexing purposes) can mint the matching EDV id without
 * re-deriving or re-hashing anything.
 *
 * The result passes `@interop/edv-client`'s `assertDocId` and is
 * indistinguishable on the wire from a randomly generated id.
 */
import { base58 } from '@scure/base'

/**
 * Formats 16 bytes as an EDV document id.
 *
 * @param bytes {Uint8Array}   exactly 16 bytes
 * @returns {string}
 */
export function edvIdFromBytes(bytes: Uint8Array): string {
  if (!(bytes instanceof Uint8Array) || bytes.length !== 16) {
    throw new TypeError('"bytes" must be a Uint8Array of exactly 16 bytes.')
  }
  const buf = new Uint8Array(18)
  buf[0] = 0x00
  buf[1] = 0x10
  buf.set(bytes, 2)
  return 'z' + base58.encode(buf)
}

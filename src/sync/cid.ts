/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Content-addressed identifiers and Space-id derivation for cross-replica WAS
 * synchronization.
 *
 * A content id (CID) is `base64url(SHA-256(utf8(JCS-canonicalized JSON)))`, no
 * padding. Canonicalization (RFC 8785 / JCS, via `json-canonicalize`) makes the
 * id independent of key order and insignificant whitespace, so the same logical
 * document mints the same id on every replica -- the stable, replica-independent
 * primary key a content-addressed collection needs. The exact byte sequence
 * hashed is the canonical JSON STRING itself (not a re-`JSON.stringify` of it),
 * which is the contract every replica must agree on for ids to converge.
 *
 * Hashing is synchronous and pure-JS (`@noble/hashes`), so the same code runs
 * in Node, the browser, and React Native (Hermes) with identical output.
 */
import { sha256 } from '@noble/hashes/sha2.js'
import { base64urlnopad } from '@scure/base'
import { canonicalize } from 'json-canonicalize'
import type { Json } from '../types.js'

/**
 * Derives a document's content id: `base64url(SHA-256(utf8(canonicalize(doc))))`,
 * no padding. Byte-identical across replicas for the same logical document, so a
 * content-addressed resource lands on the same id everywhere it is stored.
 *
 * @param doc {Json}   the document to address
 * @returns {string}   the unpadded base64url content id (43 chars for SHA-256)
 */
export function contentCid(doc: Json): string {
  return base64urlnopad.encode(
    sha256(new TextEncoder().encode(canonicalize(doc)))
  )
}

/**
 * Named-options alias of {@link contentCid}, for callers that address a `doc`
 * by keyword. Synchronous; a caller that `await`s the result still works.
 *
 * @param options {object}
 * @param options.doc {object}   the document to address
 * @returns {string}
 */
export function cidFrom({ doc }: { doc: object }): string {
  return contentCid(doc as Json)
}

/**
 * Derives a Space id from a controller DID: `base64url(SHA-256(utf8(did)))`, no
 * padding. Byte-identical across replicas, so the same controller lands on the
 * same WAS Space wherever it connects.
 *
 * @param controllerDid {string}   the Space controller (e.g. a `did:key`)
 * @returns {string}   the unpadded base64url Space id
 */
export function deriveSpaceId(controllerDid: string): string {
  return base64urlnopad.encode(sha256(new TextEncoder().encode(controllerDid)))
}

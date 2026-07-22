/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Unit tests for the content-id and Space-id derivation. The cross-replica
 * contract is a byte-exact output, so these lock the exact strings for fixture
 * inputs AND cross-check against an independent `node:crypto` oracle (proving
 * the `@noble/hashes` + `@scure/base` path agrees with WebCrypto-style hashing).
 *
 * The canonical id is `base64url(SHA-256(utf8(canonicalize(doc))))` -- SHA-256
 * over the JCS canonical JSON STRING itself, NOT a re-`JSON.stringify` of it.
 * Every replica must agree on this exact byte sequence for ids to converge.
 */
import { describe, it, expect } from 'vitest'
import { createHash } from 'node:crypto'
import { canonicalize } from 'json-canonicalize'

import { contentCid, cidFrom, deriveSpaceId } from '../../src/sync/index.js'
import type { Json } from '../../src/sync/index.js'

/** Independent oracle: the canonical id computed on `node:crypto`. */
function oracleCid(doc: object): string {
  return createHash('sha256')
    .update(canonicalize(doc), 'utf8')
    .digest('base64url')
}

/** Independent oracle: the canonical Space id computed on `node:crypto`. */
function oracleSpaceId(did: string): string {
  return createHash('sha256').update(did, 'utf8').digest('base64url')
}

const CREDENTIAL: Json = {
  '@context': ['https://www.w3.org/2018/credentials/v1'],
  type: ['VerifiableCredential'],
  issuer: 'did:key:zIssuer',
  credentialSubject: { id: 'did:key:zHolder', name: 'Alice' }
}

describe('contentCid', () => {
  it('locks the exact content id for a fixture credential', () => {
    // A change to this string is a cross-replica break, not a refactor.
    expect(contentCid(CREDENTIAL)).toBe(
      'zu-AtxYOcJeYPk0MUJ0QkZakFAubBDb_wR5U0Z-4fI0'
    )
  })

  it('matches an independent node:crypto oracle byte-for-byte', () => {
    expect(contentCid(CREDENTIAL)).toBe(oracleCid(CREDENTIAL))
  })

  it('hashes the canonical string itself, not a re-stringify of it', () => {
    // Guards against the double-encode variant
    // (`SHA-256(JSON.stringify(canonicalize(doc)))`), which is a DIFFERENT,
    // cross-replica-incompatible byte sequence.
    const doubleEncoded = createHash('sha256')
      .update(JSON.stringify(canonicalize(CREDENTIAL)), 'utf8')
      .digest('base64url')
    expect(contentCid(CREDENTIAL)).not.toBe(doubleEncoded)
  })

  it('is key-order independent (canonicalized)', () => {
    expect(contentCid({ a: 1, b: 'x' })).toBe(contentCid({ b: 'x', a: 1 }))
  })

  it('changes when the content changes', () => {
    expect(contentCid({ a: 1 })).not.toBe(contentCid({ a: 2 }))
  })

  it('is unpadded base64url (43 chars for SHA-256)', () => {
    expect(contentCid(CREDENTIAL)).toMatch(/^[A-Za-z0-9_-]{43}$/)
  })

  it('cidFrom is the named-options alias of contentCid', () => {
    expect(cidFrom({ doc: CREDENTIAL })).toBe(contentCid(CREDENTIAL))
  })
})

describe('deriveSpaceId', () => {
  const DID = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK'

  it('locks the exact Space id for a fixture DID', () => {
    expect(deriveSpaceId(DID)).toBe(
      'hVH0BOz-ZAPC_pYKsmfNjHSpoHAWKM4ksXU5RvLrsW4'
    )
  })

  it('matches base64url(SHA-256(utf8(did))) computed by an independent impl', () => {
    expect(deriveSpaceId(DID)).toBe(oracleSpaceId(DID))
  })

  it('is deterministic and did-sensitive', () => {
    expect(deriveSpaceId('did:key:a')).toBe(deriveSpaceId('did:key:a'))
    expect(deriveSpaceId('did:key:a')).not.toBe(deriveSpaceId('did:key:b'))
  })
})

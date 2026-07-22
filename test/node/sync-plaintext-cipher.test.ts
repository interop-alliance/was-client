/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Unit tests for the plaintext (identity) DocCipher and the EDV-envelope
 * predicate. The plaintext cipher is the seam for a content-addressed plaintext
 * collection: `encrypt` is the identity transform keyed by the content id,
 * `decrypt` returns the body unchanged, and `encryptUpdate` throws.
 */
import { describe, it, expect } from 'vitest'

import {
  contentCid,
  createPlaintextDocCipher,
  isEncryptedEnvelope
} from '../../src/sync/index.js'
import type { Json } from '../../src/sync/index.js'

const CREDENTIAL: Json = {
  '@context': ['https://www.w3.org/2018/credentials/v1'],
  type: ['VerifiableCredential'],
  issuer: 'did:key:zIssuer',
  credentialSubject: { id: 'did:key:zHolder', name: 'Alice' }
}

describe('createPlaintextDocCipher', () => {
  const cipher = createPlaintextDocCipher({
    collectionId: 'public-credentials'
  })

  it('encrypt is identity with a content-id key', async () => {
    const { id, envelope, epoch } = await cipher.encrypt({ data: CREDENTIAL })
    expect(id).toBe(contentCid(CREDENTIAL))
    expect(envelope).toEqual(CREDENTIAL)
    expect(epoch).toBeUndefined()
  })

  it('decrypt is identity', async () => {
    expect(await cipher.decrypt({ envelope: CREDENTIAL })).toEqual(CREDENTIAL)
  })

  it('round-trips through encrypt then decrypt', async () => {
    const { envelope } = await cipher.encrypt({ data: CREDENTIAL })
    expect(await cipher.decrypt({ envelope })).toEqual(CREDENTIAL)
  })

  it('encryptUpdate throws (content-addressed docs never update in place)', async () => {
    await expect(
      cipher.encryptUpdate!({ id: 'x', data: CREDENTIAL, current: CREDENTIAL })
    ).rejects.toThrow(/public-credentials.*never updated in place/s)
  })
})

describe('isEncryptedEnvelope', () => {
  it('is true for a body carrying an object jwe', () => {
    expect(isEncryptedEnvelope({ id: 'x', sequence: 0, jwe: {} })).toBe(true)
  })

  it('is false for a plaintext document', () => {
    expect(isEncryptedEnvelope(CREDENTIAL)).toBe(false)
  })

  it('is false for undefined, null, and non-objects', () => {
    expect(isEncryptedEnvelope(undefined)).toBe(false)
    expect(isEncryptedEnvelope(null)).toBe(false)
    expect(isEncryptedEnvelope('str' as unknown as Json)).toBe(false)
  })

  it('is false when jwe is present but not an object', () => {
    expect(isEncryptedEnvelope({ jwe: 'nope' })).toBe(false)
    expect(isEncryptedEnvelope({ jwe: null })).toBe(false)
  })
})

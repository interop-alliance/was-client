/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Unit tests for the plaintext (identity) DocCipher and the EDV-envelope
 * predicate. The plaintext cipher is the seam for a content-addressed plaintext
 * collection: `encrypt` is the identity transform keyed by the content id,
 * `decrypt` returns the body unchanged once its content id matches the id it
 * was read under, and `encryptUpdate` throws.
 */
import { describe, it, expect } from 'vitest'

import {
  contentCid,
  createPlaintextDocCipher,
  IntegrityError,
  isEncryptedEnvelope,
  isIntegrityError
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
    expect(
      await cipher.decrypt({ id: contentCid(CREDENTIAL), envelope: CREDENTIAL })
    ).toEqual(CREDENTIAL)
  })

  it('round-trips through encrypt then decrypt', async () => {
    const { id, envelope } = await cipher.encrypt({ data: CREDENTIAL })
    expect(await cipher.decrypt({ id, envelope })).toEqual(CREDENTIAL)
  })

  it('decrypt refuses a document stored under an id it does not hash to', async () => {
    const { id } = await cipher.encrypt({ data: CREDENTIAL })
    const tampered: Json = {
      ...(CREDENTIAL as Record<string, Json>),
      issuer: 'did:key:zMallory'
    }
    const refusal = await cipher
      .decrypt({ id, envelope: tampered })
      .then(() => null)
      .catch((err: unknown) => err)
    expect(refusal).toBeInstanceOf(IntegrityError)
    expect(isIntegrityError(refusal)).toBe(true)
  })

  it('decrypt refuses an authentic document presented under another id', async () => {
    const other = await cipher.encrypt({ data: { note: 'other' } })
    await expect(
      cipher.decrypt({ id: other.id, envelope: CREDENTIAL })
    ).rejects.toThrow(IntegrityError)
  })

  it('decrypt refuses a call without a resource id', async () => {
    const refusal = await cipher
      .decrypt({ envelope: CREDENTIAL } as unknown as {
        id: string
        envelope: Json
      })
      .then(() => null)
      .catch((err: unknown) => err)
    expect((refusal as Error).name).toBe('ValidationError')
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

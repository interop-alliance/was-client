/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Unit tests for the EDV `DocCipher` wrapper (`createEdvDocCipher`). Uses real
 * X25519 keys and the real cipher (no network) to prove the seam genuinely
 * encrypts/decrypts: `encrypt` produces an opaque EDV envelope (an object `jwe`,
 * no plaintext leak) keyed by a content-derived id, `decrypt` round-trips it
 * back, and the mutable-collection `encryptUpdate` path re-encrypts under a
 * caller id. The multi-recipient (key-epoch) codec path is a thin pass-through
 * to `codecFor` and is covered by the epoch codec tests; here we cover the
 * wrapper's single-recipient behavior, `ownerRecipient`, and the exports.
 */
import { describe, it, expect } from 'vitest'
import { X25519KeyAgreementKey2020 } from '@interop/x25519-key-agreement-key'
import type {
  IKeyAgreementKey,
  IKeyResolver
} from '@interop/data-integrity-core'

import {
  createEdvDocCipher,
  ownerRecipient,
  UnknownEpochError,
  isEncryptedEnvelope
} from '../../src/edv/index.js'
import type { Json } from '../../src/sync/index.js'

/** A fresh real X25519 key-agreement key plus a resolver that returns it. */
async function makeKeys(): Promise<{
  keyAgreementKey: IKeyAgreementKey
  keyResolver: IKeyResolver
}> {
  const kak = await X25519KeyAgreementKey2020.generate({
    controller: 'did:example:alice'
  })
  const keyResolver = (async ({ id }: { id?: string }) => {
    if (id !== kak.id) {
      throw new Error(`Unknown key id "${id}".`)
    }
    return {
      id: kak.id,
      type: kak.type,
      publicKeyMultibase: kak.publicKeyMultibase
    }
  }) as unknown as IKeyResolver
  return { keyAgreementKey: kak as unknown as IKeyAgreementKey, keyResolver }
}

const DOC: Json = { greeting: 'hello', subject: { name: 'Alice', n: 42 } }

describe('createEdvDocCipher (single-recipient, content derivation)', () => {
  it('encrypts to an opaque envelope keyed by a content-derived id', async () => {
    const keys = await makeKeys()
    const cipher = await createEdvDocCipher({
      ...keys,
      collectionId: 'private-credentials'
    })

    const { id, envelope, epoch } = await cipher.encrypt({ data: DOC })
    expect(typeof id).toBe('string')
    expect(id.length).toBeGreaterThan(0)
    expect(epoch).toBeUndefined() // single-key: no epoch stamp
    expect(isEncryptedEnvelope(envelope)).toBe(true)
    // No plaintext leak in the stored envelope.
    expect(JSON.stringify(envelope)).not.toContain('Alice')
  })

  it('round-trips encrypt then decrypt', async () => {
    const keys = await makeKeys()
    const cipher = await createEdvDocCipher({
      ...keys,
      collectionId: 'private-credentials'
    })
    const { envelope } = await cipher.encrypt({ data: DOC })
    expect(await cipher.decrypt({ envelope })).toEqual(DOC)
  })
})

describe('createEdvDocCipher (random derivation, encryptUpdate)', () => {
  it('re-encrypts a mutable head document under its existing id', async () => {
    const keys = await makeKeys()
    const cipher = await createEdvDocCipher({
      ...keys,
      collectionId: 'wallet-head',
      idDerivation: 'random'
    })

    const first = await cipher.encrypt({ data: { v: 1 } })
    const updated = await cipher.encryptUpdate!({
      id: first.id,
      data: { v: 2 },
      current: first.envelope
    })

    expect(updated.id).toBe(first.id)
    expect(isEncryptedEnvelope(updated.envelope)).toBe(true)
    expect(await cipher.decrypt({ envelope: updated.envelope })).toEqual({
      v: 2
    })
    // The re-encryption advanced the envelope sequence from the prior one.
    const seqOf = (env: Json) => (env as { sequence?: number }).sequence
    expect(seqOf(updated.envelope)).toBe((seqOf(first.envelope) ?? 0) + 1)
  })
})

describe('ownerRecipient', () => {
  it('builds a RecipientPublicKey from a key-agreement key', async () => {
    const { keyAgreementKey } = await makeKeys()
    const recipient = ownerRecipient({ keyAgreementKey })
    expect(recipient.id).toBe(keyAgreementKey.id)
    expect(typeof recipient.publicKeyMultibase).toBe('string')
  })

  it('throws when the key lacks a public multibase', () => {
    expect(() =>
      ownerRecipient({
        keyAgreementKey: { id: 'did:key:zX#kak' } as unknown as IKeyAgreementKey
      })
    ).toThrow(/publicKeyMultibase/)
  })
})

describe('UnknownEpochError', () => {
  it('is an Error naming the collection and the unroutable kids', () => {
    const err = new UnknownEpochError({
      collectionId: 'private-credentials',
      kids: ['did:key:zEpoch#k']
    })
    expect(err).toBeInstanceOf(Error)
    expect(err.name).toBe('UnknownEpochError')
    expect(err.message).toContain('private-credentials')
    expect(err.message).toContain('did:key:zEpoch#k')
  })
})

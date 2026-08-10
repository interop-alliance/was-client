/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Unit tests for the EDV `DocCipher` wrapper (`createEdvDocCipher`). Uses real
 * X25519 keys and the real cipher (no network) to prove the seam genuinely
 * encrypts/decrypts: `encrypt` produces an opaque EDV envelope (an object `jwe`,
 * no plaintext leak) keyed by a content-derived id and stamped with the
 * descriptor's current key epoch, `decrypt` round-trips it back, and the
 * mutable-collection `encryptUpdate` path re-encrypts under a caller id.
 *
 * Every encrypted collection carries a key-epoch roster from birth, so the
 * `encryption` descriptor is required and every cipher here is built over one:
 * a descriptor without epochs is refused fail-closed, and an envelope sealed
 * straight to the reader's own key-agreement key is unroutable. Also covers
 * `ownerRecipient` and the exports.
 */
import { describe, it, expect } from 'vitest'
import { X25519KeyAgreementKey2020 } from '@interop/x25519-key-agreement-key'
import { EdvClientCore } from '@interop/edv-client'
import type {
  IKeyAgreementKey,
  IKeyResolver
} from '@interop/data-integrity-core'

import { EncryptionError } from '../../src/index.js'
import {
  createEdvDocCipher,
  ownerRecipient,
  UnknownEpochError,
  isEncryptedEnvelope
} from '../../src/edv/index.js'
import { mintEpoch, wrapEpochSecret } from '../../src/edv/epochCrypto.js'
import type {
  CollectionEncryption,
  CollectionEncryptionRecipient
} from '../../src/index.js'
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

/**
 * Builds the single-epoch `edv` descriptor an encrypted collection carries from
 * birth, wrapping one freshly-minted epoch key to every given reader.
 *
 * @param readers {IKeyAgreementKey[]}   the recipients of epoch zero
 * @returns {Promise<CollectionEncryption>}
 */
async function epochDescriptorFor(
  readers: IKeyAgreementKey[]
): Promise<CollectionEncryption> {
  const { epochId, secret } = await mintEpoch()
  const recipients: CollectionEncryptionRecipient[] = []
  for (const keyAgreementKey of readers) {
    recipients.push(
      await wrapEpochSecret({
        epochSecret: secret,
        recipient: ownerRecipient({ keyAgreementKey })
      })
    )
  }
  const encryption: CollectionEncryption = {
    scheme: 'edv',
    epochs: [{ id: epochId, recipients }],
    currentEpoch: epochId
  }
  return encryption
}

/**
 * A fresh reader plus the single-epoch descriptor it is recipient zero of --
 * the whole input every cipher in this file is built from.
 *
 * @returns {Promise<{ keyAgreementKey: IKeyAgreementKey;
 *   keyResolver: IKeyResolver; encryption: CollectionEncryption }>}
 */
async function makeReaderWithDescriptor(): Promise<{
  keyAgreementKey: IKeyAgreementKey
  keyResolver: IKeyResolver
  encryption: CollectionEncryption
}> {
  const keys = await makeKeys()
  return {
    ...keys,
    encryption: await epochDescriptorFor([keys.keyAgreementKey])
  }
}

const DOC: Json = { greeting: 'hello', subject: { name: 'Alice', n: 42 } }

describe('createEdvDocCipher (epoch roster, content derivation)', () => {
  it('encrypts to an opaque envelope keyed by a content-derived id', async () => {
    const { encryption, ...keys } = await makeReaderWithDescriptor()
    const cipher = await createEdvDocCipher({
      ...keys,
      collectionId: 'private-credentials',
      encryption
    })

    const { id, envelope, epoch } = await cipher.encrypt({ data: DOC })
    expect(typeof id).toBe('string')
    expect(id.length).toBeGreaterThan(0)
    // Every write seals to the current epoch key and reports which epoch.
    expect(epoch).toBe(encryption.currentEpoch)
    expect(isEncryptedEnvelope(envelope)).toBe(true)
    // No plaintext leak in the stored envelope.
    expect(JSON.stringify(envelope)).not.toContain('Alice')
  })

  it('round-trips encrypt then decrypt', async () => {
    const { encryption, ...keys } = await makeReaderWithDescriptor()
    const cipher = await createEdvDocCipher({
      ...keys,
      collectionId: 'private-credentials',
      encryption
    })
    const { envelope } = await cipher.encrypt({ data: DOC })
    expect(await cipher.decrypt({ envelope })).toEqual(DOC)
  })

  it('throws UnknownEpochError for an envelope from another collection epoch', async () => {
    // The codec owns decrypt routing: an envelope whose recipient kids match
    // none of the reader's resolved epoch keys is unroutable, the signal that
    // the reader's cached descriptor does not cover the writer's epoch.
    const aliceKeys = await makeReaderWithDescriptor()
    const malloryKeys = await makeReaderWithDescriptor()
    const alice = await createEdvDocCipher({
      keyAgreementKey: aliceKeys.keyAgreementKey,
      keyResolver: aliceKeys.keyResolver,
      collectionId: 'private-credentials',
      encryption: aliceKeys.encryption
    })
    const mallory = await createEdvDocCipher({
      keyAgreementKey: malloryKeys.keyAgreementKey,
      keyResolver: malloryKeys.keyResolver,
      collectionId: 'private-credentials',
      encryption: malloryKeys.encryption
    })
    const { envelope } = await alice.encrypt({ data: DOC })
    await expect(mallory.decrypt({ envelope })).rejects.toThrow(
      UnknownEpochError
    )
  })
})

describe('createEdvDocCipher (epoch-from-birth refusals)', () => {
  it('refuses a descriptor that carries no key epochs', async () => {
    const keys = await makeKeys()
    await expect(
      createEdvDocCipher({
        ...keys,
        collectionId: 'private-credentials',
        encryption: { scheme: 'edv' }
      })
    ).rejects.toBeInstanceOf(EncryptionError)
  })

  it('refuses an envelope sealed straight to the reader own key', async () => {
    const owner = await makeKeys()
    // An envelope sealed directly to the owner's own key-agreement key rather
    // than to an epoch key. The reader's own key is never a read candidate, so
    // such an envelope is unroutable even for the very reader it was sealed to.
    const edv = new EdvClientCore({
      keyAgreementKey: owner.keyAgreementKey,
      keyResolver: owner.keyResolver
    })
    const sealedToOwnKey = await edv.documentCipher.encrypt({
      doc: {
        id: 'z' + 'A'.repeat(21),
        content: DOC as Record<string, unknown>,
        meta: { contentType: 'application/json' }
      },
      recipients: edv.documentCipher.createDefaultRecipients(
        owner.keyAgreementKey
      ),
      keyResolver: owner.keyResolver,
      update: false
    })

    const encryption = await epochDescriptorFor([owner.keyAgreementKey])
    const cipher = await createEdvDocCipher({
      ...owner,
      collectionId: 'private-credentials',
      encryption
    })
    await expect(
      cipher.decrypt({ envelope: sealedToOwnKey as unknown as Json })
    ).rejects.toThrow(UnknownEpochError)

    // Writes under the epoch roster round-trip as usual.
    const fresh = await cipher.encrypt({ data: DOC })
    expect(fresh.epoch).toBe(encryption.currentEpoch)
    expect(await cipher.decrypt({ envelope: fresh.envelope })).toEqual(DOC)
  })
})

describe('createEdvDocCipher (random derivation, encryptUpdate)', () => {
  it('re-encrypts a mutable head document under its existing id', async () => {
    const { encryption, ...keys } = await makeReaderWithDescriptor()
    const cipher = await createEdvDocCipher({
      ...keys,
      collectionId: 'wallet-head',
      idDerivation: 'random',
      encryption
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

  it('updates in place under a pre-existing foreign (uuid) id', async () => {
    // A head document authored by a client that minted its own row id (e.g. a
    // legacy freewallet uuidv7 contact): the id is already the server resource
    // id, so the update path takes it verbatim instead of asserting the EDV
    // multibase format (which only guards creates against URL leaks).
    const { encryption, ...keys } = await makeReaderWithDescriptor()
    const cipher = await createEdvDocCipher({
      ...keys,
      collectionId: 'contacts',
      idDerivation: 'random',
      encryption
    })

    const uuid = '01890a5d-ac96-774b-bcce-b302099a8057'
    const { envelope } = await cipher.encrypt({ data: { v: 1 } })
    const updated = await cipher.encryptUpdate!({
      id: uuid,
      data: { v: 2 },
      current: envelope
    })
    expect(updated.id).toBe(uuid)
    expect(await cipher.decrypt({ envelope: updated.envelope })).toEqual({
      v: 2
    })
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
    expect(err.message).toContain('match no key epoch this reader resolved')
  })
})

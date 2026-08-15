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

import { EncryptionError, ValidationError } from '../../src/index.js'
import {
  createEdvDocCipher,
  createEdvEncryptOnlyDocCipher,
  createEdvEncryption,
  ownerRecipient,
  EncryptOnlyCipherError,
  UnknownEpochError,
  isEncryptedEnvelope
} from '../../src/edv/index.js'
import { mintEpoch, wrapEpochSecret } from '../../src/edv/epochCrypto.js'
import { mintHmacKey } from '../../src/edv/hmacKey.js'
import type { SingleWriteCodec } from '../helpers/codec.js'
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

describe('createEdvEncryptOnlyDocCipher', () => {
  it('seals to the current epoch from the descriptor alone; a recipient opens it', async () => {
    const { encryption, ...keys } = await makeReaderWithDescriptor()
    // The writer holds nothing but the descriptor -- no key-agreement secret.
    const writer = await createEdvEncryptOnlyDocCipher({
      collectionId: 'keyring',
      encryption
    })
    const { id, envelope, epoch } = await writer.encrypt({ data: DOC })
    expect(typeof id).toBe('string')
    expect(epoch).toBe(encryption.currentEpoch)
    expect(isEncryptedEnvelope(envelope)).toBe(true)
    expect(JSON.stringify(envelope)).not.toContain('Alice')

    // The envelope is shaped exactly like a multi-recipient build's write, so
    // an ordinary reading cipher held by a roster recipient opens it.
    const reader = await createEdvDocCipher({
      ...keys,
      collectionId: 'keyring',
      encryption
    })
    expect(await reader.decrypt({ envelope })).toEqual(DOC)
  })

  it('refuses decrypt with the typed encrypt-only error', async () => {
    const { encryption } = await makeReaderWithDescriptor()
    const writer = await createEdvEncryptOnlyDocCipher({
      collectionId: 'keyring',
      encryption
    })
    const { envelope } = await writer.encrypt({ data: DOC })
    const refusal = await writer
      .decrypt({ envelope })
      .then(() => null)
      .catch((err: unknown) => err as Error)
    expect(refusal).toBeInstanceOf(EncryptOnlyCipherError)
    // The name is the stable dispatch contract across package copies.
    expect(refusal!.name).toBe('EncryptOnlyCipherError')
  })

  it('refuses a descriptor that carries no key epochs', async () => {
    await expect(
      createEdvEncryptOnlyDocCipher({
        collectionId: 'keyring',
        encryption: { scheme: 'edv' }
      })
    ).rejects.toBeInstanceOf(EncryptionError)
  })

  it('falls back to the last listed epoch when currentEpoch is unlisted', async () => {
    // A two-epoch roster, so "last listed" is distinguishable from "first
    // listed": a regression to epochs[0] would seal to the rotated-out epoch
    // and fail the assertion below.
    const { encryption, ...keys } = await makeReaderWithDescriptor()
    const rotated = await epochDescriptorFor([keys.keyAgreementKey])
    const lastEpochId = rotated.epochs![0]!.id
    const multi: CollectionEncryption = {
      scheme: 'edv',
      epochs: [...encryption.epochs!, ...rotated.epochs!],
      // Set, but naming an epoch the roster does not list.
      currentEpoch: 'did:key:z6LSoWfUS2Fk8Gv6ZaJZeXm895iS9DWQZ2bPNBPmvv9EnLmz'
    }
    const writer = await createEdvEncryptOnlyDocCipher({
      collectionId: 'keyring',
      encryption: multi
    })
    const { envelope, epoch } = await writer.encrypt({ data: DOC })
    expect(epoch).toBe(lastEpochId)
    expect(epoch).not.toBe(encryption.epochs![0]!.id)
    const reader = await createEdvDocCipher({
      ...keys,
      collectionId: 'keyring',
      encryption: { ...multi, currentEpoch: lastEpochId }
    })
    expect(await reader.decrypt({ envelope })).toEqual(DOC)
  })

  it('falls back to the last listed epoch when currentEpoch is absent', async () => {
    const { encryption, ...keys } = await makeReaderWithDescriptor()
    const { currentEpoch: _currentEpoch, ...absent } = encryption
    const writer = await createEdvEncryptOnlyDocCipher({
      collectionId: 'keyring',
      encryption: absent
    })
    const { envelope, epoch } = await writer.encrypt({ data: DOC })
    expect(epoch).toBe(encryption.epochs![0]!.id)
    const reader = await createEdvDocCipher({
      ...keys,
      collectionId: 'keyring',
      encryption
    })
    expect(await reader.decrypt({ envelope })).toEqual(DOC)
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

  it('refuses a binary payload over the single-document threshold', async () => {
    // Reachable only from an untyped caller: `encrypt` is typed for JSON, but
    // JS can hand it a large binary value, which the codec answers with a
    // multi-request chunked plan (a document plus chunk resources on a server).
    // There is no single envelope to store in a replica, so the seam refuses
    // the payload by name instead of reporting a missing envelope body.
    const { encryption, ...keys } = await makeReaderWithDescriptor()
    const cipher = await createEdvDocCipher({
      ...keys,
      collectionId: 'blobs',
      idDerivation: 'random',
      encryption
    })
    const oversize = new Uint8Array(600 * 1024)
    await expect(
      cipher.encrypt({ data: oversize as unknown as Json })
    ).rejects.toBeInstanceOf(ValidationError)
  })
})

/**
 * A reader plus a descriptor that also carries a blinded-index HMAC key -- the
 * searchable-collection fixture the schema-install tests are built from. The
 * blinding key is distributed exactly like an epoch key, so the same wrap
 * builds it.
 *
 * @returns {Promise<{ keyAgreementKey: IKeyAgreementKey;
 *   keyResolver: IKeyResolver; encryption: CollectionEncryption }>}
 */
async function makeIndexableReader(): Promise<{
  keyAgreementKey: IKeyAgreementKey
  keyResolver: IKeyResolver
  encryption: CollectionEncryption
}> {
  const keys = await makeKeys()
  const epochs = await epochDescriptorFor([keys.keyAgreementKey])
  const hmac = await mintHmacKey()
  return {
    ...keys,
    encryption: {
      ...epochs,
      hmac: {
        id: hmac.id,
        type: hmac.type,
        recipients: [
          await wrapEpochSecret({
            epochSecret: hmac.secret,
            recipient: ownerRecipient({ keyAgreementKey: keys.keyAgreementKey })
          })
        ]
      }
    }
  }
}

/**
 * The direct (Collection-handle) codec for the same collection, built straight
 * through the public provider. The sync cipher must emit the very tokens this
 * one does.
 *
 * @param options {object}
 * @param options.collectionId {string}
 * @param options.encryption {CollectionEncryption}
 * @param options.keys {object}   the reader's key material
 * @returns {Promise<SingleWriteCodec>}
 */
async function directCodecFor({
  collectionId,
  encryption,
  keys
}: {
  collectionId: string
  encryption: CollectionEncryption
  keys: { keyAgreementKey: IKeyAgreementKey; keyResolver: IKeyResolver }
}): Promise<SingleWriteCodec> {
  const provider = createEdvEncryption({ resolveKeys: async () => keys })
  const codec = await provider.codecFor({
    spaceId: 's',
    collectionId,
    scheme: 'edv',
    encryption
  })
  if (!codec) {
    throw new Error('expected a codec')
  }
  return codec as SingleWriteCodec
}

/** One entry of an envelope's blinded index list. */
interface IndexedEntry {
  hmac: { id: string }
  attributes: Array<{ name: string; value: string }>
}

/**
 * The blinded index entries of a stored envelope.
 *
 * @param envelope {Json}
 * @returns {IndexedEntry[]}
 */
function indexedOf(envelope: Json): IndexedEntry[] {
  return (envelope as { indexed?: IndexedEntry[] }).indexed ?? []
}

const SCHEMA = {
  revision: 1,
  indexes: [{ attribute: 'content.type', addedIn: 1 }]
}

describe('createEdvDocCipher (blinded index schema)', () => {
  it('emits the same tokens a direct-path write does', async () => {
    const { encryption, ...keys } = await makeIndexableReader()
    // The direct path: apply the schema, persist it in the collection metadata
    // envelope (no id -- a Collection-level write, bound to `was.collection`),
    // and capture the tokens an ordinary write stores.
    const direct = await directCodecFor({
      collectionId: 'c',
      encryption,
      keys
    })
    direct.indexing!.applySchema(SCHEMA)
    const { custom } = await direct.encodeMeta({
      custom: { indexSchema: SCHEMA }
    })
    const encoded = await direct.encode({ data: { type: 'note' } })
    const expected = indexedOf(
      JSON.parse(new TextDecoder().decode(encoded.body as Uint8Array)) as Json
    )

    // The sync path: the same schema, discovered from the same metadata.
    const cipher = await createEdvDocCipher({
      ...keys,
      collectionId: 'c',
      encryption,
      meta: { custom }
    })
    const { envelope } = await cipher.encrypt({ data: { type: 'note' } })
    const indexed = indexedOf(envelope)
    expect(indexed).toHaveLength(1)
    expect(indexed[0]!.hmac.id).toBe(encryption.hmac!.id)
    expect(indexed[0]!.attributes).toEqual(expected[0]!.attributes)
    // Blinded, so neither the attribute nor the value is in the clear.
    expect(JSON.stringify(indexed)).not.toContain('content.type')
    expect(JSON.stringify(indexed)).not.toContain('note')
  })

  it('emits no index entries when no metadata is supplied', async () => {
    // Backward compatible: an offline replica that holds no collection
    // metadata writes exactly what it wrote before.
    const { encryption, ...keys } = await makeIndexableReader()
    const cipher = await createEdvDocCipher({
      ...keys,
      collectionId: 'c',
      encryption
    })
    const { envelope } = await cipher.encrypt({ data: { type: 'note' } })
    expect(indexedOf(envelope)).toEqual([])
  })

  it('installs the schema after the fact via applyMeta', async () => {
    const { encryption, ...keys } = await makeIndexableReader()
    const direct = await directCodecFor({ collectionId: 'c', encryption, keys })
    const { custom } = await direct.encodeMeta({
      custom: { indexSchema: SCHEMA }
    })

    const cipher = await createEdvDocCipher({
      ...keys,
      collectionId: 'c',
      encryption
    })
    const before = await cipher.encrypt({ data: { type: 'note' } })
    expect(indexedOf(before.envelope)).toEqual([])

    // The mid-session declaration case: the replica's copy of the collection
    // metadata changed, so the cipher re-reads the schema from it.
    const schema = await cipher.applyMeta({ custom })
    expect(schema.revision).toBe(1)
    expect(schema.indexes).toHaveLength(1)
    const after = await cipher.encrypt({ data: { type: 'note' } })
    expect(indexedOf(after.envelope)).toHaveLength(1)
  })

  it('indexes the mutable encryptUpdate path too', async () => {
    const { encryption, ...keys } = await makeIndexableReader()
    const direct = await directCodecFor({ collectionId: 'c', encryption, keys })
    const { custom } = await direct.encodeMeta({
      custom: { indexSchema: SCHEMA }
    })
    const cipher = await createEdvDocCipher({
      ...keys,
      collectionId: 'c',
      idDerivation: 'random',
      encryption,
      meta: { custom }
    })

    const first = await cipher.encrypt({ data: { type: 'note' } })
    const updated = await cipher.encryptUpdate!({
      id: first.id,
      data: { type: 'task' },
      current: first.envelope
    })
    expect(indexedOf(updated.envelope)).toHaveLength(1)
  })

  it('is a no-op on a collection with no blinded-index key', async () => {
    // No `hmac` on the descriptor means no search capability at all, so a
    // caller may call applyMeta unconditionally.
    const { encryption, ...keys } = await makeReaderWithDescriptor()
    const cipher = await createEdvDocCipher({
      ...keys,
      collectionId: 'private-credentials',
      encryption
    })
    await expect(cipher.applyMeta({ custom: undefined })).resolves.toEqual({
      revision: 0,
      indexes: []
    })
    const { envelope } = await cipher.encrypt({ data: DOC })
    expect(await cipher.decrypt({ envelope })).toEqual(DOC)
  })

  it('refuses a metadata envelope bound to another collection', async () => {
    const { encryption, ...keys } = await makeIndexableReader()
    const foreign = await directCodecFor({
      collectionId: 'other',
      encryption,
      keys
    })
    const { custom } = await foreign.encodeMeta({
      custom: { indexSchema: SCHEMA }
    })
    const cipher = await createEdvDocCipher({
      ...keys,
      collectionId: 'c',
      encryption
    })
    await expect(cipher.applyMeta({ custom })).rejects.toThrow(
      /bound to collection "other"/
    )
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
    expect(err.message).toContain(
      'not on the Collection Description this reader holds'
    )
  })
})

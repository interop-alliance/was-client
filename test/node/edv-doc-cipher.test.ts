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
import { describe, it, expect, vi } from 'vitest'
import { X25519KeyAgreementKey2020 } from '@interop/x25519-key-agreement-key'
import { EdvClientCore } from '@interop/edv-client'
import type {
  IEDVChunk,
  IKeyAgreementKey,
  IKeyResolver
} from '@interop/data-integrity-core'

import {
  EncryptionError,
  IntegrityError,
  NotFoundError,
  NotSupportedError,
  ValidationError
} from '../../src/index.js'
import type {
  ChunkedWrite,
  CodecRequestContext,
  EncodedWrite,
  ResourceCodec
} from '../../src/index.js'
import { blobBytes } from '../../src/edv/core.js'
import { edvIdFromBytes } from '../../src/edv/cipher.js'
import type { ChunkSource, EdvDocCipher } from '../../src/edv/core.js'
import { EdvCodec } from '../../src/edv/EdvCodec.js'
import {
  createEdvDocCipher,
  createEdvEncryptOnlyDocCipher,
  createEdvEncryption,
  createRefreshingEdvDocCipher,
  ownerRecipient,
  EncryptOnlyCipherError,
  KeyUnwrapError,
  UnknownEpochError,
  isEncryptedEnvelope
} from '../../src/edv/index.js'
import { mintEpoch, wrapEpochSecret } from '../../src/edv/epochCrypto.js'
import { mintHmacKey } from '../../src/edv/hmacKey.js'
import type { SingleWriteCodec } from '../helpers/codec.js'
import { memoryBackend } from '../helpers/codec.js'
import type {
  CollectionEncryption,
  CollectionEncryptionRecipient
} from '../../src/index.js'
import { isIntegrityError } from '../../src/sync/index.js'
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

  it('never forces the codec wire body on a local-replica encrypt', async () => {
    const { encryption, ...keys } = await makeReaderWithDescriptor()
    const cipher = await createEdvDocCipher({
      ...keys,
      collectionId: 'private-credentials',
      encryption
    })

    // The replica path takes the codec's object-form `envelope`, so it must
    // leave the lazy `body` getter -- a full stringify plus UTF-8 encode of the
    // envelope -- unforced.
    let forced = false
    const encode = EdvCodec.prototype.encode
    const spy = vi
      .spyOn(EdvCodec.prototype, 'encode')
      .mockImplementation(async function (this: EdvCodec, ...encodeArgs) {
        const encoded = (await encode.apply(this, encodeArgs)) as EncodedWrite
        // Replace the descriptor in place: spreading `encoded` would read the
        // lazy getter during setup, serializing the body before the test runs.
        Object.defineProperty(encoded, 'body', {
          configurable: true,
          enumerable: true,
          get() {
            forced = true
            return undefined
          }
        })
        return encoded
      })
    try {
      const { envelope } = await cipher.encrypt({ data: DOC })
      expect(isEncryptedEnvelope(envelope)).toBe(true)
      expect(forced).toBe(false)
    } finally {
      spy.mockRestore()
    }
  })

  it('round-trips encrypt then decrypt', async () => {
    const { encryption, ...keys } = await makeReaderWithDescriptor()
    const cipher = await createEdvDocCipher({
      ...keys,
      collectionId: 'private-credentials',
      encryption
    })
    const { id, envelope } = await cipher.encrypt({ data: DOC })
    expect(await cipher.decrypt({ id, envelope })).toEqual(DOC)
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
    const { id, envelope } = await alice.encrypt({ data: DOC })
    await expect(mallory.decrypt({ id, envelope })).rejects.toThrow(
      UnknownEpochError
    )
  })
})

describe('createEdvDocCipher (envelope-to-resource binding)', () => {
  for (const idDerivation of ['content', 'random'] as const) {
    it(`refuses an authentic envelope presented under another id (${idDerivation})`, async () => {
      // A replication read hands the cipher the feed row id. A server serving
      // resource A's authentic envelope in row B must not decrypt as B: the
      // content-derived id re-derives from the ciphertext, and a random id is
      // the AEAD-bound `was.resource`.
      const { encryption, ...keys } = await makeReaderWithDescriptor()
      const cipher = await createEdvDocCipher({
        ...keys,
        collectionId: 'private-credentials',
        idDerivation,
        encryption
      })
      const resourceA = await cipher.encrypt({ data: DOC })
      const resourceB = await cipher.encrypt({ data: { other: true } })
      expect(
        await cipher.decrypt({ id: resourceA.id, envelope: resourceA.envelope })
      ).toEqual(DOC)

      const refusal = await cipher
        .decrypt({ id: resourceB.id, envelope: resourceA.envelope })
        .then(() => null)
        .catch((err: unknown) => err)
      expect(refusal).toBeInstanceOf(IntegrityError)
      expect(isIntegrityError(refusal)).toBe(true)
    })
  }

  it('refuses a decrypt without a resource id instead of skipping the check', async () => {
    const { encryption, ...keys } = await makeReaderWithDescriptor()
    const cipher = await createEdvDocCipher({
      ...keys,
      collectionId: 'private-credentials',
      encryption
    })
    const { envelope } = await cipher.encrypt({ data: DOC })
    await expect(
      cipher.decrypt({ envelope } as unknown as { id: string; envelope: Json })
    ).rejects.toBeInstanceOf(ValidationError)
  })
})

describe('createEdvDocCipher (chunked envelopes)', () => {
  const blob = new Uint8Array(64).map((_value, index) => (index * 7) % 251)

  /**
   * Writes `blob` as a chunked document (an envelope plus chunk resources) to
   * an in-memory backend, through a handle-style codec over the same reader and
   * descriptor the cipher under test uses.
   *
   * @returns {Promise<object>}   the reader's keys and descriptor, the backend,
   *   the written resource id, and its stored envelope
   */
  async function writeChunked(): Promise<{
    keys: { keyAgreementKey: IKeyAgreementKey; keyResolver: IKeyResolver }
    encryption: CollectionEncryption
    backend: ReturnType<typeof memoryBackend>
    id: string
    envelope: Json
  }> {
    const { encryption, ...keys } = await makeReaderWithDescriptor()
    const codec = (await createEdvEncryption({
      resolveKeys: async () => keys,
      maxBlobBytes: 16,
      chunkSize: 24
    }).codecFor({
      spaceId: 's',
      collectionId: 'c',
      scheme: 'edv',
      encryption
    })) as ResourceCodec
    const backend = memoryBackend()
    const plan = (await codec.encode({
      data: blob,
      contentType: 'application/octet-stream'
    })) as ChunkedWrite
    await plan.execute(backend.context)
    const envelope = JSON.parse(
      new TextDecoder().decode(backend.store.get(`/space/s/c/${plan.id}`))
    ) as Json
    return { keys, encryption, backend, id: plan.id, envelope }
  }

  it('reassembles a chunked envelope given the Space and a request context', async () => {
    const { keys, encryption, backend, id, envelope } = await writeChunked()
    const cipher = await createEdvDocCipher({
      ...keys,
      collectionId: 'c',
      spaceId: 's',
      encryption
    })
    const decrypted = await cipher.decrypt({
      id,
      envelope,
      context: backend.context
    })
    expect(decrypted).toBeInstanceOf(Blob)
    expect((decrypted as Blob).type).toBe('application/octet-stream')
    expect(new Uint8Array(await (decrypted as Blob).arrayBuffer())).toEqual(
      blob
    )
  })

  it('refuses a chunked envelope without a request context', async () => {
    const { keys, encryption, id, envelope } = await writeChunked()
    const cipher = await createEdvDocCipher({
      ...keys,
      collectionId: 'c',
      spaceId: 's',
      encryption
    })
    await expect(cipher.decrypt({ id, envelope })).rejects.toBeInstanceOf(
      EncryptionError
    )
  })

  it('refuses a chunked envelope when the cipher was built without a Space', async () => {
    const { keys, encryption, backend, id, envelope } = await writeChunked()
    const cipher = await createEdvDocCipher({
      ...keys,
      collectionId: 'c',
      encryption
    })
    await expect(
      cipher.decrypt({ id, envelope, context: backend.context })
    ).rejects.toBeInstanceOf(NotSupportedError)
  })

  it('checks the resource binding before fetching any chunk', async () => {
    const { keys, encryption, backend, envelope } = await writeChunked()
    const cipher = await createEdvDocCipher({
      ...keys,
      collectionId: 'c',
      spaceId: 's',
      encryption
    })
    await expect(
      cipher.decrypt({
        id: 'zOtherResource',
        envelope,
        context: backend.context
      })
    ).rejects.toBeInstanceOf(IntegrityError)
    expect(backend.reads).toEqual([])
  })
})

describe('createEdvDocCipher (chunkSource)', () => {
  const blob = new Uint8Array(64).map((_value, index) => (index * 7) % 251)
  const otherBlob = new Uint8Array(64).map(
    (_value, index) => (index * 11) % 251
  )

  /**
   * Writes chunked documents to one in-memory backend through a handle-style
   * codec, and builds a cipher over the same reader and descriptor that has
   * no Space, so it can read chunks only from a `chunkSource`.
   *
   * @param [options] {object}
   * @param [options.wrap] {function}   wraps the backend context for the
   *   writes, to make a chosen request fail
   * @returns {Promise<object>}   the backend, the cipher, and a writer
   */
  async function setup({
    wrap
  }: {
    wrap?: (context: CodecRequestContext) => CodecRequestContext
  } = {}): Promise<{
    backend: ReturnType<typeof memoryBackend>
    cipher: EdvDocCipher
    write: (data: Uint8Array) => Promise<{ id: string; envelope: Json }>
  }> {
    const { encryption, ...keys } = await makeReaderWithDescriptor()
    const codec = (await createEdvEncryption({
      resolveKeys: async () => keys,
      maxBlobBytes: 16,
      chunkSize: 24
    }).codecFor({
      spaceId: 's',
      collectionId: 'c',
      scheme: 'edv',
      encryption
    })) as ResourceCodec
    const backend = memoryBackend()
    const context = wrap ? wrap(backend.context) : backend.context
    const write = async (
      data: Uint8Array
    ): Promise<{ id: string; envelope: Json }> => {
      const plan = (await codec.encode({
        data,
        contentType: 'image/png'
      })) as ChunkedWrite
      await plan.execute(context).catch(() => undefined)
      const envelope = JSON.parse(
        new TextDecoder().decode(backend.store.get(`/space/s/c/${plan.id}`))
      ) as Json
      return { id: plan.id, envelope }
    }
    const cipher = await createEdvDocCipher({
      ...keys,
      collectionId: 'c',
      encryption
    })
    return { backend, cipher, write }
  }

  /**
   * A chunk source over the backend's stored chunk files, recording each
   * request it serves.
   *
   * @param backend {object}   the in-memory backend
   * @param [redirect] {function}   maps a requested chunk path to the path to
   *   serve instead
   * @returns {object}   the source and its request log
   */
  function sourceOver(
    backend: ReturnType<typeof memoryBackend>,
    redirect: (path: string) => string = path => path
  ): {
    chunkSource: ChunkSource
    requests: Array<{ docId: string; chunkIndex: number }>
  } {
    const requests: Array<{ docId: string; chunkIndex: number }> = []
    const chunkSource: ChunkSource = async ({ docId, chunkIndex }) => {
      requests.push({ docId, chunkIndex })
      const bytes = backend.store.get(
        redirect(`/space/s/c/${docId}/chunks/${chunkIndex}`)
      )
      return bytes === undefined
        ? undefined
        : (JSON.parse(new TextDecoder().decode(bytes)) as IEDVChunk)
    }
    return { chunkSource, requests }
  }

  it('reassembles a chunked envelope from the source, with no Space and no request', async () => {
    const { backend, cipher, write } = await setup()
    const { id, envelope } = await write(blob)
    const readsBefore = backend.reads.length
    const { chunkSource, requests } = sourceOver(backend)
    const decrypted = await cipher.decrypt({ id, envelope, chunkSource })
    expect(decrypted).toBeInstanceOf(Blob)
    expect((decrypted as Blob).type).toBe('image/png')
    expect(await blobBytes(decrypted as Blob)).toEqual(blob)
    // Asked by the bound id, in index order, up to the sealed count.
    expect(requests.map(request => request.chunkIndex)).toEqual([0, 1, 2])
    expect(requests.every(request => request.docId === id)).toBe(true)
    expect(backend.reads.length).toBe(readsBefore)
  })

  it('keeps the bound-id refusal: no chunk is asked for', async () => {
    const { backend, cipher, write } = await setup()
    const { envelope } = await write(blob)
    const { chunkSource, requests } = sourceOver(backend)
    await expect(
      cipher.decrypt({ id: 'zOtherResource', envelope, chunkSource })
    ).rejects.toBeInstanceOf(IntegrityError)
    expect(requests).toEqual([])
  })

  it('keeps the sealed-count refusal for a pending stub: no chunk is asked for', async () => {
    // The chunk writes fail and so does the cleanup delete, so the stub
    // stays stored with its sealed stream state still `{ pending: true }`.
    const { backend, cipher, write } = await setup({
      wrap: context => ({
        async request(input) {
          const path = input.path as string
          if (
            (input.method === 'PUT' && path.includes('/chunks/')) ||
            input.method === 'DELETE'
          ) {
            throw Object.assign(new Error('HTTP 500'), { status: 500 })
          }
          return context.request(input)
        }
      })
    })
    const { id, envelope } = await write(blob)
    const { chunkSource, requests } = sourceOver(backend)
    await expect(
      cipher.decrypt({ id, envelope, chunkSource })
    ).rejects.toBeInstanceOf(EncryptionError)
    expect(requests).toEqual([])
  })

  it('refuses a chunk whose binding differs from the envelope binding', async () => {
    // A genuine chunk of resource B, served as chunk 1 of resource A. It is
    // sealed under the same epoch key, so it would decrypt cleanly: only the
    // chunk's own `was` binding tells it apart.
    const { backend, cipher, write } = await setup()
    const a = await write(blob)
    const b = await write(otherBlob)
    const { chunkSource } = sourceOver(backend, path =>
      path.endsWith('/chunks/1') ? path.replace(a.id, b.id) : path
    )
    const failure = await cipher
      .decrypt({ id: a.id, envelope: a.envelope, chunkSource })
      .catch((err: unknown) => err)
    expect(failure).toBeInstanceOf(EncryptionError)
    expect((failure as Error).message).toMatch(/chunk 1 .* is not bound/)
  })

  it('applies the chunk-binding check on the network path too', async () => {
    const { encryption, ...keys } = await makeReaderWithDescriptor()
    const codec = (await createEdvEncryption({
      resolveKeys: async () => keys,
      maxBlobBytes: 16,
      chunkSize: 24
    }).codecFor({
      spaceId: 's',
      collectionId: 'c',
      scheme: 'edv',
      encryption
    })) as ResourceCodec
    const backend = memoryBackend()
    const plans: ChunkedWrite[] = []
    for (const data of [blob, otherBlob]) {
      const plan = (await codec.encode({ data })) as ChunkedWrite
      await plan.execute(backend.context)
      plans.push(plan)
    }
    const [a, b] = plans as [ChunkedWrite, ChunkedWrite]
    // The server swaps B's chunk into A's chunk directory.
    backend.store.set(
      `/space/s/c/${a.id}/chunks/0`,
      backend.store.get(`/space/s/c/${b.id}/chunks/0`)!
    )
    const cipher = await createEdvDocCipher({
      ...keys,
      collectionId: 'c',
      spaceId: 's',
      encryption
    })
    const envelope = JSON.parse(
      new TextDecoder().decode(backend.store.get(`/space/s/c/${a.id}`))
    ) as Json
    const failure = await cipher
      .decrypt({ id: a.id, envelope, context: backend.context })
      .catch((err: unknown) => err)
    expect(failure).toBeInstanceOf(EncryptionError)
    expect((failure as Error).message).toMatch(/chunk 0 .* is not bound/)
  })

  it("raises was-client's NotFoundError for an index the source does not hold", async () => {
    const { backend, cipher, write } = await setup()
    const { id, envelope } = await write(blob)
    const { chunkSource } = sourceOver(backend, path =>
      path.endsWith('/chunks/2') ? `${path}-missing` : path
    )
    const failure = await cipher
      .decrypt({ id, envelope, chunkSource })
      .catch((err: unknown) => err)
    expect(failure).toBeInstanceOf(NotFoundError)
    expect((failure as Error).name).toBe('NotFoundError')
  })

  it('refuses a chunkSource passed together with a request context', async () => {
    const { backend, cipher, write } = await setup()
    const { id, envelope } = await write(blob)
    const { chunkSource, requests } = sourceOver(backend)
    await expect(
      cipher.decrypt({ id, envelope, chunkSource, context: backend.context })
    ).rejects.toBeInstanceOf(ValidationError)
    expect(requests).toEqual([])
  })

  it('reads a small document without consulting the source', async () => {
    const { backend, cipher } = await setup()
    const { chunkSource, requests } = sourceOver(backend)
    const { id, envelope } = await cipher.encrypt({ data: DOC })
    await expect(
      cipher.decrypt({ id, envelope, chunkSource })
    ).resolves.toEqual(DOC)
    expect(requests).toEqual([])
  })
})

describe('createEdvDocCipher (isPendingStub)', () => {
  const blob = new Uint8Array(64).map((_value, index) => (index * 7) % 251)

  it('recognizes the stub a torn chunked write leaves, and nothing else', async () => {
    const { encryption, ...keys } = await makeReaderWithDescriptor()
    const codec = (await createEdvEncryption({
      resolveKeys: async () => keys,
      maxBlobBytes: 16,
      chunkSize: 24
    }).codecFor({
      spaceId: 's',
      collectionId: 'c',
      scheme: 'edv',
      encryption
    })) as ResourceCodec
    const backend = memoryBackend()
    // The process stops after the first document write: every later request
    // fails, the cleanup delete included.
    let documentWrites = 0
    const torn: CodecRequestContext = {
      async request(input) {
        if (input.method === 'PUT' && documentWrites === 0) {
          documentWrites++
          return backend.context.request(input)
        }
        throw Object.assign(new Error('HTTP 503'), { status: 503 })
      }
    }
    const stubPlan = (await codec.encode({ data: blob })) as ChunkedWrite
    await expect(stubPlan.execute(torn)).rejects.toBeInstanceOf(EncryptionError)
    const completePlan = (await codec.encode({ data: blob })) as ChunkedWrite
    await completePlan.execute(backend.context)
    const envelopeOf = (id: string): Json =>
      JSON.parse(
        new TextDecoder().decode(backend.store.get(`/space/s/c/${id}`))
      ) as Json

    const cipher = await createEdvDocCipher({
      ...keys,
      collectionId: 'c',
      encryption
    })
    await expect(
      cipher.isPendingStub({
        id: stubPlan.id,
        envelope: envelopeOf(stubPlan.id)
      })
    ).resolves.toBe(true)
    await expect(
      cipher.isPendingStub({
        id: completePlan.id,
        envelope: envelopeOf(completePlan.id)
      })
    ).resolves.toBe(false)
    const small = await cipher.encrypt({ data: DOC })
    await expect(cipher.isPendingStub(small)).resolves.toBe(false)
    // The answer rests on the envelope's binding: a stub read under another
    // id is refused, not reported.
    await expect(
      cipher.isPendingStub({
        id: completePlan.id,
        envelope: envelopeOf(stubPlan.id)
      })
    ).rejects.toBeInstanceOf(IntegrityError)
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
      cipher.decrypt({
        id: sealedToOwnKey.id,
        envelope: sealedToOwnKey as unknown as Json
      })
    ).rejects.toThrow(UnknownEpochError)

    // Writes under the epoch roster round-trip as usual.
    const fresh = await cipher.encrypt({ data: DOC })
    expect(fresh.epoch).toBe(encryption.currentEpoch)
    expect(
      await cipher.decrypt({ id: fresh.id, envelope: fresh.envelope })
    ).toEqual(DOC)
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
    expect(await reader.decrypt({ id, envelope })).toEqual(DOC)
  })

  it('refuses decrypt with the typed encrypt-only error', async () => {
    const { encryption } = await makeReaderWithDescriptor()
    const writer = await createEdvEncryptOnlyDocCipher({
      collectionId: 'keyring',
      encryption
    })
    const { id, envelope } = await writer.encrypt({ data: DOC })
    const refusal = await writer
      .decrypt({ id, envelope })
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

  it('refuses a currentEpoch the epoch roster does not list', async () => {
    // `currentEpoch` MUST name a listed epoch; an unlisted one marks a stale
    // or tampered descriptor, and silently sealing to another epoch could
    // reach a rotated-out epoch's removed recipients.
    const { encryption } = await makeReaderWithDescriptor()
    await expect(
      createEdvEncryptOnlyDocCipher({
        collectionId: 'keyring',
        encryption: {
          ...encryption,
          currentEpoch:
            'did:key:z6LSoWfUS2Fk8Gv6ZaJZeXm895iS9DWQZ2bPNBPmvv9EnLmz'
        }
      })
    ).rejects.toBeInstanceOf(EncryptionError)
  })

  it('refuses a descriptor that declares no currentEpoch', async () => {
    // Listed newest-first with no `currentEpoch`, a last-entry fallback would
    // seal to the older epoch, whose key a reader removed at the rotation to
    // the newer one still holds. Both the encrypt-only writer and the reader
    // build refuse rather than guess.
    const { encryption, ...keys } = await makeReaderWithDescriptor()
    const rotated = await epochDescriptorFor([keys.keyAgreementKey])
    const unmarked: CollectionEncryption = {
      scheme: 'edv',
      epochs: [...rotated.epochs!, ...encryption.epochs!]
    }
    await expect(
      createEdvEncryptOnlyDocCipher({
        collectionId: 'keyring',
        encryption: unmarked
      })
    ).rejects.toBeInstanceOf(EncryptionError)
    await expect(
      createEdvDocCipher({
        ...keys,
        collectionId: 'keyring',
        encryption: unmarked
      })
    ).rejects.toBeInstanceOf(EncryptionError)
  })
})

describe('createEdvDocCipher (encrypt at a caller-supplied id)', () => {
  for (const idDerivation of ['content', 'random'] as const) {
    it(`seals a new document at the given id and opens it there (${idDerivation})`, async () => {
      const { encryption, ...keys } = await makeReaderWithDescriptor()
      const cipher = await createEdvDocCipher({
        ...keys,
        collectionId: 'connections',
        idDerivation,
        encryption
      })
      const id = edvIdFromBytes(new Uint8Array(16).fill(7))
      const sealed = await cipher.encrypt({ id, data: DOC })

      expect(sealed.id).toBe(id)
      expect(sealed.epoch).toBe(encryption.currentEpoch)
      expect(isEncryptedEnvelope(sealed.envelope)).toBe(true)
      expect((sealed.envelope as { id?: string }).id).toBe(id)
      expect((sealed.envelope as { sequence?: number }).sequence ?? 0).toBe(0)
      expect(await cipher.decrypt({ id, envelope: sealed.envelope })).toEqual(
        DOC
      )

      const elsewhere = edvIdFromBytes(new Uint8Array(16).fill(9))
      const refusal = await cipher
        .decrypt({ id: elsewhere, envelope: sealed.envelope })
        .then(() => null)
        .catch((err: unknown) => err)
      expect(refusal).toBeInstanceOf(IntegrityError)
    })
  }

  it('re-seals the document in place through encryptUpdate', async () => {
    const { encryption, ...keys } = await makeReaderWithDescriptor()
    const cipher = await createEdvDocCipher({
      ...keys,
      collectionId: 'connections',
      idDerivation: 'random',
      encryption
    })
    const id = edvIdFromBytes(new Uint8Array(16).fill(3))
    const first = await cipher.encrypt({ id, data: { v: 1 } })
    const updated = await cipher.encryptUpdate!({
      id,
      data: { v: 2 },
      current: first.envelope
    })
    expect(updated.id).toBe(id)
    expect(await cipher.decrypt({ id, envelope: updated.envelope })).toEqual({
      v: 2
    })
  })

  it('refuses a human-readable id, which would leak onto the URL', async () => {
    const { encryption, ...keys } = await makeReaderWithDescriptor()
    const cipher = await createEdvDocCipher({
      ...keys,
      collectionId: 'connections',
      idDerivation: 'random',
      encryption
    })
    await expect(
      cipher.encrypt({ id: 'alice-at-example', data: DOC })
    ).rejects.toBeInstanceOf(ValidationError)
  })

  it('forwards the id through the self-refreshing cipher', async () => {
    const { encryption, ...keys } = await makeReaderWithDescriptor()
    const cipher = await createRefreshingEdvDocCipher({
      ...keys,
      collectionId: 'connections',
      idDerivation: 'random',
      cache: {
        readDescriptor: async () => encryption,
        writeDescriptor: async () => {}
      }
    })
    const id = edvIdFromBytes(new Uint8Array(16).fill(5))
    const sealed = await cipher.encrypt({ id, data: DOC })
    expect(sealed.id).toBe(id)
    expect(await cipher.decrypt({ id, envelope: sealed.envelope })).toEqual(DOC)
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
    expect(
      await cipher.decrypt({ id: updated.id, envelope: updated.envelope })
    ).toEqual({
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
    expect(
      await cipher.decrypt({ id: updated.id, envelope: updated.envelope })
    ).toEqual({
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
      custom: { indexSchema: SCHEMA },
      slot: { kind: 'collection' }
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
      custom: { indexSchema: SCHEMA },
      slot: { kind: 'collection' }
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

  it('re-applies the last applyMeta after a descriptor refresh', async () => {
    const { encryption, ...keys } = await makeIndexableReader()
    const direct = await directCodecFor({ collectionId: 'c', encryption, keys })
    const { custom } = await direct.encodeMeta({
      custom: { indexSchema: SCHEMA },
      slot: { kind: 'collection' }
    })
    // A rotation: a second epoch, wrapped to the same reader, becomes current.
    const { epochId, secret } = await mintEpoch()
    const rotated: CollectionEncryption = {
      ...encryption,
      epochs: [
        ...encryption.epochs!,
        {
          id: epochId,
          recipients: [
            await wrapEpochSecret({
              epochSecret: secret,
              recipient: ownerRecipient({
                keyAgreementKey: keys.keyAgreementKey
              })
            })
          ]
        }
      ],
      currentEpoch: epochId
    }
    let served = encryption
    const cipher = await createRefreshingEdvDocCipher({
      ...keys,
      collectionId: 'c',
      source: { collectionEncryption: async () => served },
      cache: {
        readDescriptor: async () => undefined,
        writeDescriptor: async () => {}
      }
    })
    await cipher.applyMeta({ custom })

    // A document under the new epoch drives the refresh and rebuild...
    served = rotated
    const writer = await createEdvDocCipher({
      ...keys,
      collectionId: 'c',
      encryption: rotated
    })
    const written = await writer.encrypt({ data: { type: 'note' } })
    await expect(cipher.decrypt(written)).resolves.toEqual({ type: 'note' })

    // ...and the rebuilt cipher still indexes with the installed schema.
    const after = await cipher.encrypt({ data: { type: 'note' } })
    expect(after.epoch).toBe(epochId)
    expect(indexedOf(after.envelope)).toHaveLength(1)
  })

  it('indexes the mutable encryptUpdate path too', async () => {
    const { encryption, ...keys } = await makeIndexableReader()
    const direct = await directCodecFor({ collectionId: 'c', encryption, keys })
    const { custom } = await direct.encodeMeta({
      custom: { indexSchema: SCHEMA },
      slot: { kind: 'collection' }
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
    const { id, envelope } = await cipher.encrypt({ data: DOC })
    expect(await cipher.decrypt({ id, envelope })).toEqual(DOC)
  })

  it('refuses a metadata envelope bound to another collection', async () => {
    const { encryption, ...keys } = await makeIndexableReader()
    const foreign = await directCodecFor({
      collectionId: 'other',
      encryption,
      keys
    })
    const { custom } = await foreign.encodeMeta({
      custom: { indexSchema: SCHEMA },
      slot: { kind: 'collection' }
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

describe('the decrypt refusals', () => {
  it('both reach a consumer from this subpath, beside the cipher', () => {
    // The pair is what a caller scanning rows dispatches on, so both ship
    // from `/edv` rather than one here and its sibling at the package root.
    // Each assigns its `name` explicitly, which is the contract a consumer
    // whose cipher arrives through an injected seam matches on.
    expect(new UnknownEpochError({ collectionId: 'c', kids: [] }).name).toBe(
      'UnknownEpochError'
    )
    expect(new KeyUnwrapError('no key').name).toBe('KeyUnwrapError')
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
      'not on the Collection Metadata object this reader holds'
    )
  })
})

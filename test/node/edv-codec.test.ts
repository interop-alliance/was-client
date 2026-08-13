/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Unit tests for the EDV codec. These use real X25519 keys, real key epochs and
 * the real `EdvClientCore` cipher (no network) to prove that the codec genuinely
 * encrypts/decrypts at the seam: `encode` produces an opaque JWE envelope (no
 * plaintext leak) and `decode` round-trips it back. Every fixture here carries
 * the epoch-bearing `encryption` descriptor an encrypted collection has from
 * birth, so each envelope seals to the collection's current epoch key and binds
 * that epoch into its protected header. Also covers the documents-only contract
 * decisions: minted EDV ids on add (random by default, content-derived with
 * `idDerivation: 'content'`), human ids rejected on put, small binary as a
 * single JWE, oversized binary rejected, and the provider's null (no-keys) and
 * fail-closed (no-epochs) paths.
 */
import { describe, it, expect } from 'vitest'
import { base64urlnopad } from '@scure/base'
import { X25519KeyAgreementKey2020 } from '@interop/x25519-key-agreement-key'
import { EdvClientCore, EdvDocumentCipher } from '@interop/edv-client'
import type {
  IEDVDocument,
  IKeyAgreementKey,
  IKeyResolver
} from '@interop/data-integrity-core'
import type { HttpResponse } from '@interop/http-client'

import {
  EncryptionError,
  IntegrityError,
  isChunkedWrite,
  KeyUnwrapError,
  NotSupportedError,
  ValidationError
} from '../../src/index.js'
import type {
  ChunkedWrite,
  CodecRequestContext,
  CollectionEncryption,
  EncodedWrite,
  ResourceCodec
} from '../../src/index.js'
import type { SingleWriteCodec } from '../helpers/codec.js'
import { stubFeatures } from '../helpers/codec.js'
import { installFileReader, rnBlob } from '../helpers/rnBlob.js'
import {
  createEdvEncryption,
  EdvCodec,
  EDV_SCHEME_VERSION,
  JOSE_CONTENT_TYPE,
  UnknownEpochError
} from '../../src/edv/index.js'
import {
  didKeyResolver,
  epochKeyIdFor,
  mintEpoch,
  reconstructEpochKeyPair,
  wrapEpochSecret
} from '../../src/edv/epochCrypto.js'

/**
 * The provider options every codec fixture in this file forwards to
 * `createEdvEncryption`.
 */
interface EdvFixtureOptions {
  contentType?: string
  maxBlobBytes?: number
  chunkSize?: number
  idDerivation?: 'random' | 'content'
}

/**
 * Generates a fresh real X25519 key agreement key and a matching resolver, so
 * the codec's encrypt/decrypt actually run.
 *
 * @returns {Promise<{ kak: IKeyAgreementKey; publicKeyMultibase: string;
 *   keyResolver: function }>}
 */
async function makeKeys(): Promise<{
  kak: IKeyAgreementKey
  publicKeyMultibase: string
  keyResolver: IKeyResolver
}> {
  const kak = await X25519KeyAgreementKey2020.generate({
    controller: 'did:example:alice'
  })
  const keyResolver = async ({ id }: { id?: string }) => {
    if (id !== kak.id) {
      throw new Error(`Unknown key id "${id}".`)
    }
    return {
      id: kak.id,
      type: kak.type,
      publicKeyMultibase: kak.publicKeyMultibase
    }
  }
  // `X25519KeyAgreementKey2020.id` is typed optional, but a key generated with a
  // `controller` always derives one, so narrow it to the `IKeyAgreementKey`
  // contract the EDV keystore expects.
  return {
    kak: kak as IKeyAgreementKey,
    publicKeyMultibase: kak.publicKeyMultibase,
    keyResolver
  }
}

/**
 * Mints a key epoch and wraps its secret to one reader, producing the
 * epoch-bearing `CollectionEncryption` descriptor an encrypted collection
 * carries from birth, plus the reconstructed epoch key pair. That pair is the
 * key every envelope is sealed to; the reader's own key-agreement key only
 * unwraps the epoch secret and never encrypts or decrypts a resource itself.
 *
 * @param reader {object}
 * @param reader.id {string}                   the reader's key-agreement key id
 * @param reader.publicKeyMultibase {string}   its public key
 * @returns {Promise<{ encryption: CollectionEncryption; epochId: string;
 *   epochKeyPair: IKeyAgreementKey }>}
 */
async function mintEpochFor({
  id,
  publicKeyMultibase
}: {
  id: string
  publicKeyMultibase: string
}): Promise<{
  encryption: CollectionEncryption
  epochId: string
  epochKeyPair: IKeyAgreementKey
}> {
  const { epochId, secret } = await mintEpoch()
  const encryption: CollectionEncryption = {
    scheme: 'edv',
    epochs: [
      {
        id: epochId,
        recipients: [
          await wrapEpochSecret({
            epochSecret: secret,
            recipient: { id, publicKeyMultibase }
          })
        ]
      }
    ],
    currentEpoch: epochId
  }
  return {
    encryption,
    epochId,
    epochKeyPair: reconstructEpochKeyPair({ epochId, secret })
  }
}

/**
 * Builds an EDV codec over a fresh real X25519 reader and a freshly-minted
 * epoch wrapped to it, via the public `createEdvEncryption` provider, and
 * returns the epoch material alongside it. Also hands back a `decrypt` helper
 * that unseals an encoded envelope to its decrypted `{ content, meta }`, so a
 * test can assert the on-the-wire inner document (e.g. that text is stored
 * verbatim, not base64); it decrypts with the epoch key pair, the recipient
 * every envelope names.
 *
 * @param [options] {EdvFixtureOptions}
 * @returns {Promise<{ codec: SingleWriteCodec; encryption: CollectionEncryption;
 *   epochId: string; decrypt: function }>}
 */
async function makeFixture(options: EdvFixtureOptions = {}): Promise<{
  codec: SingleWriteCodec
  encryption: CollectionEncryption
  epochId: string
  decrypt: (body: Uint8Array | Blob | undefined) => Promise<IEDVDocument>
}> {
  const { kak, publicKeyMultibase, keyResolver } = await makeKeys()
  const { encryption, epochId, epochKeyPair } = await mintEpochFor({
    id: kak.id,
    publicKeyMultibase
  })
  const provider = createEdvEncryption({
    resolveKeys: async () => ({ keyAgreementKey: kak, keyResolver }),
    ...options
  })
  // Core decides policy (descriptor/override) and then asks the provider to
  // build the codec for the declared scheme; mirror that here, descriptor and
  // all -- `codecFor` routes on the descriptor's epoch roster.
  const codec = await provider.codecFor({
    spaceId: 's',
    collectionId: 'c',
    scheme: 'edv',
    encryption
  })
  if (!codec) {
    throw new Error('expected a codec')
  }
  const edv = new EdvClientCore({
    keyAgreementKey: epochKeyPair,
    keyResolver: didKeyResolver
  })
  const decrypt = async (
    body: Uint8Array | Blob | undefined
  ): Promise<IEDVDocument> => {
    const encryptedDoc = JSON.parse(
      new TextDecoder().decode(body as Uint8Array)
    )
    return edv.documentCipher.decrypt({
      encryptedDoc,
      keyAgreementKey: epochKeyPair
    })
  }
  return { codec: codec as SingleWriteCodec, encryption, epochId, decrypt }
}

/**
 * The codec alone, for the tests that need no epoch material of their own.
 *
 * @param [options] {EdvFixtureOptions}
 * @returns {Promise<SingleWriteCodec>}
 */
async function makeCodec(
  options: EdvFixtureOptions = {}
): Promise<SingleWriteCodec> {
  return (await makeFixture(options)).codec
}

/**
 * Wraps an encoded write's body bytes as a minimal read response the codec's
 * `decode` accepts (mirroring how core hands the GET response back).
 *
 * @param body {Uint8Array}
 * @returns {object}
 */
function responseFrom(body?: Uint8Array | Blob): HttpResponse {
  const envelope = JSON.parse(new TextDecoder().decode(body as Uint8Array))
  return {
    data: envelope,
    async json() {
      return envelope
    }
  } as unknown as HttpResponse
}

/**
 * Parses the `was` binding out of an envelope object's JWE protected header.
 *
 * @param envelope {unknown}
 * @returns {Record<string, unknown> | undefined}
 */
function wasOf(envelope: unknown): Record<string, unknown> | undefined {
  const { jwe } = envelope as { jwe: { protected: string } }
  const decoded = JSON.parse(
    new TextDecoder().decode(base64urlnopad.decode(jwe.protected))
  )
  return decoded.was
}

describe('EdvCodec: JSON round trip', () => {
  it('encrypts on encode (no plaintext leak) and decrypts on decode', async () => {
    const { codec, epochId } = await makeFixture()
    const encoded = await codec.encode({
      data: { secret: 'do not leak', n: 42 }
    })

    // add(): a fresh EDV multibase id is minted and the body is an opaque JWE.
    expect(encoded.id).toMatch(/^z/)
    // The wire type is the opaque envelope; the resource type is the plaintext.
    expect(encoded.contentType).toBe('application/json')
    expect(encoded.resourceContentType).toBe('application/json')
    const json = new TextDecoder().decode(encoded.body as Uint8Array)
    expect(json).not.toContain('do not leak')
    const envelope = JSON.parse(json)
    expect(envelope.jwe).toBeTruthy()
    expect(envelope.content).toBeUndefined()
    // The envelope seals to the collection's CURRENT EPOCH key (not to the
    // reader's own key-agreement key, which only unwraps that epoch), and the
    // write reports the epoch it encrypted under.
    expect(envelope.jwe.recipients[0].header.kid).toBe(epochKeyIdFor(epochId))
    expect(encoded.epoch).toBe(epochId)

    const decoded = await codec.decode(responseFrom(encoded.body))
    expect(decoded).toEqual({ secret: 'do not leak', n: 42 })
  })

  it('stores JSON content verbatim and typed application/json in meta', async () => {
    const { codec, decrypt } = await makeFixture()
    const value = { type: ['VerifiableCredential'], claim: 'legible' }
    const encoded = await codec.encode({ data: value })

    // Inside the JWE: content is the value verbatim (no wrapper), meta carries
    // the JSON content type and NO encoding discriminator.
    const doc = await decrypt(encoded.body)
    expect(doc.content).toEqual(value)
    expect(doc.meta).toEqual({ contentType: 'application/json' })
    expect(doc.meta?.encoding).toBeUndefined()
  })

  it('honors an opted-in application/jose+json content type', async () => {
    const codec = await makeCodec({ contentType: JOSE_CONTENT_TYPE })
    const encoded = await codec.encode({ data: { a: 1 } })
    expect(encoded.contentType).toBe('application/jose+json')
  })
})

describe('EdvCodec: id strategy', () => {
  it('rejects a human-readable id on put', async () => {
    const codec = await makeCodec()
    await expect(
      codec.encode({ id: '2020-01-01-hello', data: { a: 1 } })
    ).rejects.toThrow(ValidationError)
  })

  it('accepts a (re-used) EDV-format id on put', async () => {
    const codec = await makeCodec()
    const minted = (await codec.encode({ data: { v: 1 } })).id as string
    const updated = await codec.encode({ id: minted, data: { v: 2 } })
    expect(updated.id).toBe(minted)
    const decoded = await codec.decode(responseFrom(updated.body))
    expect(decoded).toEqual({ v: 2 })
  })

  it('accepts a pre-existing non-EDV id verbatim on the update path', async () => {
    // A resource authored by a client that mints its own row ids (e.g. a
    // legacy uuid): the id is already on the server, so an update (`current`
    // pre-read) must take it verbatim -- refusing it prevents no leak, it only
    // strands the document. The create path keeps the guard.
    const codec = await makeCodec()
    const uuid = '01890a5d-ac96-774b-bcce-b302099a8057'
    const prior = await codec.encode({ data: { v: 1 } })
    const priorEnvelope = JSON.parse(
      new TextDecoder().decode(prior.body as Uint8Array)
    ) as Record<string, unknown>
    const updated = await codec.encode({
      id: uuid,
      data: { v: 2 },
      current: {
        data: priorEnvelope,
        async json() {
          return priorEnvelope
        },
        headers: { get: () => '"1"' }
      } as unknown as HttpResponse
    })
    expect(updated.id).toBe(uuid)
    expect(updated.ifMatch).toBe('"1"')
    // The re-encrypted envelope binds the true (foreign) resource id, and
    // decodes under it.
    expect(await codec.decode(responseFrom(updated.body), uuid)).toEqual({
      v: 2
    })
    // Without `current` (a create), the same id is still rejected.
    await expect(codec.encode({ id: uuid, data: { v: 1 } })).rejects.toThrow(
      ValidationError
    )
  })
})

describe("EdvCodec: content-derived ids (idDerivation: 'content')", () => {
  it("derives the add() id from the envelope's JWE ciphertext and stamps it", async () => {
    const codec = await makeCodec({ idDerivation: 'content' })
    const encoded = await codec.encode({ data: { secret: 'addressed' } })
    const envelope = JSON.parse(
      new TextDecoder().decode(encoded.body as Uint8Array)
    )
    // The write id IS the stamped envelope id, in the standard EDV format...
    expect(encoded.id).toMatch(/^z[1-9A-HJ-NP-Za-km-z]{21,}$/)
    expect(envelope.id).toBe(encoded.id)
    // ...and recomputes from the ciphertext (content-derived, not random).
    await expect(
      EdvDocumentCipher.deriveId({ jwe: envelope.jwe })
    ).resolves.toBe(encoded.id)
  })

  it('guards the content-derived insert with If-None-Match: * and round-trips', async () => {
    const codec = await makeCodec({ idDerivation: 'content' })
    const encoded = await codec.encode({ data: { v: 1 } })
    expect(encoded.ifNoneMatch).toBe(true)
    expect(encoded.ifMatch).toBeUndefined()
    // The stamped id satisfies the cipher's decrypt-side id assertion.
    const decoded = await codec.decode(responseFrom(encoded.body))
    expect(decoded).toEqual({ v: 1 })
  })

  it('accepts an explicit EDV-format id and still rejects a human-readable one', async () => {
    const codec = await makeCodec({ idDerivation: 'content' })
    const derived = (await codec.encode({ data: { v: 1 } })).id as string
    const rewrite = await codec.encode({ id: derived, data: { v: 1 } })
    expect(rewrite.id).toBe(derived)
    await expect(
      codec.encode({ id: '2020-01-01-hello', data: { a: 1 } })
    ).rejects.toThrow(ValidationError)
  })

  it("default 'random' mode does not content-derive the id", async () => {
    const codec = await makeCodec()
    const encoded = await codec.encode({ data: { v: 1 } })
    const envelope = JSON.parse(
      new TextDecoder().decode(encoded.body as Uint8Array)
    )
    const derived = await EdvDocumentCipher.deriveId({ jwe: envelope.jwe })
    expect(encoded.id).not.toBe(derived)
  })
})

describe('EdvCodec: binary', () => {
  it('round-trips a small blob as base64 in a single JWE document', async () => {
    const { codec, decrypt } = await makeFixture()
    const bytes = new Uint8Array([1, 2, 3, 4, 250])
    const encoded = await codec.encode({
      data: bytes,
      contentType: 'application/octet-stream'
    })
    // Stored inline as base64 under `content.bytes`, typed in meta.
    const doc = await decrypt(encoded.body)
    expect(doc.meta).toEqual({
      contentType: 'application/octet-stream',
      encoding: 'base64'
    })
    expect(typeof (doc.content as { bytes?: unknown }).bytes).toBe('string')
    expect(encoded.resourceContentType).toBe('application/octet-stream')

    const decoded = await codec.decode(responseFrom(encoded.body))
    expect(decoded).toBeInstanceOf(Blob)
    const out = new Uint8Array(await (decoded as Blob).arrayBuffer())
    expect(out).toEqual(bytes)
    expect((decoded as Blob).type).toBe('application/octet-stream')
  })

  it('seals a React Native blob (no arrayBuffer(), FileReader fallback)', async () => {
    // RN's `Blob` implements no `arrayBuffer()`, so the inline byte path reads
    // it through the global `FileReader` the runtime provides instead.
    const restore = installFileReader()
    try {
      const { codec, decrypt } = await makeFixture()
      const bytes = new Uint8Array([1, 2, 3, 4, 250])
      const blob = rnBlob([bytes], { type: 'application/octet-stream' })
      const encoded = await codec.encode({ data: blob })
      const doc = await decrypt(encoded.body)
      expect(doc.meta).toEqual({
        contentType: 'application/octet-stream',
        encoding: 'base64'
      })
      const decoded = await codec.decode(responseFrom(encoded.body))
      expect(decoded).toBeInstanceOf(Blob)
      expect(new Uint8Array(await (decoded as Blob).arrayBuffer())).toEqual(
        bytes
      )
    } finally {
      restore()
    }
  })

  it('surfaces the resolved content type of a typed blob', async () => {
    const codec = await makeCodec()
    const png = new Blob([new Uint8Array([137, 80, 78, 71])], {
      type: 'image/png'
    })
    const encoded = await codec.encode({ data: png })
    // Finding 15: add() reports the plaintext type, not the envelope type.
    expect(encoded.contentType).toBe('application/json')
    expect(encoded.resourceContentType).toBe('image/png')
  })

  it('keeps a binary write at the threshold on the single-document path', async () => {
    const codec: ResourceCodec = await makeCodec({ maxBlobBytes: 8 })
    const write = await codec.encode({
      data: new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8])
    })
    expect(isChunkedWrite(write)).toBe(false)
    expect((write as EncodedWrite).body).toBeInstanceOf(Uint8Array)
  })

  it('routes on the default threshold: 512 KiB inline, one byte more chunked', async () => {
    // The default is sized so a single-document envelope stays under a server's
    // ~1 MiB JSON body cap (~1.78x inflation: base64 inside the document, then
    // base64url in the JWE ciphertext). Every other threshold test overrides
    // `maxBlobBytes` to a tiny value, so this is the only guard on the default.
    const codec: ResourceCodec = await makeCodec()
    const contentType = 'application/octet-stream'
    const atThreshold = await codec.encode({
      data: new Uint8Array(512 * 1024),
      contentType
    })
    expect(isChunkedWrite(atThreshold)).toBe(false)
    expect((atThreshold as EncodedWrite).body).toBeInstanceOf(Uint8Array)

    // One byte over: a plan, asserted without executing it (there is no
    // backend here -- only the routing decision is under test).
    const overThreshold = await codec.encode({
      data: new Uint8Array(512 * 1024 + 1),
      contentType
    })
    expect(isChunkedWrite(overThreshold)).toBe(true)
  })

  it('rejects a bare primitive', async () => {
    const codec = await makeCodec()
    await expect(
      // A bare string is excluded by the `ResourceData` type; cast to prove the
      // runtime guard still rejects it.
      codec.encode({ data: 'just a string' as unknown as Uint8Array })
    ).rejects.toThrow(ValidationError)
  })
})

/**
 * An in-memory WAS backend for the chunked-blob tests: it answers the request
 * context a handle hands the codec, storing every `PUT` body under its path and
 * serving it back on `GET`. That is the whole surface `WasTransport` needs, so
 * a chunked write plan and a chunked read run end to end with no network.
 *
 * It also answers `DELETE` (dropping the stored body), which the chunked
 * write's failure cleanup needs.
 *
 * @param [options] {object}
 * @param [options.features] {string[]}   the backend's advertised affordances
 * @param [options.descriptorAbsent] {boolean}   whether the feature probe
 *   should report that the backend descriptor could not be read at all
 * @returns {object}   the request context, the stored bodies by path, and the
 *   ordered lists of written and deleted paths
 */
function memoryBackend({
  features = ['chunked-streams', 'conditional-writes'],
  descriptorAbsent = false
}: { features?: string[]; descriptorAbsent?: boolean } = {}): {
  context: CodecRequestContext
  store: Map<string, Uint8Array>
  writes: string[]
  deletes: string[]
} {
  const store = new Map<string, Uint8Array>()
  const writes: string[] = []
  const deletes: string[] = []
  const respond = (
    body: Uint8Array | undefined,
    etag?: string
  ): HttpResponse => {
    const text = body === undefined ? '' : new TextDecoder().decode(body)
    return {
      headers: {
        get: (name: string) =>
          name.toLowerCase() === 'etag' ? (etag ?? null) : null
      },
      async json() {
        return JSON.parse(text)
      },
      async text() {
        return text
      }
    } as unknown as HttpResponse
  }
  const context: CodecRequestContext = {
    features: stubFeatures(features, { descriptorAbsent }),
    async request(input) {
      const path = input.path as string
      const method = input.method ?? 'GET'
      if (method === 'PUT') {
        writes.push(path)
        store.set(path, input.body as Uint8Array)
        return respond(undefined, '"v1"')
      }
      if (method === 'DELETE') {
        deletes.push(path)
        store.delete(path)
        return respond(undefined)
      }
      const stored = store.get(path)
      if (stored === undefined) {
        throw Object.assign(new Error(`HTTP 404 ${path}`), { status: 404 })
      }
      return respond(stored)
    }
  }
  return { context, store, writes, deletes }
}

describe('EdvCodec: chunked blob auto-routing', () => {
  const blob = new Uint8Array(64).map((_value, index) => (index * 7) % 251)

  /**
   * A codec whose threshold routes `blob` to the chunked path, with a chunk
   * size small enough that the write emits several chunks.
   *
   * @returns {Promise<ResourceCodec>}
   */
  async function chunkingCodec(): Promise<ResourceCodec> {
    return makeCodec({ maxBlobBytes: 16, chunkSize: 24 })
  }

  it('returns a chunked plan for a binary payload over the threshold', async () => {
    const codec = await chunkingCodec()
    const write = await codec.encode({
      data: blob,
      contentType: 'application/octet-stream'
    })
    expect(isChunkedWrite(write)).toBe(true)
    const plan = write as ChunkedWrite
    expect(plan.id).toMatch(/^z/)
    expect(plan.resourceContentType).toBe('application/octet-stream')
  })

  it('writes the document and its chunks, then reads the bytes back exactly', async () => {
    const codec = await chunkingCodec()
    const backend = memoryBackend()
    const plan = (await codec.encode({
      data: blob,
      contentType: 'application/octet-stream'
    })) as ChunkedWrite

    const result = await plan.execute(backend.context)
    expect(result.id).toBe(plan.id)
    expect(result.etag).toBe('"v1"')

    // The document was written to its own resource path, and the bytes went to
    // the reserved chunk sub-segment -- more than one, so reassembly is real.
    const documentPath = `/space/s/c/${plan.id}`
    expect(backend.store.has(documentPath)).toBe(true)
    const chunkPaths = [...backend.store.keys()].filter(path =>
      path.startsWith(`${documentPath}/chunks/`)
    )
    expect(chunkPaths.length).toBeGreaterThan(1)
    // Nothing readable leaked: the stored document carries no plaintext bytes.
    const stored = JSON.parse(
      new TextDecoder().decode(backend.store.get(documentPath))
    ) as { jwe?: unknown; content?: unknown }
    expect(stored.jwe).toBeTruthy()
    expect(stored.content).toBeUndefined()

    const decoded = await codec.decode(
      responseFrom(backend.store.get(documentPath)),
      plan.id,
      backend.context
    )
    expect(decoded).toBeInstanceOf(Blob)
    expect((decoded as Blob).type).toBe('application/octet-stream')
    const out = new Uint8Array(await (decoded as Blob).arrayBuffer())
    expect(out).toEqual(blob)
  })

  it('refuses to write anything when the backend lacks chunked-streams', async () => {
    const codec = await chunkingCodec()
    const backend = memoryBackend({ features: ['conditional-writes'] })
    const plan = (await codec.encode({
      data: blob,
      contentType: 'application/octet-stream'
    })) as ChunkedWrite
    await expect(plan.execute(backend.context)).rejects.toBeInstanceOf(
      NotSupportedError
    )
    // The gate runs before the first write, so no document stub is left behind.
    expect(backend.writes).toEqual([])
  })

  it('names the descriptor it read when the backend lacks the feature', async () => {
    const codec = await chunkingCodec()
    const backend = memoryBackend({ features: ['conditional-writes'] })
    const plan = (await codec.encode({
      data: blob,
      contentType: 'application/octet-stream'
    })) as ChunkedWrite
    const failure = await plan
      .execute(backend.context)
      .catch((err: unknown) => err)
    expect((failure as Error).message).toMatch(/which it does not/)
    expect((failure as Error).message).not.toMatch(/could not be read/)
  })

  it('names an unreadable backend descriptor instead of blaming the server', async () => {
    // The descriptor 404s (no such endpoint, a deleted collection, or a
    // capability that cannot read it), which also probes as "no features". The
    // gate must not report that as an incapable server.
    const codec = await chunkingCodec()
    const backend = memoryBackend({ features: [], descriptorAbsent: true })
    const plan = (await codec.encode({
      data: blob,
      contentType: 'application/octet-stream'
    })) as ChunkedWrite
    const failure = await plan
      .execute(backend.context)
      .catch((err: unknown) => err)
    expect(failure).toBeInstanceOf(NotSupportedError)
    expect((failure as Error).message).toMatch(
      /backend descriptor could not be read at all/
    )
    expect(backend.writes).toEqual([])
  })

  it('refuses to decode a chunked document without a request context', async () => {
    const codec = await chunkingCodec()
    const backend = memoryBackend()
    const plan = (await codec.encode({
      data: blob,
      contentType: 'application/octet-stream'
    })) as ChunkedWrite
    await plan.execute(backend.context)
    const stored = responseFrom(backend.store.get(`/space/s/c/${plan.id}`))
    await expect(codec.decode(stored, plan.id)).rejects.toBeInstanceOf(
      EncryptionError
    )
  })

  it('addresses chunks by the AEAD-bound id, not the cleartext envelope id', async () => {
    const codec = await chunkingCodec()
    const backend = memoryBackend()
    const otherBlob = new Uint8Array(64).map(
      (_value, index) => (index * 11) % 251
    )
    const planA = (await codec.encode({
      data: blob,
      contentType: 'application/octet-stream'
    })) as ChunkedWrite
    await planA.execute(backend.context)
    const planB = (await codec.encode({
      data: otherBlob,
      contentType: 'application/octet-stream'
    })) as ChunkedWrite
    await planB.execute(backend.context)

    // The server serves A's authentic envelope -- its sealed `was.resource`
    // still names A, so the binding check passes -- with only the cleartext
    // top-level id swapped to B. B's chunks decrypt cleanly under the shared
    // epoch key, so addressing them by that cleartext id would silently return
    // B's bytes for a read of A.
    const envelope = JSON.parse(
      new TextDecoder().decode(backend.store.get(`/space/s/c/${planA.id}`))
    ) as { id: string }
    envelope.id = planB.id
    const swapped = responseFrom(
      new TextEncoder().encode(JSON.stringify(envelope))
    )

    const reads: string[] = []
    const watching: CodecRequestContext = {
      features: backend.context.features,
      async request(input) {
        reads.push(input.path as string)
        return backend.context.request(input)
      }
    }
    const decoded = await codec.decode(swapped, planA.id, watching)
    const out = new Uint8Array(await (decoded as Blob).arrayBuffer())
    expect(out).toEqual(blob)
    expect(out).not.toEqual(otherBlob)
    // Nothing under B's document path was ever fetched.
    expect(reads.some(path => path.startsWith(`/space/s/c/${planB.id}`))).toBe(
      false
    )

    // And served into B's own slot, the same envelope is refused outright by
    // the `was.resource` binding check, before any chunk is fetched.
    await expect(
      codec.decode(swapped, planB.id, backend.context)
    ).rejects.toBeInstanceOf(IntegrityError)
  })

  it('ignores a forged cleartext stream on a single-document blob', async () => {
    // The routing signal is the sealed `meta.encoding`, so a server bolting a
    // cleartext `stream` onto an ordinary small document cannot mask its
    // sealed content or turn the read into chunk fetches.
    const codec = await makeCodec({ maxBlobBytes: 16, chunkSize: 24 })
    const backend = memoryBackend()
    const small = new Uint8Array([1, 2, 3])
    const encoded = await codec.encode({
      data: small,
      contentType: 'application/octet-stream'
    })
    const envelope = JSON.parse(
      new TextDecoder().decode(encoded.body as Uint8Array)
    ) as { stream?: unknown }
    envelope.stream = { chunks: 1 }

    const reads: string[] = []
    const watching: CodecRequestContext = {
      features: backend.context.features,
      async request(input) {
        reads.push(input.path as string)
        return backend.context.request(input)
      }
    }
    const decoded = await codec.decode(
      responseFrom(new TextEncoder().encode(JSON.stringify(envelope))),
      encoded.id,
      watching
    )
    expect(decoded).toBeInstanceOf(Blob)
    const out = new Uint8Array(await (decoded as Blob).arrayBuffer())
    expect(out).toEqual(small)
    expect(reads).toEqual([])
  })

  it('routes an over-threshold Blob on its size alone', async () => {
    // The routing decision reads `Blob.size`, so a blob never has to be
    // buffered to be measured -- it is handed on as `blob.stream()`.
    const codec = await chunkingCodec()
    const backend = memoryBackend()
    const write = await codec.encode({
      data: new Blob([blob as BlobPart], { type: 'application/octet-stream' })
    })
    expect(isChunkedWrite(write)).toBe(true)
    const plan = write as ChunkedWrite
    await plan.execute(backend.context)
    const decoded = await codec.decode(
      responseFrom(backend.store.get(`/space/s/c/${plan.id}`)),
      plan.id,
      backend.context
    )
    const out = new Uint8Array(await (decoded as Blob).arrayBuffer())
    expect(out).toEqual(blob)
  })

  /**
   * Wraps a backend context so a chosen request fails, for the failure-cleanup
   * tests.
   *
   * @param options {object}
   * @param options.context {CodecRequestContext}   the backend to wrap
   * @param options.failOn {function}   true for a request that must fail
   * @param options.failure {Error}   the error to fail it with
   * @returns {CodecRequestContext}
   */
  function failingBackend({
    context,
    failOn,
    failure
  }: {
    context: CodecRequestContext
    failOn: (input: { path?: string; method?: string }) => boolean
    failure: Error
  }): CodecRequestContext {
    return {
      features: context.features,
      async request(input) {
        if (failOn(input as { path?: string; method?: string })) {
          throw failure
        }
        return context.request(input)
      }
    }
  }

  it('deletes the orphaned document stub when a chunk write fails', async () => {
    const codec = await chunkingCodec()
    const backend = memoryBackend()
    const plan = (await codec.encode({
      data: blob,
      contentType: 'application/octet-stream'
    })) as ChunkedWrite
    const failure = Object.assign(new Error('HTTP 413'), { status: 413 })
    const context = failingBackend({
      context: backend.context,
      failOn: input =>
        input.method === 'PUT' && input.path!.includes('/chunks/'),
      failure
    })

    // The document stub was already written when the chunk failed, and its
    // sealed stream state is still `{ pending: true }` -- undecryptable, and
    // never re-used (a retry mints a fresh id). So the plan compensates.
    const documentPath = `/space/s/c/${plan.id}`
    await expect(plan.execute(context)).rejects.toBeInstanceOf(EncryptionError)
    expect(backend.writes).toContain(documentPath)
    expect(backend.deletes).toEqual([documentPath])
    expect(backend.store.has(documentPath)).toBe(false)

    // The original failure is preserved as the cause.
    const plan2 = (await codec.encode({
      data: blob,
      contentType: 'application/octet-stream'
    })) as ChunkedWrite
    const err = await plan2.execute(context).catch(caught => caught)
    expect((err as Error).cause).toBe(failure)
  })

  it('deletes nothing when the write fails before the document is written', async () => {
    // The id is freshly minted, so a failure here is the server or the
    // network, not a collision: a DELETE would remove a resource this write
    // never created. The raw failure propagates unwrapped.
    const codec = await chunkingCodec()
    const backend = memoryBackend()
    const plan = (await codec.encode({
      data: blob,
      contentType: 'application/octet-stream'
    })) as ChunkedWrite
    const failure = Object.assign(new Error('HTTP 503'), { status: 503 })
    const context = failingBackend({
      context: backend.context,
      failOn: input => input.method === 'PUT',
      failure
    })
    await expect(plan.execute(context)).rejects.toBe(failure)
    expect(backend.deletes).toEqual([])
  })

  it('does not mask the write failure when the cleanup delete also fails', async () => {
    const codec = await chunkingCodec()
    const backend = memoryBackend()
    const plan = (await codec.encode({
      data: blob,
      contentType: 'application/octet-stream'
    })) as ChunkedWrite
    const failure = Object.assign(new Error('HTTP 413'), { status: 413 })
    const context: CodecRequestContext = {
      features: backend.context.features,
      async request(input) {
        const path = input.path as string
        if (input.method === 'PUT' && path.includes('/chunks/')) {
          throw failure
        }
        if (input.method === 'DELETE') {
          throw Object.assign(new Error('HTTP 500'), { status: 500 })
        }
        return backend.context.request(input)
      }
    }
    const err = await plan.execute(context).catch(caught => caught)
    expect(err).toBeInstanceOf(EncryptionError)
    expect((err as Error).cause).toBe(failure)
    // The stub is still stored, and the message says so.
    expect((err as Error).message).toContain('could NOT be deleted')
    expect(backend.store.has(`/space/s/c/${plan.id}`)).toBe(true)
  })

  it('refuses a content-addressed collection (no derivable id for a two-phase write)', async () => {
    const codec: ResourceCodec = await makeCodec({
      maxBlobBytes: 16,
      idDerivation: 'content'
    })
    await expect(
      codec.encode({ data: blob, contentType: 'application/octet-stream' })
    ).rejects.toBeInstanceOf(ValidationError)
  })
})

describe('EdvCodec: text', () => {
  it('stores text as a legible UTF-8 string (no base64) and reads a Blob', async () => {
    const { codec, decrypt } = await makeFixture()
    const html = '<!doctype html><h1>héllo</h1>'
    const encoded = await codec.encode({
      data: new Blob([html], { type: 'text/html' })
    })
    expect(encoded.resourceContentType).toBe('text/html')

    // Stored verbatim under `content.text` with `encoding: 'utf-8'` -- legible,
    // not base64.
    const doc = await decrypt(encoded.body)
    expect(doc.meta).toEqual({ contentType: 'text/html', encoding: 'utf-8' })
    expect((doc.content as { text?: unknown }).text).toBe(html)

    // Reads back as a Blob typed text/html whose .text() matches.
    const decoded = await codec.decode(responseFrom(encoded.body))
    expect(decoded).toBeInstanceOf(Blob)
    expect((decoded as Blob).type).toBe('text/html')
    expect(await (decoded as Blob).text()).toBe(html)
  })

  it('falls back to base64 for a text-typed blob carrying invalid UTF-8', async () => {
    const { codec, decrypt } = await makeFixture()
    // 0xff is not valid UTF-8; the text gate must reject it and store base64.
    const encoded = await codec.encode({
      data: new Blob([new Uint8Array([0xff, 0xfe, 0x00])], {
        type: 'text/plain'
      })
    })
    const doc = await decrypt(encoded.body)
    expect(doc.meta).toEqual({ contentType: 'text/plain', encoding: 'base64' })
    expect(typeof (doc.content as { bytes?: unknown }).bytes).toBe('string')
  })

  it('preserves a leading UTF-8 BOM through the text round trip', async () => {
    // BOM-prefixed UTF-8 is valid UTF-8, so the text gate stores it as a
    // string -- and the decoder must not strip the BOM (`ignoreBOM: true`), or
    // the round-tripped bytes come back 3 bytes short, corrupting any hash or
    // signature over the original file.
    const { codec, decrypt } = await makeFixture()
    const bytes = new Uint8Array([
      0xef,
      0xbb,
      0xbf,
      ...new TextEncoder().encode('hello')
    ])
    const encoded = await codec.encode({
      data: bytes,
      contentType: 'text/plain'
    })
    const doc = await decrypt(encoded.body)
    expect(doc.meta).toEqual({ contentType: 'text/plain', encoding: 'utf-8' })

    const decoded = await codec.decode(responseFrom(encoded.body))
    const roundTripped = new Uint8Array(await (decoded as Blob).arrayBuffer())
    expect(roundTripped).toEqual(bytes)
  })
})

describe('EdvCodec: caller-data collision (no in-band descriptor)', () => {
  it('round-trips a JSON object shaped like the binary container as itself', async () => {
    const codec = await makeCodec()
    const value = { bytes: 'aGk=' }
    const encoded = await codec.encode({ data: value })
    const decoded = await codec.decode(responseFrom(encoded.body))
    // No `meta.encoding`, so it is JSON -- returned verbatim, not a Blob.
    expect(decoded).not.toBeInstanceOf(Blob)
    expect(decoded).toEqual(value)
  })

  it('round-trips a JSON object shaped like the text container as itself', async () => {
    const codec = await makeCodec()
    const value = { text: 'hi' }
    const encoded = await codec.encode({ data: value })
    const decoded = await codec.decode(responseFrom(encoded.body))
    expect(decoded).not.toBeInstanceOf(Blob)
    expect(decoded).toEqual(value)
  })
})

describe('EdvCodec: malformed inner document', () => {
  /**
   * Encrypts an arbitrary `{ content, meta }` under a fresh collection's epoch
   * key -- a well-formed envelope, `was` binding and all, that only its inner
   * shape is wrong -- and returns a `{ codec, response }` pair so `decode` can
   * be exercised against that deliberately malformed inner document.
   *
   * @param content {Record<string, unknown>}
   * @param meta {Record<string, unknown>}
   * @returns {Promise<{ codec: SingleWriteCodec; response: HttpResponse }>}
   */
  async function encodedDocWith(
    content: Record<string, unknown>,
    meta: Record<string, unknown>
  ): Promise<{ codec: SingleWriteCodec; response: HttpResponse }> {
    const { kak, publicKeyMultibase, keyResolver } = await makeKeys()
    const { encryption, epochId, epochKeyPair } = await mintEpochFor({
      id: kak.id,
      publicKeyMultibase
    })
    const provider = createEdvEncryption({
      resolveKeys: async () => ({ keyAgreementKey: kak, keyResolver })
    })
    const codec = (await provider.codecFor({
      spaceId: 's',
      collectionId: 'c',
      scheme: 'edv',
      encryption
    })) as SingleWriteCodec
    const edv = new EdvClientCore({
      keyAgreementKey: epochKeyPair,
      keyResolver: didKeyResolver
    })
    const recipients = edv.documentCipher.createDefaultRecipients(epochKeyPair)
    const docId = 'z' + 'A'.repeat(21)
    const encrypted = await edv.documentCipher.encrypt({
      doc: { id: docId, content, meta },
      recipients,
      keyResolver: didKeyResolver,
      update: false,
      additionalProtectedParams: {
        was: { v: EDV_SCHEME_VERSION, resource: docId, epoch: epochId }
      }
    })
    return {
      codec,
      response: responseFrom(
        new TextEncoder().encode(JSON.stringify(encrypted))
      )
    }
  }

  it('throws EncryptionError when encoding is base64 but content.bytes is not a string', async () => {
    const { codec, response } = await encodedDocWith(
      { bytes: 123 },
      { contentType: 'image/png', encoding: 'base64' }
    )
    await expect(codec.decode(response)).rejects.toThrow(EncryptionError)
  })

  it('throws EncryptionError when encoding is utf-8 but content.text is not a string', async () => {
    const { codec, response } = await encodedDocWith(
      { text: 42 },
      { contentType: 'text/html', encoding: 'utf-8' }
    )
    await expect(codec.decode(response)).rejects.toThrow(EncryptionError)
  })
})

describe('EdvCodec: non-envelope guard', () => {
  /**
   * A read response carrying an arbitrary JSON document (mirroring how core
   * hands a GET response back), used to simulate a plaintext/foreign resource
   * stored in an encrypted collection.
   *
   * @param doc {unknown}
   * @returns {HttpResponse}
   */
  function jsonResponse(doc: unknown): HttpResponse {
    return {
      data: doc,
      async json() {
        return doc
      },
      headers: {
        get: () => '"1"'
      }
    } as unknown as HttpResponse
  }

  it('throws a typed EncryptionError when decoding a non-envelope body', async () => {
    const codec = await makeCodec()
    await expect(
      codec.decode(jsonResponse({ hello: 'plaintext, no jwe' }))
    ).rejects.toThrow(EncryptionError)
  })

  it('throws a typed EncryptionError when updating over a non-envelope prior doc', async () => {
    const codec = await makeCodec()
    const minted = (await codec.encode({ data: { v: 1 } })).id as string
    await expect(
      codec.encode({
        id: minted,
        data: { v: 2 },
        current: jsonResponse({ hello: 'plaintext, no jwe' })
      })
    ).rejects.toThrow(EncryptionError)
  })

  it('throws a typed EncryptionError when the prior envelope has no sequence', async () => {
    // A foreign `{ id, jwe }` envelope without a `sequence`: spreading its
    // undefined `sequence` onto the update doc would make the cipher's
    // `'sequence' in encrypted` check throw a raw untyped Error.
    const codec = await makeCodec()
    const first = await codec.encode({ data: { v: 1 } })
    const envelope = JSON.parse(
      new TextDecoder().decode(first.body as Uint8Array)
    ) as { sequence?: number }
    delete envelope.sequence
    const failure = await codec
      .encode({
        id: first.id as string,
        data: { v: 2 },
        current: jsonResponse(envelope)
      })
      .catch((err: unknown) => err)
    expect(failure).toBeInstanceOf(EncryptionError)
    expect((failure as Error).message).toMatch(/sequence/)
  })

  it('throws a typed EncryptionError for a malformed prior sequence', async () => {
    const codec = await makeCodec()
    const first = await codec.encode({ data: { v: 1 } })
    const envelope = JSON.parse(
      new TextDecoder().decode(first.body as Uint8Array)
    ) as { sequence?: unknown }
    envelope.sequence = 'not-a-number'
    await expect(
      codec.encode({
        id: first.id as string,
        data: { v: 2 },
        current: jsonResponse(envelope)
      })
    ).rejects.toThrow(EncryptionError)
  })
})

describe('EdvCodec: conditional writes (sequence enforcement)', () => {
  /**
   * A read response the codec's `encode` accepts as `current`: the prior
   * envelope plus an `ETag` header (the server's conditional-writes validator).
   *
   * @param body {Uint8Array | Blob}   the prior encoded envelope bytes
   * @param etag {string | null}       the prior ETag (null to simulate a backend
   *   without the conditional-writes feature)
   * @returns {object}
   */
  function currentFrom(
    body: Uint8Array | Blob | undefined,
    etag: string | null
  ): HttpResponse {
    const envelope = JSON.parse(new TextDecoder().decode(body as Uint8Array))
    return {
      data: envelope,
      async json() {
        return envelope
      },
      headers: {
        get: (name: string) => (name.toLowerCase() === 'etag' ? etag : null)
      }
    } as unknown as HttpResponse
  }

  function sequenceOf(body: Uint8Array | Blob | undefined): number {
    return JSON.parse(new TextDecoder().decode(body as Uint8Array)).sequence
  }

  it('marks the codec as driving conditional writes', async () => {
    const codec = await makeCodec()
    expect(codec.conditionalWrites).toBe(true)
  })

  it('a fresh insert is sequence 0 guarded by If-None-Match', async () => {
    const codec = await makeCodec()
    const minted = await codec.encode({ data: { v: 1 } })
    expect(sequenceOf(minted.body)).toBe(0)
    expect(minted.ifNoneMatch).toBe(true)
    expect(minted.ifMatch).toBeUndefined()
  })

  it('an update advances the sequence and pins If-Match to the current ETag', async () => {
    const codec = await makeCodec()
    const first = await codec.encode({ data: { v: 1 } })
    const id = first.id as string
    expect(sequenceOf(first.body)).toBe(0)

    const second = await codec.encode({
      id,
      data: { v: 2 },
      current: currentFrom(first.body, '"1"')
    })
    expect(sequenceOf(second.body)).toBe(1)
    expect(second.ifMatch).toBe('"1"')
    expect(second.ifNoneMatch).toBeUndefined()
    expect(await codec.decode(responseFrom(second.body))).toEqual({ v: 2 })

    // A third update advances again from the prior envelope.
    const third = await codec.encode({
      id,
      data: { v: 3 },
      current: currentFrom(second.body, '"2"')
    })
    expect(sequenceOf(third.body)).toBe(2)
    expect(third.ifMatch).toBe('"2"')
  })

  it('degrades to advisory (no If-Match) when the backend sends no ETag', async () => {
    const codec = await makeCodec()
    const first = await codec.encode({ data: { v: 1 } })
    const second = await codec.encode({
      id: first.id as string,
      data: { v: 2 },
      current: currentFrom(first.body, null)
    })
    // The sequence still advances, but with no validator there is no
    // precondition.
    expect(sequenceOf(second.body)).toBe(1)
    expect(second.ifMatch).toBeUndefined()
    expect(second.ifNoneMatch).toBeUndefined()
  })
})

describe('EdvCodec: decrypt failure discrimination', () => {
  /**
   * Re-serializes an encoded envelope after mutating its parsed form, returning
   * a read response the codec's `decode` accepts. Used to tamper with a real
   * JWE's ciphertext/tag before reading it back.
   *
   * @param body {Uint8Array | Blob}   the encoded envelope bytes
   * @param mutate {function}          mutates the parsed envelope in place
   * @returns {HttpResponse}
   */
  function tamperedResponse(
    body: Uint8Array | Blob | undefined,
    mutate: (envelope: { jwe: { ciphertext: string; tag: string } }) => void
  ): HttpResponse {
    const envelope = JSON.parse(new TextDecoder().decode(body as Uint8Array))
    mutate(envelope)
    const bytes = new TextEncoder().encode(JSON.stringify(envelope))
    return responseFrom(bytes)
  }

  /**
   * Flips the last character of a base64url string to a different one, so the
   * value stays well-formed base64url but decodes to different bytes.
   *
   * @param value {string}
   * @returns {string}
   */
  function flipLast(value: string): string {
    const last = value.slice(-1)
    return value.slice(0, -1) + (last === 'A' ? 'B' : 'A')
  }

  it('throws IntegrityError (not KeyUnwrapError) on a tampered ciphertext read by a legitimate recipient', async () => {
    const codec = await makeCodec()
    const encoded = await codec.encode({ data: { secret: 'authentic' } })
    // The reader holds the recipient key, but the sealed content is corrupted:
    // the AEAD tag must fail and surface as an integrity failure, NOT as a
    // membership/KeyUnwrapError.
    const response = tamperedResponse(encoded.body, envelope => {
      envelope.jwe.ciphertext = flipLast(envelope.jwe.ciphertext)
    })
    const failure = await codec.decode(response).catch((err: unknown) => err)
    expect(failure).toBeInstanceOf(IntegrityError)
    expect(failure).not.toBeInstanceOf(KeyUnwrapError)
    // Still under the EncryptionError umbrella (fail-closed handling catches
    // it).
    expect(failure).toBeInstanceOf(EncryptionError)
  })

  it('throws IntegrityError on a tampered AEAD tag read by a legitimate recipient', async () => {
    const codec = await makeCodec()
    const encoded = await codec.encode({ data: { secret: 'authentic' } })
    const response = tamperedResponse(encoded.body, envelope => {
      envelope.jwe.tag = flipLast(envelope.jwe.tag)
    })
    await expect(codec.decode(response)).rejects.toThrow(IntegrityError)
  })

  it('throws UnknownEpochError (not IntegrityError) when no candidate key is a recipient', async () => {
    // Encode under one collection's epoch, then read with a codec resolved
    // from an unrelated collection's epoch roster: the envelope's recipient
    // kid (the writer's epoch key) matches none of the reader's epoch keys,
    // so routing fails fast with the stale-descriptor signal -- decryption
    // never reaches the AEAD stage and must not misreport tampering.
    const writer = await makeCodec()
    const encoded = await writer.encode({
      data: { secret: 'for someone else' }
    })
    const reader = await makeCodec()
    const failure = await reader
      .decode(responseFrom(encoded.body))
      .catch((err: unknown) => err)
    expect(failure).toBeInstanceOf(UnknownEpochError)
    expect(failure).not.toBeInstanceOf(IntegrityError)
  })

  it('throws KeyUnwrapError (not UnknownEpochError) for a listed epoch this reader is not a recipient of', async () => {
    // A removed reader's view: the shared descriptor lists epoch 2 (so it is
    // not stale), but only readerA is a recipient of it. readerB, handed a
    // post-rotation envelope, must get the membership signal (KeyUnwrapError:
    // re-reading the descriptor cannot help), not the stale-descriptor one.
    const readerA = await makeKeys()
    const readerB = await makeKeys()
    const epoch1 = await mintEpoch()
    const epoch2 = await mintEpoch()
    const encryption: CollectionEncryption = {
      scheme: 'edv',
      epochs: [
        {
          id: epoch1.epochId,
          recipients: [
            await wrapEpochSecret({
              epochSecret: epoch1.secret,
              recipient: {
                id: readerA.kak.id,
                publicKeyMultibase: readerA.publicKeyMultibase
              }
            }),
            await wrapEpochSecret({
              epochSecret: epoch1.secret,
              recipient: {
                id: readerB.kak.id,
                publicKeyMultibase: readerB.publicKeyMultibase
              }
            })
          ]
        },
        {
          id: epoch2.epochId,
          recipients: [
            await wrapEpochSecret({
              epochSecret: epoch2.secret,
              recipient: {
                id: readerA.kak.id,
                publicKeyMultibase: readerA.publicKeyMultibase
              }
            })
          ]
        }
      ],
      currentEpoch: epoch2.epochId
    }
    const codecOf = async (
      reader: Awaited<ReturnType<typeof makeKeys>>,
      descriptor: CollectionEncryption
    ) => {
      const provider = createEdvEncryption({
        resolveKeys: async () => ({
          keyAgreementKey: reader.kak,
          keyResolver: reader.keyResolver
        })
      })
      return (await provider.codecFor({
        spaceId: 's',
        collectionId: 'c',
        scheme: 'edv',
        encryption: descriptor
      }))! as SingleWriteCodec
    }
    // readerA writes under epoch 2 (the currentEpoch).
    const writer = await codecOf(readerA, encryption)
    const encoded = await writer.encode({ data: { secret: 'post-rotation' } })
    // readerB decodes with the SAME (current) descriptor.
    const reader = await codecOf(readerB, encryption)
    const failure = await reader
      .decode(responseFrom(encoded.body))
      .catch((err: unknown) => err)
    expect(failure).toBeInstanceOf(KeyUnwrapError)
    expect(failure).not.toBeInstanceOf(UnknownEpochError)
    // ...while an epoch-1 envelope (written before the rotation, via a
    // pre-rotation descriptor) still decodes: rotation never claws back what
    // readerB could already read.
    const preRotation: CollectionEncryption = {
      ...encryption,
      epochs: [encryption.epochs![0]!],
      currentEpoch: epoch1.epochId
    }
    const earlyWriter = await codecOf(readerA, preRotation)
    const early = await earlyWriter.encode({ data: { secret: 'pre-rotation' } })
    await expect(reader.decode(responseFrom(early.body))).resolves.toEqual({
      secret: 'pre-rotation'
    })
  })

  it('treats a candidate throwing KeyUnwrapError as a key miss and tries the next key', async () => {
    // A lazy epoch key whose recipient entry is corrupt raises KeyUnwrapError
    // from its own deriveSecret when a decrypt first forces the unwrap. That
    // says nothing about the stored envelope, so the loop must move on to the
    // next candidate (which decrypts fine) instead of misreporting tampering.
    const { epochId, secret } = await mintEpoch()
    const epochKeyPair = reconstructEpochKeyPair({ epochId, secret })
    const edv = new EdvClientCore({
      keyAgreementKey: epochKeyPair,
      keyResolver: didKeyResolver
    })
    const corrupt = {
      // Same kid as the envelope recipient (the epoch key id), so this
      // candidate is tried first.
      id: epochKeyPair.id,
      async deriveSecret(): Promise<Uint8Array> {
        throw new KeyUnwrapError(
          `This reader's recipient entry for epoch "${epochId}" did ` +
            'not unwrap (a corrupt entry).'
        )
      }
    } as IKeyAgreementKey
    const codec: SingleWriteCodec = new EdvCodec({
      edv,
      keyAgreementKey: epochKeyPair,
      readKeys: [corrupt, epochKeyPair],
      writeEpoch: epochId,
      contentType: 'application/json',
      maxBlobBytes: 512 * 1024,
      idDerivation: 'random',
      spaceId: 's',
      collectionId: 'c',
      epochIds: [epochId]
    })
    const encoded = await codec.encode({ data: { secret: 'still readable' } })
    await expect(codec.decode(responseFrom(encoded.body))).resolves.toEqual({
      secret: 'still readable'
    })
  })
})

describe('createEdvEncryption: provider (keystore)', () => {
  /**
   * A minimal epoch-bearing descriptor for the routing tests that never reach
   * the crypto (no real wrap needed -- the roster only has to be non-empty).
   */
  const epochBearing: CollectionEncryption = {
    scheme: 'edv',
    epochs: [{ id: 'did:key:zEpoch1', recipients: [] }],
    currentEpoch: 'did:key:zEpoch1'
  }

  it('returns null when resolveKeys yields no keys (core then fails closed)', async () => {
    const provider = createEdvEncryption({ resolveKeys: async () => null })
    const codec = await provider.codecFor({
      spaceId: 's',
      collectionId: 'c',
      scheme: 'edv',
      encryption: epochBearing
    })
    // Null no longer means "plaintext" -- policy already said encrypted, so core
    // turns this into a fail-closed EncryptionError rather than a codec.
    expect(codec).toBeNull()
  })

  it('refuses an encrypted descriptor that carries no key epochs', async () => {
    // Epoch-from-birth: there is no single-recipient era to route to, so a
    // descriptor whose epoch roster is missing (or empty) is refused rather
    // than encrypted straight to the reader's key-agreement key.
    const { kak, keyResolver } = await makeKeys()
    const provider = createEdvEncryption({
      resolveKeys: async () => ({ keyAgreementKey: kak, keyResolver })
    })
    await expect(
      provider.codecFor({
        spaceId: 's',
        collectionId: 'c',
        scheme: 'edv',
        encryption: { scheme: 'edv' }
      })
    ).rejects.toBeInstanceOf(EncryptionError)
    await expect(
      provider.codecFor({
        spaceId: 's',
        collectionId: 'c',
        scheme: 'edv',
        encryption: { scheme: 'edv', epochs: [] }
      })
    ).rejects.toBeInstanceOf(EncryptionError)
  })

  it('returns null for a scheme it does not handle', async () => {
    const { kak, keyResolver } = await makeKeys()
    const provider = createEdvEncryption({
      resolveKeys: async () => ({ keyAgreementKey: kak, keyResolver })
    })
    const codec = await provider.codecFor({
      spaceId: 's',
      collectionId: 'c',
      scheme: 'age',
      encryption: epochBearing
    })
    expect(codec).toBeNull()
  })

  it('uses override-supplied keys instead of the keystore', async () => {
    const { kak, publicKeyMultibase, keyResolver } = await makeKeys()
    const { encryption } = await mintEpochFor({
      id: kak.id,
      publicKeyMultibase
    })
    let keystoreCalls = 0
    const provider = createEdvEncryption({
      resolveKeys: async () => {
        keystoreCalls++
        return null
      }
    })
    const codec = await provider.codecFor({
      spaceId: 's',
      collectionId: 'c',
      scheme: 'edv',
      encryption,
      keys: { keyAgreementKey: kak, keyResolver }
    })
    expect(codec).not.toBeNull()
    expect(keystoreCalls).toBe(0)
  })
})

describe('EdvCodec: metadata (encodeMeta / decodeMeta)', () => {
  it('encrypts custom into an EDV Document envelope (no plaintext leak)', async () => {
    const codec = await makeCodec()
    const { custom } = await codec.encodeMeta({
      custom: { name: 'Secret Name', tags: { project: 'x' } }
    })
    // The stored `custom` is an EDV Document envelope (`{ jwe, ... }`), not the
    // plaintext name/tags.
    expect((custom as { jwe?: unknown }).jwe).toBeTruthy()
    expect(JSON.stringify(custom)).not.toContain('Secret Name')
  })

  it('round-trips custom through encodeMeta then decodeMeta', async () => {
    const codec = await makeCodec()
    const original = { name: 'Hello', tags: { a: 'b', c: 'd' } }
    const { custom } = await codec.encodeMeta({ custom: original })
    expect(await codec.decodeMeta({ custom })).toEqual(original)
  })

  it('round-trips an empty custom (envelope on the wire, {} decoded)', async () => {
    const codec = await makeCodec()
    const { custom } = await codec.encodeMeta({ custom: {} })
    expect((custom as { jwe?: unknown }).jwe).toBeTruthy()
    expect(await codec.decodeMeta({ custom })).toEqual({})
  })

  it('decodeMeta returns {} for an absent custom (no metadata written)', async () => {
    const codec = await makeCodec()
    expect(await codec.decodeMeta({})).toEqual({})
    expect(await codec.decodeMeta({ custom: undefined })).toEqual({})
  })

  it('decodeMeta fails closed on a foreign plaintext custom (no `jwe`)', async () => {
    const codec = await makeCodec()
    await expect(
      codec.decodeMeta({ custom: { name: 'plaintext' } })
    ).rejects.toThrow(EncryptionError)
  })

  it('encodeMeta with an id binds `was.resource` and reports the write epoch', async () => {
    const { codec, epochId } = await makeFixture()
    const { custom, epoch } = await codec.encodeMeta({
      custom: { name: 'Secret' },
      id: 'zResourceId'
    })
    expect(wasOf(custom)).toEqual({
      v: 1,
      resource: 'zResourceId',
      epoch: epochId
    })
    expect(epoch).toBe(epochId)
  })

  it('encodeMeta without an id binds `was.collection`, not `was.resource`', async () => {
    const { codec, epochId } = await makeFixture()
    const { custom, epoch } = await codec.encodeMeta({
      custom: { name: 'Collection Label' }
    })
    // A Collection's metadata belongs to no resource, so instead of a resource
    // id the envelope binds the collection it was written for -- which is what
    // declares the slot positively.
    expect(wasOf(custom)).toEqual({ v: 1, collection: 'c', epoch: epochId })
    // The epoch is surfaced so the Collection `/meta` PUT can stamp it in the
    // body (an omitted body member clears the server's stored stamp).
    expect(epoch).toBe(epochId)
  })

  it('round-trips Collection-level custom without an expected id', async () => {
    const codec = await makeCodec()
    const original = { name: 'Collection Label', tags: { a: 'b' } }
    const { custom } = await codec.encodeMeta({ custom: original })
    expect(await codec.decodeMeta({ custom })).toEqual(original)
  })
})

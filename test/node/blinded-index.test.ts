/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Unit tests for content search on the codec path: the persisted index schema,
 * the blinded `indexed` entries a write emits, `Collection.declareIndex()` and
 * `Collection.find()`. Real X25519 keys, a real key epoch, a real blinded-index
 * HMAC key and the real cipher (no network) prove the tokens a write stores are
 * the same tokens a query blinds to -- the whole point of the scheme, since the
 * server compares them as opaque strings.
 *
 * The handle-level tests drive a `WasClient` over a small in-memory WAS stub
 * that serves the Collection Description, the Collection `/meta` slot (with its
 * own `metaVersion` ETag, so the declare path's compare-and-swap is exercised
 * for real) and the `/query` endpoint.
 */
import { describe, it, expect } from 'vitest'
import { X25519KeyAgreementKey2020 } from '@interop/x25519-key-agreement-key'
import type {
  IKeyAgreementKey,
  IKeyResolver
} from '@interop/data-integrity-core'
import type { HttpResponse } from '@interop/http-client'

import { WasClient, ValidationError } from '../../src/index.js'
import type {
  CollectionDescription,
  CollectionEncryption,
  ResourceCodec
} from '../../src/index.js'
import { identityCodec } from '../../src/internal/codec.js'
import { createEdvEncryption } from '../../src/edv/index.js'
import { mintEpoch, wrapEpochSecret } from '../../src/edv/epochCrypto.js'
import { mintHmacKey } from '../../src/edv/hmacKey.js'

/**
 * A reader plus the epoch-and-blinding-key-bearing descriptor an indexable
 * encrypted collection carries from birth. `keys` is what a keystore hands the
 * provider; `encryption` is what the Collection Description declares.
 *
 * @returns {Promise<{ encryption: CollectionEncryption; keys: object }>}
 */
async function makeIndexableCollection(): Promise<{
  encryption: CollectionEncryption
  keys: { keyAgreementKey: IKeyAgreementKey; keyResolver: IKeyResolver }
}> {
  const kak = await X25519KeyAgreementKey2020.generate({
    controller: 'did:example:alice'
  })
  const recipient = {
    id: kak.id as string,
    publicKeyMultibase: kak.publicKeyMultibase
  }
  const keyResolver: IKeyResolver = async ({ id }: { id?: string }) => {
    if (id !== kak.id) {
      throw new Error(`Unknown key id "${id}".`)
    }
    return {
      id: kak.id as string,
      type: kak.type,
      publicKeyMultibase: kak.publicKeyMultibase
    }
  }
  const { epochId, secret } = await mintEpoch()
  const hmac = await mintHmacKey()
  const encryption: CollectionEncryption = {
    scheme: 'edv',
    epochs: [
      {
        id: epochId,
        recipients: [await wrapEpochSecret({ epochSecret: secret, recipient })]
      }
    ],
    currentEpoch: epochId,
    hmac: {
      id: hmac.id,
      type: hmac.type,
      recipients: [
        await wrapEpochSecret({ epochSecret: hmac.secret, recipient })
      ]
    }
  }
  return {
    encryption,
    keys: { keyAgreementKey: kak as IKeyAgreementKey, keyResolver }
  }
}

/**
 * Builds the EDV codec for an indexable collection directly through the public
 * provider, bypassing the handle layer (the codec-level tests need no server).
 *
 * @param options {object}
 * @param options.encryption {CollectionEncryption}
 * @param options.keys {object}
 * @returns {Promise<ResourceCodec>}
 */
async function makeCodec({
  encryption,
  keys
}: {
  encryption: CollectionEncryption
  keys: { keyAgreementKey: IKeyAgreementKey; keyResolver: IKeyResolver }
}): Promise<ResourceCodec> {
  const provider = createEdvEncryption({ resolveKeys: async () => keys })
  const codec = await provider.codecFor({
    spaceId: 's',
    collectionId: 'c',
    scheme: 'edv',
    encryption
  })
  if (!codec) {
    throw new Error('expected a codec')
  }
  return codec
}

/**
 * Parses an encoded write's body bytes back into the stored envelope object.
 *
 * @param body {Uint8Array | Blob | undefined}
 * @returns {Record<string, any>}
 */
function envelopeOf(body: Uint8Array | Blob | undefined): {
  id?: string
  indexed?: Array<{
    hmac: { id: string }
    attributes: Array<{ name: string; value: string }>
  }>
} {
  return JSON.parse(new TextDecoder().decode(body as Uint8Array))
}

describe('indexed emission at the content encrypt seam', () => {
  it('emits no index entries until an attribute is declared', async () => {
    const fixture = await makeIndexableCollection()
    const codec = await makeCodec(fixture)
    const encoded = await codec.encode({ data: { type: 'note' } })
    // The envelope carries the (empty) entry list every EDV document has, and
    // nothing blinded: with no declared attribute there is nothing to index.
    expect(envelopeOf(encoded.body).indexed).toEqual([])
  })

  it('blinds the declared attributes into the stored envelope', async () => {
    const fixture = await makeIndexableCollection()
    const codec = await makeCodec(fixture)
    codec.indexing!.applySchema({
      revision: 1,
      indexes: [{ attribute: 'content.type', addedIn: 1 }]
    })
    const encoded = await codec.encode({ data: { type: 'note' } })
    const envelope = envelopeOf(encoded.body)
    expect(envelope.indexed).toHaveLength(1)
    expect(envelope.indexed![0]!.hmac.id).toBe(fixture.encryption.hmac!.id)
    expect(envelope.indexed![0]!.attributes).toHaveLength(1)
    // The blinded name/value leaks neither the attribute nor the value.
    const [attribute] = envelope.indexed![0]!.attributes
    expect(attribute!.name).not.toContain('type')
    expect(attribute!.value).not.toContain('note')
  })

  it('blinds a query to the same tokens a write stored', async () => {
    const fixture = await makeIndexableCollection()
    const codec = await makeCodec(fixture)
    codec.indexing!.applySchema({
      revision: 1,
      indexes: [{ attribute: 'content.type', addedIn: 1 }]
    })
    const encoded = await codec.encode({ data: { type: 'note' } })
    const stored = envelopeOf(encoded.body).indexed![0]!.attributes[0]!
    const query = await codec.indexing!.buildQuery({
      equals: { 'content.type': 'note' }
    })
    expect(query.index).toBe(fixture.encryption.hmac!.id)
    expect(query.equals).toEqual([{ [stored.name]: stored.value }])
  })

  it('refuses a query on an attribute the schema does not declare', async () => {
    const fixture = await makeIndexableCollection()
    const codec = await makeCodec(fixture)
    codec.indexing!.applySchema({
      revision: 1,
      indexes: [{ attribute: 'content.type', addedIn: 1 }]
    })
    await expect(
      codec.indexing!.buildQuery({ equals: { 'content.author': 'alice' } })
    ).rejects.toThrow(/content\.author/)
    await expect(
      codec.indexing!.buildQuery({ equals: { 'content.author': 'alice' } })
    ).rejects.toBeInstanceOf(ValidationError)
  })

  it('leaves the metadata envelope un-blinded', async () => {
    const fixture = await makeIndexableCollection()
    const codec = await makeCodec(fixture)
    codec.indexing!.applySchema({
      revision: 1,
      indexes: [{ attribute: 'content.name', addedIn: 1 }]
    })
    const { custom } = await codec.encodeMeta({ custom: { name: 'secret' } })
    // No blinded entries even though `content.name` IS declared: the metadata
    // envelope is a different slot, which the search endpoint never reads.
    expect((custom as { indexed?: unknown }).indexed).toEqual([])
  })

  it('gives the plaintext codec no search capability at all', () => {
    expect(identityCodec.indexing).toBeUndefined()
  })
})

/**
 * The mutable state of the in-memory WAS stub: the Collection `/meta` slot
 * (value plus its own `metaVersion` validator), the canned `/query` answer, and
 * a one-shot hook that fails the next metadata write with a 412 the way a
 * concurrent writer would.
 */
interface ServerState {
  meta: { custom?: unknown; version: number }
  queryResult: unknown
  collideOnce?: () => void
}

interface RequestArgs {
  url?: string
  method?: string
  json?: unknown
  headers?: Record<string, string>
}

/**
 * A canned 200 response in the shape `@interop/http-client` returns.
 *
 * @param data {unknown}
 * @param [etag] {string}
 * @returns {HttpResponse}
 */
function ok(data: unknown, etag?: string): HttpResponse {
  return {
    status: 200,
    headers: new Headers(etag !== undefined ? { etag } : {}),
    data,
    async json() {
      return data
    }
  } as unknown as HttpResponse
}

/**
 * Builds a `WasClient` (with the EDV keystore) over an in-memory WAS stub for
 * one encrypted collection: it serves the Collection Description, the
 * Collection `/meta` slot with a monotonic `metaVersion` ETag it enforces
 * `If-Match` against, and the `/query` endpoint.
 *
 * @param options {object}
 * @param options.encryption {CollectionEncryption}
 * @param options.keys {object}
 * @returns {{ client: WasClient; state: ServerState; calls: RequestArgs[] }}
 */
function serverFor({
  encryption,
  keys
}: {
  encryption: CollectionEncryption
  keys: { keyAgreementKey: IKeyAgreementKey; keyResolver: IKeyResolver }
}): { client: WasClient; state: ServerState; calls: RequestArgs[] } {
  const state: ServerState = { meta: { version: 0 }, queryResult: {} }
  const calls: RequestArgs[] = []
  const description: CollectionDescription = {
    id: 'c',
    type: ['Collection'],
    encryption
  }
  const zcapClient = {
    invocationSigner: { id: 'did:example:alice#key-1' },
    async request(args: RequestArgs) {
      calls.push(args)
      const path = new URL(args.url!).pathname
      const method = args.method ?? 'GET'
      if (path === '/space/s/c' && method === 'GET') {
        return ok(description)
      }
      if (path === '/space/s/c/meta' && method === 'GET') {
        return ok({ custom: state.meta.custom }, String(state.meta.version))
      }
      if (path === '/space/s/c/meta' && method === 'PUT') {
        state.collideOnce?.()
        const ifMatch = args.headers?.['if-match'] ?? args.headers?.['If-Match']
        if (ifMatch !== undefined && ifMatch !== String(state.meta.version)) {
          throw { status: 412, response: { status: 412 } }
        }
        state.meta = {
          custom: (args.json as { custom?: unknown }).custom,
          version: state.meta.version + 1
        }
        return ok({}, String(state.meta.version))
      }
      if (path === '/space/s/c/query' && method === 'POST') {
        return ok(state.queryResult)
      }
      throw { status: 404, response: { status: 404 } }
    }
  } as unknown as ConstructorParameters<typeof WasClient>[0]['zcapClient']
  const client = new WasClient({
    serverUrl: 'https://was.example',
    zcapClient,
    encryption: createEdvEncryption({ resolveKeys: async () => keys })
  })
  return { client, state, calls }
}

describe('Collection.declareIndex', () => {
  it('persists the schema in the encrypted metadata envelope', async () => {
    const fixture = await makeIndexableCollection()
    const { client, state } = serverFor(fixture)
    const schema = await client
      .space('s')
      .collection('c')
      .declareIndex({ attribute: 'content.type' })

    expect(schema).toEqual({
      revision: 1,
      indexes: [{ attribute: 'content.type', addedIn: 1 }]
    })
    // What the server holds is an opaque envelope, not the attribute name.
    expect(JSON.stringify(state.meta.custom)).not.toContain('content.type')
    expect((state.meta.custom as { jwe?: unknown }).jwe).toBeTruthy()
  })

  it('is idempotent: re-declaring the same index writes nothing', async () => {
    const fixture = await makeIndexableCollection()
    const { client, state } = serverFor(fixture)
    const collection = client.space('s').collection('c')
    await collection.declareIndex({ attribute: 'content.type' })
    const afterFirst = state.meta.version
    const schema = await collection.declareIndex({ attribute: 'content.type' })
    expect(state.meta.version).toBe(afterFirst)
    expect(schema.revision).toBe(1)
  })

  it('reconciles a concurrent declaration instead of erasing it', async () => {
    const fixture = await makeIndexableCollection()
    const { client, state } = serverFor(fixture)
    const rival = client.space('s').collection('c')
    // The first write loses the race: a rival declaration lands between this
    // handle's read and its conditional write.
    state.collideOnce = () => {
      state.collideOnce = undefined
      state.meta = {
        custom: state.meta.custom,
        version: state.meta.version + 1
      }
    }
    await rival.declareIndex({ attribute: 'content.type' })
    // The retry re-read the (now bumped) validator and wrote on top of it.
    expect(state.meta.version).toBeGreaterThan(1)

    const schema = await client
      .space('s')
      .collection('c')
      .declareIndex({ attribute: 'content.author' })
    expect(schema.indexes.map(entry => entry.attribute)).toEqual([
      'content.type',
      'content.author'
    ])
    expect(schema.revision).toBe(2)
    // The later attribute is marked as added later, so a querier knows matches
    // on it may be partial.
    expect(schema.indexes[1]!.addedIn).toBe(2)
  })

  it('refuses to redeclare an index with different uniqueness', async () => {
    const fixture = await makeIndexableCollection()
    const { client } = serverFor(fixture)
    const collection = client.space('s').collection('c')
    await collection.declareIndex({ attribute: 'content.slug', unique: true })
    await expect(
      collection.declareIndex({ attribute: 'content.slug' })
    ).rejects.toBeInstanceOf(ValidationError)
  })

  it('is discovered by a second handle, which then indexes its writes', async () => {
    const fixture = await makeIndexableCollection()
    const { client, state } = serverFor(fixture)
    await client
      .space('s')
      .collection('c')
      .declareIndex({ attribute: 'content.type' })

    // A fresh handle -- standing in for another app granted access later --
    // learns what is searchable from the collection itself.
    const second = client.space('s').collection('c')
    expect(await second.indexes()).toEqual([
      { attribute: 'content.type', addedIn: 1 }
    ])
    // And a query built on that handle blinds under the collection's key.
    state.queryResult = { documents: [], hasMore: false }
    await expect(
      second.find({ equals: { 'content.type': 'note' } })
    ).resolves.toEqual({ items: [], hasMore: false })
  })
})

describe('Collection.find', () => {
  it('posts the blinded-index profile and decrypts the documents', async () => {
    const fixture = await makeIndexableCollection()
    const { client, state, calls } = serverFor(fixture)
    const collection = client.space('s').collection('c')
    await collection.declareIndex({ attribute: 'content.type' })

    // Store a document the way a write would, and serve it back as the match.
    const codec = await makeCodec(fixture)
    codec.indexing!.applySchema({
      revision: 1,
      indexes: [{ attribute: 'content.type', addedIn: 1 }]
    })
    const encoded = await codec.encode({
      data: { type: 'note', body: 'hello' }
    })
    const envelope = envelopeOf(encoded.body)
    state.queryResult = {
      documents: [envelope],
      hasMore: true,
      cursor: 'next-page'
    }

    const page = await collection.find({
      equals: { 'content.type': 'note' },
      limit: 10
    })
    expect(page).toEqual({
      items: [{ id: envelope.id, data: { type: 'note', body: 'hello' } }],
      hasMore: true,
      cursor: 'next-page'
    })
    const query = calls.at(-1)!.json as Record<string, unknown>
    expect(query.profile).toBe('blinded-index')
    expect(query.index).toBe(fixture.encryption.hmac!.id)
    expect(query.limit).toBe(10)
    expect(JSON.stringify(query)).not.toContain('content.type')
  })

  it('returns a bare count when asked for one', async () => {
    const fixture = await makeIndexableCollection()
    const { client, state, calls } = serverFor(fixture)
    const collection = client.space('s').collection('c')
    await collection.declareIndex({ attribute: 'content.type' })
    state.queryResult = { count: 7 }

    await expect(
      collection.find({ equals: { 'content.type': 'note' }, count: true })
    ).resolves.toEqual({ count: 7 })
    expect((calls.at(-1)!.json as { count?: boolean }).count).toBe(true)
  })

  it('refuses an attribute the collection never declared', async () => {
    const fixture = await makeIndexableCollection()
    const { client } = serverFor(fixture)
    const collection = client.space('s').collection('c')
    await collection.declareIndex({ attribute: 'content.type' })
    await expect(
      collection.find({ equals: { 'content.author': 'alice' } })
    ).rejects.toThrow(/content\.author/)
  })

  it('refuses find() and declareIndex() on a plaintext collection', async () => {
    const fixture = await makeIndexableCollection()
    const { client } = serverFor(fixture)
    const plaintext = client
      .space('s')
      .collection('c', { encryption: 'plaintext' })
    await expect(
      plaintext.find({ equals: { 'content.type': 'note' } })
    ).rejects.toBeInstanceOf(ValidationError)
    await expect(
      plaintext.declareIndex({ attribute: 'content.type' })
    ).rejects.toBeInstanceOf(ValidationError)
  })
})

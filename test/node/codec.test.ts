/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Unit tests for the resource codec seam. Verify that:
 *  - a client with no `EncryptionProvider` behaves exactly as before (identity);
 *  - a per-handle encryption override marks the collection encrypted and binds
 *    the injected codec -- with no backend round-trip (encryption is a
 *    per-collection client concern, not a backend capability);
 *  - a bound codec's `encode`/`decode` are actually invoked on write/read, and a
 *    codec that mints an id turns `add()` from a POST into a PUT;
 *  - `setMeta`/`setName`/`setTags` throw when the codec forbids server metadata.
 *
 * A stub `ZcapClient` routes by URL, recording every call, so no signer or
 * server is involved.
 */
import { describe, it, expect } from 'vitest'

import type { HttpResponse } from '@interop/http-client'
import { WasClient, ValidationError, EncryptionError } from '../../src/index.js'
import type {
  CollectionEncryption,
  EncryptionProvider,
  ResourceCodec,
  EncodedWrite
} from '../../src/index.js'

interface RequestArgs {
  url?: string
  method?: string
  json?: unknown
  body?: unknown
  headers?: Record<string, string>
}

/**
 * Builds a `WasClient` over a stub `ZcapClient` that records every request and
 * routes by URL. A GET returns `readData` (with `readContentType`); writes
 * return an empty 204-ish response. (No `/backend` route: the keys switch never
 * probes the backend.)
 *
 * @param options {object}
 * @param [options.encryption] {EncryptionProvider}
 * @param [options.readData] {unknown}            body for a resource GET
 * @param [options.readContentType] {string}      content-type for a resource GET
 * @returns {object} { client, calls }
 */
function clientWithRouter({
  encryption,
  readData,
  readContentType = 'application/json',
  readEtag,
  writeEtag,
  readStatus = 200,
  marker
}: {
  encryption?: EncryptionProvider
  readData?: unknown
  readContentType?: string
  readEtag?: string
  writeEtag?: string
  readStatus?: number
  /** When set, a collection-description GET (`/space/{s}/{c}`) carries it. */
  marker?: CollectionEncryption
} = {}): { client: WasClient; calls: RequestArgs[] } {
  const calls: RequestArgs[] = []
  const zcapClient = {
    invocationSigner: { id: 'did:example:alice#key-1' },
    async request(args: RequestArgs) {
      calls.push(args)
      const isGet = (args.method ?? 'GET').toUpperCase() === 'GET'
      if (isGet) {
        if (readStatus === 404) {
          throw { status: 404, response: { status: 404 } }
        }
        // A collection-description GET (`/space/{spaceId}/{collectionId}`, three
        // path segments) drives marker discovery; carry the marker when set.
        const segments = new URL(args.url ?? '').pathname
          .split('/')
          .filter(Boolean)
        if (segments.length === 3 && segments[0] === 'space') {
          const description = {
            id: segments[2],
            type: ['Collection'],
            ...(marker && { encryption: marker })
          }
          return {
            status: 200,
            headers: new Headers({ 'content-type': 'application/json' }),
            data: description,
            async json() {
              return description
            }
          } as unknown as HttpResponse
        }
        return {
          status: readStatus,
          headers: new Headers({
            'content-type': readContentType,
            ...(readEtag && { etag: readEtag })
          }),
          data: readData,
          async json() {
            return readData
          },
          async blob() {
            return new Blob([], { type: readContentType })
          }
        } as unknown as HttpResponse
      }
      // Writes (PUT/POST): echo a created id for POST.
      return {
        status: 200,
        headers: new Headers(writeEtag ? { etag: writeEtag } : {}),
        data: { id: 'server-minted' },
        async json() {
          return { id: 'server-minted' }
        }
      } as unknown as HttpResponse
    }
  } as unknown as ConstructorParameters<typeof WasClient>[0]['zcapClient']
  const client = new WasClient({
    serverUrl: 'https://was.example',
    zcapClient,
    encryption
  })
  return { client, calls }
}

/**
 * A fake encrypting codec that records its calls and mints a fixed id, so the
 * tests can assert routing without any real crypto.
 */
function fakeCodec(
  log: string[],
  { allowsServerMetadata = false }: { allowsServerMetadata?: boolean } = {}
): ResourceCodec {
  return {
    allowsServerMetadata,
    async encode({ id, data }): Promise<EncodedWrite> {
      log.push(`encode:${id ?? 'mint'}`)
      return {
        id: id ?? 'zMintedEdvId',
        body: new TextEncoder().encode(JSON.stringify({ jwe: data })),
        contentType: 'application/jose+json'
      }
    },
    async decode(): Promise<{ decrypted: true }> {
      log.push('decode')
      return { decrypted: true }
    }
  }
}

describe('codec seam: no provider (plaintext, unchanged)', () => {
  it('add() POSTs to the items path and never probes the backend', async () => {
    const { client, calls } = clientWithRouter()
    const result = await client
      .space('s')
      .collection('c')
      .add({ hello: 'world' })
    expect(calls.every(call => !call.url?.endsWith('/backend'))).toBe(true)
    expect(calls[0]?.method).toBe('POST')
    expect(calls[0]?.url).toBe('https://was.example/space/s/c/')
    expect(result.id).toBe('server-minted')
  })

  it('put() PUTs JSON to the resource path', async () => {
    const { client, calls } = clientWithRouter()
    await client.space('s').collection('c').put('r', { hello: 'world' })
    expect(calls[0]?.method).toBe('PUT')
    expect(calls[0]?.url).toBe('https://was.example/space/s/c/r')
    expect(calls[0]?.json).toEqual({ hello: 'world' })
  })
})

describe('codec seam: encryption override binds the codec (no backend probe)', () => {
  it('uses identity for an unmarked collection with no override', async () => {
    const encryption: EncryptionProvider = {
      async codecFor() {
        return fakeCodec([])
      }
    }
    // No override and (the GET marker resolves undefined) no marker => identity,
    // so the provider's codecFor is never reached and the write stays plaintext.
    const { client, calls } = clientWithRouter({ encryption })
    await client.space('s').collection('c').put('r', { hello: 'world' })
    const write = calls.find(call => call.method === 'PUT')
    expect(write?.json).toEqual({ hello: 'world' }) // plaintext JSON
  })

  it('binds the codec under an override -- with no backend round-trip', async () => {
    const log: string[] = []
    const encryption: EncryptionProvider = {
      async codecFor() {
        return fakeCodec(log)
      }
    }
    const { client, calls } = clientWithRouter({ encryption })
    // The override marks the collection encrypted and skips marker discovery.
    // add(): codec mints an id, so the write is a PUT to that id, not a POST.
    const result = await client
      .space('s')
      .collection('c', { encryption: { scheme: 'edv' } })
      .add({ secret: 1 })
    expect(log).toContain('encode:mint')
    expect(result.id).toBe('zMintedEdvId')
    const write = calls.find(call => call.method === 'PUT')
    expect(write?.url).toBe('https://was.example/space/s/c/zMintedEdvId')
    expect(write?.headers?.['content-type']).toBe('application/jose+json')
    expect(write?.body).toBeInstanceOf(Uint8Array)
    // The override skips both the backend probe and marker discovery: no GET.
    expect(calls.every(call => !call.url?.endsWith('/backend'))).toBe(true)
    expect(calls.some(call => (call.method ?? 'GET') === 'GET')).toBe(false)
  })

  it('decodes reads through the bound codec', async () => {
    const log: string[] = []
    const encryption: EncryptionProvider = {
      async codecFor() {
        return fakeCodec(log)
      }
    }
    const { client } = clientWithRouter({
      encryption,
      readData: { jwe: 'ciphertext' },
      readContentType: 'application/jose+json'
    })
    const value = await client
      .space('s')
      .collection('c', { encryption: { scheme: 'edv' } })
      .get('zDoc')
    expect(log).toContain('decode')
    expect(value).toEqual({ decrypted: true })
  })

  it('resolves the codec once and reuses it across resource handles', async () => {
    let resolveCount = 0
    const log: string[] = []
    const encryption: EncryptionProvider = {
      async codecFor() {
        resolveCount++
        return fakeCodec(log)
      }
    }
    const { client } = clientWithRouter({ encryption })
    const collection = client
      .space('s')
      .collection('c', { encryption: { scheme: 'edv' } })
    await collection.put('a', { n: 1 })
    await collection.put('b', { n: 2 })
    await collection.get('a')
    expect(resolveCount).toBe(1)
  })
})

describe('codec seam: policy resolution (override > marker > plaintext)', () => {
  it('discovers the marker and binds the codec (no override)', async () => {
    const log: string[] = []
    const encryption: EncryptionProvider = {
      async codecFor() {
        return fakeCodec(log)
      }
    }
    const { client, calls } = clientWithRouter({
      encryption,
      marker: { scheme: 'edv' }
    })
    // No override: the collection-description GET reveals the marker, which
    // binds the codec; the write is then an encrypted PUT (bytes, not JSON).
    await client.space('s').collection('c').put('zDoc', { secret: 1 })
    const markerGet = calls.find(
      call =>
        (call.method ?? 'GET') === 'GET' &&
        call.url === 'https://was.example/space/s/c'
    )
    expect(markerGet).toBeTruthy()
    expect(log).toContain('encode:zDoc')
    const write = calls.find(call => call.method === 'PUT')
    expect(write?.body).toBeInstanceOf(Uint8Array)
    expect(write?.json).toBeUndefined()
  })

  it("a 'plaintext' override beats a marker (and skips discovery)", async () => {
    const log: string[] = []
    const encryption: EncryptionProvider = {
      async codecFor() {
        log.push('codecFor')
        return fakeCodec(log)
      }
    }
    const { client, calls } = clientWithRouter({
      encryption,
      marker: { scheme: 'edv' }
    })
    await client
      .space('s')
      .collection('c', { encryption: 'plaintext' })
      .put('r', { hello: 'world' })
    const write = calls.find(call => call.method === 'PUT')
    expect(write?.json).toEqual({ hello: 'world' }) // plaintext, not encrypted
    expect(log).not.toContain('codecFor') // provider never consulted
    expect(calls.some(call => (call.method ?? 'GET') === 'GET')).toBe(false)
  })

  it('fails closed when an override declares encryption but no keys are held', async () => {
    const encryption: EncryptionProvider = {
      async codecFor() {
        return null // keystore holds no keys for this collection
      }
    }
    const { client } = clientWithRouter({ encryption })
    await expect(
      client
        .space('s')
        .collection('c', { encryption: { scheme: 'edv' } })
        .put('zDoc', { secret: 1 })
    ).rejects.toThrow(EncryptionError)
  })

  it('fails closed when a marker declares encryption but no keys are held', async () => {
    const encryption: EncryptionProvider = {
      async codecFor() {
        return null
      }
    }
    const { client } = clientWithRouter({
      encryption,
      marker: { scheme: 'edv' }
    })
    await expect(client.space('s').collection('c').get('zDoc')).rejects.toThrow(
      EncryptionError
    )
  })

  it('fails closed when encrypted but no provider is configured at all', async () => {
    const { client } = clientWithRouter() // no encryption provider
    await expect(
      client
        .space('s')
        .collection('c', { encryption: { scheme: 'edv' } })
        .put('zDoc', { secret: 1 })
    ).rejects.toThrow(EncryptionError)
  })

  it('fails closed when the marker is unreadable (no fail-open to plaintext)', async () => {
    // An encryption-capable client whose collection-description GET 404s (the
    // resource-scoped-capability case WAS masks as not-found). The marker is
    // ambiguous, so resolveCodec must refuse rather than write plaintext.
    const log: string[] = []
    const encryption: EncryptionProvider = {
      async codecFor() {
        log.push('codecFor')
        return fakeCodec(log)
      }
    }
    const { client, calls } = clientWithRouter({ encryption, readStatus: 404 })
    await expect(
      client.space('s').collection('c').put('zDoc', { secret: 1 })
    ).rejects.toThrow(EncryptionError)
    // It must not have fallen back and written the plaintext secret.
    expect(calls.some(call => call.method === 'PUT')).toBe(false)
    expect(log).not.toContain('codecFor')
  })

  it("a 'plaintext' override is the documented escape hatch for an unreadable marker", async () => {
    const encryption: EncryptionProvider = {
      async codecFor() {
        return fakeCodec([])
      }
    }
    const { client, calls } = clientWithRouter({ encryption, readStatus: 404 })
    // The override skips marker discovery, so the same unreadable-marker case
    // writes plaintext deliberately rather than throwing.
    await client
      .space('s')
      .collection('c', { encryption: 'plaintext' })
      .put('r', { hello: 'world' })
    const write = calls.find(call => call.method === 'PUT')
    expect(write?.json).toEqual({ hello: 'world' })
  })
})

describe('codec seam: configure() invalidates the memoized codec', () => {
  /**
   * Builds a client over a stub whose collection is plaintext until a
   * `configure` PUT carrying an `encryption` body flips it encrypted. The marker
   * GET reflects the current server-side state, so a codec memoized while
   * plaintext is stale once encryption is enabled.
   *
   * @returns {object} { client, calls }
   */
  function flippableClient(): { client: WasClient; calls: RequestArgs[] } {
    const calls: RequestArgs[] = []
    let encrypted = false
    const log: string[] = []
    const encryption: EncryptionProvider = {
      async codecFor() {
        return fakeCodec(log)
      }
    }
    const zcapClient = {
      invocationSigner: { id: 'did:example:alice#key-1' },
      async request(args: RequestArgs) {
        calls.push(args)
        const method = (args.method ?? 'GET').toUpperCase()
        const segments = new URL(args.url ?? '').pathname
          .split('/')
          .filter(Boolean)
        const isCollectionDescription =
          segments.length === 3 && segments[0] === 'space'
        // A configure PUT to the collection description with an `encryption`
        // body flips the server-side marker on.
        if (
          method === 'PUT' &&
          isCollectionDescription &&
          (args.json as { encryption?: unknown } | undefined)?.encryption
        ) {
          encrypted = true
        }
        if (method === 'GET' && isCollectionDescription) {
          const description = {
            id: segments[2],
            type: ['Collection'],
            ...(encrypted && { encryption: { scheme: 'edv' } })
          }
          return {
            status: 200,
            headers: new Headers({ 'content-type': 'application/json' }),
            data: description,
            async json() {
              return description
            }
          } as unknown as HttpResponse
        }
        return {
          status: 200,
          headers: new Headers({ 'content-type': 'application/json' }),
          data: { id: 'server-minted' },
          async json() {
            return { id: 'server-minted' }
          }
        } as unknown as HttpResponse
      }
    } as unknown as ConstructorParameters<typeof WasClient>[0]['zcapClient']
    const client = new WasClient({
      serverUrl: 'https://was.example',
      zcapClient,
      encryption
    })
    return { client, calls }
  }

  it('re-resolves the codec after configure() enables encryption', async () => {
    const { client, calls } = flippableClient()
    const collection = client.space('s').collection('c')
    // A read while plaintext memoizes the identity codec.
    await collection.get('r')
    // Enabling encryption must drop that cached codec.
    await collection.configure({ encryption: { scheme: 'edv' } })
    await collection.put('r', { secret: 1 })
    const write = calls.find(
      call => call.method === 'PUT' && call.url?.endsWith('/c/r')
    )
    // The re-resolved encrypting codec writes bytes, not plaintext JSON.
    expect(write?.body).toBeInstanceOf(Uint8Array)
    expect(write?.json).toBeUndefined()
  })

  it('the invalidation propagates to a child resource handle', async () => {
    const { client, calls } = flippableClient()
    const collection = client.space('s').collection('c')
    const resource = collection.resource('r')
    // The child handle reads while plaintext, caching the identity codec via the
    // parent's shared thunk.
    await resource.get()
    await collection.configure({ encryption: { scheme: 'edv' } })
    await resource.put({ secret: 1 })
    const write = calls.find(
      call => call.method === 'PUT' && call.url?.endsWith('/c/r')
    )
    expect(write?.body).toBeInstanceOf(Uint8Array)
    expect(write?.json).toBeUndefined()
  })
})

describe('codec seam: a transient marker-read failure does not poison the handle', () => {
  /**
   * Builds a client whose collection-description GET (marker discovery) throws a
   * transient 500 on its first call and succeeds (revealing the marker) on every
   * call after. Resource writes succeed. This exercises the codec memo: a
   * rejected resolution must not be cached, so the next call retries.
   *
   * @returns {object} { client, calls }
   */
  function flakyMarkerClient(): { client: WasClient; calls: RequestArgs[] } {
    const calls: RequestArgs[] = []
    let markerGets = 0
    const log: string[] = []
    const encryption: EncryptionProvider = {
      async codecFor() {
        return fakeCodec(log)
      }
    }
    const zcapClient = {
      invocationSigner: { id: 'did:example:alice#key-1' },
      async request(args: RequestArgs) {
        calls.push(args)
        const method = (args.method ?? 'GET').toUpperCase()
        const segments = new URL(args.url ?? '').pathname
          .split('/')
          .filter(Boolean)
        const isCollectionDescription =
          segments.length === 3 && segments[0] === 'space'
        if (method === 'GET' && isCollectionDescription) {
          markerGets++
          if (markerGets === 1) {
            // Transient server failure during marker discovery.
            throw { status: 500, response: { status: 500 } }
          }
          const description = {
            id: segments[2],
            type: ['Collection'],
            encryption: { scheme: 'edv' }
          }
          return {
            status: 200,
            headers: new Headers({ 'content-type': 'application/json' }),
            data: description,
            async json() {
              return description
            }
          } as unknown as HttpResponse
        }
        return {
          status: 200,
          headers: new Headers({ 'content-type': 'application/json' }),
          data: { id: 'server-minted' },
          async json() {
            return { id: 'server-minted' }
          }
        } as unknown as HttpResponse
      }
    } as unknown as ConstructorParameters<typeof WasClient>[0]['zcapClient']
    const client = new WasClient({
      serverUrl: 'https://was.example',
      zcapClient,
      encryption
    })
    return { client, calls }
  }

  it('retries marker discovery after a transient failure (same handle)', async () => {
    const { client, calls } = flakyMarkerClient()
    const collection = client.space('s').collection('c')
    // First call: the marker GET 500s, so the resolution rejects and must throw.
    await expect(collection.put('r', { secret: 1 })).rejects.toThrow()
    // The transient failure must not be cached: a retry re-runs marker discovery,
    // resolves the encrypting codec, and writes encrypted bytes (not plaintext).
    await collection.put('r', { secret: 1 })
    const write = calls.find(
      call => call.method === 'PUT' && call.url?.endsWith('/c/r')
    )
    expect(write?.body).toBeInstanceOf(Uint8Array)
    expect(write?.json).toBeUndefined()
  })
})

describe('codec seam: encrypted metadata is forbidden', () => {
  it('setMeta throws a ValidationError on an encrypted collection', async () => {
    const encryption: EncryptionProvider = {
      async codecFor() {
        return fakeCodec([])
      }
    }
    const { client } = clientWithRouter({ encryption })
    const resource = client
      .space('s')
      .collection('c', { encryption: { scheme: 'edv' } })
      .resource('zDoc')
    await expect(resource.setMeta({ custom: { name: 'x' } })).rejects.toThrow(
      ValidationError
    )
    await expect(resource.setName('x')).rejects.toThrow(ValidationError)
    await expect(resource.setTags({ a: 'b' })).rejects.toThrow(ValidationError)
  })

  it('setMeta still works on a plaintext (no-provider) collection', async () => {
    const { client, calls } = clientWithRouter()
    await client
      .space('s')
      .collection('c')
      .resource('r')
      .setMeta({ custom: { name: 'ok' } })
    const write = calls.find(call => call.method === 'PUT')
    expect(write?.json).toEqual({ custom: { name: 'ok' } })
  })
})

/**
 * A fake conditional codec: declares `conditionalWrites`, derives its `ifMatch`
 * from the pre-read `current` ETag (or `ifNoneMatch` for a fresh write), so the
 * handle-level wiring (pre-read GET, then PUT with the precondition) can be
 * asserted without real crypto.
 */
function conditionalFakeCodec(log: string[]): ResourceCodec {
  return {
    allowsServerMetadata: false,
    conditionalWrites: true,
    async encode({ id, data, current }): Promise<EncodedWrite> {
      const etag = current?.headers.get('etag') ?? undefined
      log.push(`encode:${id ?? 'mint'}:etag=${etag ?? 'none'}`)
      return {
        id: id ?? 'zMintedEdvId',
        body: new TextEncoder().encode(JSON.stringify({ jwe: data })),
        contentType: 'application/jose+json',
        ...(etag ? { ifMatch: etag } : { ifNoneMatch: true })
      }
    },
    async decode(): Promise<{ decrypted: true }> {
      return { decrypted: true }
    }
  }
}

describe('conditional writes: plaintext handle options', () => {
  it('put forwards ifMatch as an If-Match header', async () => {
    const { client, calls } = clientWithRouter()
    await client
      .space('s')
      .collection('c')
      .put('r', { hello: 'world' }, { ifMatch: '"3"' })
    const write = calls.find(call => call.method === 'PUT')
    expect(write?.headers?.['if-match']).toBe('"3"')
    expect(write?.headers?.['if-none-match']).toBeUndefined()
  })

  it('put forwards ifNoneMatch as If-None-Match: *', async () => {
    const { client, calls } = clientWithRouter()
    await client
      .space('s')
      .collection('c')
      .put('r', { hello: 'world' }, { ifNoneMatch: true })
    const write = calls.find(call => call.method === 'PUT')
    expect(write?.headers?.['if-none-match']).toBe('*')
  })

  it('a plaintext put does not pre-read (no conditional codec)', async () => {
    const { client, calls } = clientWithRouter()
    await client.space('s').collection('c').put('r', { hello: 'world' })
    expect(calls.some(call => call.method === 'GET')).toBe(false)
  })

  it('put returns the new ETag from the write response', async () => {
    const { client } = clientWithRouter({ writeEtag: '"7"' })
    const result = await client
      .space('s')
      .collection('c')
      .put('r', { hello: 'world' })
    expect(result.etag).toBe('"7"')
  })

  it('delete forwards ifMatch as an If-Match header', async () => {
    const { client, calls } = clientWithRouter()
    await client
      .space('s')
      .collection('c')
      .resource('r')
      .delete({ ifMatch: '"4"' })
    const del = calls.find(call => call.method === 'DELETE')
    expect(del?.headers?.['if-match']).toBe('"4"')
  })

  it('meta surfaces the ETag from the response header', async () => {
    const { client } = clientWithRouter({
      readData: { contentType: 'application/json', size: 2 },
      readEtag: '"9"'
    })
    const meta = await client.space('s').collection('c').resource('r').meta()
    expect(meta?.etag).toBe('"9"')
  })
})

describe('conditional writes: conditional codec wiring', () => {
  it('pre-reads the current resource and pins If-Match to its ETag', async () => {
    const log: string[] = []
    const encryption: EncryptionProvider = {
      async codecFor() {
        return conditionalFakeCodec(log)
      }
    }
    const { client, calls } = clientWithRouter({
      encryption,
      readData: { jwe: 'prior' },
      readContentType: 'application/jose+json',
      readEtag: '"5"'
    })
    await client
      .space('s')
      .collection('c', { encryption: { scheme: 'edv' } })
      .put('zDoc', { secret: 1 })

    // A GET precedes the PUT, and the codec's If-Match (the read ETag) is sent.
    const getIndex = calls.findIndex(call => (call.method ?? 'GET') === 'GET')
    const putIndex = calls.findIndex(call => call.method === 'PUT')
    expect(getIndex).toBeGreaterThanOrEqual(0)
    expect(putIndex).toBeGreaterThan(getIndex)
    expect(log).toContain('encode:zDoc:etag="5"')
    expect(calls[putIndex]?.headers?.['if-match']).toBe('"5"')
  })

  it('guards a first write (absent resource) with If-None-Match: *', async () => {
    const log: string[] = []
    const encryption: EncryptionProvider = {
      async codecFor() {
        return conditionalFakeCodec(log)
      }
    }
    const { client, calls } = clientWithRouter({
      encryption,
      readStatus: 404
    })
    await client
      .space('s')
      .collection('c', { encryption: { scheme: 'edv' } })
      .put('zDoc', { secret: 1 })
    const write = calls.find(call => call.method === 'PUT')
    expect(log).toContain('encode:zDoc:etag=none')
    expect(write?.headers?.['if-none-match']).toBe('*')
  })
})

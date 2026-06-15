/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Unit tests for the resource codec seam. Verify that:
 *  - a client with no `EncryptionProvider` behaves exactly as before (identity);
 *  - the keys switch binds an injected codec iff the provider returns one for the
 *    collection -- with no backend round-trip (encryption is a per-collection
 *    client concern, not a backend capability);
 *  - a bound codec's `encode`/`decode` are actually invoked on write/read, and a
 *    codec that mints an id turns `add()` from a POST into a PUT;
 *  - `setMeta`/`setName`/`setTags` throw when the codec forbids server metadata.
 *
 * A stub `ZcapClient` routes by URL, recording every call, so no signer or
 * server is involved.
 */
import { describe, it, expect } from 'vitest'

import type { HttpResponse } from '@interop/http-client'
import { WasClient, ValidationError } from '../../src/index.js'
import type {
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
  readStatus = 200
}: {
  encryption?: EncryptionProvider
  readData?: unknown
  readContentType?: string
  readEtag?: string
  writeEtag?: string
  readStatus?: number
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
        contentType: 'application/edv+json'
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

describe('codec seam: keys switch (no backend probe)', () => {
  it('uses identity when the provider returns null', async () => {
    const encryption: EncryptionProvider = {
      async resolveCodec() {
        return null
      }
    }
    const { client, calls } = clientWithRouter({ encryption })
    await client.space('s').collection('c').put('r', { hello: 'world' })
    const write = calls.find(call => call.method === 'PUT')
    expect(write?.json).toEqual({ hello: 'world' }) // plaintext JSON
  })

  it('binds the codec when the provider returns one -- with no backend round-trip', async () => {
    const log: string[] = []
    const encryption: EncryptionProvider = {
      async resolveCodec() {
        return fakeCodec(log)
      }
    }
    const { client, calls } = clientWithRouter({ encryption })
    // add(): codec mints an id, so the write is a PUT to that id, not a POST.
    const result = await client.space('s').collection('c').add({ secret: 1 })
    expect(log).toContain('encode:mint')
    expect(result.id).toBe('zMintedEdvId')
    const write = calls.find(call => call.method === 'PUT')
    expect(write?.url).toBe('https://was.example/space/s/c/zMintedEdvId')
    expect(write?.headers?.['content-type']).toBe('application/edv+json')
    expect(write?.body).toBeInstanceOf(Uint8Array)
    // The switch is keys alone: resolving the codec never reads the backend.
    expect(calls.every(call => !call.url?.endsWith('/backend'))).toBe(true)
  })

  it('decodes reads through the bound codec', async () => {
    const log: string[] = []
    const encryption: EncryptionProvider = {
      async resolveCodec() {
        return fakeCodec(log)
      }
    }
    const { client } = clientWithRouter({
      encryption,
      readData: { jwe: 'ciphertext' },
      readContentType: 'application/edv+json'
    })
    const value = await client.space('s').collection('c').get('zDoc')
    expect(log).toContain('decode')
    expect(value).toEqual({ decrypted: true })
  })

  it('resolves the codec once and reuses it across resource handles', async () => {
    let resolveCount = 0
    const log: string[] = []
    const encryption: EncryptionProvider = {
      async resolveCodec() {
        resolveCount++
        return fakeCodec(log)
      }
    }
    const { client } = clientWithRouter({ encryption })
    const collection = client.space('s').collection('c')
    await collection.put('a', { n: 1 })
    await collection.put('b', { n: 2 })
    await collection.get('a')
    expect(resolveCount).toBe(1)
  })
})

describe('codec seam: encrypted metadata is forbidden', () => {
  it('setMeta throws a ValidationError on an encrypted collection', async () => {
    const encryption: EncryptionProvider = {
      async resolveCodec() {
        return fakeCodec([])
      }
    }
    const { client } = clientWithRouter({ encryption })
    const resource = client.space('s').collection('c').resource('zDoc')
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
        contentType: 'application/edv+json',
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
      async resolveCodec() {
        return conditionalFakeCodec(log)
      }
    }
    const { client, calls } = clientWithRouter({
      encryption,
      readData: { jwe: 'prior' },
      readContentType: 'application/edv+json',
      readEtag: '"5"'
    })
    await client.space('s').collection('c').put('zDoc', { secret: 1 })

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
      async resolveCodec() {
        return conditionalFakeCodec(log)
      }
    }
    const { client, calls } = clientWithRouter({
      encryption,
      readStatus: 404
    })
    await client.space('s').collection('c').put('zDoc', { secret: 1 })
    const write = calls.find(call => call.method === 'PUT')
    expect(log).toContain('encode:zDoc:etag=none')
    expect(write?.headers?.['if-none-match']).toBe('*')
  })
})

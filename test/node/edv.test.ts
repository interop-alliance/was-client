/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Unit tests for the EDV-over-WAS transport mapping. These stub the WAS signed-
 * request layer (no network, no crypto) and assert that `WasTransport` maps EDV
 * `insert` / `update` / `get` onto the right WAS method + resource path +
 * content type, and normalizes server responses into the
 * error names `EdvClientCore` dispatches on (`DuplicateError`,
 * `InvalidStateError`, `NotFoundError`). They also cover the blinded-index
 * `find` query (method + path + body shape + verbatim response), the chunked
 * stream methods, and `updateIndex`, which stays unsupported in this profile
 * (index entries ride inside the stored envelope) and throws
 * `NotSupportedError`.
 */
import { describe, it, expect, vi } from 'vitest'
import type { HttpResponse } from '@interop/http-client'
import type {
  IEDVChunk,
  IEncryptedDocument
} from '@interop/data-integrity-core'

import { WasTransport, JOSE_CONTENT_TYPE } from '../../src/edv/index.js'

/**
 * A minimal encrypted-document fixture (the envelope shape a WAS server stores).
 */
function encryptedDoc(id = 'zDocId1'): IEncryptedDocument {
  return {
    id,
    sequence: 0,
    jwe: { ciphertext: 'AAAA' } as IEncryptedDocument['jwe'],
    indexed: []
  }
}

/**
 * Builds an error shaped like the raw ky/ezcap rejection (a flat `status`).
 *
 * @param status {number}
 * @returns {Error}
 */
function httpError(status: number): Error {
  return Object.assign(new Error(`HTTP ${status}`), { status })
}

/**
 * Decodes a `RequestInput.body` (the serialized envelope) back to an object.
 *
 * @param body {unknown}
 * @returns {Record<string, unknown>}
 */
function decodeBody(body: unknown): Record<string, unknown> {
  return JSON.parse(new TextDecoder().decode(body as Uint8Array))
}

/**
 * Builds a read-response stub carrying `body` as the http-client's pre-parsed
 * `data` (what `readJsonData` reads first), cast to `HttpResponse`.
 *
 * @param body {unknown}   the JSON body to expose as `response.data`
 * @returns {HttpResponse}
 */
function dataResponse(body: unknown): HttpResponse {
  return { data: body } as unknown as HttpResponse
}

/**
 * Builds a write-response stub: bodiless, carrying the `ETag` validator a
 * server acks a write with (none by default, for a test that does not care).
 * The transport reads it to surface its last document write.
 *
 * @param [etag] {string}   the validator to return, if any
 * @returns {HttpResponse}
 */
function writeResponse(etag?: string): HttpResponse {
  return {
    headers: {
      get: (name: string) => (name === 'etag' ? (etag ?? null) : null)
    }
  } as unknown as HttpResponse
}

function transport(request: ReturnType<typeof vi.fn>, contentType?: string) {
  return new WasTransport({
    was: { request } as never,
    spaceId: 'space 1',
    collectionId: 'docs',
    contentType
  })
}

describe('WasTransport -- insert', () => {
  /**
   * A request stub whose PUT answers `putStatus` (or succeeds when undefined).
   *
   * @param [putStatus] {number}   status the PUT fails with
   * @returns {ReturnType<typeof vi.fn>}
   */
  function insertRequest(putStatus?: number) {
    return vi.fn(async (_input: { method?: string }) => {
      if (putStatus !== undefined) {
        throw httpError(putStatus)
      }
      return writeResponse()
    })
  }

  it('inserts with a single atomic PUT + If-None-Match: *', async () => {
    const request = insertRequest()
    await transport(request).insert({ encrypted: encryptedDoc('zAbc') })
    const methods = request.mock.calls.map(
      ([input]) => (input as { method?: string }).method
    )
    // One PUT and nothing else -- no descriptor probe, no HEAD pre-check.
    expect(methods).toEqual(['PUT'])
    const put = request.mock.calls.at(-1)![0] as Record<string, unknown>
    expect((put.headers as Record<string, string>)['if-none-match']).toBe('*')
  })

  it('PUTs the envelope as application/json (default) at the resource path', async () => {
    const request = insertRequest()
    const doc = encryptedDoc('zAbc')
    await transport(request).insert({ encrypted: doc })
    const put = request.mock.calls.at(-1)![0] as Record<string, unknown>
    expect(put.method).toBe('PUT')
    expect(put.path).toBe('/space/space%201/docs/zAbc')
    expect((put.headers as Record<string, string>)['content-type']).toBe(
      'application/json'
    )
    expect(decodeBody(put.body)).toEqual(doc)
  })

  it('honors a custom content type (JOSE_CONTENT_TYPE)', async () => {
    const request = insertRequest()
    await transport(request, JOSE_CONTENT_TYPE).insert({
      encrypted: encryptedDoc('zEdv')
    })
    const put = request.mock.calls.at(-1)![0] as Record<string, unknown>
    expect((put.headers as Record<string, string>)['content-type']).toBe(
      JOSE_CONTENT_TYPE
    )
  })

  it('maps the 412 create-if-absent rejection to DuplicateError', async () => {
    const request = insertRequest(412)
    await expect(
      transport(request).insert({ encrypted: encryptedDoc() })
    ).rejects.toMatchObject({ name: 'DuplicateError' })
  })

  it('maps a 409 unique-attribute conflict to DuplicateError', async () => {
    const request = insertRequest(409)
    await expect(
      transport(request).insert({ encrypted: encryptedDoc() })
    ).rejects.toMatchObject({ name: 'DuplicateError' })
  })

  it('requires an encrypted document', async () => {
    await expect(transport(vi.fn()).insert()).rejects.toBeInstanceOf(TypeError)
  })
})

describe('WasTransport — update', () => {
  it('PUTs the envelope (upsert, no existence check)', async () => {
    const request = vi.fn(async (_input: Record<string, unknown>) =>
      writeResponse()
    )
    const doc = encryptedDoc('zUpd')
    await transport(request).update({ encrypted: doc })

    expect(request).toHaveBeenCalledOnce()
    const put = request.mock.calls[0]![0] as Record<string, unknown>
    expect(put.method).toBe('PUT')
    expect(put.path).toBe('/space/space%201/docs/zUpd')
    expect(decodeBody(put.body)).toEqual(doc)
  })

  it('maps a 412 stale-write conflict to InvalidStateError', async () => {
    const request = vi.fn(async () => {
      throw httpError(412)
    })
    await expect(
      transport(request).update({ encrypted: encryptedDoc() })
    ).rejects.toMatchObject({ name: 'InvalidStateError' })
  })

  it('maps a 409 unique-attribute conflict to DuplicateError', async () => {
    const request = vi.fn(async () => {
      throw httpError(409)
    })
    await expect(
      transport(request).update({ encrypted: encryptedDoc() })
    ).rejects.toMatchObject({ name: 'DuplicateError' })
  })
})

describe('WasTransport — get', () => {
  it('GETs and returns the parsed envelope', async () => {
    const doc = encryptedDoc('zGet')
    const request = vi.fn(async (_input: Record<string, unknown>) =>
      dataResponse(doc)
    )
    const result = await transport(request).get({ id: 'zGet' })

    expect(result).toEqual(doc)
    const get = request.mock.calls[0]![0] as Record<string, unknown>
    expect(get.method).toBe('GET')
    expect(get.path).toBe('/space/space%201/docs/zGet')
  })

  it('falls back to response.json() when data is absent', async () => {
    const doc = encryptedDoc('zJson')
    const request = vi.fn(
      async () => ({ json: async () => doc }) as unknown as HttpResponse
    )
    expect(await transport(request).get({ id: 'zJson' })).toEqual(doc)
  })

  it('throws NotFoundError on a 404', async () => {
    const request = vi.fn(async () => {
      throw httpError(404)
    })
    await expect(
      transport(request).get({ id: 'missing' })
    ).rejects.toMatchObject({ name: 'NotFoundError' })
  })
})

describe('WasTransport -- find (blinded-index query)', () => {
  /**
   * A request stub for the `find` path: the POST `/query` answers with `body`.
   *
   * @param body {object}   the server's query response body (POST /query)
   * @returns {ReturnType<typeof vi.fn>}
   */
  function queryRequest(body: object) {
    return vi.fn(async (_input: { method?: string }) => dataResponse(body))
  }

  /**
   * The POST `/query` call from a `find` request stub.
   *
   * @param request {ReturnType<typeof vi.fn>}
   * @returns {Record<string, unknown>}
   */
  function postCall(
    request: ReturnType<typeof vi.fn>
  ): Record<string, unknown> {
    return request.mock.calls.at(-1)![0] as Record<string, unknown>
  }

  it('POSTs the blinded query to the collection /query path', async () => {
    const request = queryRequest({ documents: [], hasMore: false })
    await transport(request).find({
      query: { index: 'urn:hmac:1', equals: [{ bName: 'bValue' }] }
    })

    const call = postCall(request)
    expect(call.method).toBe('POST')
    expect(call.path).toBe('/space/space%201/docs/query')
  })

  it('sends { profile: "blinded-index", ...query } as the json body', async () => {
    const request = queryRequest({ documents: [], hasMore: false })
    const query = {
      index: 'urn:hmac:1',
      equals: [{ bName: 'bValue' }],
      limit: 5
    }
    await transport(request).find({ query })

    expect(postCall(request).json).toEqual({
      profile: 'blinded-index',
      ...query
    })
  })

  it('returns a { documents, hasMore, cursor } response verbatim', async () => {
    const body = {
      documents: [encryptedDoc('zHit')],
      hasMore: true,
      cursor: 'opaque-cursor'
    }
    const result = await transport(queryRequest(body)).find({
      query: { index: 'urn:hmac:1', has: ['bName'] }
    })
    expect(result).toEqual(body)
  })

  it('returns a bare { count } response verbatim', async () => {
    const result = await transport(queryRequest({ count: 3 })).find({
      query: { index: 'urn:hmac:1', equals: [{ bName: 'bValue' }], count: true }
    })
    expect(result).toEqual({ count: 3 })
  })

  it('sends a cursor supplied in the query (native pagination)', async () => {
    const request = queryRequest({ documents: [], hasMore: false })
    await transport(request).find({
      query: {
        index: 'urn:hmac:1',
        equals: [{ bName: 'bValue' }],
        cursor: 'page-2'
      }
    })
    expect((postCall(request).json as Record<string, unknown>).cursor).toBe(
      'page-2'
    )
  })

  it('strips returnDocuments: false from the sent body and returns full documents', async () => {
    // No ids-only mode: `returnDocuments: false` is dropped like `true`, the
    // query proceeds, and full documents come back (the core's best-effort
    // degradation for this option).
    const body = { documents: [encryptedDoc('zHit')], hasMore: false }
    const request = queryRequest(body)
    const result = await transport(request).find({
      query: {
        index: 'urn:hmac:1',
        equals: [{ bName: 'bValue' }],
        returnDocuments: false
      }
    })
    expect(result).toEqual(body)
    expect(postCall(request).json).not.toHaveProperty('returnDocuments')
  })

  it('strips returnDocuments: true from the sent body', async () => {
    const request = queryRequest({ documents: [], hasMore: false })
    await transport(request).find({
      query: {
        index: 'urn:hmac:1',
        equals: [{ bName: 'bValue' }],
        returnDocuments: true
      }
    })
    const body = postCall(request).json as Record<string, unknown>
    expect(body).not.toHaveProperty('returnDocuments')
    expect(body).toEqual({
      profile: 'blinded-index',
      index: 'urn:hmac:1',
      equals: [{ bName: 'bValue' }]
    })
  })

  it('maps a 404 from the query POST to NotFoundError', async () => {
    const request = vi.fn(async () => {
      throw httpError(404) // POST /query
    })
    await expect(
      transport(request).find({
        query: { index: 'urn:hmac:1', has: ['bName'] }
      })
    ).rejects.toMatchObject({ name: 'NotFoundError' })
  })

  it('throws on a malformed (null) query response body', async () => {
    const request = queryRequest(null as unknown as object)
    await expect(
      transport(request).find({
        query: { index: 'urn:hmac:1', has: ['bName'] }
      })
    ).rejects.toThrow('Malformed blinded-index query response.')
  })

  it('throws a TypeError when no query is given', async () => {
    await expect(transport(vi.fn()).find()).rejects.toThrow(TypeError)
  })
})

describe('WasTransport -- updateIndex (unsupported, sharpened message)', () => {
  it('rejects with NotSupportedError pointing at update()', async () => {
    await expect(transport(vi.fn()).updateIndex()).rejects.toMatchObject({
      name: 'NotSupportedError',
      message: expect.stringMatching(/update\(\)/)
    })
  })
})

describe('WasTransport -- chunked streams (storeChunk / getChunk)', () => {
  const chunk = {
    sequence: 0,
    index: 2,
    offset: 4096,
    jwe: { ciphertext: 'opaque' }
  } as unknown as IEDVChunk

  /**
   * A request stub for the chunk paths: every request is handled by `handle`.
   *
   * @param handle {Function}   handles the chunk requests
   * @returns {ReturnType<typeof vi.fn>}
   */
  function chunkedRequest(
    handle: (input: { path?: string; method?: string }) => unknown
  ) {
    return vi.fn(async (input: { path?: string; method?: string }) =>
      handle(input)
    )
  }

  it('PUTs a serialized chunk to its own chunks/{index} URL as opaque bytes', async () => {
    const request = chunkedRequest(() => ({}) as HttpResponse)
    await transport(request).storeChunk({ docId: 'doc1', chunk })
    const put = request.mock.calls.at(-1)![0] as {
      path: string
      method: string
      body: unknown
      headers: Record<string, string>
    }
    expect(put.method).toBe('PUT')
    expect(put.path).toBe('/space/space%201/docs/doc1/chunks/2')
    expect(put.headers['content-type']).toBe('application/octet-stream')
    expect(decodeBody(put.body)).toEqual(chunk)
  })

  it('GETs and parses a chunk back into the EDV chunk object', async () => {
    const request = chunkedRequest(() => ({
      async text() {
        return JSON.stringify(chunk)
      }
    }))
    const read = await transport(request).getChunk({
      docId: 'doc1',
      chunkIndex: 2
    })
    expect(read).toEqual(chunk)
    const get = request.mock.calls.at(-1)![0] as {
      path: string
      method: string
    }
    expect(get.method).toBe('GET')
    expect(get.path).toBe('/space/space%201/docs/doc1/chunks/2')
  })

  it('maps a 404 on storeChunk (absent parent) to NotFoundError', async () => {
    const request = chunkedRequest(() => {
      throw httpError(404)
    })
    await expect(
      transport(request).storeChunk({ docId: 'gone', chunk })
    ).rejects.toMatchObject({ name: 'NotFoundError' })
  })

  it('maps a 404 on getChunk to NotFoundError', async () => {
    const request = chunkedRequest(() => {
      throw httpError(404)
    })
    await expect(
      transport(request).getChunk({ docId: 'doc1', chunkIndex: 9 })
    ).rejects.toMatchObject({ name: 'NotFoundError' })
  })

  it('requires docId and chunk', async () => {
    const t = transport(vi.fn())
    await expect(t.storeChunk()).rejects.toBeInstanceOf(TypeError)
    await expect(t.storeChunk({ docId: 'doc1' })).rejects.toBeInstanceOf(
      TypeError
    )
    await expect(t.getChunk()).rejects.toBeInstanceOf(TypeError)
    await expect(t.getChunk({ docId: 'doc1' })).rejects.toBeInstanceOf(
      TypeError
    )
  })
})

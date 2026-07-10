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
 * `find` query (method + path + body shape + verbatim response) and the
 * operations that stay unsupported in this profile -- `updateIndex` (index
 * entries ride inside the stored envelope) and the chunked-stream methods --
 * which throw `NotSupportedError`.
 */
import { describe, it, expect, vi } from 'vitest'
import type { HttpResponse } from '@interop/http-client'
import type { IEncryptedDocument } from '@interop/data-integrity-core'

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

function transport(request: ReturnType<typeof vi.fn>, contentType?: string) {
  return new WasTransport({
    was: { request } as never,
    spaceId: 'space 1',
    collectionId: 'docs',
    contentType
  })
}

describe('WasTransport — insert (advisory fallback, no conditional-writes)', () => {
  /**
   * A request stub for a backend WITHOUT the `conditional-writes` feature: the
   * backend-descriptor GET answers 404 (or 501-era servers -- any failure means
   * "no feature"), the `HEAD` existence check answers `headStatus`, and writes
   * succeed.
   *
   * @param [headStatus] {number}   status for the HEAD existence check
   * @returns {ReturnType<typeof vi.fn>}
   */
  function advisoryRequest(headStatus?: number) {
    return vi.fn(async (input: { method?: string }) => {
      if (input.method === 'GET') {
        throw httpError(404) // no backend descriptor -> no feature
      }
      if (input.method === 'HEAD' && headStatus !== undefined) {
        throw httpError(headStatus)
      }
      return {} as HttpResponse
    })
  }

  it('PUTs the envelope as application/json (default) at the resource path', async () => {
    const request = advisoryRequest(404) // existence check: absent
    const doc = encryptedDoc('zAbc')
    await transport(request).insert({ encrypted: doc })

    // Last call is the PUT.
    const put = request.mock.calls.at(-1)![0] as Record<string, unknown>
    expect(put.method).toBe('PUT')
    expect(put.path).toBe('/space/space%201/docs/zAbc')
    expect((put.headers as Record<string, string>)['content-type']).toBe(
      'application/json'
    )
    expect(decodeBody(put.body)).toEqual(doc)
  })

  it('checks existence with a bodiless HEAD, not a GET of the envelope', async () => {
    const request = advisoryRequest(404)
    await transport(request).insert({ encrypted: encryptedDoc('zAbc') })
    const methods = request.mock.calls.map(
      ([input]) => (input as { method?: string }).method
    )
    expect(methods).toContain('HEAD')
    expect(methods.filter(method => method === 'PUT')).toHaveLength(1)
  })

  it('honors a custom content type (JOSE_CONTENT_TYPE)', async () => {
    const request = advisoryRequest(404)
    await transport(request, JOSE_CONTENT_TYPE).insert({
      encrypted: encryptedDoc('zEdv')
    })
    const put = request.mock.calls.at(-1)![0] as Record<string, unknown>
    expect((put.headers as Record<string, string>)['content-type']).toBe(
      JOSE_CONTENT_TYPE
    )
  })

  it('throws DuplicateError when the document id already exists', async () => {
    // HEAD (existence check) resolves -> the resource exists.
    const request = advisoryRequest()
    await expect(
      transport(request).insert({ encrypted: encryptedDoc() })
    ).rejects.toMatchObject({ name: 'DuplicateError' })
    // It must NOT have attempted a PUT.
    expect(
      request.mock.calls.every(
        ([input]) => (input as { method?: string }).method !== 'PUT'
      )
    ).toBe(true)
  })

  it('maps a 409 unique-attribute conflict on the advisory PUT to DuplicateError', async () => {
    // No backend descriptor -> no conditional-writes; HEAD says absent; the
    // PUT then rejects 409 (a unique blinded attribute already held).
    const request = vi.fn(async (input: { method?: string }) => {
      if (input.method === 'GET') {
        throw httpError(404)
      }
      if (input.method === 'HEAD') {
        throw httpError(404)
      }
      throw httpError(409) // PUT
    })
    await expect(
      transport(request).insert({ encrypted: encryptedDoc() })
    ).rejects.toMatchObject({ name: 'DuplicateError' })
  })
})

describe('WasTransport — insert (conditional-writes backend)', () => {
  /**
   * A request stub for a backend WITH the `conditional-writes` feature: the
   * backend-descriptor GET returns it, and the PUT answers `putStatus` (or
   * succeeds when undefined).
   *
   * @param [putStatus] {number}   status the PUT fails with
   * @returns {ReturnType<typeof vi.fn>}
   */
  function conditionalRequest(putStatus?: number) {
    const descriptor = { id: 'default', features: ['conditional-writes'] }
    return vi.fn(async (input: { method?: string }) => {
      if (input.method === 'GET') {
        return {
          data: descriptor,
          async json() {
            return descriptor
          }
        } as unknown as HttpResponse
      }
      if (putStatus !== undefined) {
        throw httpError(putStatus)
      }
      return {} as HttpResponse
    })
  }

  it('inserts with a single atomic PUT + If-None-Match: * (no pre-check)', async () => {
    const request = conditionalRequest()
    await transport(request).insert({ encrypted: encryptedDoc('zAbc') })
    const methods = request.mock.calls.map(
      ([input]) => (input as { method?: string }).method
    )
    // One GET (the backend descriptor, memoized), then the PUT -- no HEAD.
    expect(methods).toEqual(['GET', 'PUT'])
    const put = request.mock.calls.at(-1)![0] as Record<string, unknown>
    expect((put.headers as Record<string, string>)['if-none-match']).toBe('*')
  })

  it('maps the 412 create-if-absent rejection to DuplicateError', async () => {
    const request = conditionalRequest(412)
    await expect(
      transport(request).insert({ encrypted: encryptedDoc() })
    ).rejects.toMatchObject({ name: 'DuplicateError' })
  })

  it('maps a 409 unique-attribute conflict on the conditional PUT to DuplicateError', async () => {
    const request = conditionalRequest(409)
    await expect(
      transport(request).insert({ encrypted: encryptedDoc() })
    ).rejects.toMatchObject({ name: 'DuplicateError' })
  })

  it('memoizes the backend-feature probe across inserts', async () => {
    const request = conditionalRequest()
    const wasTransport = transport(request)
    await wasTransport.insert({ encrypted: encryptedDoc('zAbc') })
    await wasTransport.insert({ encrypted: encryptedDoc('zDef') })
    const gets = request.mock.calls.filter(
      ([input]) => (input as { method?: string }).method === 'GET'
    )
    expect(gets).toHaveLength(1)
  })
})

describe('WasTransport — update', () => {
  it('PUTs the envelope (upsert, no existence check)', async () => {
    const request = vi.fn(
      async (_input: Record<string, unknown>) => ({}) as HttpResponse
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
   * A request stub for the `find` path: the backend-descriptor GET advertises
   * `features` (defaulting to include `blinded-index-query`, the affordance
   * `find` gates on), and the POST `/query` answers with `body`.
   *
   * @param body {object}          the server's query response body (POST /query)
   * @param [features] {string[]}   the backend features the descriptor advertises
   * @returns {ReturnType<typeof vi.fn>}
   */
  function queryRequest(
    body: object,
    features: string[] = ['blinded-index-query']
  ) {
    return vi.fn(async (input: { method?: string }) => {
      if (input.method === 'GET') {
        return dataResponse({ id: 'default', features })
      }
      return dataResponse(body)
    })
  }

  /**
   * The POST `/query` call from a `find` request stub -- the last call, since
   * the memoized backend-descriptor GET precedes it.
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

  it('throws NotSupportedError -- and makes no POST -- when the backend does not advertise blinded-index-query', async () => {
    const request = queryRequest({ documents: [], hasMore: false }, [])
    await expect(
      transport(request).find({
        query: { index: 'urn:hmac:1', has: ['bName'] }
      })
    ).rejects.toMatchObject({ name: 'NotSupportedError' })
    const methods = request.mock.calls.map(
      ([input]) => (input as { method?: string }).method
    )
    expect(methods).not.toContain('POST')
  })

  it('maps a 404 from the query POST to NotFoundError', async () => {
    const request = vi.fn(async (input: { method?: string }) => {
      if (input.method === 'GET') {
        return dataResponse({
          id: 'default',
          features: ['blinded-index-query']
        })
      }
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

describe('WasTransport -- unsupported operations', () => {
  const t = transport(vi.fn())

  it('rejects storeChunk, getChunk', async () => {
    await expect(t.storeChunk()).rejects.toMatchObject({
      name: 'NotSupportedError'
    })
    await expect(t.getChunk()).rejects.toMatchObject({
      name: 'NotSupportedError'
    })
  })
})

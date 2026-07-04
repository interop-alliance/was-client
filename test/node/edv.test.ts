/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Unit tests for the EDV-over-WAS transport mapping. These stub the WAS signed-
 * request layer (no network, no crypto) and assert that `WasTransport` maps EDV
 * `insert` / `update` / `get` onto the right WAS method + resource path +
 * content type, and normalizes server responses into the
 * error names `EdvClientCore` dispatches on (`DuplicateError`,
 * `InvalidStateError`, `NotFoundError`). Unsupported operations (find / chunks /
 * index) throw.
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

  it('maps a 409 to InvalidStateError', async () => {
    const request = vi.fn(async () => {
      throw httpError(409)
    })
    await expect(
      transport(request).update({ encrypted: encryptedDoc() })
    ).rejects.toMatchObject({ name: 'InvalidStateError' })
  })
})

describe('WasTransport — get', () => {
  it('GETs and returns the parsed envelope', async () => {
    const doc = encryptedDoc('zGet')
    const request = vi.fn(
      async (_input: Record<string, unknown>) =>
        ({ data: doc }) as unknown as HttpResponse
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

describe('WasTransport — unsupported operations', () => {
  const t = transport(vi.fn())

  it('rejects find, updateIndex, storeChunk, getChunk', async () => {
    await expect(t.find()).rejects.toMatchObject({
      name: 'NotSupportedError'
    })
    await expect(t.updateIndex()).rejects.toMatchObject({
      name: 'NotSupportedError'
    })
    await expect(t.storeChunk()).rejects.toMatchObject({
      name: 'NotSupportedError'
    })
    await expect(t.getChunk()).rejects.toMatchObject({
      name: 'NotSupportedError'
    })
  })
})

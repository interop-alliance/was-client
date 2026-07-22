/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Unit tests for `createWasSyncPort` and its ETag/status helpers. A fake
 * `WasClient` records the raw `was.request()` calls (and serves the
 * `Collection.changes()` feed), so these assert the exact request shapes -- path,
 * method, JSON body, conditional-write headers, and the `WAS-Key-Epoch` stamp --
 * plus the 412-conflict and 404-not-found error mapping and the acked-version
 * parsing, all without a live server.
 */
import { describe, it, expect, vi } from 'vitest'

import { createWasSyncPort } from '../../src/sync/index.js'
import { formatEtag, parseEtag, errorStatus } from '../../src/sync/index.js'
import {
  WasSyncConflictError,
  WasSyncNotFoundError,
  PreconditionFailedError,
  NotFoundError
} from '../../src/index.js'

type RequestOptions = {
  path?: string
  method?: string
  json?: object
  headers?: Record<string, string>
}

/** An HttpResponse-like value: a parsed `.data` body plus real `Headers`. */
function response(data: unknown, headers: Record<string, string> = {}) {
  return { data, headers: new Headers(headers) }
}

/** An error shaped like a thrown ky/ezcap non-2xx (flat `status`). */
function httpError(status: number): Error & { status: number } {
  return Object.assign(new Error(`HTTP ${status}`), { status })
}

const SPACE = 'space-abc'
const COLL = 'private-credentials'

/**
 * Builds a fake `WasClient` whose `request` is a spy driven by a per-test
 * handler, and whose `space().collection().changes()` is a separate spy.
 */
function makeWas(options: {
  onRequest?: (opts: RequestOptions) => unknown
  changesResult?: unknown
}) {
  const changes = vi.fn(async () => options.changesResult)
  const request = vi.fn(async (opts: RequestOptions) => {
    const result = options.onRequest?.(opts)
    return result
  })
  const was = {
    request,
    space: () => ({ collection: () => ({ changes }) })
  }
  // The port only touches `request` and `space().collection().changes()`.
  return { was: was as never, request, changes }
}

describe('createWasSyncPort helpers', () => {
  it('formatEtag / parseEtag round-trip a numeric version', () => {
    expect(formatEtag(3)).toBe('"3"')
    expect(parseEtag('"3"')).toBe(3)
    expect(parseEtag(null)).toBeUndefined()
    expect(parseEtag('not-a-number')).toBeUndefined()
  })

  it('errorStatus reads flat and nested shapes', () => {
    expect(errorStatus({ status: 412 })).toBe(412)
    expect(errorStatus({ response: { status: 404 } })).toBe(404)
    expect(errorStatus({})).toBeUndefined()
  })
})

describe('createWasSyncPort.query', () => {
  it('rides the changes() feed and returns documents + checkpoint', async () => {
    const page = {
      documents: [{ id: 'a', _deleted: false, updatedAt: 't1', version: 1 }],
      checkpoint: { id: 'a', updatedAt: 't1' }
    }
    const { was, changes } = makeWas({ changesResult: page })
    const port = createWasSyncPort({ was, spaceId: SPACE, collectionId: COLL })

    const checkpoint = { id: 'x', updatedAt: 't0' }
    const result = await port.query({ checkpoint, limit: 50 })

    expect(changes).toHaveBeenCalledWith({ checkpoint, limit: 50 })
    expect(result).toEqual(page)
  })
})

describe('createWasSyncPort.putContent', () => {
  it('PUTs the body verbatim with if-none-match and returns the acked version', async () => {
    const calls: RequestOptions[] = []
    const { was } = makeWas({
      onRequest: opts => {
        calls.push(opts)
        return response(null, { etag: '"1"' })
      }
    })
    const port = createWasSyncPort({ was, spaceId: SPACE, collectionId: COLL })

    const version = await port.putContent({
      id: 'res-1',
      data: { hello: 'world' },
      ifNoneMatch: true
    })

    expect(version).toBe(1)
    expect(calls).toHaveLength(1)
    expect(calls[0]!.method).toBe('PUT')
    expect(calls[0]!.path).toBe(`/space/${SPACE}/${COLL}/res-1`)
    expect(calls[0]!.json).toEqual({ hello: 'world' })
    expect(calls[0]!.headers).toMatchObject({ 'if-none-match': '*' })
  })

  it('sends if-match and the WAS-Key-Epoch header when given', async () => {
    const calls: RequestOptions[] = []
    const { was } = makeWas({
      onRequest: opts => {
        calls.push(opts)
        return response(null, { etag: '"5"' })
      }
    })
    const port = createWasSyncPort({ was, spaceId: SPACE, collectionId: COLL })

    await port.putContent({
      id: 'res-1',
      data: { a: 1 },
      ifMatch: '"4"',
      epoch: 'epoch-7'
    })

    expect(calls[0]!.headers).toMatchObject({
      'if-match': '"4"',
      'was-key-epoch': 'epoch-7'
    })
  })

  it('re-reads the version when the write response carries no ETag', async () => {
    let putCount = 0
    const { was } = makeWas({
      onRequest: opts => {
        if (opts.method === 'PUT') {
          putCount += 1
          return response(null) // no etag on the write
        }
        // the fallback content GET
        return response({ a: 1 }, { etag: '"9"' })
      }
    })
    const port = createWasSyncPort({ was, spaceId: SPACE, collectionId: COLL })

    const version = await port.putContent({ id: 'res-1', data: { a: 1 } })
    expect(putCount).toBe(1)
    expect(version).toBe(9)
  })

  it('maps a 412 to WasSyncConflictError (a PreconditionFailedError)', async () => {
    const { was } = makeWas({
      onRequest: () => {
        throw httpError(412)
      }
    })
    const port = createWasSyncPort({ was, spaceId: SPACE, collectionId: COLL })

    const err = await port
      .putContent({ id: 'res-1', data: { a: 1 }, ifNoneMatch: true })
      .catch((e: unknown) => e)
    expect(err).toBeInstanceOf(WasSyncConflictError)
    expect(err).toBeInstanceOf(PreconditionFailedError)
  })

  it('propagates a non-412 write error', async () => {
    const { was } = makeWas({
      onRequest: () => {
        throw httpError(500)
      }
    })
    const port = createWasSyncPort({ was, spaceId: SPACE, collectionId: COLL })
    await expect(
      port.putContent({ id: 'res-1', data: { a: 1 } })
    ).rejects.toMatchObject({ status: 500 })
  })
})

describe('createWasSyncPort.deleteContent', () => {
  it('DELETEs with if-match and returns the tombstone version', async () => {
    const calls: RequestOptions[] = []
    const { was } = makeWas({
      onRequest: opts => {
        calls.push(opts)
        return response(null, { etag: '"2"' })
      }
    })
    const port = createWasSyncPort({ was, spaceId: SPACE, collectionId: COLL })

    const version = await port.deleteContent({ id: 'res-1', ifMatch: '"1"' })
    expect(version).toBe(2)
    expect(calls[0]!.method).toBe('DELETE')
    expect(calls[0]!.path).toBe(`/space/${SPACE}/${COLL}/res-1`)
    expect(calls[0]!.headers).toMatchObject({ 'if-match': '"1"' })
  })

  it('maps a 404 to WasSyncNotFoundError (a NotFoundError)', async () => {
    const { was } = makeWas({
      onRequest: () => {
        throw httpError(404)
      }
    })
    const port = createWasSyncPort({ was, spaceId: SPACE, collectionId: COLL })
    const err = await port
      .deleteContent({ id: 'res-1' })
      .catch((e: unknown) => e)
    expect(err).toBeInstanceOf(WasSyncNotFoundError)
    expect(err).toBeInstanceOf(NotFoundError)
  })

  it('maps a 412 to WasSyncConflictError', async () => {
    const { was } = makeWas({
      onRequest: () => {
        throw httpError(412)
      }
    })
    const port = createWasSyncPort({ was, spaceId: SPACE, collectionId: COLL })
    await expect(
      port.deleteContent({ id: 'res-1', ifMatch: '"1"' })
    ).rejects.toBeInstanceOf(WasSyncConflictError)
  })
})

describe('createWasSyncPort.putMeta', () => {
  it('PUTs { custom } to the /meta sub-resource', async () => {
    const calls: RequestOptions[] = []
    const { was } = makeWas({
      onRequest: opts => {
        calls.push(opts)
        return response(null)
      }
    })
    const port = createWasSyncPort({ was, spaceId: SPACE, collectionId: COLL })

    await port.putMeta!({ id: 'res-1', custom: { name: 'Alice' } })
    expect(calls[0]!.method).toBe('PUT')
    expect(calls[0]!.path).toBe(`/space/${SPACE}/${COLL}/res-1/meta`)
    expect(calls[0]!.json).toEqual({ custom: { name: 'Alice' } })
  })
})

describe('createWasSyncPort.get', () => {
  it('assembles content + /meta into a MasterState', async () => {
    const { was } = makeWas({
      onRequest: opts => {
        if (opts.path?.endsWith('/meta')) {
          return response(
            {
              updatedAt: '2026-01-01T00:00:00.000Z',
              createdBy: 'did:key:zCreator',
              epoch: 'epoch-3',
              custom: { name: 'Alice' }
            },
            { etag: '"7"' }
          )
        }
        return response({ a: 1 }, { etag: '"4"' })
      }
    })
    const port = createWasSyncPort({ was, spaceId: SPACE, collectionId: COLL })

    const master = await port.get({ id: 'res-1' })
    expect(master).toEqual({
      version: 4,
      updatedAt: '2026-01-01T00:00:00.000Z',
      deleted: false,
      data: { a: 1 },
      createdBy: 'did:key:zCreator',
      epoch: 'epoch-3',
      custom: { name: 'Alice' },
      metaVersion: 7
    })
  })

  it('returns a placeholder updatedAt when the resource has no /meta yet', async () => {
    const { was } = makeWas({
      onRequest: opts => {
        if (opts.path?.endsWith('/meta')) {
          throw httpError(404)
        }
        return response({ a: 1 }, { etag: '"4"' })
      }
    })
    const port = createWasSyncPort({ was, spaceId: SPACE, collectionId: COLL })

    const master = await port.get({ id: 'res-1' })
    expect(master?.version).toBe(4)
    expect(master?.deleted).toBe(false)
    // A valid, sortable epoch-zero timestamp (not an empty string).
    expect(new Date(master!.updatedAt).getTime()).toBe(0)
  })

  it('returns null when the content is absent (404)', async () => {
    const { was } = makeWas({
      onRequest: () => {
        throw httpError(404)
      }
    })
    const port = createWasSyncPort({ was, spaceId: SPACE, collectionId: COLL })
    expect(await port.get({ id: 'gone' })).toBeNull()
  })
})

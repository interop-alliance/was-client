/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Unit tests for `createWasSyncPort` and its ETag/status helpers. A fake
 * `WasClient` records the raw `was.request()` calls (and serves the
 * `Collection.changes()` feed), so these assert the exact request shapes -- path,
 * method, JSON body, conditional-write headers, and the `Key-Epoch` stamp --
 * plus the 412-conflict and 404-not-found error mapping and the write-ack
 * parsing, all without a live server.
 *
 * The port classifies through the client's own `mapError`, so the signals it
 * raises carry the server's `problem+json` fields and every other status
 * leaves the subpath as a typed `WasError` rather than a raw ky error.
 */
import { describe, it, expect, vi } from 'vitest'

import { createWasSyncPort } from '../../src/sync/index.js'
import { parseEtag, errorStatus } from '../../src/sync/index.js'
import { errorMessage } from '../../src/sync/index.js'
import {
  WasSyncAuthError,
  WasSyncConflictError,
  WasSyncNotFoundError,
  AuthRequiredError,
  PreconditionFailedError,
  NotFoundError,
  QuotaExceededError,
  WasError,
  WasServerError
} from '../../src/index.js'
import type { IZcap } from '../../src/index.js'
import type { SyncStatus } from '../../src/sync/index.js'

type RequestOptions = {
  path?: string
  method?: string
  json?: object
  headers?: Record<string, string>
  capability?: unknown
}

/** An HttpResponse-like value: a parsed `.data` body plus real `Headers`. */
function response(data: unknown, headers: Record<string, string> = {}) {
  return { data, headers: new Headers(headers) }
}

/** An error shaped like a thrown ky/ezcap non-2xx (flat `status`). */
function httpError(status: number): Error & { status: number } {
  return Object.assign(new Error(`HTTP ${status}`), { status })
}

/**
 * A thrown ky/ezcap non-2xx carrying an `application/problem+json` body, the
 * shape a real WAS server answers a refused write with.
 */
function problemError(status: number, type: string) {
  return Object.assign(new Error(`HTTP ${status}`), {
    status,
    requestUrl: 'https://was.example/space/space-abc/private-credentials/res-1',
    data: {
      type,
      title: 'The write was refused.',
      errors: [{ detail: 'the precondition did not hold' }]
    }
  })
}

const SPACE = 'space-abc'
const COLL = 'private-credentials'

/**
 * Builds a fake `WasClient` whose `request` is a spy driven by a per-test
 * handler, and whose `space().collection().changes()` is a separate spy.
 */
function makeWas(options: {
  onRequest?: (opts: RequestOptions) => unknown
  onChanges?: () => unknown
  changesResult?: unknown
}) {
  // Records the handle options the port passes to `space().collection(...)`, so
  // the capability-threading test can assert them.
  const collectionOptions: unknown[] = []
  const changes = vi.fn(async () =>
    options.onChanges ? options.onChanges() : options.changesResult
  )
  const request = vi.fn(async (opts: RequestOptions) => {
    const result = options.onRequest?.(opts)
    return result
  })
  const was = {
    request,
    space: () => ({
      collection: (_collectionId: string, handleOptions?: unknown) => {
        collectionOptions.push(handleOptions)
        return { changes }
      }
    })
  }
  // The port only touches `request` and `space().collection().changes()`.
  return { was: was as never, request, changes, collectionOptions }
}

describe('createWasSyncPort helpers', () => {
  it('parseEtag rejects a validator with no generation segment', () => {
    expect(parseEtag('"3"')).toBeUndefined()
    expect(parseEtag(null)).toBeUndefined()
    expect(parseEtag('not-a-number')).toBeUndefined()
  })

  it('parseEtag accepts only a run of decimal digits as the revision', () => {
    expect(parseEtag('"g.1e2"')).toBeUndefined()
    expect(parseEtag('"g.0x10"')).toBeUndefined()
    expect(parseEtag('"g.+5"')).toBeUndefined()
    expect(parseEtag('"g. 5"')).toBeUndefined()
    expect(parseEtag('"g.007"')).toBe(7)
  })

  it('parseEtag reads the version after the final "." in a generation.version etag', () => {
    expect(parseEtag('"3mJr7AoUXx2.3"')).toBe(3)
    expect(parseEtag('"g.7.12"')).toBe(12)
    expect(parseEtag('"3mJr7AoUXx2."')).toBeUndefined()
    expect(parseEtag('"3mJr7AoUXx2.abc"')).toBeUndefined()
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
  it('PUTs the body verbatim with if-none-match and returns the acked write', async () => {
    const calls: RequestOptions[] = []
    const { was } = makeWas({
      onRequest: opts => {
        calls.push(opts)
        return response(null, { etag: '"g1.1"' })
      }
    })
    const port = createWasSyncPort({ was, spaceId: SPACE, collectionId: COLL })

    const ack = await port.putContent({
      id: 'res-1',
      data: { hello: 'world' },
      ifNoneMatch: true
    })

    expect(ack).toEqual({ version: 1, etag: '"g1.1"' })
    expect(calls).toHaveLength(1)
    expect(calls[0]!.method).toBe('PUT')
    expect(calls[0]!.path).toBe(`/space/${SPACE}/${COLL}/res-1`)
    expect(calls[0]!.json).toEqual({ hello: 'world' })
    expect(calls[0]!.headers).toMatchObject({ 'if-none-match': '*' })
  })

  it('sends if-match and the Key-Epoch header when given', async () => {
    const calls: RequestOptions[] = []
    const { was } = makeWas({
      onRequest: opts => {
        calls.push(opts)
        return response(null, { etag: '"g.5"' })
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
      'key-epoch': 'epoch-7'
    })
  })

  it('acks version 0 with no etag, and does not re-read, when the write response carries no ETag', async () => {
    const methods: Array<string | undefined> = []
    const { was } = makeWas({
      onRequest: opts => {
        methods.push(opts.method)
        return response(null) // no etag on the write
      }
    })
    const port = createWasSyncPort({ was, spaceId: SPACE, collectionId: COLL })

    const ack = await port.putContent({ id: 'res-1', data: { a: 1 } })
    expect(methods).toEqual(['PUT'])
    expect(ack).toEqual({ version: 0, etag: undefined })
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

  it('propagates a non-412 write error as a typed WasError', async () => {
    const { was } = makeWas({
      onRequest: () => {
        throw httpError(500)
      }
    })
    const port = createWasSyncPort({ was, spaceId: SPACE, collectionId: COLL })
    const err = await port
      .putContent({ id: 'res-1', data: { a: 1 } })
      .catch((caught: unknown) => caught)
    expect(err).toBeInstanceOf(WasServerError)
    expect(err).toMatchObject({ status: 500 })
  })
})

describe('createWasSyncPort.deleteContent', () => {
  it('DELETEs with if-match and returns the tombstone write ack', async () => {
    const calls: RequestOptions[] = []
    const { was } = makeWas({
      onRequest: opts => {
        calls.push(opts)
        return response(null, { etag: '"g2.2"' })
      }
    })
    const port = createWasSyncPort({ was, spaceId: SPACE, collectionId: COLL })

    const ack = await port.deleteContent({ id: 'res-1', ifMatch: '"1"' })
    expect(ack).toEqual({ version: 2, etag: '"g2.2"' })
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
            { etag: '"gMeta.7"' }
          )
        }
        return response({ a: 1 }, { etag: '"gContent.4"' })
      }
    })
    const port = createWasSyncPort({ was, spaceId: SPACE, collectionId: COLL })

    const master = await port.get({ id: 'res-1' })
    expect(master).toEqual({
      version: 4,
      etag: '"gContent.4"',
      updatedAt: '2026-01-01T00:00:00.000Z',
      data: { a: 1 },
      createdBy: 'did:key:zCreator',
      epoch: 'epoch-3',
      custom: { name: 'Alice' },
      metaVersion: 7,
      metaEtag: '"gMeta.7"'
    })
  })

  it('returns a placeholder updatedAt when the resource has no /meta yet', async () => {
    const { was } = makeWas({
      onRequest: opts => {
        if (opts.path?.endsWith('/meta')) {
          throw httpError(404)
        }
        return response({ a: 1 }, { etag: '"g.4"' })
      }
    })
    const port = createWasSyncPort({ was, spaceId: SPACE, collectionId: COLL })

    const master = await port.get({ id: 'res-1' })
    expect(master?.version).toBe(4)
    expect(master?.etag).toBe('"g.4"')
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

/**
 * A stand-in delegated capability. The port never inspects it -- it only has to
 * arrive verbatim on every request -- so a minimal shape is enough.
 */
const CAPABILITY = {
  id: 'urn:uuid:cap-1',
  invocationTarget: `https://was.example/space/${SPACE}/${COLL}`
} as unknown as IZcap

describe('createWasSyncPort capability threading', () => {
  it('attaches the capability to the changes feed and to every request', async () => {
    const calls: RequestOptions[] = []
    const { was, collectionOptions } = makeWas({
      changesResult: { documents: [], checkpoint: null },
      onRequest: opts => {
        calls.push(opts)
        if (opts.path?.endsWith('/meta') && opts.method === 'GET') {
          throw httpError(404)
        }
        return response({ a: 1 }, { etag: '"g.1"' })
      }
    })
    const port = createWasSyncPort({
      was,
      spaceId: SPACE,
      collectionId: COLL,
      capability: CAPABILITY
    })

    await port.query({ limit: 10 })
    await port.putContent({ id: 'res-1', data: { a: 1 } })
    await port.putMeta!({ id: 'res-1', custom: { name: 'Alice' } })
    await port.deleteContent({ id: 'res-1' })
    await port.get({ id: 'res-1' })

    // The pull path rides `Collection.changes()`, which honors the handle's
    // own capability rather than a per-request one.
    expect(collectionOptions).toEqual([{ capability: CAPABILITY }])
    expect(calls.length).toBeGreaterThan(0)
    for (const call of calls) {
      expect(call.capability).toBe(CAPABILITY)
    }
  })

  it('attaches no capability by default', async () => {
    const calls: RequestOptions[] = []
    const { was, collectionOptions } = makeWas({
      onRequest: opts => {
        calls.push(opts)
        return response(null, { etag: '"g.1"' })
      }
    })
    const port = createWasSyncPort({ was, spaceId: SPACE, collectionId: COLL })

    await port.putContent({ id: 'res-1', data: { a: 1 } })

    expect(collectionOptions).toEqual([{ capability: undefined }])
    expect(calls[0]!.capability).toBeUndefined()
  })
})

describe('createWasSyncPort.putMeta clear + write ack', () => {
  it('writes {} when custom is omitted (the cleared state)', async () => {
    const calls: RequestOptions[] = []
    const { was } = makeWas({
      onRequest: opts => {
        calls.push(opts)
        return response(null, { etag: '"g3.3"' })
      }
    })
    const port = createWasSyncPort({ was, spaceId: SPACE, collectionId: COLL })

    await port.putMeta!({ id: 'res-1' })

    expect(calls[0]!.json).toEqual({})
    // Wire-identical to the `{ custom: undefined }` body this used to send.
    expect(JSON.stringify(calls[0]!.json)).toBe(
      JSON.stringify({ custom: undefined })
    )
  })

  it('returns the new write ack parsed from the response ETag', async () => {
    const { was } = makeWas({
      onRequest: () => response(null, { etag: '"g3.3"' })
    })
    const port = createWasSyncPort({ was, spaceId: SPACE, collectionId: COLL })

    expect(await port.putMeta!({ id: 'res-1', custom: { a: 1 } })).toEqual({
      version: 3,
      etag: '"g3.3"'
    })
  })

  it('returns undefined when the response carries no ETag', async () => {
    const { was } = makeWas({ onRequest: () => response(null) })
    const port = createWasSyncPort({ was, spaceId: SPACE, collectionId: COLL })

    expect(
      await port.putMeta!({ id: 'res-1', custom: { a: 1 } })
    ).toBeUndefined()
  })
})

describe('createWasSyncPort mapAuthErrors', () => {
  /** Builds a port whose every request (and `changes()`) throws `status`. */
  function failingPort(status: number, mapAuthErrors: boolean) {
    const { was } = makeWas({
      onRequest: () => {
        throw httpError(status)
      },
      onChanges: () => {
        throw httpError(status)
      }
    })
    return createWasSyncPort({
      was,
      spaceId: SPACE,
      collectionId: COLL,
      mapAuthErrors
    })
  }

  for (const status of [401, 403, 404]) {
    it(`maps ${status} on query / putContent / putMeta when on`, async () => {
      const port = failingPort(status, true)
      for (const attempt of [
        () => port.query({ limit: 10 }),
        () => port.putContent({ id: 'res-1', data: { a: 1 } }),
        () => port.putMeta!({ id: 'res-1', custom: { a: 1 } })
      ]) {
        const err = await attempt().catch((caught: unknown) => caught)
        expect(err).toBeInstanceOf(WasSyncAuthError)
        expect(err).toBeInstanceOf(AuthRequiredError)
        expect(err).toMatchObject({ status })
      }
    })
  }

  for (const status of [401, 403]) {
    it(`maps ${status} on deleteContent when on`, async () => {
      const port = failingPort(status, true)
      const err = await port
        .deleteContent({ id: 'res-1' })
        .catch((caught: unknown) => caught)
      expect(err).toBeInstanceOf(WasSyncAuthError)
      expect(err).toMatchObject({ status })
    })
  }

  it('treats a 404 delete as an idempotent success when on', async () => {
    const port = failingPort(404, true)
    expect(await port.deleteContent({ id: 'res-1' })).toBeUndefined()
  })

  it('still maps 412 to WasSyncConflictError when on', async () => {
    const port = failingPort(412, true)
    await expect(
      port.putContent({ id: 'res-1', data: { a: 1 } })
    ).rejects.toBeInstanceOf(WasSyncConflictError)
  })

  it('leaves a get 404 as null when on (absent or tombstoned)', async () => {
    const port = failingPort(404, true)
    expect(await port.get({ id: 'gone' })).toBeNull()
  })

  it('leaves a missing /meta benign when on', async () => {
    const { was } = makeWas({
      onRequest: opts => {
        if (opts.path?.endsWith('/meta')) {
          throw httpError(404)
        }
        return response({ a: 1 }, { etag: '"g.4"' })
      }
    })
    const port = createWasSyncPort({
      was,
      spaceId: SPACE,
      collectionId: COLL,
      mapAuthErrors: true
    })
    expect((await port.get({ id: 'res-1' }))?.version).toBe(4)
  })

  it('raises the not-found signal on a /meta 404 when off', async () => {
    // A metadata-only edit against a resource another replica deleted: the
    // push loop corroborates the signal off the feed instead of retrying.
    const err = await failingPort(404, false).putMeta!({
      id: 'res-1',
      custom: { a: 1 }
    }).catch((caught: unknown) => caught)
    expect(err).toBeInstanceOf(WasSyncNotFoundError)
    expect(err).toBeInstanceOf(NotFoundError)
    expect(err).not.toBeInstanceOf(WasSyncAuthError)
    expect(err).toMatchObject({ name: 'WasSyncNotFoundError', status: 404 })
  })

  it('preserves today behavior when off', async () => {
    // 404 keeps the delete-specific not-found signal ...
    await expect(
      failingPort(404, false).deleteContent({ id: 'res-1' })
    ).rejects.toBeInstanceOf(WasSyncNotFoundError)
    // ... and 401 / 403 / 404 stay their ordinary typed class everywhere
    // else, never the auth signal.
    for (const status of [401, 403, 404]) {
      const port = failingPort(status, false)
      for (const attempt of [
        () => port.query({ limit: 10 }),
        () => port.putContent({ id: 'res-1', data: { a: 1 } }),
        () => port.putMeta!({ id: 'res-1', custom: { a: 1 } })
      ]) {
        const err = await attempt().catch((caught: unknown) => caught)
        expect(err).not.toBeInstanceOf(WasSyncAuthError)
        expect(err).toMatchObject({ status })
      }
    }
  })
})

describe('errorMessage', () => {
  it('reads an Error message and coerces anything else', () => {
    expect(errorMessage(new Error('boom'))).toBe('boom')
    expect(errorMessage('boom')).toBe('boom')
    expect(errorMessage(undefined)).toBe('undefined')
  })
})

describe('createWasSyncPort error classification', () => {
  const PRECONDITION_FAILED = 'https://wallet.storage/spec#precondition-failed'
  const QUOTA_EXCEEDED = 'https://wallet.storage/spec#quota-exceeded'

  /** A port whose every request fails with the given problem response. */
  function refusingPort(status: number, type: string) {
    const { was } = makeWas({
      onRequest: () => {
        throw problemError(status, type)
      }
    })
    return createWasSyncPort({ was, spaceId: SPACE, collectionId: COLL })
  }

  it('carries the problem fields and a cause onto a write conflict', async () => {
    const raw = problemError(412, PRECONDITION_FAILED)
    const { was } = makeWas({
      onRequest: () => {
        throw raw
      }
    })
    const port = createWasSyncPort({ was, spaceId: SPACE, collectionId: COLL })

    const err = await port
      .putContent({ id: 'res-1', data: { a: 1 }, ifMatch: '"1"' })
      .catch((caught: unknown) => caught)
    expect(err).toBeInstanceOf(WasSyncConflictError)
    expect(err).toMatchObject({
      status: 412,
      type: PRECONDITION_FAILED,
      title: 'The write was refused.',
      details: ['the precondition did not hold'],
      requestUrl: raw.requestUrl
    })
    expect((err as Error).cause).toBe(raw)
  })

  it('carries the problem fields and a cause onto a delete not-found', async () => {
    const raw = problemError(404, 'https://wallet.storage/spec#not-found')
    const { was } = makeWas({
      onRequest: () => {
        throw raw
      }
    })
    const port = createWasSyncPort({ was, spaceId: SPACE, collectionId: COLL })

    const err = await port
      .deleteContent({ id: 'res-1', ifMatch: '"1"' })
      .catch((caught: unknown) => caught)
    expect(err).toBeInstanceOf(WasSyncNotFoundError)
    expect(err).toMatchObject({
      status: 404,
      type: 'https://wallet.storage/spec#not-found',
      requestUrl: raw.requestUrl
    })
    expect((err as Error).cause).toBe(raw)
  })

  it('classifies by problem type, not by the status list', async () => {
    // A 507 quota-exceeded is outside the port's own signal list; it still
    // leaves the sync subpath as the client's typed class.
    const err = await refusingPort(507, QUOTA_EXCEEDED)
      .putContent({ id: 'res-1', data: { a: 1 } })
      .catch((caught: unknown) => caught)
    expect(err).toBeInstanceOf(QuotaExceededError)
    expect(err).toMatchObject({ status: 507, type: QUOTA_EXCEEDED })
  })

  it('types a read failure the port has no signal for', async () => {
    const err = await refusingPort(500, 'https://wallet.storage/spec#storage')
      .get({ id: 'res-1' })
      .catch((caught: unknown) => caught)
    expect(err).toBeInstanceOf(WasError)
    expect(err).toMatchObject({ status: 500 })
  })

  it('carries the problem fields onto the auth signal', async () => {
    const raw = problemError(403, 'https://wallet.storage/spec#not-authorized')
    const { was } = makeWas({
      onRequest: () => {
        throw raw
      }
    })
    const port = createWasSyncPort({
      was,
      spaceId: SPACE,
      collectionId: COLL,
      mapAuthErrors: true
    })

    const err = await port
      .putContent({ id: 'res-1', data: { a: 1 } })
      .catch((caught: unknown) => caught)
    expect(err).toBeInstanceOf(WasSyncAuthError)
    expect(err).toMatchObject({ status: 403, requestUrl: raw.requestUrl })
    expect((err as Error).cause).toBe(raw)
  })
})

describe('SyncStatus', () => {
  it('names the four states a feed reports', () => {
    const states: SyncStatus[] = ['idle', 'syncing', 'synced', 'error']
    expect(states).toHaveLength(4)
  })
})

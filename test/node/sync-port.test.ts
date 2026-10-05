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
import { errorStatus } from '../../src/sync/index.js'
import { errorMessage } from '../../src/sync/index.js'
import {
  WasSyncAuthError,
  WasSyncCheckpointError,
  WasSyncConflictError,
  WasSyncNotFoundError,
  AuthRequiredError,
  PreconditionFailedError,
  NotFoundError,
  QuotaExceededError,
  ValidationError,
  WasError,
  WasServerError
} from '../../src/index.js'
import type { IZcap } from '../../src/index.js'
import { Collection } from '../../src/Collection.js'
import { feedEntry } from '../helpers/changesFeed.js'

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
        // The real page walk over the stubbed `changes()`, so the port's
        // skip-and-resume tests drive the same code a live handle runs.
        return {
          id: COLL,
          changes,
          resourceChanges: Collection.prototype.resourceChanges
        }
      }
    })
  }
  // The port only touches `request` and the collection's feed walk.
  return { was: was as never, request, changes, collectionOptions }
}

describe('createWasSyncPort helpers', () => {
  it('errorStatus reads flat and nested shapes', () => {
    expect(errorStatus({ status: 412 })).toBe(412)
    expect(errorStatus({ response: { status: 404 } })).toBe(404)
    expect(errorStatus({})).toBeUndefined()
  })
})

/**
 * The Collection's own Metadata record on the feed, one of the kinds the port
 * skips.
 */
function metaEntry(checkpoint: string) {
  return feedEntry({
    id: 'https://x/meta',
    kind: 'collection-metadata',
    checkpoint
  })
}

describe('createWasSyncPort.query', () => {
  it('rides the changes() feed and returns documents + checkpoint', async () => {
    const entry = feedEntry({ id: 'a', checkpoint: 'c1', data: { n: 1 } })
    const page = {
      documents: [{ ...entry, writerId: 'writer-a' }],
      checkpoint: 'c1'
    }
    const { was, changes } = makeWas({ changesResult: page })
    const port = createWasSyncPort({ was, spaceId: SPACE, collectionId: COLL })

    const checkpoint = 'c0'
    const result = await port.query({ checkpoint, limit: 50 })

    expect(changes).toHaveBeenCalledWith({ checkpoint, limit: 50 })
    // The feed's `deleted` reaches the port's consumers as `_deleted`; every
    // other member, `writerId` included, rides along unchanged.
    const { deleted, ...rest } = entry
    expect(result).toEqual({
      documents: [{ ...rest, _deleted: deleted, writerId: 'writer-a' }],
      checkpoint: 'c1'
    })
  })

  it('maps a tombstone to _deleted: true', async () => {
    const { was } = makeWas({
      changesResult: {
        documents: [feedEntry({ id: 'gone', checkpoint: 'c1', deleted: true })],
        checkpoint: 'c1'
      }
    })
    const port = createWasSyncPort({ was, spaceId: SPACE, collectionId: COLL })

    const { documents } = await port.query({ limit: 50 })
    expect(documents).toHaveLength(1)
    expect(documents[0]!._deleted).toBe(true)
    expect(documents[0]).not.toHaveProperty('deleted')
    expect(documents[0]).not.toHaveProperty('data')
  })

  it('skips non-Resource kinds and non-JSON Resources, keeping the page checkpoint', async () => {
    const { was } = makeWas({
      changesResult: {
        documents: [
          metaEntry('c1'),
          feedEntry({ id: 'a', checkpoint: 'c2', data: { n: 1 } }),
          feedEntry({
            id: 'https://x/meta/log',
            kind: 'log',
            checkpoint: 'c3'
          }),
          feedEntry({
            id: 'https://x/policy',
            kind: 'policy',
            checkpoint: 'c4'
          }),
          feedEntry({ id: 'pic', contentType: 'image/png', checkpoint: 'c5' }),
          feedEntry({
            id: 'did.jsonl',
            contentType: 'text/jsonl',
            checkpoint: 'c6'
          }),
          feedEntry({
            id: 'https://x/a/policy',
            kind: 'policy',
            deleted: true,
            checkpoint: 'c7'
          })
        ],
        checkpoint: 'c7'
      }
    })
    const port = createWasSyncPort({ was, spaceId: SPACE, collectionId: COLL })

    const result = await port.query({ limit: 50 })
    expect(result.documents.map(doc => doc.id)).toEqual(['a'])
    // The resume point is the page's, past the skipped trailing entries.
    expect(result.checkpoint).toBe('c7')
  })

  it('resumes past a page of skipped entries instead of returning it empty', async () => {
    const pages: Record<string, unknown> = {
      c0: {
        documents: [
          metaEntry('c1'),
          feedEntry({ id: 'pic', contentType: 'image/png', checkpoint: 'c2' })
        ],
        checkpoint: 'c2'
      },
      c2: {
        documents: [
          feedEntry({ id: 'https://x/meta/log', kind: 'log', checkpoint: 'c3' })
        ],
        checkpoint: 'c3'
      },
      c3: {
        documents: [feedEntry({ id: 'b', checkpoint: 'c4', data: { n: 2 } })],
        checkpoint: 'c4'
      }
    }
    const { was, changes } = makeWas({})
    changes.mockImplementation(
      (async ({ checkpoint }: { checkpoint: string }) =>
        pages[checkpoint]) as never
    )
    const port = createWasSyncPort({ was, spaceId: SPACE, collectionId: COLL })

    const result = await port.query({ checkpoint: 'c0', limit: 2 })
    expect(result.documents.map(doc => doc.id)).toEqual(['b'])
    expect(result.checkpoint).toBe('c4')
    expect(changes.mock.calls).toEqual([
      [{ checkpoint: 'c0', limit: 2 }],
      [{ checkpoint: 'c2', limit: 2 }],
      [{ checkpoint: 'c3', limit: 2 }]
    ])
  })

  it('returns an empty end page when the feed ends on skipped entries', async () => {
    const { was } = makeWas({
      changesResult: {
        documents: [metaEntry('c1')],
        checkpoint: null
      }
    })
    const port = createWasSyncPort({ was, spaceId: SPACE, collectionId: COLL })

    await expect(port.query({ limit: 50 })).resolves.toEqual({
      documents: [],
      checkpoint: null
    })
  })

  it('fails on a server that repeats a checkpoint over skipped entries', async () => {
    const { was, changes } = makeWas({
      changesResult: {
        documents: [metaEntry('c1')],
        checkpoint: 'c1'
      }
    })
    const port = createWasSyncPort({ was, spaceId: SPACE, collectionId: COLL })

    const err = await port
      .query({ limit: 50 })
      .catch((caught: unknown) => caught)
    expect(err).toBeInstanceOf(WasServerError)
    expect((err as Error).message).toContain('repeated checkpoint')
    expect(changes).toHaveBeenCalledTimes(2)
  })

  it('maps a refused checkpoint to WasSyncCheckpointError, carrying the problems', async () => {
    const refusal = Object.assign(new Error('HTTP 400'), {
      status: 400,
      data: {
        type: 'https://w3id.org/pws#invalid-request-body',
        title: 'The request body was invalid.',
        errors: [
          {
            detail: 'The checkpoint was not issued by this server.',
            pointer: '#/checkpoint'
          }
        ]
      }
    })
    const { was } = makeWas({
      onChanges: () => {
        throw refusal
      }
    })
    const port = createWasSyncPort({ was, spaceId: SPACE, collectionId: COLL })

    const err = await port
      .query({ checkpoint: 'issued-elsewhere', limit: 50 })
      .catch((caught: unknown) => caught)
    expect(err).toBeInstanceOf(WasSyncCheckpointError)
    expect(err).toBeInstanceOf(ValidationError)
    expect((err as WasSyncCheckpointError).name).toBe('WasSyncCheckpointError')
    expect((err as WasSyncCheckpointError).status).toBe(400)
    expect((err as WasSyncCheckpointError).problems).toEqual([
      {
        detail: 'The checkpoint was not issued by this server.',
        pointer: '#/checkpoint'
      }
    ])
  })

  it('leaves an invalid-request-body 400 that points elsewhere a plain ValidationError', async () => {
    const { was } = makeWas({
      onChanges: () => {
        throw Object.assign(new Error('HTTP 400'), {
          status: 400,
          data: {
            type: 'https://w3id.org/pws#invalid-request-body',
            errors: [{ detail: 'Unknown profile.', pointer: '#/profile' }]
          }
        })
      }
    })
    const port = createWasSyncPort({ was, spaceId: SPACE, collectionId: COLL })

    const err = await port
      .query({ checkpoint: 'c0', limit: 50 })
      .catch((caught: unknown) => caught)
    expect(err).toBeInstanceOf(ValidationError)
    expect(err).not.toBeInstanceOf(WasSyncCheckpointError)
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

    expect(ack).toEqual({ etag: '"g1.1"' })
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

  it('sends the Writer-Id header when given', async () => {
    const calls: RequestOptions[] = []
    const { was } = makeWas({
      onRequest: opts => {
        calls.push(opts)
        return response(null, { etag: '"g.5"' })
      }
    })
    const port = createWasSyncPort({ was, spaceId: SPACE, collectionId: COLL })

    await port.putContent({ id: 'res-1', data: { a: 1 }, writerId: 'writer-a' })

    expect(calls[0]!.headers).toMatchObject({ 'writer-id': 'writer-a' })
  })

  it('sends no Writer-Id header when writerId is omitted', async () => {
    const calls: RequestOptions[] = []
    const { was } = makeWas({
      onRequest: opts => {
        calls.push(opts)
        return response(null, { etag: '"g.5"' })
      }
    })
    const port = createWasSyncPort({ was, spaceId: SPACE, collectionId: COLL })

    await port.putContent({ id: 'res-1', data: { a: 1 } })

    expect(calls[0]!.headers?.['writer-id']).toBeUndefined()
  })

  it('refuses an empty writerId before sending the request', async () => {
    const { was, request } = makeWas({
      onRequest: () => response(null, { etag: '"g.1"' })
    })
    const port = createWasSyncPort({ was, spaceId: SPACE, collectionId: COLL })

    await expect(
      port.putContent({ id: 'res-1', data: { a: 1 }, writerId: '' })
    ).rejects.toBeInstanceOf(ValidationError)
    expect(request).not.toHaveBeenCalled()
  })

  it('acks neither etag nor version, and does not re-read, when the write response carries no ETag', async () => {
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
    expect(ack).toStrictEqual({})
  })

  for (const opaque of [
    '"a1b2c3"',
    '"3"',
    '"g.1767225600000.0.origin-a"',
    '"g.1767225600000.0.42"'
  ]) {
    it(`round-trips the opaque validator ${opaque} verbatim`, async () => {
      const calls: RequestOptions[] = []
      const { was } = makeWas({
        onRequest: opts => {
          calls.push(opts)
          return response(null, { etag: opaque })
        }
      })
      const port = createWasSyncPort({
        was,
        spaceId: SPACE,
        collectionId: COLL
      })

      const ack = await port.putContent({
        id: 'res-1',
        data: { a: 1 },
        ifNoneMatch: true
      })
      expect(ack).toStrictEqual({ etag: opaque })

      await port.putContent({ id: 'res-1', data: { a: 2 }, ifMatch: ack.etag })
      expect(calls[1]!.headers).toMatchObject({ 'if-match': opaque })
    })
  }

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
    expect(ack).toEqual({ etag: '"g2.2"' })
    expect(calls[0]!.method).toBe('DELETE')
    expect(calls[0]!.path).toBe(`/space/${SPACE}/${COLL}/res-1`)
    expect(calls[0]!.headers).toMatchObject({ 'if-match': '"1"' })
  })

  it('sends the Writer-Id header when given, and none when omitted', async () => {
    const calls: RequestOptions[] = []
    const { was } = makeWas({
      onRequest: opts => {
        calls.push(opts)
        return response(null, { etag: '"g2.2"' })
      }
    })
    const port = createWasSyncPort({ was, spaceId: SPACE, collectionId: COLL })

    await port.deleteContent({ id: 'res-1', writerId: 'writer-a' })
    expect(calls[0]!.headers).toMatchObject({ 'writer-id': 'writer-a' })

    await port.deleteContent({ id: 'res-1' })
    expect(calls[1]!.headers?.['writer-id']).toBeUndefined()
  })

  it('refuses an empty writerId before sending the request', async () => {
    const { was, request } = makeWas({
      onRequest: () => response(null, { etag: '"g.1"' })
    })
    const port = createWasSyncPort({ was, spaceId: SPACE, collectionId: COLL })

    await expect(
      port.deleteContent({ id: 'res-1', writerId: '' })
    ).rejects.toBeInstanceOf(ValidationError)
    expect(request).not.toHaveBeenCalled()
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

    await port.putMeta({ id: 'res-1', custom: { name: 'Alice' } })
    expect(calls[0]!.method).toBe('PUT')
    expect(calls[0]!.path).toBe(`/space/${SPACE}/${COLL}/res-1/meta`)
    expect(calls[0]!.json).toEqual({ custom: { name: 'Alice' } })
  })

  it('never writes a writerId member into the /meta body', async () => {
    const calls: RequestOptions[] = []
    const { was } = makeWas({
      onRequest: opts => {
        calls.push(opts)
        return response(null)
      }
    })
    const port = createWasSyncPort({ was, spaceId: SPACE, collectionId: COLL })

    await port.putMeta({ id: 'res-1', custom: { name: 'Alice' } })
    expect(calls[0]!.json).toEqual({ custom: { name: 'Alice' } })
    expect(calls[0]!.headers ?? {}).not.toHaveProperty('writer-id')

    await port.putMeta({ id: 'res-1' })
    expect(calls[1]!.json).toEqual({})
  })
})

describe('createWasSyncPort guarded writes', () => {
  // Conditional writes are a baseline server requirement, so the port sends a
  // precondition-bearing write as given and lets the server answer it.
  const setup = (onRequest: (opts: RequestOptions) => unknown) => {
    const { was } = makeWas({ onRequest })
    return createWasSyncPort({ was, spaceId: SPACE, collectionId: COLL })
  }

  it('sends the precondition-bearing write', async () => {
    const calls: RequestOptions[] = []
    const port = setup(opts => {
      calls.push(opts)
      return response(null, { etag: '"g.2"' })
    })

    expect(
      await port.putContent({ id: 'res-1', data: { a: 1 }, ifMatch: '"g.1"' })
    ).toEqual({ etag: '"g.2"' })
    await port.deleteContent({ id: 'res-1', ifMatch: '"g.1"' })
    await port.putMeta({ id: 'res-1', custom: { name: 'A' }, ifMatch: '"g.1"' })
    expect(calls.map(call => call.method)).toEqual(['PUT', 'DELETE', 'PUT'])
    expect(calls[0]!.headers).toMatchObject({ 'if-match': '"g.1"' })
  })

  it('sends the create-if-absent guard as `If-None-Match: *`', async () => {
    const calls: RequestOptions[] = []
    const port = setup(opts => {
      calls.push(opts)
      return response(null, { etag: '"g.1"' })
    })
    await port.putContent({ id: 'res-1', data: { a: 1 }, ifNoneMatch: true })
    expect(calls[0]!.headers).toMatchObject({ 'if-none-match': '*' })
  })

  it('still raises the port not-found signal on a guarded delete', async () => {
    const port = setup(() => {
      throw httpError(404)
    })
    await expect(
      port.deleteContent({ id: 'res-1', ifMatch: '"g.1"' })
    ).rejects.toBeInstanceOf(WasSyncNotFoundError)
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
              updatedAtCounter: 2,
              originId: 'origin-a',
              meta: {
                updatedAt: '2026-01-01T00:00:00.007Z',
                updatedAtCounter: 0,
                originId: 'origin-a',
                generation: 'gMeta'
              },
              createdBy: 'did:key:zCreator',
              epoch: 'epoch-3',
              writerId: 'writer-a',
              custom: { name: 'Alice' }
            },
            { etag: '"gMeta.1767225600007.0.origin-a"' }
          )
        }
        return response(
          { a: 1 },
          { etag: '"gContent.1767225600000.2.origin-a"' }
        )
      }
    })
    const port = createWasSyncPort({ was, spaceId: SPACE, collectionId: COLL })

    const master = await port.get({ id: 'res-1' })
    expect(master).toEqual({
      etag: '"gContent.1767225600000.2.origin-a"',
      updatedAt: '2026-01-01T00:00:00.000Z',
      updatedAtCounter: 2,
      originId: 'origin-a',
      meta: {
        updatedAt: '2026-01-01T00:00:00.007Z',
        updatedAtCounter: 0,
        originId: 'origin-a',
        generation: 'gMeta'
      },
      data: { a: 1 },
      createdBy: 'did:key:zCreator',
      epoch: 'epoch-3',
      writerId: 'writer-a',
      custom: { name: 'Alice' },
      metaEtag: '"gMeta.1767225600007.0.origin-a"'
    })
  })

  it('drops a partial write stamp instead of tearing it', async () => {
    const { was } = makeWas({
      onRequest: opts => {
        if (opts.path?.endsWith('/meta')) {
          // No `updatedAt`, so the counter and origin have no stamp to
          // belong to; the nested `meta` lacks `originId`.
          return response(
            {
              updatedAtCounter: 3,
              originId: 'origin-a',
              meta: {
                updatedAt: '2026-01-01T00:00:00.007Z',
                updatedAtCounter: 0,
                generation: 'gMeta'
              }
            },
            { etag: '"gMeta.1767225600007.0.origin-a"' }
          )
        }
        return response({ a: 1 }, { etag: '"c"' })
      }
    })
    const port = createWasSyncPort({ was, spaceId: SPACE, collectionId: COLL })

    const master = await port.get({ id: 'res-1' })
    expect(master).toEqual({
      etag: '"c"',
      updatedAt: '1970-01-01T00:00:00.000Z',
      data: { a: 1 },
      metaEtag: '"gMeta.1767225600007.0.origin-a"'
    })
  })

  it('keeps the placeholder updatedAt when /meta serves a bare updatedAt', async () => {
    const { was } = makeWas({
      onRequest: opts => {
        if (opts.path?.endsWith('/meta')) {
          return response(
            { updatedAt: '2026-01-01T00:00:00.000Z', createdBy: 'did:key:z' },
            { etag: '"m"' }
          )
        }
        return response({ a: 1 }, { etag: '"c"' })
      }
    })
    const port = createWasSyncPort({ was, spaceId: SPACE, collectionId: COLL })

    const master = await port.get({ id: 'res-1' })
    expect(master).toEqual({
      etag: '"c"',
      updatedAt: '1970-01-01T00:00:00.000Z',
      data: { a: 1 },
      createdBy: 'did:key:z',
      metaEtag: '"m"'
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
    expect(master?.etag).toBe('"g.4"')
    // A valid, sortable epoch-zero timestamp (not an empty string).
    expect(new Date(master!.updatedAt).getTime()).toBe(0)
  })

  it('reports an opaque validator as the etag with no version', async () => {
    const { was } = makeWas({
      onRequest: opts => {
        if (opts.path?.endsWith('/meta')) {
          throw httpError(404)
        }
        return response({ a: 1 }, { etag: '"a1b2c3"' })
      }
    })
    const port = createWasSyncPort({ was, spaceId: SPACE, collectionId: COLL })

    const master = await port.get({ id: 'res-1' })
    expect(master?.etag).toBe('"a1b2c3"')
    expect(master).not.toHaveProperty('version')
  })

  it('reports neither etag nor version when the read carries no ETag', async () => {
    const { was } = makeWas({
      onRequest: opts => {
        if (opts.path?.endsWith('/meta')) {
          throw httpError(404)
        }
        return response({ a: 1 })
      }
    })
    const port = createWasSyncPort({ was, spaceId: SPACE, collectionId: COLL })

    const master = await port.get({ id: 'res-1' })
    expect(master).not.toHaveProperty('etag')
    expect(master).not.toHaveProperty('version')
    expect(master?.data).toEqual({ a: 1 })
  })

  it('refuses a stored body the port cannot carry as JSON', async () => {
    // `@interop/http-client` populates `.data` only for a JSON media type, so
    // a resource stored as `text/jsonl` (or any opaque bytes) arrives with a
    // real `version`/`etag` and no body. Reporting that as live-but-empty
    // state would have a replica push an empty document over real content.
    const { was } = makeWas({
      onRequest: opts => {
        if (opts.path?.endsWith('/meta')) {
          throw httpError(404)
        }
        return response(undefined, {
          etag: '"g.4"',
          'content-type': 'text/jsonl'
        })
      }
    })
    const port = createWasSyncPort({ was, spaceId: SPACE, collectionId: COLL })
    await expect(port.get({ id: 'res-1' })).rejects.toThrow(WasServerError)
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
    await port.putMeta({ id: 'res-1', custom: { name: 'Alice' } })
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

    await port.putMeta({ id: 'res-1' })

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

    expect(await port.putMeta({ id: 'res-1', custom: { a: 1 } })).toEqual({
      etag: '"g3.3"'
    })
  })

  it('acks an opaque validator with no version', async () => {
    const { was } = makeWas({
      onRequest: () => response(null, { etag: '"a1b2c3"' })
    })
    const port = createWasSyncPort({ was, spaceId: SPACE, collectionId: COLL })

    expect(await port.putMeta({ id: 'res-1', custom: { a: 1 } })).toStrictEqual(
      { etag: '"a1b2c3"' }
    )
  })

  it('returns undefined when the response carries neither ETag nor body', async () => {
    const { was } = makeWas({ onRequest: () => response(null) })
    const port = createWasSyncPort({ was, spaceId: SPACE, collectionId: COLL })

    expect(
      await port.putMeta({ id: 'res-1', custom: { a: 1 } })
    ).toBeUndefined()
  })
})

describe('createWasSyncPort write ack body', () => {
  const stamp = {
    updatedAt: '2026-10-04T12:00:00.000Z',
    updatedAtCounter: 0,
    originId: 'origin-a'
  }
  const metaStamp = { ...stamp, updatedAtCounter: 1, generation: 'g1' }
  const created = {
    contentType: 'application/json',
    size: 7,
    createdAt: '2026-10-04T12:00:00.000Z',
    createdBy: 'did:key:z6MkCreator',
    ...stamp
  }

  it('acks the stamp and createdBy from a 201 body beside the etag', async () => {
    const { was } = makeWas({
      onRequest: () => response(created, { etag: '"g.1"' })
    })
    const port = createWasSyncPort({ was, spaceId: SPACE, collectionId: COLL })

    const ack = await port.putContent({
      id: 'res-1',
      data: { a: 1 },
      ifNoneMatch: true
    })
    expect(ack).toStrictEqual({
      etag: '"g.1"',
      ...stamp,
      createdBy: 'did:key:z6MkCreator'
    })
  })

  it('acks the stamp alone from a 200 body (no provenance on an update)', async () => {
    const { contentType, size } = created
    const { was } = makeWas({
      onRequest: () =>
        response({ contentType, size, ...stamp }, { etag: '"g.2"' })
    })
    const port = createWasSyncPort({ was, spaceId: SPACE, collectionId: COLL })

    const ack = await port.putContent({ id: 'res-1', data: { a: 2 } })
    expect(ack).toStrictEqual({ etag: '"g.2"', ...stamp })
  })

  it('acks the /meta stamp under meta on a metadata write', async () => {
    const { contentType, size } = created
    const { was } = makeWas({
      onRequest: () =>
        response(
          { contentType, size, ...stamp, meta: metaStamp },
          { etag: '"m.1"' }
        )
    })
    const port = createWasSyncPort({ was, spaceId: SPACE, collectionId: COLL })

    expect(await port.putMeta({ id: 'res-1', custom: { a: 1 } })).toStrictEqual(
      { etag: '"m.1"', ...stamp, meta: metaStamp }
    )
  })

  it('returns a /meta ack with no validator when only the body reached the client', async () => {
    const { contentType, size } = created
    const { was } = makeWas({
      onRequest: () =>
        response({ contentType, size, ...stamp, meta: metaStamp })
    })
    const port = createWasSyncPort({ was, spaceId: SPACE, collectionId: COLL })

    expect(await port.putMeta({ id: 'res-1', custom: { a: 1 } })).toStrictEqual(
      { ...stamp, meta: metaStamp }
    )
  })

  it('copies a stamp whole or not at all', async () => {
    const { contentType, size } = created
    const { was } = makeWas({
      onRequest: () =>
        response(
          {
            contentType,
            size,
            updatedAt: stamp.updatedAt,
            meta: { updatedAt: stamp.updatedAt, generation: 'g1' }
          },
          { etag: '"g.3"' }
        )
    })
    const port = createWasSyncPort({ was, spaceId: SPACE, collectionId: COLL })

    const ack = await port.putContent({ id: 'res-1', data: { a: 1 } })
    expect(ack).toStrictEqual({ etag: '"g.3"' })
  })

  it('ignores a body that is not the Resource Metadata shape', async () => {
    const { was } = makeWas({
      onRequest: () => response({ a: 1, ...stamp }, { etag: '"g.4"' })
    })
    const port = createWasSyncPort({ was, spaceId: SPACE, collectionId: COLL })

    const ack = await port.putContent({ id: 'res-1', data: { a: 1 } })
    expect(ack).toStrictEqual({ etag: '"g.4"' })
  })

  it('ignores a non-string createdBy', async () => {
    const { was } = makeWas({
      onRequest: () =>
        response({ ...created, createdBy: 42 }, { etag: '"g.5"' })
    })
    const port = createWasSyncPort({ was, spaceId: SPACE, collectionId: COLL })

    const ack = await port.putContent({ id: 'res-1', data: { a: 1 } })
    expect(ack).toStrictEqual({ etag: '"g.5"', ...stamp })
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
        () => port.putMeta({ id: 'res-1', custom: { a: 1 } })
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
    expect((await port.get({ id: 'res-1' }))?.etag).toBe('"g.4"')
  })

  it('raises the not-found signal on a /meta 404 when off', async () => {
    // A metadata-only edit against a resource another replica deleted: the
    // push loop corroborates the signal off the feed instead of retrying.
    const err = await failingPort(404, false)
      .putMeta({
        id: 'res-1',
        custom: { a: 1 }
      })
      .catch((caught: unknown) => caught)
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
        () => port.putMeta({ id: 'res-1', custom: { a: 1 } })
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
  const PRECONDITION_FAILED = 'https://w3id.org/pws#precondition-failed'
  const QUOTA_EXCEEDED = 'https://w3id.org/pws#quota-exceeded'

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
    const raw = problemError(404, 'https://w3id.org/pws#not-found')
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
      type: 'https://w3id.org/pws#not-found',
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
    const err = await refusingPort(500, 'https://w3id.org/pws#storage')
      .get({ id: 'res-1' })
      .catch((caught: unknown) => caught)
    expect(err).toBeInstanceOf(WasError)
    expect(err).toMatchObject({ status: 500 })
  })

  it('carries the problem fields onto the auth signal', async () => {
    const raw = problemError(403, 'https://w3id.org/pws#not-authorized')
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

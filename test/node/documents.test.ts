/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Unit tests for `Collection.documents()`, the snapshot walk over the
 * `changes` feed, and for the server-fault guards in `Collection.changes()`
 * it relies on. A stub `ZcapClient` answers each `changes` POST with a canned
 * page keyed by the checkpoint it was resumed from, so no server is involved.
 */
import { describe, it, expect } from 'vitest'

import type { HttpResponse } from '@interop/http-client'
import { WasServerError } from '../../src/index.js'
import type {
  ChangeDocument,
  ChangesPage,
  Collection
} from '../../src/index.js'
import { clientWithStub, jsonResponse } from '../helpers/stubClient.js'

/**
 * Builds a feed entry. A live entry with no `data` models the server's own
 * read-fault shape.
 *
 * @param id {string}
 * @param updatedAt {string}
 * @param [options] {object}
 * @param [options.data] {unknown}
 * @param [options.deleted] {boolean}   a tombstone
 * @returns {ChangeDocument}
 */
function entry(
  id: string,
  updatedAt: string,
  { data, deleted = false }: { data?: unknown; deleted?: boolean } = {}
): ChangeDocument {
  return {
    id,
    _deleted: deleted,
    updatedAt,
    version: 1,
    ...(data !== undefined && { data })
  }
}

/**
 * A collection handle over a stub client whose `changes` POST answers with the
 * page keyed by the request's checkpoint id (`''` for the first request), or
 * throws the error registered under that key. Records every request body.
 *
 * @param pages {Record<string, ChangesPage | Error | HttpResponse>}   a raw
 *   `HttpResponse` is returned as-is, for malformed-response cases
 * @returns {object} { notes, bodies }
 */
function collectionWithFeed(
  pages: Record<string, ChangesPage | Error | HttpResponse>
): {
  notes: Collection
  bodies: Array<Record<string, unknown>>
} {
  const bodies: Array<Record<string, unknown>> = []
  const client = clientWithStub(({ json }) => {
    const body = json as Record<string, unknown>
    bodies.push(body)
    const key = (body.checkpoint as { id: string } | undefined)?.id ?? ''
    const page = pages[key]
    if (page === undefined) {
      throw new Error(`no page registered for checkpoint "${key}"`)
    }
    if (page instanceof Error) {
      throw page
    }
    if ('status' in page) {
      return page
    }
    return jsonResponse({ data: page })
  })
  return { notes: client.space('s').collection('notes'), bodies }
}

const notFound = () => Object.assign(new Error('not found'), { status: 404 })

describe('Collection.documents()', () => {
  it('walks to the null checkpoint and reduces the pages to the live documents', async () => {
    const { notes, bodies } = collectionWithFeed({
      '': {
        documents: [
          entry('a', '2026-01-01T00:00:00.000Z', { data: { n: 1 } }),
          entry('b', '2026-01-02T00:00:00.000Z', { data: { n: 2 } })
        ],
        checkpoint: { id: 'b', updatedAt: '2026-01-02T00:00:00.000Z' }
      },
      // `b` rewritten mid-walk takes its later position; `a` is tombstoned.
      b: {
        documents: [
          entry('b', '2026-01-03T00:00:00.000Z', { data: { n: 3 } }),
          entry('a', '2026-01-04T00:00:00.000Z', { deleted: true })
        ],
        checkpoint: { id: 'a', updatedAt: '2026-01-04T00:00:00.000Z' }
      },
      // A short page is not the end: only the null checkpoint is.
      a: {
        documents: [entry('c', '2026-01-05T00:00:00.000Z', { data: { n: 4 } })],
        checkpoint: { id: 'c', updatedAt: '2026-01-05T00:00:00.000Z' }
      },
      c: { documents: [], checkpoint: null }
    })

    const docs = await notes.documents({ limit: 2 })

    expect(docs!.map(doc => [doc.id, doc.data])).toEqual([
      ['b', { n: 3 }],
      ['c', { n: 4 }]
    ])
    expect(bodies).toEqual([
      { profile: 'changes', limit: 2 },
      {
        profile: 'changes',
        checkpoint: { id: 'b', updatedAt: '2026-01-02T00:00:00.000Z' },
        limit: 2
      },
      {
        profile: 'changes',
        checkpoint: { id: 'a', updatedAt: '2026-01-04T00:00:00.000Z' },
        limit: 2
      },
      {
        profile: 'changes',
        checkpoint: { id: 'c', updatedAt: '2026-01-05T00:00:00.000Z' },
        limit: 2
      }
    ])
  })

  it('asks for 1000 documents per page by default', async () => {
    const { notes, bodies } = collectionWithFeed({
      '': { documents: [], checkpoint: null }
    })

    await expect(notes.documents()).resolves.toEqual([])
    expect(bodies).toEqual([{ profile: 'changes', limit: 1000 }])
  })

  it('fails the walk on a live entry the server could not read', async () => {
    const { notes } = collectionWithFeed({
      '': {
        documents: [
          entry('a', '2026-01-01T00:00:00.000Z', { data: { n: 1 } }),
          entry('b', '2026-01-02T00:00:00.000Z')
        ],
        checkpoint: null
      }
    })

    const err = await notes.documents().catch((err: unknown) => err)
    expect(err).toBeInstanceOf(WasServerError)
    expect((err as Error).message).toContain('served resource "b" with no body')
  })

  it('fails the walk on a 2xx page with no JSON body', async () => {
    const { notes } = collectionWithFeed({
      '': jsonResponse({
        status: 200,
        headers: { 'content-type': 'text/plain' }
      })
    })

    const err = await notes.documents().catch((err: unknown) => err)
    expect(err).toBeInstanceOf(WasServerError)
    expect((err as Error).message).toContain('text/plain')
  })

  it('fails the walk on a server that repeats a checkpoint', async () => {
    const { notes, bodies } = collectionWithFeed({
      '': {
        documents: [entry('a', '2026-01-01T00:00:00.000Z', { data: { n: 1 } })],
        checkpoint: { id: 'a', updatedAt: '2026-01-01T00:00:00.000Z' }
      },
      a: {
        documents: [],
        checkpoint: { id: 'a', updatedAt: '2026-01-01T00:00:00.000Z' }
      }
    })

    const err = await notes.documents().catch((err: unknown) => err)
    expect(err).toBeInstanceOf(WasServerError)
    expect((err as Error).message).toContain('repeated checkpoint')
    expect(bodies).toHaveLength(2)
  })

  it('resolves null for a missing or invisible collection', async () => {
    const { notes } = collectionWithFeed({ '': notFound() })

    await expect(notes.documents()).resolves.toBeNull()
  })

  it('throws a 404 met after the first page rather than dropping pages read', async () => {
    const { notes } = collectionWithFeed({
      '': {
        documents: [entry('a', '2026-01-01T00:00:00.000Z', { data: { n: 1 } })],
        checkpoint: { id: 'a', updatedAt: '2026-01-01T00:00:00.000Z' }
      },
      a: notFound()
    })

    await expect(notes.documents()).rejects.toThrow('not found')
  })

  it('rethrows any other feed error', async () => {
    const { notes } = collectionWithFeed({
      '': Object.assign(new Error('nope'), { status: 501 })
    })

    await expect(notes.documents()).rejects.toThrow()
  })
})

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
import type { ChangesPage, Collection } from '../../src/index.js'
import { feedEntry, recordEntry } from '../helpers/changesFeed.js'
import { clientWithStub, jsonResponse } from '../helpers/stubClient.js'

/**
 * A collection handle over a stub client whose `changes` POST answers with the
 * page keyed by the request's checkpoint (`''` for the first request), or
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
    const key = (body.checkpoint as string | undefined) ?? ''
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
          feedEntry({ id: 'a', checkpoint: 'cp-1', data: { n: 1 } }),
          feedEntry({ id: 'b', checkpoint: 'cp-2', data: { n: 2 } })
        ],
        checkpoint: 'cp-2'
      },
      // `b` rewritten mid-walk takes its later position; `a` is tombstoned.
      'cp-2': {
        documents: [
          feedEntry({ id: 'b', checkpoint: 'cp-3', data: { n: 3 } }),
          feedEntry({ id: 'a', checkpoint: 'cp-4', deleted: true })
        ],
        checkpoint: 'cp-4'
      },
      // A short page is not the end: only the null checkpoint is.
      'cp-4': {
        documents: [feedEntry({ id: 'c', checkpoint: 'cp-5', data: { n: 4 } })],
        checkpoint: 'cp-5'
      },
      'cp-5': { documents: [], checkpoint: null }
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
        checkpoint: 'cp-2',
        limit: 2
      },
      {
        profile: 'changes',
        checkpoint: 'cp-4',
        limit: 2
      },
      {
        profile: 'changes',
        checkpoint: 'cp-5',
        limit: 2
      }
    ])
  })

  it('skips every entry but a JSON Resource and still resumes past them', async () => {
    const { notes, bodies } = collectionWithFeed({
      '': {
        documents: [
          recordEntry('collection-metadata', 'cp-1'),
          feedEntry({ id: 'a', checkpoint: 'cp-2', data: { n: 1 } }),
          recordEntry('log', 'cp-3')
        ],
        checkpoint: 'cp-3'
      },
      // A page of skipped entries alone is not the end of the walk.
      'cp-3': {
        documents: [
          recordEntry('policy', 'cp-4'),
          feedEntry({
            id: 'pic',
            checkpoint: 'cp-5',
            contentType: 'image/png'
          }),
          feedEntry({
            id: 'did.jsonl',
            checkpoint: 'cp-6',
            contentType: 'text/jsonl'
          })
        ],
        checkpoint: 'cp-6'
      },
      'cp-6': {
        documents: [feedEntry({ id: 'b', checkpoint: 'cp-7', data: { n: 2 } })],
        checkpoint: 'cp-7'
      },
      'cp-7': { documents: [], checkpoint: null }
    })

    const docs = await notes.documents({ limit: 3 })

    expect(docs!.map(doc => [doc.kind, doc.id, doc.data])).toEqual([
      ['resource', 'a', { n: 1 }],
      ['resource', 'b', { n: 2 }]
    ])
    expect(bodies.map(body => body.checkpoint)).toEqual([
      undefined,
      'cp-3',
      'cp-6',
      'cp-7'
    ])
  })

  it('drops a JSON Resource rewritten to a non-JSON type', async () => {
    const { notes } = collectionWithFeed({
      '': {
        documents: [
          feedEntry({ id: 'a', checkpoint: 'cp-1', data: { n: 1 } }),
          feedEntry({ id: 'b', checkpoint: 'cp-2', data: { n: 2 } }),
          feedEntry({
            id: 'a',
            checkpoint: 'cp-3',
            contentType: 'application/octet-stream'
          }),
          feedEntry({ id: 'b', checkpoint: 'cp-4', deleted: true })
        ],
        checkpoint: null
      }
    })

    await expect(notes.documents()).resolves.toEqual([])
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
          feedEntry({ id: 'a', checkpoint: 'cp-1', data: { n: 1 } }),
          feedEntry({ id: 'b', checkpoint: 'cp-2' })
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
        documents: [feedEntry({ id: 'a', checkpoint: 'cp-1', data: { n: 1 } })],
        checkpoint: 'cp-1'
      },
      'cp-1': {
        documents: [],
        checkpoint: 'cp-1'
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
        documents: [feedEntry({ id: 'a', checkpoint: 'cp-1', data: { n: 1 } })],
        checkpoint: 'cp-1'
      },
      'cp-1': notFound()
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

describe('Collection.changes() record kinds', () => {
  it('passes every record kind through, an unknown one included', async () => {
    const documents = [
      recordEntry('collection-metadata', 'cp-1'),
      feedEntry({ id: 'a', checkpoint: 'cp-2', data: { n: 1 } }),
      recordEntry('log', 'cp-3'),
      recordEntry('policy', 'cp-4')
    ]
    const { notes } = collectionWithFeed({
      '': { documents, checkpoint: 'cp-4' }
    })

    await expect(notes.changes()).resolves.toEqual({
      documents,
      checkpoint: 'cp-4'
    })
  })

  it('accepts a binary or text/jsonl Resource with no data', async () => {
    const documents = [
      feedEntry({ id: 'pic', checkpoint: 'cp-1', contentType: 'image/png' }),
      feedEntry({
        id: 'did.jsonl',
        checkpoint: 'cp-2',
        contentType: 'text/jsonl'
      }),
      feedEntry({ id: 'gone', checkpoint: 'cp-3', deleted: true })
    ]
    const { notes } = collectionWithFeed({
      '': { documents, checkpoint: 'cp-3' }
    })

    const page = await notes.changes()
    expect(page.documents).toEqual(documents)
  })

  it('refuses a live JSON Resource with no data', async () => {
    const { notes } = collectionWithFeed({
      '': {
        documents: [
          feedEntry({
            id: 'a',
            checkpoint: 'cp-1',
            contentType: 'application/ld+json'
          })
        ],
        checkpoint: 'cp-1'
      }
    })

    const err = await notes.changes().catch((err: unknown) => err)
    expect(err).toBeInstanceOf(WasServerError)
    expect((err as Error).message).toContain('served resource "a" with no body')
  })
})

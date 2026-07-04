/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Unit tests for list pagination: the `collectPages` helper and its two callers,
 * the signed `Collection.list()` and the unsigned `was.publicListCollection()`.
 * Both transparently follow the server's `next` continuation links and aggregate
 * every page into one listing. A stub `ZcapClient` (signed path) and a stubbed
 * global `fetch` (public path) return canned pages keyed by request URL, so no
 * server is involved.
 */
import { describe, it, expect, vi, afterEach } from 'vitest'

import type { HttpResponse } from '@interop/http-client'
import { WasClient } from '../../src/index.js'
import { collectPages } from '../../src/internal/pagination.js'
import type { CollectionResourcesList } from '../../src/types.js'

/**
 * Builds a one-item page envelope; `next` is included only when given.
 *
 * @param items {string[]}   resource ids for this page
 * @param [next] {string}    continuation URL, if any
 * @returns {CollectionResourcesList}
 */
function page(items: string[], next?: string): CollectionResourcesList {
  const listing: CollectionResourcesList = {
    id: 'c',
    url: '/space/s/c',
    type: ['Collection'],
    totalItems: 5,
    items: items.map(id => ({
      id,
      url: `/space/s/c/${id}`,
      contentType: 'application/json'
    }))
  }
  if (next !== undefined) {
    listing.next = next
  }
  return listing
}

/**
 * Builds a `WasClient` over a stub `ZcapClient` that returns each page in
 * `pages` keyed by request URL, recording the URLs it was asked for.
 *
 * @param pages {Record<string, CollectionResourcesList>}
 * @returns {object} { client, urls }
 */
function clientWithPages(pages: Record<string, CollectionResourcesList>): {
  client: WasClient
  urls: string[]
} {
  const urls: string[] = []
  const zcapClient = {
    invocationSigner: { id: 'did:example:alice#key-1' },
    async request({ url }: { url: string }) {
      urls.push(url)
      const data = pages[url]
      return {
        status: 200,
        headers: new Headers(),
        data,
        async json() {
          return data
        }
      } as unknown as HttpResponse
    }
  } as unknown as ConstructorParameters<typeof WasClient>[0]['zcapClient']
  const client = new WasClient({ serverUrl: 'https://was.example', zcapClient })
  return { client, urls }
}

afterEach(() => {
  vi.unstubAllGlobals()
})

describe('collectPages()', () => {
  it('returns the single page unchanged when there is no `next`', async () => {
    const first = page(['a', 'b'])
    const result = await collectPages({
      first,
      firstUrl: 'https://was.example/space/s/c/',
      fetchPage: async () => {
        throw new Error('should not fetch')
      }
    })
    expect(result.items.map(item => item.id)).toEqual(['a', 'b'])
    expect(result.next).toBeUndefined()
  })

  it('follows `next`, resolving a relative link against the page URL', async () => {
    const fetched: string[] = []
    const result = await collectPages({
      first: page(['a'], '/space/s/c/?cursor=2'),
      firstUrl: 'https://was.example/space/s/c/',
      fetchPage: async url => {
        fetched.push(url)
        return page(['b'])
      }
    })
    expect(fetched).toEqual(['https://was.example/space/s/c/?cursor=2'])
    expect(result.items.map(item => item.id)).toEqual(['a', 'b'])
    expect(result.next).toBeUndefined()
  })

  it('stops on a self-referential `next` rather than looping forever', async () => {
    let calls = 0
    const result = await collectPages({
      first: page(['a'], 'https://was.example/space/s/c/'),
      firstUrl: 'https://was.example/space/s/c/',
      fetchPage: async () => {
        calls += 1
        return page(['b'], 'https://was.example/space/s/c/')
      }
    })
    // `next` points back at the first (already-seen) URL, so no fetch happens.
    expect(calls).toBe(0)
    expect(result.items.map(item => item.id)).toEqual(['a'])
  })

  it('ends the traversal when a page comes back null (missing/unauthorized)', async () => {
    const result = await collectPages({
      first: page(['a'], '/space/s/c/?cursor=2'),
      firstUrl: 'https://was.example/space/s/c/',
      fetchPage: async () => null
    })
    expect(result.items.map(item => item.id)).toEqual(['a'])
  })

  it('detects a cycle even when the first URL is not in canonical form', async () => {
    // The cycle guard seed must be canonicalized the same way followed links
    // are: `https://host:443/...` (explicit default port) and the portless form
    // are the same URL, so a next-link back to page 1 must end the traversal
    // instead of yielding its items twice.
    let calls = 0
    const result = await collectPages({
      first: page(['a'], 'https://was.example/space/s/c/'),
      firstUrl: 'https://was.example:443/space/s/c/',
      fetchPage: async () => {
        calls += 1
        return page(['b'])
      }
    })
    expect(calls).toBe(0)
    expect(result.items.map(item => item.id)).toEqual(['a'])
  })
})

describe('Collection.list() pagination', () => {
  it('follows `next` across pages and aggregates the items', async () => {
    const { client, urls } = clientWithPages({
      'https://was.example/space/s/c/': page(
        ['a', 'b'],
        '/space/s/c/?cursor=2'
      ),
      'https://was.example/space/s/c/?cursor=2': page(['c'])
    })
    const result = await client.space('s').collection('c').list()
    expect(urls).toEqual([
      'https://was.example/space/s/c/',
      'https://was.example/space/s/c/?cursor=2'
    ])
    expect(result?.items.map(item => item.id)).toEqual(['a', 'b', 'c'])
    expect(result?.next).toBeUndefined()
    expect(result?.totalItems).toBe(5)
  })
})

describe('Collection.listPages() / listItems()', () => {
  it('listPages() yields each page lazily', async () => {
    const { client } = clientWithPages({
      'https://was.example/space/s/c/': page(
        ['a', 'b'],
        '/space/s/c/?cursor=2'
      ),
      'https://was.example/space/s/c/?cursor=2': page(['c'])
    })
    const sizes: number[] = []
    for await (const pageResult of client
      .space('s')
      .collection('c')
      .listPages()) {
      sizes.push(pageResult.items.length)
    }
    expect(sizes).toEqual([2, 1])
  })

  it('listItems() flattens items across pages', async () => {
    const { client } = clientWithPages({
      'https://was.example/space/s/c/': page(
        ['a', 'b'],
        '/space/s/c/?cursor=2'
      ),
      'https://was.example/space/s/c/?cursor=2': page(['c'])
    })
    const ids: string[] = []
    for await (const item of client.space('s').collection('c').listItems()) {
      ids.push(item.id)
    }
    expect(ids).toEqual(['a', 'b', 'c'])
  })

  it('listItems() stops fetching when the consumer breaks early', async () => {
    const { client, urls } = clientWithPages({
      'https://was.example/space/s/c/': page(
        ['a', 'b'],
        '/space/s/c/?cursor=2'
      ),
      'https://was.example/space/s/c/?cursor=2': page(['c'])
    })
    const ids: string[] = []
    for await (const item of client.space('s').collection('c').listItems()) {
      ids.push(item.id)
      if (ids.length === 1) {
        break
      }
    }
    expect(ids).toEqual(['a'])
    // Broke during the first page, so the second page was never requested.
    expect(urls).toEqual(['https://was.example/space/s/c/'])
  })

  it('listPages() yields nothing for a missing collection', async () => {
    const zcapClient = {
      invocationSigner: { id: 'did:example:alice#key-1' },
      async request() {
        throw { status: 404, response: { status: 404 } }
      }
    } as unknown as ConstructorParameters<typeof WasClient>[0]['zcapClient']
    const client = new WasClient({
      serverUrl: 'https://was.example',
      zcapClient
    })
    const pages: CollectionResourcesList[] = []
    for await (const pageResult of client
      .space('s')
      .collection('missing')
      .listPages()) {
      pages.push(pageResult)
    }
    expect(pages).toEqual([])
  })
})

describe('publicListCollection() pagination', () => {
  it('follows `next` across pages with an unsigned fetch', async () => {
    const pages: Record<string, CollectionResourcesList> = {
      'https://was.example/space/s/c/': page(['a'], '/space/s/c/?cursor=2'),
      'https://was.example/space/s/c/?cursor=2': page(['b', 'c'])
    }
    const requested: string[] = []
    vi.stubGlobal('fetch', async (input: string) => {
      requested.push(input)
      return new Response(JSON.stringify(pages[input]), {
        headers: { 'content-type': 'application/json' }
      })
    })
    const zcapClient = {
      invocationSigner: { id: 'did:example:alice#key-1' }
    } as unknown as ConstructorParameters<typeof WasClient>[0]['zcapClient']
    const client = new WasClient({
      serverUrl: 'https://was.example',
      zcapClient
    })
    const result = await client.publicListCollection({
      collectionUrl: 'https://was.example/space/s/c'
    })
    expect(requested).toEqual([
      'https://was.example/space/s/c/',
      'https://was.example/space/s/c/?cursor=2'
    ])
    expect(result?.items.map(item => item.id)).toEqual(['a', 'b', 'c'])
    expect(result?.next).toBeUndefined()
  })

  it('publicListCollectionItems() streams items and stops early', async () => {
    const pages: Record<string, CollectionResourcesList> = {
      'https://was.example/space/s/c/': page(['a'], '/space/s/c/?cursor=2'),
      'https://was.example/space/s/c/?cursor=2': page(['b'])
    }
    const requested: string[] = []
    vi.stubGlobal('fetch', async (input: string) => {
      requested.push(input)
      return new Response(JSON.stringify(pages[input]), {
        headers: { 'content-type': 'application/json' }
      })
    })
    const zcapClient = {
      invocationSigner: { id: 'did:example:alice#key-1' }
    } as unknown as ConstructorParameters<typeof WasClient>[0]['zcapClient']
    const client = new WasClient({
      serverUrl: 'https://was.example',
      zcapClient
    })
    const ids: string[] = []
    for await (const item of client.publicListCollectionItems({
      collectionUrl: 'https://was.example/space/s/c'
    })) {
      ids.push(item.id)
      break
    }
    expect(ids).toEqual(['a'])
    // Stopped during the first page, so the continuation was never fetched.
    expect(requested).toEqual(['https://was.example/space/s/c/'])
  })
})

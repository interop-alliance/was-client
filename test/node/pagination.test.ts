/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Unit tests for list pagination: the `collectPages` helper and the listing
 * methods built on it -- the signed `Collection.list()`, `Space.collections()`,
 * and `WasClient.listSpaces()`, and the unsigned `was.publicListCollection()`.
 * All transparently follow the server's `next` continuation links and aggregate
 * every page into one listing. A stub `ZcapClient` (signed path) and a stubbed
 * global `fetch` (public path) return canned pages keyed by request URL, so no
 * server is involved. The walk's trust boundary is covered too: a hostile
 * `next` outside the listing is never requested, and a walk that never ends is
 * bounded.
 */
import { describe, it, expect, vi, afterEach } from 'vitest'

import type { HttpResponse } from '@interop/http-client'
import { WasClient, WasServerError } from '../../src/index.js'
import {
  DEFAULT_MAX_PAGES,
  collectPages,
  walkPages
} from '../../src/internal/pagination.js'
import type {
  CollectionResourcesList,
  CollectionsList,
  SpaceListing
} from '../../src/types.js'
import { clientWithStub, serviceDescriptionFor } from '../helpers/stubClient.js'

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
 * Builds a one-collection page envelope for a List Collections listing; `next`
 * is included only when given.
 *
 * @param ids {string[]}     collection ids for this page
 * @param [next] {string}    continuation URL, if any
 * @returns {CollectionsList}
 */
function collectionsPage(ids: string[], next?: string): CollectionsList {
  const listing: CollectionsList = {
    url: '/space/s/',
    totalItems: 5,
    items: ids.map(id => ({ id, url: `/space/s/${id}`, name: id }))
  }
  if (next !== undefined) {
    listing.next = next
  }
  return listing
}

/**
 * Builds a page envelope for a List Spaces listing. `totalItems` is included
 * only when given (a paginating server omits it on truncated pages); `next` is
 * included only when given.
 *
 * @param ids {string[]}          space ids for this page
 * @param options {object}
 * @param [options.next] {string}         continuation URL, if any
 * @param [options.totalItems] {number}   listing total, if the server sent one
 * @returns {SpaceListing}
 */
function spacesPage(
  ids: string[],
  { next, totalItems }: { next?: string; totalItems?: number } = {}
): SpaceListing {
  const listing: SpaceListing = {
    url: '/spaces/',
    items: ids.map(id => ({ id, url: `/space/${id}`, name: id }))
  }
  if (totalItems !== undefined) {
    listing.totalItems = totalItems
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
 * @param pages {Record<string, object>}   listing envelopes keyed by request URL
 * @returns {object} { client, urls }
 */
function clientWithPages(pages: Record<string, object>): {
  client: WasClient
  urls: string[]
} {
  const urls: string[] = []
  const client = clientWithStub(async ({ url }) => {
    urls.push(url as string)
    const data = pages[url as string]
    return {
      status: 200,
      headers: new Headers(),
      data,
      async json() {
        return data
      }
    } as unknown as HttpResponse
  })
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
    const client = clientWithStub(async () => {
      throw { status: 404, response: { status: 404 } }
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
      serviceDescription: serviceDescriptionFor(),
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
      serviceDescription: serviceDescriptionFor(),
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

describe('Space.collections() pagination', () => {
  it('follows `next` across pages and aggregates, dropping `next`', async () => {
    const { client, urls } = clientWithPages({
      'https://was.example/space/s/': collectionsPage(
        ['a', 'b'],
        '/space/s/?cursor=2'
      ),
      'https://was.example/space/s/?cursor=2': collectionsPage(['c'])
    })
    const result = await client.space('s').collections()
    expect(urls).toEqual([
      'https://was.example/space/s/',
      'https://was.example/space/s/?cursor=2'
    ])
    expect(result?.items.map(item => item.id)).toEqual(['a', 'b', 'c'])
    expect(result?.next).toBeUndefined()
    expect(result?.totalItems).toBe(5)
  })

  it('returns the single page unchanged when there is no `next`', async () => {
    const { client, urls } = clientWithPages({
      'https://was.example/space/s/': collectionsPage(['a', 'b'])
    })
    const result = await client.space('s').collections()
    expect(urls).toEqual(['https://was.example/space/s/'])
    expect(result?.items.map(item => item.id)).toEqual(['a', 'b'])
    expect(result?.next).toBeUndefined()
  })

  it('returns null for a missing/unauthorized space', async () => {
    const client = clientWithStub(async () => {
      throw { status: 404, response: { status: 404 } }
    })
    const result = await client.space('missing').collections()
    expect(result).toBeNull()
  })
})

describe('Space.collectionsPages()', () => {
  it('yields each page lazily', async () => {
    const { client } = clientWithPages({
      'https://was.example/space/s/': collectionsPage(
        ['a', 'b'],
        '/space/s/?cursor=2'
      ),
      'https://was.example/space/s/?cursor=2': collectionsPage(['c'])
    })
    const sizes: number[] = []
    for await (const pageResult of client.space('s').collectionsPages()) {
      sizes.push(pageResult.items.length)
    }
    expect(sizes).toEqual([2, 1])
  })

  it('stops fetching when the consumer breaks early', async () => {
    const { client, urls } = clientWithPages({
      'https://was.example/space/s/': collectionsPage(
        ['a', 'b'],
        '/space/s/?cursor=2'
      ),
      'https://was.example/space/s/?cursor=2': collectionsPage(['c'])
    })
    const ids: string[] = []
    for await (const pageResult of client.space('s').collectionsPages()) {
      for (const item of pageResult.items) {
        ids.push(item.id)
      }
      break
    }
    expect(ids).toEqual(['a', 'b'])
    // Broke during the first page, so the second page was never requested.
    expect(urls).toEqual(['https://was.example/space/s/'])
  })

  it('yields nothing for a missing/unauthorized space', async () => {
    const client = clientWithStub(async () => {
      throw { status: 404, response: { status: 404 } }
    })
    const pages: CollectionsList[] = []
    for await (const pageResult of client.space('missing').collectionsPages()) {
      pages.push(pageResult)
    }
    expect(pages).toEqual([])
  })
})

describe('WasClient.listSpaces() pagination', () => {
  it('follows `next` across pages and recomputes totalItems', async () => {
    const { client, urls } = clientWithPages({
      // A paginating server omits `totalItems` on the truncated first page.
      'https://was.example/spaces/': spacesPage(['a', 'b'], {
        next: '/spaces/?cursor=2'
      }),
      'https://was.example/spaces/?cursor=2': spacesPage(['c'])
    })
    const result = await client.listSpaces()
    expect(urls).toEqual([
      'https://was.example/spaces/',
      'https://was.example/spaces/?cursor=2'
    ])
    expect(result.items.map(item => item.id)).toEqual(['a', 'b', 'c'])
    expect(result.next).toBeUndefined()
    // Recomputed from the collected items, not inherited from the first page.
    expect(result.totalItems).toBe(3)
  })

  it('returns the single page with totalItems recomputed when there is no `next`', async () => {
    const { client, urls } = clientWithPages({
      'https://was.example/spaces/': spacesPage(['a', 'b'], { totalItems: 2 })
    })
    const result = await client.listSpaces()
    expect(urls).toEqual(['https://was.example/spaces/'])
    expect(result.items.map(item => item.id)).toEqual(['a', 'b'])
    expect(result.next).toBeUndefined()
    expect(result.totalItems).toBe(2)
  })
})

/**
 * Builds a `WasClient` whose unsigned public reads go through a stubbed global
 * `fetch` that returns each page in `pages` keyed by request URL, recording the
 * URLs it was asked for.
 *
 * @param pages {Record<string, object>}   listing envelopes keyed by request URL
 * @returns {object} { client, urls }
 */
function publicClientWithPages(pages: Record<string, object>): {
  client: WasClient
  urls: string[]
} {
  const urls: string[] = []
  vi.stubGlobal('fetch', async (input: string) => {
    urls.push(input)
    return new Response(JSON.stringify(pages[input] ?? {}), {
      headers: { 'content-type': 'application/json' }
    })
  })
  const zcapClient = {
    invocationSigner: { id: 'did:example:alice#key-1' }
  } as unknown as ConstructorParameters<typeof WasClient>[0]['zcapClient']
  const client = new WasClient({
    serverUrl: 'https://was.example',
    serviceDescription: serviceDescriptionFor(),
    zcapClient
  })
  return { client, urls }
}

/**
 * Consumes an async iterable to the end, returning what it yielded.
 *
 * @param iterable {AsyncIterable<T>}
 * @returns {Promise<T[]>}
 */
async function drain<T>(iterable: AsyncIterable<T>): Promise<T[]> {
  const yielded: T[] = []
  for await (const entry of iterable) {
    yielded.push(entry)
  }
  return yielded
}

/**
 * Every listing surface that follows `next`: its first page URL, a builder
 * for a one-item page envelope, and how to drive the whole walk.
 */
const LISTING_SURFACES: {
  name: string
  firstUrl: string
  envelope: (next?: unknown) => object
  publicRead?: boolean
  run: (client: WasClient) => Promise<unknown>
}[] = [
  {
    name: 'WasClient.listSpaces()',
    firstUrl: 'https://was.example/spaces/',
    envelope: next => ({ ...spacesPage(['a']), next }),
    run: client => client.listSpaces()
  },
  {
    name: 'Space.collections()',
    firstUrl: 'https://was.example/space/s/',
    envelope: next => ({ ...collectionsPage(['a']), next }),
    run: client => client.space('s').collections()
  },
  {
    name: 'Space.collectionsPages()',
    firstUrl: 'https://was.example/space/s/',
    envelope: next => ({ ...collectionsPage(['a']), next }),
    run: client => drain(client.space('s').collectionsPages())
  },
  {
    name: 'Collection.list()',
    firstUrl: 'https://was.example/space/s/c/',
    envelope: next => ({ ...page(['a']), next }),
    run: client => client.space('s').collection('c').list()
  },
  {
    name: 'Collection.listPages()',
    firstUrl: 'https://was.example/space/s/c/',
    envelope: next => ({ ...page(['a']), next }),
    run: client => drain(client.space('s').collection('c').listPages())
  },
  {
    name: 'Collection.listItems()',
    firstUrl: 'https://was.example/space/s/c/',
    envelope: next => ({ ...page(['a']), next }),
    run: client => drain(client.space('s').collection('c').listItems())
  },
  {
    name: 'WasClient.publicListCollection()',
    firstUrl: 'https://was.example/space/s/c/',
    envelope: next => ({ ...page(['a']), next }),
    publicRead: true,
    run: client =>
      client.publicListCollection({
        collectionUrl: 'https://was.example/space/s/c'
      })
  },
  {
    name: 'WasClient.publicListCollectionPages()',
    firstUrl: 'https://was.example/space/s/c/',
    envelope: next => ({ ...page(['a']), next }),
    publicRead: true,
    run: client =>
      drain(
        client.publicListCollectionPages({
          collectionUrl: 'https://was.example/space/s/c'
        })
      )
  },
  {
    name: 'WasClient.publicListCollectionItems()',
    firstUrl: 'https://was.example/space/s/c/',
    envelope: next => ({ ...page(['a']), next }),
    publicRead: true,
    run: client =>
      drain(
        client.publicListCollectionItems({
          collectionUrl: 'https://was.example/space/s/c'
        })
      )
  }
]

/**
 * `next` values that leave every listing above: another origin, a
 * protocol-relative host, a scheme downgrade, a path outside the base path, a
 * dot-segment escape, a backslash host, and a non-string value. Each surface
 * also gets a `next` that matches its own listing but carries credentials.
 */
const HOSTILE_NEXTS: unknown[] = [
  'http://169.254.169.254/latest/meta-data/',
  '//evil.example/space/s/c/?cursor=2',
  'http://was.example/space/s/c/?cursor=2',
  '/space/other/?cursor=2',
  '../../../other/?cursor=2',
  '\\\\evil.example/space/s/c/',
  42
]

/**
 * The first page URL of a surface with a username and password added, so the
 * credentials are the only thing wrong with it.
 *
 * @param firstUrl {string}
 * @returns {string}
 */
function withCredentials(firstUrl: string): string {
  const url = new URL(firstUrl)
  url.username = 'attacker'
  url.password = 'x'
  url.search = '?cursor=2'
  return url.toString()
}

describe('walk trust boundary: a hostile `next` is never requested', () => {
  for (const surface of LISTING_SURFACES) {
    for (const hostileNext of [
      ...HOSTILE_NEXTS,
      withCredentials(surface.firstUrl)
    ]) {
      it(`${surface.name} rejects next=${JSON.stringify(hostileNext)}`, async () => {
        const pages = { [surface.firstUrl]: surface.envelope(hostileNext) }
        const { client, urls } = surface.publicRead
          ? publicClientWithPages(pages)
          : clientWithPages(pages)
        const error = await surface.run(client).then(
          () => undefined,
          (err: unknown) => err
        )
        expect(error).toBeInstanceOf(WasServerError)
        expect((error as WasServerError).requestUrl).toBe(surface.firstUrl)
        expect((error as WasServerError).message).toContain(surface.firstUrl)
        // Only the first page was fetched; the hostile URL got no request.
        expect(urls).toEqual([surface.firstUrl])
      })
    }
  }

  it('follows a `next` under the base path resolved against a later page', async () => {
    const { client, urls } = clientWithPages({
      'https://was.example/space/s/c/': page(['a'], '?cursor=2'),
      'https://was.example/space/s/c/?cursor=2': page(['b'], 'page/3'),
      'https://was.example/space/s/c/page/3': page(['c'])
    })
    const result = await client.space('s').collection('c').list()
    expect(urls).toEqual([
      'https://was.example/space/s/c/',
      'https://was.example/space/s/c/?cursor=2',
      'https://was.example/space/s/c/page/3'
    ])
    expect(result?.items.map(item => item.id)).toEqual(['a', 'b', 'c'])
  })

  it("checks a later page's `next` against the first page, not its own", async () => {
    const { client, urls } = clientWithPages({
      'https://was.example/space/s/c/': page(['a'], 'page/2/'),
      'https://was.example/space/s/c/page/2/': page(['b'], '../../../d/')
    })
    await expect(client.space('s').collection('c').list()).rejects.toThrow(
      WasServerError
    )
    expect(urls).toEqual([
      'https://was.example/space/s/c/',
      'https://was.example/space/s/c/page/2/'
    ])
  })

  it('scopes a slash-less first URL at a path segment boundary', async () => {
    const fetched: string[] = []
    const pages = await drain(
      walkPages({
        first: page(['a'], '/spaces?cursor=2'),
        firstUrl: 'https://was.example/spaces',
        fetchPage: async url => {
          fetched.push(url)
          return page(['b'], '/spaces-other/')
        }
      })
    ).catch((err: unknown) => err)
    expect(pages).toBeInstanceOf(WasServerError)
    // `/spaces-other/` shares a string prefix with `/spaces` but is not under it.
    expect(fetched).toEqual(['https://was.example/spaces?cursor=2'])
  })
})

describe('walk page-count bound', () => {
  it('fails with a typed error naming the listing URL past `maxPages`', async () => {
    const fetched: string[] = []
    const yielded: CollectionResourcesList[] = []
    let error: unknown
    try {
      for await (const pageResult of walkPages(
        {
          first: page(['a'], '?cursor=1'),
          firstUrl: 'https://was.example/space/s/c/',
          fetchPage: async url => {
            fetched.push(url)
            return page(['b'], `?cursor=${fetched.length + 1}`)
          }
        },
        { maxPages: 3 }
      )) {
        yielded.push(pageResult)
      }
    } catch (err) {
      error = err
    }
    expect(yielded).toHaveLength(3)
    expect(fetched).toHaveLength(2)
    expect(error).toBeInstanceOf(WasServerError)
    expect((error as WasServerError).message).toContain(
      'https://was.example/space/s/c/'
    )
  })

  it('does not trip when the walk ends exactly at `maxPages`', async () => {
    const pages = await drain(
      walkPages(
        {
          first: page(['a'], '?cursor=2'),
          firstUrl: 'https://was.example/space/s/c/',
          fetchPage: async () => page(['b'])
        },
        { maxPages: 2 }
      )
    )
    expect(pages).toHaveLength(2)
  })

  it('bounds an endless cursor on a listing surface by default', async () => {
    const urls: string[] = []
    const client = clientWithStub(async ({ url }) => {
      urls.push(url as string)
      const data = page(['x'], `?cursor=${urls.length}`)
      return {
        status: 200,
        headers: new Headers(),
        data,
        async json() {
          return data
        }
      } as unknown as HttpResponse
    })
    await expect(client.space('s').collection('c').list()).rejects.toThrow(
      WasServerError
    )
    expect(urls).toHaveLength(DEFAULT_MAX_PAGES)
  })
})

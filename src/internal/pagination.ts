/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Pagination helpers for WAS list responses. A paginated listing carries a
 * `next` continuation URL when more items may follow; its absence is the
 * authoritative end-of-list signal (the spec forbids inferring page count from
 * `totalItems`). `walkPages` is the single traversal core: it follows `next`
 * from page to page, dereferencing each with the same authorization as the first
 * request, and yields one page at a time (constant memory, early-exit-friendly).
 * `collectPages` builds on it to eagerly aggregate every page into one envelope.
 */
import type { CollectionResourcesList, ResourceSummary } from '../types.js'

/**
 * The first page (already read) plus the means to fetch each following page.
 * The `fetchPage` callback fetches a single page by absolute URL, returning
 * `null` if it is missing/unauthorized (which ends the traversal).
 */
export interface PageWalk {
  first: CollectionResourcesList
  firstUrl: string
  fetchPage: (url: string) => Promise<CollectionResourcesList | null>
}

/**
 * Builds a {@link PageWalk} by fetching the first page with the same
 * `fetchPage` used for every following page -- the shared shape of the signed
 * (`Collection._listWalk`) and unsigned (`WasClient._publicListWalk`) walks,
 * which differ only in how a single page URL is fetched. Returns `null` when
 * the first page is missing/unauthorized (404 conflation caveat).
 *
 * @param options {object}
 * @param options.firstUrl {string}      the absolute listing URL
 * @param options.fetchPage {function}   fetches one page by absolute URL
 * @returns {Promise<PageWalk | null>}
 */
export async function buildPageWalk({
  firstUrl,
  fetchPage
}: {
  firstUrl: string
  fetchPage: PageWalk['fetchPage']
}): Promise<PageWalk | null> {
  const first = await fetchPage(firstUrl)
  return first === null ? null : { first, firstUrl, fetchPage }
}

/**
 * Lazily walks a list response page by page, yielding the first page and then
 * each page reached by following `next`. Each `next` is resolved relative to the
 * URL of the page that produced it, and a self-referential or already-seen
 * `next` ends the traversal defensively rather than looping forever. Yields one
 * page at a time, so a consumer can stop early without fetching the rest.
 *
 * @param walk {PageWalk}
 * @returns {AsyncGenerator<CollectionResourcesList>}
 */
export async function* walkPages(
  walk: PageWalk
): AsyncGenerator<CollectionResourcesList> {
  const { first, firstUrl, fetchPage } = walk
  yield first
  // Seed the cycle guard with the canonicalized first URL -- every followed
  // `next` is canonicalized via `new URL(...)`, so an equivalent-but-unequal
  // seed (e.g. an explicit default port) would let a next-link back to page 1
  // defeat the guard and yield its items twice.
  const seen = new Set<string>([new URL(firstUrl).toString()])
  let baseUrl = firstUrl
  let next = first.next
  while (next) {
    const pageUrl = new URL(next, baseUrl).toString()
    if (seen.has(pageUrl)) {
      break
    }
    seen.add(pageUrl)
    const page = await fetchPage(pageUrl)
    if (page === null) {
      break
    }
    yield page
    baseUrl = pageUrl
    next = page.next
  }
}

/**
 * Eagerly follows every `next` link, aggregating all pages' items into a single
 * envelope shaped like the first page (with `next` dropped, since the whole list
 * has been collected). Buffers the entire collection in memory; for a large
 * collection prefer `walkPages` (one page at a time) or an item iterator.
 *
 * @param walk {PageWalk}
 * @returns {Promise<CollectionResourcesList>}
 */
export async function collectPages(
  walk: PageWalk
): Promise<CollectionResourcesList> {
  let aggregate: CollectionResourcesList | undefined
  const items: CollectionResourcesList['items'] = []
  for await (const page of walkPages(walk)) {
    aggregate ??= page
    // Append one by one: spreading a page's items as call arguments would hit
    // the engine's max-arguments ceiling on a very large page.
    for (const item of page.items) {
      items.push(item)
    }
  }
  // `walkPages` always yields `first`, so `aggregate` is set here.
  const result: CollectionResourcesList = { ...aggregate!, items }
  delete result.next
  return result
}

/**
 * The buffering list surface over a possibly-absent walk: collects every page
 * into one envelope, mapping a `null` walk (missing/unauthorized listing) to
 * `null`. The shared dispatch behind `Collection.list()` and
 * `WasClient.publicListCollection()`.
 *
 * @param walk {PageWalk | null}
 * @returns {Promise<CollectionResourcesList | null>}
 */
export async function collectWalk(
  walk: PageWalk | null
): Promise<CollectionResourcesList | null> {
  return walk === null ? null : collectPages(walk)
}

/**
 * The lazy page surface over a possibly-absent walk: yields each page, or
 * nothing for a `null` walk (which an iterator cannot distinguish from an
 * empty listing). The shared dispatch behind `Collection.listPages()` and
 * `WasClient.publicListCollectionPages()`.
 *
 * @param walk {PageWalk | null}
 * @returns {AsyncGenerator<CollectionResourcesList>}
 */
export async function* walkPagesOrEmpty(
  walk: PageWalk | null
): AsyncGenerator<CollectionResourcesList> {
  if (walk !== null) {
    yield* walkPages(walk)
  }
}

/**
 * The lazy item surface: flattens a page iterator into its `ResourceSummary`
 * entries. The shared dispatch behind `Collection.listItems()` and
 * `WasClient.publicListCollectionItems()`.
 *
 * @param pages {AsyncIterable<CollectionResourcesList>}
 * @returns {AsyncGenerator<ResourceSummary>}
 */
export async function* walkItems(
  pages: AsyncIterable<CollectionResourcesList>
): AsyncGenerator<ResourceSummary> {
  for await (const page of pages) {
    yield* page.items
  }
}

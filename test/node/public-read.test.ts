/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Unit tests for the unauthenticated public-read methods (`was.publicRead()` /
 * `was.publicListCollection()`), which read `PublicCanRead` resources with an
 * unsigned plain `fetch`. A stubbed global `fetch` records the request and
 * returns canned `Response`s, so no server is involved.
 */
import { describe, it, expect, vi, afterEach } from 'vitest'

import { WasClient, WasServerError } from '../../src/index.js'

/**
 * Builds a `WasClient` over a minimal stub `ZcapClient`. The public-read
 * methods never sign, so the signer is unused here.
 *
 * @returns {WasClient}
 */
function publicClient(): WasClient {
  const zcapClient = {
    invocationSigner: { id: 'did:example:alice#key-1' }
  } as unknown as ConstructorParameters<typeof WasClient>[0]['zcapClient']
  return new WasClient({ serverUrl: 'https://was.example', zcapClient })
}

/**
 * Stubs the global `fetch` to return `response`, recording the URL it was
 * called with.
 *
 * @param response {Response}
 * @returns {() => string | undefined} a getter for the last requested URL
 */
function stubFetch(response: Response): () => string | undefined {
  let url: string | undefined
  vi.stubGlobal('fetch', async (input: string) => {
    url = input
    return response
  })
  return () => url
}

afterEach(() => {
  vi.unstubAllGlobals()
})

describe('publicRead()', () => {
  it('GETs the resource URL unsigned and parses JSON', async () => {
    const lastUrl = stubFetch(
      new Response(JSON.stringify({ hello: 'world' }), {
        headers: { 'content-type': 'application/json' }
      })
    )
    const result = await publicClient().publicRead({
      resourceUrl: 'https://was.example/space/s/c/r'
    })
    expect(lastUrl()).toBe('https://was.example/space/s/c/r')
    expect(result).toEqual({ hello: 'world' })
  })

  it('returns binary content as a Blob', async () => {
    stubFetch(
      new Response('plain text body', {
        headers: { 'content-type': 'text/plain' }
      })
    )
    const result = await publicClient().publicRead({
      resourceUrl: 'https://was.example/space/s/c/note.txt'
    })
    expect(result).toBeInstanceOf(Blob)
    expect(await (result as Blob).text()).toBe('plain text body')
  })

  it('returns null on a 404 (missing or not publicly readable)', async () => {
    stubFetch(new Response('', { status: 404 }))
    const result = await publicClient().publicRead({
      resourceUrl: 'https://was.example/space/s/c/missing'
    })
    expect(result).toBeNull()
  })

  it('returns null on a 401/403 (not publicly readable)', async () => {
    for (const status of [401, 403]) {
      stubFetch(new Response('', { status }))
      const result = await publicClient().publicRead({
        resourceUrl: 'https://was.example/space/s/c/private'
      })
      expect(result).toBeNull()
    }
  })

  it('throws a mapped error for a non-404 failure', async () => {
    stubFetch(new Response('', { status: 500 }))
    await expect(
      publicClient().publicRead({
        resourceUrl: 'https://was.example/space/s/c/boom'
      })
    ).rejects.toBeInstanceOf(WasServerError)
  })
})

describe('publicListCollection()', () => {
  it('GETs the trailing-slash items URL and returns the listing', async () => {
    const listing = {
      id: 'c',
      url: '...',
      type: ['Collection'],
      totalItems: 0,
      items: []
    }
    const lastUrl = stubFetch(
      new Response(JSON.stringify(listing), {
        headers: { 'content-type': 'application/json' }
      })
    )
    const result = await publicClient().publicListCollection({
      collectionUrl: 'https://was.example/space/s/c'
    })
    expect(lastUrl()).toBe('https://was.example/space/s/c/')
    expect(result).toEqual(listing)
  })

  it('does not double the trailing slash when one is already present', async () => {
    const lastUrl = stubFetch(
      new Response(JSON.stringify({ items: [] }), {
        headers: { 'content-type': 'application/json' }
      })
    )
    await publicClient().publicListCollection({
      collectionUrl: 'https://was.example/space/s/c/'
    })
    expect(lastUrl()).toBe('https://was.example/space/s/c/')
  })

  it('returns null on a 404', async () => {
    stubFetch(new Response('', { status: 404 }))
    const result = await publicClient().publicListCollection({
      collectionUrl: 'https://was.example/space/s/c'
    })
    expect(result).toBeNull()
  })
})

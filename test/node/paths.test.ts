/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Unit tests for the URL path builders. The trailing-slash rules and
 * percent-encoding here must match the server's per-operation `allowedTarget`
 * exactly, since the zcap `invocationTarget` is derived from the request URL.
 */
import { describe, it, expect } from 'vitest'

import { ValidationError } from '../../src/index.js'
import {
  spacesRoot,
  spacePath,
  spaceItems,
  spaceCollections,
  spaceExport,
  spaceImport,
  spaceBackends,
  registeredBackend,
  spaceQuotas,
  spacePolicy,
  spaceLinkset,
  collectionPath,
  collectionItems,
  collectionPolicy,
  collectionLinkset,
  collectionBackend,
  collectionQuota,
  collectionQuery,
  resourcePath,
  resourcePolicy,
  resourceMeta,
  toUrl,
  parseSpacePath
} from '../../src/internal/paths.js'

describe('path builders', () => {
  it('uses a trailing slash for the spaces repository (create / list)', () => {
    expect(spacesRoot()).toBe('/spaces/')
  })

  it('omits the trailing slash for get / update / delete of a space', () => {
    expect(spacePath('home')).toBe('/space/home')
  })

  it('uses a trailing slash for creating a collection within a space', () => {
    expect(spaceItems('home')).toBe('/space/home/')
  })

  it('uses a trailing slash for listing collections', () => {
    expect(spaceCollections('home')).toBe('/space/home/collections/')
  })

  it('builds the export and import paths', () => {
    expect(spaceExport('home')).toBe('/space/home/export')
    expect(spaceImport('home')).toBe('/space/home/import')
  })

  it('omits the trailing slash for a collection by id', () => {
    expect(collectionPath('home', 'docs')).toBe('/space/home/docs')
  })

  it('uses a trailing slash for listing items / adding a resource', () => {
    expect(collectionItems('home', 'docs')).toBe('/space/home/docs/')
  })

  it('omits the trailing slash for a resource by id', () => {
    expect(resourcePath('home', 'docs', 'note')).toBe('/space/home/docs/note')
  })

  it('builds the policy resource paths at each level', () => {
    expect(spacePolicy('home')).toBe('/space/home/policy')
    expect(collectionPolicy('home', 'docs')).toBe('/space/home/docs/policy')
    expect(resourcePolicy('home', 'docs', 'note')).toBe(
      '/space/home/docs/note/policy'
    )
  })

  it('builds the linkset paths (space and collection)', () => {
    expect(spaceLinkset('home')).toBe('/space/home/linkset')
    expect(collectionLinkset('home', 'docs')).toBe('/space/home/docs/linkset')
  })

  it('builds the backends and quotas paths (space level)', () => {
    expect(spaceBackends('home')).toBe('/space/home/backends')
    expect(spaceQuotas('home')).toBe('/space/home/quotas')
  })

  it('builds the per-id registered backend path (replace / deregister)', () => {
    expect(registeredBackend('home', 'gdrive')).toBe(
      '/space/home/backends/gdrive'
    )
  })

  it('builds the backend and quota paths (collection level)', () => {
    expect(collectionBackend('home', 'docs')).toBe('/space/home/docs/backend')
    expect(collectionQuota('home', 'docs')).toBe('/space/home/docs/quota')
  })

  it('builds the collection query path and encodes its ids', () => {
    expect(collectionQuery('home', 'docs')).toBe('/space/home/docs/query')
    expect(collectionQuery('a b', 'c/d')).toBe('/space/a%20b/c%2Fd/query')
  })

  it('builds the resource metadata path', () => {
    expect(resourceMeta('home', 'docs', 'note')).toBe(
      '/space/home/docs/note/meta'
    )
  })

  it('percent-encodes path segments so ids cannot break out of their slot', () => {
    expect(spacePath('a/b')).toBe('/space/a%2Fb')
    expect(collectionPath('s p', 'd?x')).toBe('/space/s%20p/d%3Fx')
    expect(resourcePath('s', 'c', 'r#1')).toBe('/space/s/c/r%231')
  })

  it('rejects dot-segment ids, which URL resolution would collapse', () => {
    // `encodeURIComponent` leaves `.`/`..` intact, and `new URL()` collapses
    // them -- `/space/s/c/.` is the collection items endpoint and
    // `/space/s/c/..` the space -- so a delete would target the wrong thing.
    expect(() => resourcePath('s', 'c', '.')).toThrow(ValidationError)
    expect(() => resourcePath('s', 'c', '..')).toThrow(ValidationError)
    expect(() => collectionPath('s', '.')).toThrow(ValidationError)
    expect(() => spacePath('..')).toThrow(ValidationError)
  })

  it('rejects an empty id, which collapses into the parent endpoint', () => {
    expect(() => resourcePath('s', 'c', '')).toThrow(ValidationError)
    expect(() => collectionPath('s', '')).toThrow(ValidationError)
    expect(() => spacePath('')).toThrow(ValidationError)
  })
})

describe('parseSpacePath', () => {
  it('classifies space / collection / resource depths', () => {
    expect(parseSpacePath('/space/s')).toEqual({ kind: 'space', spaceId: 's' })
    expect(parseSpacePath('/space/s/c')).toEqual({
      kind: 'collection',
      spaceId: 's',
      collectionId: 'c'
    })
    expect(parseSpacePath('/space/s/c/r')).toEqual({
      kind: 'resource',
      spaceId: 's',
      collectionId: 'c',
      resourceId: 'r'
    })
  })

  it('percent-decodes each segment (the builders re-encode them)', () => {
    expect(parseSpacePath('/space/a%20b/c%2Fd')).toEqual({
      kind: 'collection',
      spaceId: 'a b',
      collectionId: 'c/d'
    })
  })

  it('classifies reserved space-level sub-endpoints as sub-resources', () => {
    expect(parseSpacePath('/space/s/policy')).toMatchObject({
      kind: 'sub-resource',
      spaceId: 's'
    })
    expect(parseSpacePath('/space/s/backends/gdrive')).toMatchObject({
      kind: 'sub-resource',
      spaceId: 's'
    })
  })

  it('classifies reserved collection-level sub-endpoints as sub-resources', () => {
    expect(parseSpacePath('/space/s/c/policy')).toMatchObject({
      kind: 'sub-resource'
    })
    expect(parseSpacePath('/space/s/c/backend')).toMatchObject({
      kind: 'sub-resource'
    })
  })

  it('classifies 5-segment resource sub-endpoints as sub-resources', () => {
    expect(parseSpacePath('/space/s/c/r/meta')).toMatchObject({
      kind: 'sub-resource'
    })
    expect(parseSpacePath('/space/s/c/r/policy')).toMatchObject({
      kind: 'sub-resource'
    })
  })

  it('returns null for a pathname outside the /space/ tree', () => {
    expect(parseSpacePath('/other/x')).toBeNull()
    expect(parseSpacePath('/space')).toBeNull()
    expect(parseSpacePath('/spaces/')).toBeNull()
  })

  it('returns null (not a raw URIError) for a malformed percent-escape', () => {
    // `decodeURIComponent('%ff')` throws a `URIError`; a malformed escape makes
    // the pathname an unparseable target, which callers convert to their own
    // typed error rather than a raw crash.
    expect(parseSpacePath('/space/%ff')).toBeNull()
    expect(parseSpacePath('/space/s/%c3%28')).toBeNull()
  })
})

describe('toUrl', () => {
  it('resolves a leading-slash path against the server base URL', () => {
    expect(toUrl({ serverUrl: 'https://was.example', path: '/space/x' })).toBe(
      'https://was.example/space/x'
    )
  })

  it('preserves an explicit port', () => {
    expect(
      toUrl({ serverUrl: 'http://localhost:9787', path: '/spaces/' })
    ).toBe('http://localhost:9787/spaces/')
  })

  it('preserves a base-path prefix on the server URL', () => {
    expect(toUrl({ serverUrl: 'https://host/was/', path: '/space/x' })).toBe(
      'https://host/was/space/x'
    )
  })

  it('preserves a base-path prefix without a trailing slash', () => {
    expect(toUrl({ serverUrl: 'https://host/was', path: '/space/x' })).toBe(
      'https://host/was/space/x'
    )
  })
})

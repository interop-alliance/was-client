/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Unit tests for the URL path builders. The trailing-slash rules and
 * percent-encoding here must match the server's per-operation `allowedTarget`
 * exactly, since the zcap `invocationTarget` is derived from the request URL.
 * The convention under test: a trailing slash marks a container in canonical
 * form, everything else has none, and no two paths differ only by a trailing
 * slash.
 */
import { describe, it, expect } from 'vitest'

import { ValidationError } from '../../src/index.js'
import {
  spacesRoot,
  spacePath,
  spaceMeta,
  spaceExport,
  spaceImport,
  spaceBackends,
  registeredBackend,
  spaceQuotas,
  spacePolicy,
  spaceLinkset,
  collectionPath,
  collectionPolicy,
  collectionLinkset,
  collectionBackend,
  collectionQuota,
  collectionQuery,
  collectionMeta,
  collectionLog,
  resourcePath,
  resourcePolicy,
  resourceMeta,
  resourceChunkPath,
  toUrl,
  parseSpacePath
} from '../../src/internal/paths.js'

describe('path builders', () => {
  it('uses a trailing slash for the spaces repository (create / list)', () => {
    expect(spacesRoot()).toBe('/spaces/')
  })

  it('uses the trailing-slash canonical form for the space container', () => {
    expect(spacePath('home')).toBe('/space/home/')
  })

  it('reads and writes the space description at its meta segment', () => {
    expect(spaceMeta('home')).toBe('/space/home/meta')
  })

  it('builds the export and import paths', () => {
    expect(spaceExport('home')).toBe('/space/home/export')
    expect(spaceImport('home')).toBe('/space/home/import')
  })

  it('uses the trailing-slash canonical form for a collection container', () => {
    // The container is one URL under one builder: it lists the Collection's
    // Resources, adds one, and deletes the Collection.
    expect(collectionPath('home', 'docs')).toBe('/space/home/docs/')
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

  it('builds a chunk member path (no trailing slash) with the index verbatim', () => {
    expect(resourceChunkPath('home', 'docs', 'note', 0)).toBe(
      '/space/home/docs/note/chunks/0'
    )
    expect(resourceChunkPath('a b', 'c/d', 'e#f', 12)).toBe(
      '/space/a%20b/c%2Fd/e%23f/chunks/12'
    )
  })

  it('percent-encodes path segments so ids cannot break out of their slot', () => {
    expect(spacePath('a/b')).toBe('/space/a%2Fb/')
    expect(collectionPath('s p', 'd?x')).toBe('/space/s%20p/d%3Fx/')
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

describe('the trailing-slash convention', () => {
  /**
   * Every builder, applied to the same ids -- so the whole grammar can be
   * checked at once rather than one assertion per path. A capability's
   * `invocationTarget` covers its URL and everything under it by prefix, so
   * two paths differing only by a trailing slash could not be granted
   * separately; the server's route table has none, and neither may this.
   */
  const everyPath = {
    spacesRoot: spacesRoot(),
    spacePath: spacePath('home'),
    spaceMeta: spaceMeta('home'),
    spaceExport: spaceExport('home'),
    spaceImport: spaceImport('home'),
    spaceBackends: spaceBackends('home'),
    registeredBackend: registeredBackend('home', 'b1'),
    spaceQuotas: spaceQuotas('home'),
    spacePolicy: spacePolicy('home'),
    spaceLinkset: spaceLinkset('home'),
    collectionPath: collectionPath('home', 'docs'),
    collectionMeta: collectionMeta('home', 'docs'),
    collectionLog: collectionLog('home', 'docs'),
    collectionPolicy: collectionPolicy('home', 'docs'),
    collectionLinkset: collectionLinkset('home', 'docs'),
    collectionBackend: collectionBackend('home', 'docs'),
    collectionQuota: collectionQuota('home', 'docs'),
    collectionQuery: collectionQuery('home', 'docs'),
    resourcePath: resourcePath('home', 'docs', 'note'),
    resourceMeta: resourceMeta('home', 'docs', 'note'),
    resourcePolicy: resourcePolicy('home', 'docs', 'note'),
    resourceChunkPath: resourceChunkPath('home', 'docs', 'note', 0)
  }

  it('produces no two paths that differ only by a trailing slash', () => {
    const collisions = Object.entries(everyPath).filter(([, path]) =>
      Object.entries(everyPath).some(
        ([, other]) => other !== path && `${other}/` === path
      )
    )
    expect(collisions).toEqual([])
  })

  it('ends every container path with a slash and no other path', () => {
    const containers = new Set(['spacesRoot', 'spacePath', 'collectionPath'])
    const slashed = Object.entries(everyPath)
      .filter(([, path]) => path.endsWith('/'))
      .map(([name]) => name)
    expect(new Set(slashed)).toEqual(containers)
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
    // The Space Metadata object sits at the Collection-id position, so `meta`
    // directly under a Space is a space-level sub-endpoint rather than a
    // Collection named `meta`.
    expect(parseSpacePath('/space/s/meta')).toEqual({
      kind: 'sub-resource',
      spaceId: 's',
      segments: ['meta']
    })
  })

  it('reads the canonical trailing-slash container forms', () => {
    // The empty final segment is filtered, so a container URL classifies as
    // the container it names.
    expect(parseSpacePath('/space/s/')).toEqual({ kind: 'space', spaceId: 's' })
    expect(parseSpacePath('/space/s/c/')).toEqual({
      kind: 'collection',
      spaceId: 's',
      collectionId: 'c'
    })
  })

  it('also reads the bare (slash-less) container form a third party minted', () => {
    // The builders emit only the canonical trailing-slash form, but the
    // targets parsed here come from delegated capabilities minted elsewhere --
    // `WasClient.fromCapability` and the revocation route's `spaceIdOf` read
    // an `invocationTarget` this client did not write. Both forms name the same
    // container, so refusing the bare one would reject valid capabilities over
    // a spelling this client does not control.
    expect(parseSpacePath('/space/s')).toEqual(parseSpacePath('/space/s/'))
    expect(parseSpacePath('/space/s/c')).toEqual(parseSpacePath('/space/s/c/'))
  })

  it('classifies reserved collection-level sub-endpoints as sub-resources', () => {
    expect(parseSpacePath('/space/s/c/policy')).toMatchObject({
      kind: 'sub-resource'
    })
    expect(parseSpacePath('/space/s/c/backend')).toMatchObject({
      kind: 'sub-resource'
    })
    // `meta` joined the registry with the Collection metadata endpoint, so
    // `/space/s/c/meta` classifies as a collection-level sub-endpoint rather
    // than a resource named `meta`.
    expect(parseSpacePath('/space/s/c/meta')).toEqual({
      kind: 'sub-resource',
      spaceId: 's',
      segments: ['c', 'meta']
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

describe('the ./paths subpath barrel', () => {
  it('re-exports the builders, the inverse grammar, and the root zcap', async () => {
    const barrel = await import('../../src/paths.js')

    expect(Object.keys(barrel).sort()).toEqual(
      [
        'collectionLog',
        'collectionMeta',
        'collectionPath',
        'collectionQuery',
        'parseSpacePath',
        'parseSpaceTarget',
        'resourceMeta',
        'resourcePath',
        'rootCapability',
        'rootCapabilityId',
        'spaceMeta',
        'spacePath',
        'toUrl'
      ].sort()
    )
    // Same functions as the internal module, not re-implementations.
    expect(barrel.resourceMeta('s', 'c', 'r')).toBe(resourceMeta('s', 'c', 'r'))
    expect(barrel.collectionMeta('s', 'c')).toBe('/space/s/c/meta')
    expect(barrel.parseSpacePath('/space/s/c')).toEqual({
      kind: 'collection',
      spaceId: 's',
      collectionId: 'c'
    })
  })

  it('mints the root capability id and its object form', async () => {
    const { rootCapability, rootCapabilityId } =
      await import('../../src/paths.js')
    const target = 'http://localhost:3000/space/s/c/r'

    expect(rootCapabilityId(target)).toBe(
      `urn:zcap:root:${encodeURIComponent(target)}`
    )
    expect(rootCapability({ target, controller: 'did:key:zAlice' })).toEqual({
      '@context': 'https://w3id.org/zcap/v1',
      id: rootCapabilityId(target),
      invocationTarget: target,
      controller: 'did:key:zAlice'
    })
  })
})

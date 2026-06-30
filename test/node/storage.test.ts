/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Unit tests for the storage-introspection and metadata handle methods:
 * `space.backends()` / `space.quotas()`, `resource.meta()` / `setMeta()` /
 * `setName()` / `setTags()`, and the reserved-id guard on
 * `Collection.configure()`. A stub `ZcapClient` captures the request args and
 * returns canned `HttpResponse`s, so no signer or server is involved.
 */
import { describe, it, expect } from 'vitest'

import type { HttpResponse } from '@interop/http-client'
import { WasClient, ValidationError, ConflictError } from '../../src/index.js'

interface RequestArgs {
  url?: string
  method?: string
  json?: unknown
}

/**
 * Builds a `WasClient` over a stub `ZcapClient` that records every
 * `request(...)` call and returns each entry of `responses` in turn (a single
 * `data` payload is reused for every call). When `fail` is set, the stub throws
 * an error carrying that HTTP status.
 *
 * @param options {object}
 * @param [options.data] {unknown}     the response `data` payload
 * @param [options.fail] {number}      an HTTP status to throw instead
 * @returns {object} { client, calls }
 */
function clientWithRequestSpy({
  data,
  fail
}: { data?: unknown; fail?: number } = {}): {
  client: WasClient
  calls: RequestArgs[]
} {
  const calls: RequestArgs[] = []
  const zcapClient = {
    invocationSigner: { id: 'did:example:alice#key-1' },
    async request(args: RequestArgs) {
      calls.push(args)
      if (fail !== undefined) {
        throw { status: fail, response: { status: fail } }
      }
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
  return { client, calls }
}

describe('space.backends()', () => {
  it('GETs the backends endpoint and returns the array', async () => {
    const backends = [
      { id: 'default', name: 'Server Filesystem', managedBy: 'server' }
    ]
    const { client, calls } = clientWithRequestSpy({ data: backends })
    const result = await client.space('s').backends()
    expect(calls[0]?.url).toBe('https://was.example/space/s/backends')
    expect(calls[0]?.method).toBe('GET')
    expect(result).toEqual(backends)
  })

  it('returns null when the space is missing or not visible (404)', async () => {
    const { client } = clientWithRequestSpy({ fail: 404 })
    expect(await client.space('s').backends()).toBeNull()
  })

  it('surfaces a backend descriptor `features` array', async () => {
    const backends = [
      {
        id: 'default',
        name: 'Server Filesystem',
        features: ['conditional-writes']
      }
    ]
    const { client } = clientWithRequestSpy({ data: backends })
    const result = await client.space('s').backends()
    expect(result?.[0]?.features).toContain('conditional-writes')
  })
})

describe('space.registerBackend()', () => {
  const registration = {
    id: 'gdrive-personal',
    provider: 'google-drive',
    connection: { kind: 'oauth2-google', authorizationCode: '4/0Ab' }
  }

  it('POSTs the registration and returns the sanitized descriptor', async () => {
    const descriptor = {
      id: 'gdrive-personal',
      managedBy: 'external',
      provider: 'google-drive',
      connection: { kind: 'oauth2-google', status: 'registered' }
    }
    const { client, calls } = clientWithRequestSpy({ data: descriptor })
    const result = await client.space('s').registerBackend(registration)
    expect(calls[0]?.url).toBe('https://was.example/space/s/backends')
    expect(calls[0]?.method).toBe('POST')
    expect(calls[0]?.json).toEqual(registration)
    expect(result).toEqual(descriptor)
  })

  it('throws ConflictError when the id already exists / provider is barred (409)', async () => {
    const { client } = clientWithRequestSpy({ fail: 409 })
    await expect(
      client.space('s').registerBackend(registration)
    ).rejects.toBeInstanceOf(ConflictError)
  })
})

describe('space.updateBackend()', () => {
  const registration = {
    id: 'gdrive-personal',
    provider: 'google-drive',
    connection: { kind: 'oauth2-google', refreshToken: '1//0g' }
  }

  it('PUTs to the per-id path and returns the descriptor on create (201)', async () => {
    const descriptor = {
      id: 'gdrive-personal',
      managedBy: 'external',
      provider: 'google-drive',
      connection: { kind: 'oauth2-google', status: 'registered' }
    }
    const { client, calls } = clientWithRequestSpy({ data: descriptor })
    const result = await client.space('s').updateBackend(registration)
    expect(calls[0]?.url).toBe(
      'https://was.example/space/s/backends/gdrive-personal'
    )
    expect(calls[0]?.method).toBe('PUT')
    expect(calls[0]?.json).toEqual(registration)
    expect(result).toEqual(descriptor)
  })

  it('returns null on an in-place replace (204, no body)', async () => {
    // No `data` -> the stub mimics a 204 with no parsed body.
    const { client } = clientWithRequestSpy()
    expect(await client.space('s').updateBackend(registration)).toBeNull()
  })
})

describe('space.deregisterBackend()', () => {
  it('DELETEs the per-id path', async () => {
    const { client, calls } = clientWithRequestSpy()
    await client.space('s').deregisterBackend('gdrive-personal')
    expect(calls[0]?.url).toBe(
      'https://was.example/space/s/backends/gdrive-personal'
    )
    expect(calls[0]?.method).toBe('DELETE')
  })

  it('resolves (idempotent) when the backend is absent (404)', async () => {
    const { client } = clientWithRequestSpy({ fail: 404 })
    await expect(
      client.space('s').deregisterBackend('missing')
    ).resolves.toBeUndefined()
  })
})

describe('space.quotas()', () => {
  it('GETs the quotas endpoint and returns the report', async () => {
    const report = { respondedAt: '2026-06-12T13:25:00Z', backends: [] }
    const { client, calls } = clientWithRequestSpy({ data: report })
    const result = await client.space('s').quotas()
    expect(calls[0]?.url).toBe('https://was.example/space/s/quotas')
    expect(calls[0]?.method).toBe('GET')
    expect(result).toEqual(report)
  })

  it('requests the per-collection breakdown with includeCollections', async () => {
    const report = { respondedAt: '2026-06-12T13:25:00Z', backends: [] }
    const { client, calls } = clientWithRequestSpy({ data: report })
    await client.space('s').quotas({ includeCollections: true })
    expect(calls[0]?.url).toBe(
      'https://was.example/space/s/quotas?include=collections'
    )
    expect(calls[0]?.method).toBe('GET')
  })

  it('returns null when the space is missing or not visible (404)', async () => {
    const { client } = clientWithRequestSpy({ fail: 404 })
    expect(await client.space('s').quotas()).toBeNull()
  })
})

describe('collection.backend()', () => {
  it('GETs the backend endpoint and returns the descriptor', async () => {
    const backend = {
      id: 'default',
      name: 'Server Filesystem',
      managedBy: 'server'
    }
    const { client, calls } = clientWithRequestSpy({ data: backend })
    const result = await client.space('s').collection('c').backend()
    expect(calls[0]?.url).toBe('https://was.example/space/s/c/backend')
    expect(calls[0]?.method).toBe('GET')
    expect(result).toEqual(backend)
  })

  it('returns null when the collection is missing or not visible (404)', async () => {
    const { client } = clientWithRequestSpy({ fail: 404 })
    expect(await client.space('s').collection('c').backend()).toBeNull()
  })

  it('surfaces the backend descriptor `features` array', async () => {
    // `features` advertises optional server affordances (e.g. conditional-writes).
    const backend = {
      id: 'default',
      name: 'Server Filesystem',
      features: ['conditional-writes']
    }
    const { client } = clientWithRequestSpy({ data: backend })
    const result = await client.space('s').collection('c').backend()
    expect(result?.features).toContain('conditional-writes')
  })
})

describe('collection.quota()', () => {
  it('GETs the quota endpoint and returns the usage report', async () => {
    const usage = {
      id: 'default',
      managedBy: 'server',
      state: 'ok',
      usageBytes: 16,
      limit: { maxBytes: 1024 },
      restrictedActions: [],
      measuredAt: '2026-06-12T13:25:00Z'
    }
    const { client, calls } = clientWithRequestSpy({ data: usage })
    const result = await client.space('s').collection('c').quota()
    expect(calls[0]?.url).toBe('https://was.example/space/s/c/quota')
    expect(calls[0]?.method).toBe('GET')
    expect(result).toEqual(usage)
  })

  it('returns null when the collection is missing or not visible (404)', async () => {
    const { client } = clientWithRequestSpy({ fail: 404 })
    expect(await client.space('s').collection('c').quota()).toBeNull()
  })
})

describe('resource.meta()', () => {
  it('GETs the meta endpoint and returns the metadata object', async () => {
    const meta = {
      contentType: 'application/json',
      size: 16,
      custom: { name: 'Hello' }
    }
    const { client, calls } = clientWithRequestSpy({ data: meta })
    const result = await client.space('s').collection('c').resource('r').meta()
    expect(calls[0]?.url).toBe('https://was.example/space/s/c/r/meta')
    expect(calls[0]?.method).toBe('GET')
    expect(result).toEqual(meta)
  })

  it('returns null when the resource is missing or not visible (404)', async () => {
    const { client } = clientWithRequestSpy({ fail: 404 })
    const result = await client.space('s').collection('c').resource('r').meta()
    expect(result).toBeNull()
  })
})

describe('resource.setMeta()', () => {
  it('PUTs the custom object to the meta endpoint', async () => {
    const { client, calls } = clientWithRequestSpy()
    await client
      .space('s')
      .collection('c')
      .resource('r')
      .setMeta({ custom: { name: 'Hi', tags: { project: 'demo' } } })
    expect(calls[0]?.url).toBe('https://was.example/space/s/c/r/meta')
    expect(calls[0]?.method).toBe('PUT')
    expect(calls[0]?.json).toEqual({
      custom: { name: 'Hi', tags: { project: 'demo' } }
    })
  })

  it('clears the custom object when called with no argument', async () => {
    const { client, calls } = clientWithRequestSpy()
    await client.space('s').collection('c').resource('r').setMeta()
    expect(calls[0]?.json).toEqual({ custom: {} })
  })
})

describe('resource.setName() / setTags()', () => {
  it('setName() preserves existing tags (read-modify-write)', async () => {
    const { client, calls } = clientWithRequestSpy({
      data: {
        contentType: 'application/json',
        size: 16,
        custom: { name: 'Old', tags: { project: 'demo' } }
      }
    })
    await client.space('s').collection('c').resource('r').setName('New')
    // First call is the GET (meta), second is the PUT.
    expect(calls[1]?.method).toBe('PUT')
    expect(calls[1]?.json).toEqual({
      custom: { name: 'New', tags: { project: 'demo' } }
    })
  })

  it('setTags() preserves the existing name (read-modify-write)', async () => {
    const { client, calls } = clientWithRequestSpy({
      data: {
        contentType: 'application/json',
        size: 16,
        custom: { name: 'Keep', tags: { project: 'demo' } }
      }
    })
    await client
      .space('s')
      .collection('c')
      .resource('r')
      .setTags({ status: 'final' })
    expect(calls[1]?.json).toEqual({
      custom: { name: 'Keep', tags: { status: 'final' } }
    })
  })
})

describe('was.listSpaces()', () => {
  it('GETs the spaces repository and returns the listing', async () => {
    const listing = {
      url: '/spaces/',
      totalItems: 2,
      items: [
        { id: 's1', url: '/space/s1', name: 'Home' },
        { id: 's2', url: '/space/s2' }
      ]
    }
    const { client, calls } = clientWithRequestSpy({ data: listing })
    const result = await client.listSpaces()
    expect(calls[0]?.url).toBe('https://was.example/spaces/')
    expect(calls[0]?.method).toBe('GET')
    expect(result).toEqual(listing)
  })

  it('returns the empty listing the server sends an unauthorized caller', async () => {
    const empty = { url: '/spaces/', totalItems: 0, items: [] }
    const { client } = clientWithRequestSpy({ data: empty })
    const result = await client.listSpaces()
    expect(result.items).toEqual([])
    expect(result.totalItems).toBe(0)
  })
})

describe('Collection.configure() reserved-id guard', () => {
  it('rejects a handle built on a reserved id before any request', async () => {
    const { client, calls } = clientWithRequestSpy()
    await expect(
      client.space('s').collection('export').configure({ name: 'X' })
    ).rejects.toThrow(ValidationError)
    expect(calls).toHaveLength(0)
  })

  it('allows configuring an ordinary collection id', async () => {
    const { client, calls } = clientWithRequestSpy({ data: {} })
    await client.space('s').collection('docs').configure({ name: 'Docs' })
    // describe() GET + configure() PUT.
    expect(calls.some(call => call.method === 'PUT')).toBe(true)
  })

  it('merges current backend/encryption forward when only name changes', async () => {
    // The `describe()` GET returns this canned current description; a
    // replace-semantics server would drop any field omitted from the PUT body,
    // so `configure({ name })` must carry `backend` and `encryption` forward.
    const current = {
      id: 'docs',
      type: ['Collection'],
      name: 'Docs',
      backend: { id: 'custom' },
      encryption: { scheme: 'edv' }
    }
    const { client, calls } = clientWithRequestSpy({ data: current })
    const result = await client
      .space('s')
      .collection('docs')
      .configure({ name: 'Renamed' })
    const put = calls.find(call => call.method === 'PUT')
    expect(put?.json).toEqual({
      id: 'docs',
      name: 'Renamed',
      backend: { id: 'custom' },
      encryption: { scheme: 'edv' }
    })
    expect(result.backend).toEqual({ id: 'custom' })
    expect(result.encryption).toEqual({ scheme: 'edv' })
  })
})

describe('Resource reserved-id guard (path-collision safety)', () => {
  it('rejects a reserved resource id at handle construction (no I/O)', () => {
    // `resource('policy')` would otherwise target the collection's policy
    // endpoint -- a `delete()` would wipe access control. The guard fires
    // synchronously, before any request, for every reserved segment that
    // collides with a collection-level path.
    const { client, calls } = clientWithRequestSpy()
    for (const reserved of ['policy', 'backend', 'quota', 'linkset', 'query']) {
      expect(() =>
        client.space('s').collection('c').resource(reserved)
      ).toThrow(ValidationError)
    }
    expect(calls).toHaveLength(0)
  })

  it('guards reads/deletes too, not just writes', async () => {
    const { client, calls } = clientWithRequestSpy()
    // Construction throws, so get()/delete() never even build a request.
    expect(() => client.space('s').collection('c').resource('policy')).toThrow(
      ValidationError
    )
    expect(calls).toHaveLength(0)
  })

  it('allows an ordinary resource id', () => {
    const { client } = clientWithRequestSpy()
    expect(() =>
      client.space('s').collection('c').resource('greeting')
    ).not.toThrow()
  })
})

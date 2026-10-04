/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Unit tests for the access-control policy handle methods (`getPolicy`,
 * `getPolicyWithEtag`, `setPolicy`, `setPublic`, `clearPolicy`) and
 * `linkset()` on Space, Collection, and Resource. A stub `ZcapClient`
 * captures the request args and returns a canned `HttpResponse`, so no signer
 * or server is involved.
 */
import { describe, it, expect } from 'vitest'

import type { Collection, Resource, Space, WasClient } from '../../src/index.js'
import { clientWithRequestSpy } from '../helpers/stubClient.js'

describe('policy handle methods', () => {
  it('setPublic() PUTs { type: PublicCanRead } to the collection policy', async () => {
    const { client, lastRequest } = clientWithRequestSpy()
    await client.space('s').collection('c').setPublic()
    const req = lastRequest()
    expect(req?.url).toBe('https://was.example/space/s/c/policy')
    expect(req?.method).toBe('PUT')
    expect(req?.json).toEqual({ type: 'PublicCanRead' })
  })

  it('setPolicy() passes an arbitrary (extensible) policy document through', async () => {
    const { client, lastRequest } = clientWithRequestSpy()
    const policy = { type: 'Cedar', policies: ['permit(...)'] }
    await client.space('s').collection('c').setPolicy(policy)
    expect(lastRequest()?.json).toEqual(policy)
  })

  it('clearPolicy() DELETEs the collection policy', async () => {
    const { client, lastRequest } = clientWithRequestSpy()
    await client.space('s').collection('c').clearPolicy()
    const req = lastRequest()
    expect(req?.url).toBe('https://was.example/space/s/c/policy')
    expect(req?.method).toBe('DELETE')
  })

  it('getPolicy() returns the response data', async () => {
    const { client } = clientWithRequestSpy({ data: { type: 'PublicCanRead' } })
    const policy = await client.space('s').collection('c').getPolicy()
    expect(policy).toEqual({ type: 'PublicCanRead' })
  })

  it('getPolicy() returns null when no policy is set (404)', async () => {
    const { client } = clientWithRequestSpy({ fail: 404 })
    const policy = await client.space('s').collection('c').getPolicy()
    expect(policy).toBeNull()
  })

  it('targets the policy resource at the space level', async () => {
    const { client, lastRequest } = clientWithRequestSpy()
    await client.space('s').setPublic()
    expect(lastRequest()?.url).toBe('https://was.example/space/s/policy')
  })

  it('targets the policy resource at the resource level', async () => {
    const { client, lastRequest } = clientWithRequestSpy()
    await client.space('s').collection('c').resource('r').setPublic()
    expect(lastRequest()?.url).toBe('https://was.example/space/s/c/r/policy')
  })

  it('getPolicyWithEtag() returns null when no policy is set (404)', async () => {
    const { client } = clientWithRequestSpy({ fail: 404 })
    expect(
      await client.space('s').collection('c').getPolicyWithEtag()
    ).toBeNull()
  })

  it('setPolicy() with ifNoneMatch sends If-None-Match: *', async () => {
    const { client, lastRequest } = clientWithRequestSpy({ etag: '"p1"' })
    await client
      .space('s')
      .collection('c')
      .setPolicy({ type: 'PublicCanRead' }, { ifNoneMatch: true })
    expect(lastRequest()?.headers?.['if-none-match']).toBe('*')
    expect(lastRequest()?.headers?.['if-match']).toBeUndefined()
  })

  it('setPolicy() with no precondition sends no conditional headers', async () => {
    const { client, lastRequest } = clientWithRequestSpy()
    await client.space('s').collection('c').setPolicy({ type: 'PublicCanRead' })
    expect(lastRequest()?.headers).toBeUndefined()
  })

  it('setPolicy() rejects ifMatch and ifNoneMatch together, sending nothing', async () => {
    const { client, lastRequest } = clientWithRequestSpy()
    await expect(
      client
        .space('s')
        .collection('c')
        .setPolicy(
          { type: 'PublicCanRead' },
          { ifMatch: '"p1"', ifNoneMatch: true }
        )
    ).rejects.toMatchObject({ name: 'ValidationError' })
    expect(lastRequest()).toBeUndefined()
  })

  it('setPublic() passes ifMatch through and returns the new ETag', async () => {
    const { client, lastRequest } = clientWithRequestSpy({ etag: '"p2"' })
    const result = await client
      .space('s')
      .collection('c')
      .setPublic({ ifMatch: '"p1"' })
    expect(lastRequest()?.json).toEqual({ type: 'PublicCanRead' })
    expect(lastRequest()?.headers?.['if-match']).toBe('"p1"')
    expect(result).toEqual({ etag: '"p2"' })
  })

  it('clearPolicy() of an absent policy returns no ETag', async () => {
    const { client } = clientWithRequestSpy()
    expect(await client.space('s').collection('c').clearPolicy()).toEqual({
      etag: undefined
    })
  })

  describe('ETag round trip', () => {
    const itRoundTripsEtag = (
      level: string, // 'space', 'collection', 'resource'
      policyUrl: string,
      getHandle: (client: WasClient) => Space | Collection | Resource
    ): void => {
      describe(level, () => {
        it('getPolicyWithEtag() returns the policy with its ETag', async () => {
          const { client, lastRequest } = clientWithRequestSpy({
            data: { type: 'PublicCanRead', updatedAtCounter: 1 },
            etag: '"p1"'
          })
          const read = await getHandle(client).getPolicyWithEtag()
          expect(lastRequest()?.url).toBe(policyUrl)
          expect(lastRequest()?.method).toBe('GET')
          expect(read).toEqual({
            policy: { type: 'PublicCanRead', updatedAtCounter: 1 },
            etag: '"p1"'
          })
        })

        it('setPolicy() sends If-Match and returns the new ETag', async () => {
          const { client, lastRequest } = clientWithRequestSpy({ etag: '"p2"' })
          const result = await getHandle(client).setPolicy(
            { type: 'PublicCanRead' },
            { ifMatch: '"p1"' }
          )
          expect(lastRequest()?.url).toBe(policyUrl)
          expect(lastRequest()?.headers?.['if-match']).toBe('"p1"')
          expect(lastRequest()?.headers?.['if-none-match']).toBeUndefined()
          expect(result).toEqual({ etag: '"p2"' })
        })

        it('clearPolicy() sends If-Match and returns the tombstone ETag', async () => {
          const { client, lastRequest } = clientWithRequestSpy({ etag: '"p3"' })
          const result = await getHandle(client).clearPolicy({
            ifMatch: '"p2"'
          })
          expect(lastRequest()?.url).toBe(policyUrl)
          expect(lastRequest()?.method).toBe('DELETE')
          expect(lastRequest()?.headers?.['if-match']).toBe('"p2"')
          expect(result).toEqual({ etag: '"p3"' })
        })
      })
    }

    itRoundTripsEtag('space', 'https://was.example/space/s/policy', client =>
      client.space('s')
    )
    itRoundTripsEtag(
      'collection',
      'https://was.example/space/s/c/policy',
      client => client.space('s').collection('c')
    )
    itRoundTripsEtag(
      'resource',
      'https://was.example/space/s/c/r/policy',
      client => client.space('s').collection('c').resource('r')
    )
  })

  describe('isPublic()', () => {
    const itChecksIsPublic = (
      level: string, // 'space', 'collection', 'resource'
      getHandle: (client: WasClient) => { isPublic(): Promise<boolean> }
    ): void => {
      describe(level, () => {
        it(`is true when the ${level} policy is PublicCanRead`, async () => {
          const { client } = clientWithRequestSpy({
            data: { type: 'PublicCanRead' }
          })
          expect(await getHandle(client).isPublic()).toBe(true)
        })

        it(`is false when the ${level} policy type is unsupported`, async () => {
          const { client } = clientWithRequestSpy({
            data: { type: 'SomethingUnsupported' }
          })
          expect(await getHandle(client).isPublic()).toBe(false)
        })

        it(`is false when the ${level} has no policy`, async () => {
          const { client } = clientWithRequestSpy({ fail: 404 })
          expect(await getHandle(client).isPublic()).toBe(false)
        })
      })
    }

    itChecksIsPublic('space', client => client.space('s'))
    itChecksIsPublic('collection', client => client.space('s').collection('c'))
    itChecksIsPublic('resource', client =>
      client.space('s').collection('c').resource('r')
    )
  })

  it('linkset() reads the space/collection linkset resource', async () => {
    const { client, lastRequest } = clientWithRequestSpy({
      data: { linkset: [{ anchor: '/space/s/c' }] }
    })
    const result = await client.space('s').collection('c').linkset()
    expect(lastRequest()?.url).toBe('https://was.example/space/s/c/linkset')
    expect(result).toEqual({ linkset: [{ anchor: '/space/s/c' }] })
  })
})

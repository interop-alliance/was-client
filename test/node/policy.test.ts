/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Unit tests for the access-control policy handle methods
 * (`getPolicy`/`setPolicy`/`setPublic`/`clearPolicy`) and `linkset()` on Space,
 * Collection, and Resource. A stub `ZcapClient` captures the request args and
 * returns a canned `HttpResponse`, so no signer or server is involved.
 */
import { describe, it, expect } from 'vitest'

import type { HttpResponse } from '@interop/http-client'
import { WasClient } from '../../src/index.js'

interface RequestArgs {
  url?: string
  method?: string
  action?: string
  json?: unknown
  capability?: unknown
}

/**
 * Builds a `WasClient` over a stub `ZcapClient` that records the most recent
 * `request(...)` call and returns a canned response. When `fail` is set, the
 * stub throws an error carrying that HTTP status (to exercise 404 -> null).
 *
 * @param options {object}
 * @param [options.data] {unknown}   the response `data` payload
 * @param [options.fail] {number}    an HTTP status to throw instead
 * @returns {object} { client, lastRequest }
 */
function clientWithRequestSpy({
  data,
  fail
}: { data?: unknown; fail?: number } = {}): {
  client: WasClient
  lastRequest: () => RequestArgs | undefined
} {
  let captured: RequestArgs | undefined
  const zcapClient = {
    invocationSigner: { id: 'did:example:alice#key-1' },
    async request(args: RequestArgs) {
      captured = args
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
  return { client, lastRequest: () => captured }
}

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

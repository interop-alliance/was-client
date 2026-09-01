/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Unit tests for the lazy navigational handles and capability-rebuilding. A
 * `WasClient` over a stub `ZcapClient` builds `Space`/`Collection`/`Resource`
 * handles synchronously, with no network or key material, and `fromCapability`
 * derives a handle at the depth implied by a zcap's `invocationTarget`.
 */
import { describe, it, expect } from 'vitest'

import type { HttpResponse } from '@interop/http-client'
import {
  WasClient,
  Space,
  Collection,
  Resource,
  ValidationError,
  AuthRequiredError
} from '../../src/index.js'

/**
 * Builds a `WasClient` over a minimal stub `ZcapClient` -- enough to construct
 * handles and derive `controllerDid`, without a signer or server.
 *
 * @param [signerId] {string}   the invocationSigner id (DID + key fragment)
 * @returns {WasClient}
 */
function stubClient(signerId = 'did:example:alice#key-1'): WasClient {
  const zcapClient = {
    invocationSigner: { id: signerId }
  } as unknown as ConstructorParameters<typeof WasClient>[0]['zcapClient']
  return new WasClient({ serverUrl: 'https://was.example', zcapClient })
}

describe('lazy handles', () => {
  it('builds the space/collection/resource chain synchronously, no I/O', () => {
    const client = stubClient()
    const space = client.space('does-not-exist')
    expect(space).toBeInstanceOf(Space)

    const collection = space.collection('nope')
    expect(collection).toBeInstanceOf(Collection)

    const resource = collection.resource('whatever')
    expect(resource).toBeInstanceOf(Resource)
    expect(resource.spaceId).toBe('does-not-exist')
    expect(resource.collectionId).toBe('nope')
    expect(resource.id).toBe('whatever')
  })

  it('derives controllerDid from the signer id (drops the key fragment)', () => {
    expect(stubClient('did:example:alice#key-1').controllerDid).toBe(
      'did:example:alice'
    )
  })

  it('throws if the wrapped client has no invocationSigner id', () => {
    const zcapClient = {
      invocationSigner: {}
    } as unknown as ConstructorParameters<typeof WasClient>[0]['zcapClient']
    const client = new WasClient({
      serverUrl: 'https://was.example',
      zcapClient
    })
    expect(() => client.controllerDid).toThrow(ValidationError)
  })
})

describe('fromCapability', () => {
  const client = stubClient()

  it('rebuilds a Space handle from a space-scoped invocationTarget', () => {
    const handle = client.fromCapability({
      invocationTarget: 'https://was.example/space/s'
    } as never)
    expect(handle).toBeInstanceOf(Space)
    expect((handle as Space).id).toBe('s')
  })

  it('rebuilds a Collection handle from a collection-scoped target', () => {
    const handle = client.fromCapability({
      invocationTarget: 'https://was.example/space/s/c'
    } as never)
    expect(handle).toBeInstanceOf(Collection)
    expect((handle as Collection).spaceId).toBe('s')
    expect((handle as Collection).id).toBe('c')
  })

  it('rebuilds a Resource handle from a resource-scoped target', () => {
    const handle = client.fromCapability({
      invocationTarget: 'https://was.example/space/s/c/r'
    } as never)
    expect(handle).toBeInstanceOf(Resource)
    expect((handle as Resource).spaceId).toBe('s')
    expect((handle as Resource).collectionId).toBe('c')
    expect((handle as Resource).id).toBe('r')
  })

  it('throws for an invocationTarget outside the /space/ tree', () => {
    expect(() =>
      client.fromCapability({
        invocationTarget: 'https://was.example/other/x'
      } as never)
    ).toThrow(ValidationError)
  })

  it('throws a ValidationError (not a raw TypeError) on a malformed target', () => {
    expect(() =>
      client.fromCapability({ invocationTarget: 'not a url' } as never)
    ).toThrow(ValidationError)
  })

  it('decodes percent-encoded id segments so they are not double-encoded', () => {
    const handle = client.fromCapability({
      invocationTarget: 'https://was.example/space/a%20b/c%2Fd'
    } as never)
    expect(handle).toBeInstanceOf(Collection)
    expect((handle as Collection).spaceId).toBe('a b')
    expect((handle as Collection).id).toBe('c/d')
  })

  it('throws for a 5-segment sub-resource target instead of dropping the tail', () => {
    // A capability delegated against `/space/s/c/r/meta` must not come back as
    // a Resource handle for `/space/s/c/r` -- the handle would sign invocations
    // against the content URL with a capability targeting the meta URL.
    expect(() =>
      client.fromCapability({
        invocationTarget: 'https://was.example/space/s/c/r/meta'
      } as never)
    ).toThrow(ValidationError)
    expect(() =>
      client.fromCapability({
        invocationTarget: 'https://was.example/space/s/c/r/meta'
      } as never)
    ).toThrow(/sub-resource/)
  })

  it('throws for a collection-policy target instead of a reserved-id error', () => {
    expect(() =>
      client.fromCapability({
        invocationTarget: 'https://was.example/space/s/c/policy'
      } as never)
    ).toThrow(/sub-resource/)
  })

  it('throws for a space-policy target instead of a Collection("policy")', () => {
    expect(() =>
      client.fromCapability({
        invocationTarget: 'https://was.example/space/s/policy'
      } as never)
    ).toThrow(/sub-resource/)
  })
})

interface RequestArgs {
  url?: string
  method?: string
  action?: string
  json?: unknown
  capability?: unknown
}

/**
 * Builds a `WasClient` over a stub `ZcapClient` that records the most recent
 * `request(...)` call and either returns a canned 2xx response or throws an
 * error carrying the given HTTP status (so `mapError` sees a real status).
 *
 * @param options {object}
 * @param [options.fail] {number}   an HTTP status to throw instead of
 *   succeeding
 * @returns {object} { client, lastRequest }
 */
function clientWithRequestSpy({ fail }: { fail?: number } = {}): {
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
        status: 204,
        headers: new Headers(),
        async json() {
          return undefined
        }
      } as unknown as HttpResponse
    }
  } as unknown as ConstructorParameters<typeof WasClient>[0]['zcapClient']
  const client = new WasClient({ serverUrl: 'https://was.example', zcapClient })
  return { client, lastRequest: () => captured }
}

describe('Space.deleteWithOutcome / delete', () => {
  it('deleteWithOutcome() resolves { outcome: "deleted" } on a 2xx response', async () => {
    const { client, lastRequest } = clientWithRequestSpy()
    const capability = { id: 'urn:zcap:delete-only' } as never
    const result = await client
      .space('s', { capability })
      .deleteWithOutcome()
    expect(result).toEqual({ outcome: 'deleted' })
    const req = lastRequest()
    expect(req?.url).toBe('https://was.example/space/s')
    expect(req?.method).toBe('DELETE')
    expect(req?.capability).toBe(capability)
  })

  it('deleteWithOutcome() resolves { outcome: "not-found" } on a 404, without throwing', async () => {
    const { client } = clientWithRequestSpy({ fail: 404 })
    const result = await client.space('s').deleteWithOutcome()
    expect(result).toEqual({ outcome: 'not-found' })
  })

  it('deleteWithOutcome() rethrows the mapped WasError for a non-404 status', async () => {
    const { client: clientForServerError } = clientWithRequestSpy({
      fail: 500
    })
    await expect(
      clientForServerError.space('s').deleteWithOutcome()
    ).rejects.toThrow()

    const { client: clientForForbidden } = clientWithRequestSpy({ fail: 403 })
    await expect(
      clientForForbidden.space('s').deleteWithOutcome()
    ).rejects.toBeInstanceOf(AuthRequiredError)
  })

  it('delete() still resolves void on a 404 (idempotent, regression pin)', async () => {
    const { client } = clientWithRequestSpy({ fail: 404 })
    await expect(client.space('s').delete()).resolves.toBeUndefined()
  })
})

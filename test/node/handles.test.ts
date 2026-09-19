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

import {
  WasClient,
  Space,
  Collection,
  Resource,
  ValidationError,
  AuthRequiredError
} from '../../src/index.js'
import type { IDID } from '../../src/index.js'
import type { RequestArgs } from '../helpers/stubClient.js'
import {
  clientWithStub,
  jsonResponse,
  serviceDescriptionFor
} from '../helpers/stubClient.js'

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
  return new WasClient({
    serverUrl: 'https://was.example',
    zcapClient,
    serviceDescription: serviceDescriptionFor()
  })
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
      serviceDescription: serviceDescriptionFor(),
      zcapClient
    })
    expect(() => client.controllerDid).toThrow(ValidationError)
  })
})

describe('fromCapability', () => {
  const client = stubClient()

  it('rebuilds a Space handle from a space-scoped invocationTarget', () => {
    const handle = client.fromCapability({
      invocationTarget: 'https://was.example/space/s/'
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

/**
 * Builds a `WasClient` over a stub `ZcapClient` that records the most recent
 * `request(...)` call and either returns a canned 204 or throws an error
 * carrying the given HTTP status (so `mapError` sees a real status).
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
  const client = clientWithStub(args => {
    captured = args
    if (fail !== undefined) {
      throw { status: fail, response: { status: fail } }
    }
    return jsonResponse()
  })
  return { client, lastRequest: () => captured }
}

describe('Space.deleteWithOutcome / delete', () => {
  it('deleteWithOutcome() resolves { outcome: "deleted" } on a 2xx response', async () => {
    const { client, lastRequest } = clientWithRequestSpy()
    const capability = { id: 'urn:zcap:delete-only' } as never
    const result = await client.space('s', { capability }).deleteWithOutcome()
    expect(result).toEqual({ outcome: 'deleted' })
    const req = lastRequest()
    expect(req?.url).toBe('https://was.example/space/s/')
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

/**
 * `space()` accepts the same `HandleOptions` as `collection()` and
 * `resource()`, so its `encryption` override is the default for every
 * Collection reached through that handle. A `'plaintext'` default is the
 * observable case: it short-circuits codec resolution, so an
 * encryption-capable client neither consults its keystore nor reads the
 * Collection Metadata object to discover a descriptor.
 */
describe('space() encryption default', () => {
  /**
   * Builds an encryption-capable `WasClient` over a stub that records every
   * request URL and a keystore that fails if it is ever consulted.
   *
   * @returns {object}
   * @returns return.client {WasClient}
   * @returns return.urls {string[]}   the recorded request URLs
   */
  function encryptingClient(): { client: WasClient; urls: string[] } {
    const urls: string[] = []
    const zcapClient = {
      invocationSigner: { id: 'did:example:alice#key-1' },
      request(args: RequestArgs) {
        urls.push(args.url as string)
        if ((args.method ?? 'GET') === 'GET') {
          return jsonResponse({ data: { id: 'c' } })
        }
        return jsonResponse()
      }
    } as unknown as ConstructorParameters<typeof WasClient>[0]['zcapClient']
    const encryption = {
      async codecFor() {
        throw new Error('the keystore must not be consulted for plaintext')
      }
    } as unknown as ConstructorParameters<typeof WasClient>[0]['encryption']
    const client = new WasClient({
      serverUrl: 'https://was.example',
      zcapClient,
      encryption,
      serviceDescription: serviceDescriptionFor()
    })
    return { client, urls }
  }

  it("honors space('s', { encryption }) as the collection() default", async () => {
    const { client, urls } = encryptingClient()
    await client
      .space('s', { encryption: 'plaintext' })
      .collection('c')
      .put('r', { hello: 'world' })
    expect(urls).toEqual(['https://was.example/space/s/c/r'])
  })

  it('lets collection() override the space-level default', async () => {
    const { client, urls } = encryptingClient()
    await client
      .space('s')
      .collection('c', { encryption: 'plaintext' })
      .put('r', { hello: 'world' })
    expect(urls).toEqual(['https://was.example/space/s/c/r'])
  })

  it('without the default, discovers the descriptor from the metadata object', async () => {
    const { client, urls } = encryptingClient()
    await client.space('s').collection('c').put('r', { hello: 'world' })
    expect(urls).toEqual([
      'https://was.example/space/s/c/meta',
      'https://was.example/space/s/c/r'
    ])
  })
})

/**
 * `createCollection`'s `generator` is typed `IDID`, which the root entry
 * exports: a caller holding a plain `string` needs the annotation to narrow
 * to it, and the handle a create returns reflects the collection's own
 * declaration rather than the Space handle's encryption default.
 */
describe('createCollection', () => {
  it('accepts a generator narrowed to the exported IDID type', async () => {
    const urls: string[] = []
    const zcapClient = {
      invocationSigner: { id: 'did:example:alice#key-1' },
      request(args: RequestArgs) {
        urls.push(args.url as string)
        return jsonResponse({ data: { id: 'c' } })
      }
    } as unknown as ConstructorParameters<typeof WasClient>[0]['zcapClient']
    const client = new WasClient({
      serverUrl: 'https://was.example',
      zcapClient,
      serviceDescription: serviceDescriptionFor()
    })

    const appDid = 'did:key:zApp' as IDID
    const collection = await client
      .space('s')
      .createCollection({ id: 'c', generator: appDid })
    expect(collection.id).toBe('c')
    expect(urls).toEqual(['https://was.example/space/s/'])
  })

  it('does not inherit the Space handle encryption default', async () => {
    const urls: string[] = []
    const zcapClient = {
      invocationSigner: { id: 'did:example:alice#key-1' },
      request(args: RequestArgs) {
        urls.push(args.url as string)
        return jsonResponse({ data: { id: 'c' } })
      }
    } as unknown as ConstructorParameters<typeof WasClient>[0]['zcapClient']
    const encryption = {
      async codecFor() {
        throw new Error('the keystore must not be consulted')
      }
    } as unknown as ConstructorParameters<typeof WasClient>[0]['encryption']
    const client = new WasClient({
      serverUrl: 'https://was.example',
      zcapClient,
      encryption,
      serviceDescription: serviceDescriptionFor()
    })

    // The Space handle defaults to `'plaintext'`, but a collection created
    // without an `encryption` declaration takes descriptor discovery, so its
    // first write reads the Collection Metadata object.
    const collection = await client
      .space('s', { encryption: 'plaintext' })
      .createCollection({ id: 'c' })
    await collection.put('r', { hello: 'world' })
    expect(urls).toEqual([
      'https://was.example/space/s/',
      'https://was.example/space/s/c/meta',
      'https://was.example/space/s/c/r'
    ])
  })
})

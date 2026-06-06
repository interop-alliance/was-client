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
  ValidationError
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
})

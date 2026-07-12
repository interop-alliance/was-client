/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Unit tests for two whole-codebase-review fixes whose natural test homes are
 * off-limits to this change: `fromCapability` on a sub-path-mounted server (it
 * must strip `serverUrl`'s base path via `parseSpaceTarget`, not classify the
 * raw pathname), and the deterministic write-epoch selection in
 * `resolveEpochKeys` (currentEpoch by id lookup, with a marker-order fallback).
 */
import { describe, it, expect } from 'vitest'
import { X25519KeyAgreementKey2020 } from '@interop/x25519-key-agreement-key'
import type { IKeyAgreementKey } from '@interop/data-integrity-core'

import { WasClient, ValidationError } from '../../src/index.js'
import type { CollectionEncryption } from '../../src/index.js'
import { Space } from '../../src/Space.js'
import { Collection } from '../../src/Collection.js'
import { Resource } from '../../src/Resource.js'
import {
  mintEpoch,
  wrapEpochSecret,
  epochKeyIdFor
} from '../../src/edv/epochCrypto.js'
import { resolveEpochKeys } from '../../src/edv/epochKeys.js'

/**
 * Builds a `WasClient` over a stub `ZcapClient` (no signer, no I/O -- only the
 * `invocationSigner.id` `fromCapability` needs for its context).
 *
 * @param serverUrl {string}
 * @returns {WasClient}
 */
function clientFor(serverUrl: string): WasClient {
  const zcapClient = {
    invocationSigner: { id: 'did:example:alice#key-1' }
  } as unknown as ConstructorParameters<typeof WasClient>[0]['zcapClient']
  return new WasClient({ serverUrl, zcapClient })
}

describe('fromCapability on a sub-path-mounted server', () => {
  it('derives a resource handle under a base-path prefix', () => {
    const client = clientFor('https://host/was/')
    const handle = client.fromCapability({
      invocationTarget: 'https://host/was/space/s/c/r'
    } as never)
    expect(handle).toBeInstanceOf(Resource)
    const resource = handle as Resource
    expect(resource.spaceId).toBe('s')
    expect(resource.collectionId).toBe('c')
    expect(resource.id).toBe('r')
  })

  it('derives a collection handle under a base-path prefix', () => {
    const client = clientFor('https://host/was')
    const handle = client.fromCapability({
      invocationTarget: 'https://host/was/space/s/c'
    } as never)
    expect(handle).toBeInstanceOf(Collection)
  })

  it('derives a space handle under a base-path prefix', () => {
    const client = clientFor('https://host/was/')
    const handle = client.fromCapability({
      invocationTarget: 'https://host/was/space/s'
    } as never)
    expect(handle).toBeInstanceOf(Space)
    expect((handle as Space).id).toBe('s')
  })

  it('rejects a target on a different base path or origin', () => {
    const client = clientFor('https://host/was/')
    // Right origin, wrong base path (no `/was/` prefix).
    expect(() =>
      client.fromCapability({
        invocationTarget: 'https://host/space/s'
      } as never)
    ).toThrow(ValidationError)
    // Different origin entirely.
    expect(() =>
      client.fromCapability({
        invocationTarget: 'https://other/was/space/s'
      } as never)
    ).toThrow(ValidationError)
  })
})

/**
 * Generates a self-describing did:key X25519 reader (its `id` is
 * `did:key:<pub>#<pub>`, matching what a recipient entry's `kid` carries).
 *
 * @returns {Promise<{ kak: IKeyAgreementKey; publicKeyMultibase: string }>}
 */
async function makeReader(): Promise<{
  kak: IKeyAgreementKey
  publicKeyMultibase: string
}> {
  const kak = await X25519KeyAgreementKey2020.generate()
  const publicKeyMultibase = kak.publicKeyMultibase
  const did = `did:key:${publicKeyMultibase}`
  kak.controller = did
  kak.id = `${did}#${publicKeyMultibase}`
  return { kak: kak as IKeyAgreementKey, publicKeyMultibase }
}

/**
 * Mints an epoch and wraps its secret to each reader, producing a marker epoch
 * entry alongside the epoch id (so a test can order epochs and pick a
 * `currentEpoch` independently of array position).
 *
 * @param readers {Array<{ kak: IKeyAgreementKey; publicKeyMultibase: string }>}
 * @returns {Promise<{ id: string; recipients: object[] }>}
 */
async function epochEntryFor(
  readers: Array<{ kak: IKeyAgreementKey; publicKeyMultibase: string }>
): Promise<{ id: string; recipients: unknown[] }> {
  const { epochId, secret } = await mintEpoch()
  const recipients = await Promise.all(
    readers.map(reader =>
      wrapEpochSecret({
        epochSecret: secret,
        recipient: {
          id: reader.kak.id,
          publicKeyMultibase: reader.publicKeyMultibase
        }
      })
    )
  )
  return { id: epochId, recipients }
}

describe('resolveEpochKeys write-epoch selection', () => {
  it('selects currentEpoch by id even when it is not the array-last epoch', async () => {
    const alice = await makeReader()
    const first = await epochEntryFor([alice])
    const second = await epochEntryFor([alice])
    // List `second` before `first`, but point `currentEpoch` at `first`: the
    // write epoch must come from the id lookup, never the array position.
    const encryption = {
      scheme: 'edv',
      epochs: [second, first],
      currentEpoch: first.id
    } as unknown as CollectionEncryption
    const resolved = await resolveEpochKeys({
      encryption,
      keyAgreementKey: alice.kak
    })
    expect(resolved!.writeEpoch).toBe(first.id)
    expect(resolved!.writeKey.id).toBe(epochKeyIdFor(first.id))
    expect(resolved!.readKeys.length).toBe(2)
  })

  it('falls back deterministically to the last named epoch when not in currentEpoch', async () => {
    const bob = await makeReader()
    const inX = await epochEntryFor([bob])
    const inY = await epochEntryFor([bob])
    const notInZ = await epochEntryFor([await makeReader()])
    // Bob is a recipient of X and Y (in that marker order) but not of the
    // current epoch Z: the fallback picks the LAST epoch in the marker's order
    // that names Bob -- Y -- deterministically.
    const encryption = {
      scheme: 'edv',
      epochs: [inX, inY, notInZ],
      currentEpoch: notInZ.id
    } as unknown as CollectionEncryption
    const resolved = await resolveEpochKeys({
      encryption,
      keyAgreementKey: bob.kak
    })
    expect(resolved!.writeEpoch).toBe(inY.id)
    expect(resolved!.writeKey.id).toBe(epochKeyIdFor(inY.id))
    expect(resolved!.readKeys.length).toBe(2)
  })
})

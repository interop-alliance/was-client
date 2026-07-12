/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Unit tests for the multi-recipient key-epoch machinery (no network): the
 * marker recipient wrap/unwrap round-trip with real local X25519 keys, the
 * unwrap-failure paths (wrong key / null-treated-as-failure), epoch selection
 * and resolution from a marker, and the compare-and-swap retry logic of
 * `addRecipient` against a fake collection whose description writes race.
 */
import { describe, it, expect } from 'vitest'
import { X25519KeyAgreementKey2020 } from '@interop/x25519-key-agreement-key'
import type { IKeyAgreementKey } from '@interop/data-integrity-core'

import { KeyUnwrapError, PreconditionFailedError } from '../../src/index.js'
import type {
  CollectionEncryption,
  CollectionEncryptionRecipient
} from '../../src/index.js'
import type { Collection } from '../../src/Collection.js'
import type { Space } from '../../src/Space.js'
import {
  mintEpoch,
  wrapEpochSecret,
  unwrapEpochSecret,
  epochKeyIdFor,
  epochIdFromKid
} from '../../src/edv/epochCrypto.js'
import { resolveEpochKeys } from '../../src/edv/epochKeys.js'
import {
  addRecipient,
  initRecipients,
  removeRecipient
} from '../../src/edv/recipients.js'

/**
 * Generates a self-describing did:key X25519 reader: its `id` is
 * `did:key:<pub>#<pub>`, so the default `did:key` recipient resolver can recover
 * its public key from the `kid` alone (what `removeRecipient` re-wraps to).
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

describe('epoch key wrap/unwrap round-trip', () => {
  it('wraps an epoch secret to two readers; each unwraps with its own key', async () => {
    const alice = await makeReader()
    const bob = await makeReader()
    const { secret } = await mintEpoch()

    const entryA = await wrapEpochSecret({
      epochSecret: secret,
      recipient: {
        id: alice.kak.id,
        publicKeyMultibase: alice.publicKeyMultibase
      }
    })
    const entryB = await wrapEpochSecret({
      epochSecret: secret,
      recipient: { id: bob.kak.id, publicKeyMultibase: bob.publicKeyMultibase }
    })

    const gotA = await unwrapEpochSecret({
      entry: entryA,
      keyAgreementKey: alice.kak
    })
    const gotB = await unwrapEpochSecret({
      entry: entryB,
      keyAgreementKey: bob.kak
    })
    expect(gotA && Buffer.from(gotA).equals(Buffer.from(secret))).toBe(true)
    expect(gotB && Buffer.from(gotB).equals(Buffer.from(secret))).toBe(true)
    // The entry is the JWE recipients shape verbatim.
    expect(entryA.header.alg).toBe('ECDH-ES+A256KW')
    expect(entryA.header.kid).toBe(alice.kak.id)
    expect(typeof entryA.encrypted_key).toBe('string')
  })

  it("returns null (never a key) when the wrong reader's key is tried", async () => {
    const alice = await makeReader()
    const bob = await makeReader()
    const { secret } = await mintEpoch()
    const entryA = await wrapEpochSecret({
      epochSecret: secret,
      recipient: {
        id: alice.kak.id,
        publicKeyMultibase: alice.publicKeyMultibase
      }
    })
    // Bob is not the recipient of entryA: unwrap fails, resolving to null.
    const got = await unwrapEpochSecret({
      entry: entryA,
      keyAgreementKey: bob.kak
    })
    expect(got).toBeNull()
  })

  it('treats a malformed entry (no epk) as a failure, not a key', async () => {
    const alice = await makeReader()
    const bad = {
      header: { kid: alice.kak.id, alg: 'ECDH-ES+A256KW' },
      encrypted_key: 'AAAA'
    }
    const got = await unwrapEpochSecret({
      entry: bad as CollectionEncryptionRecipient,
      keyAgreementKey: alice.kak
    })
    expect(got).toBeNull()
  })

  it('epoch id encodes the epoch public key (kid round-trips)', async () => {
    const { epochId } = await mintEpoch()
    expect(epochId.startsWith('did:key:z')).toBe(true)
    expect(epochIdFromKid(epochKeyIdFor(epochId))).toBe(epochId)
  })
})

describe('resolveEpochKeys', () => {
  /**
   * Builds a marker with the given epochs, wrapping each epoch to `readers`.
   */
  async function markerFor(
    readers: Array<{ kak: IKeyAgreementKey; publicKeyMultibase: string }>,
    epochCount: number
  ): Promise<CollectionEncryption> {
    const epochs = []
    let currentEpoch = ''
    for (let index = 0; index < epochCount; index++) {
      const { epochId, secret } = await mintEpoch()
      currentEpoch = epochId
      epochs.push({
        id: epochId,
        recipients: await Promise.all(
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
      })
    }
    return { scheme: 'edv', epochs, currentEpoch }
  }

  it('returns null for a single-key marker (no epochs)', async () => {
    const alice = await makeReader()
    const resolved = await resolveEpochKeys({
      encryption: { scheme: 'edv' },
      keyAgreementKey: alice.kak
    })
    expect(resolved).toBeNull()
  })

  it('resolves a read key per epoch and writes under currentEpoch', async () => {
    const alice = await makeReader()
    const encryption = await markerFor([alice], 2)
    const resolved = await resolveEpochKeys({
      encryption,
      keyAgreementKey: alice.kak
    })
    expect(resolved).not.toBeNull()
    expect(resolved!.readKeys.length).toBe(2)
    expect(resolved!.writeEpoch).toBe(encryption.currentEpoch)
    // The write key is the currentEpoch key pair.
    expect(resolved!.writeKey.id).toBe(epochKeyIdFor(encryption.currentEpoch!))
  })

  it('throws KeyUnwrapError when the reader is a recipient of no epoch', async () => {
    const alice = await makeReader()
    const stranger = await makeReader()
    const encryption = await markerFor([alice], 1)
    await expect(
      resolveEpochKeys({ encryption, keyAgreementKey: stranger.kak })
    ).rejects.toBeInstanceOf(KeyUnwrapError)
  })

  it('still resolves read keys for a reader dropped from the latest epoch', async () => {
    // Alice in epoch 1 and 2, Bob only in epoch 1 (removed before epoch 2).
    const alice = await makeReader()
    const bob = await makeReader()
    const older = await markerFor([alice, bob], 1)
    const newer = await markerFor([alice], 1)
    const encryption: CollectionEncryption = {
      scheme: 'edv',
      epochs: [...older.epochs!, ...newer.epochs!],
      currentEpoch: newer.currentEpoch
    }
    const resolvedBob = await resolveEpochKeys({
      encryption,
      keyAgreementKey: bob.kak
    })
    // Bob can still read the older epoch (history), even though he cannot write
    // the current one.
    expect(resolvedBob!.readKeys.length).toBe(1)
    expect(resolvedBob!.writeEpoch).toBe(older.currentEpoch)
  })
})

describe('addRecipient compare-and-swap retry', () => {
  /**
   * A fake Collection whose description read returns a shared marker and whose
   * write applies it, optionally failing with a 412 for the first `stale` writes
   * (simulating a concurrent writer) so the CAS loop must re-read and retry.
   */
  function fakeCollection(initial: CollectionEncryption, stale: number) {
    const state = { encryption: initial, etag: '"v1"', version: 1 }
    let staleLeft = stale
    return {
      describeWithEtag: async () => ({
        description: {
          id: 'c',
          type: ['Collection'],
          encryption: state.encryption
        },
        etag: state.etag
      }),
      replaceDescription: async (
        desc: { encryption?: CollectionEncryption },
        options: { ifMatch?: string } = {}
      ) => {
        if (staleLeft > 0) {
          staleLeft--
          // Another writer moved the version forward: bump the etag so the
          // caller's ifMatch is now stale, and reject.
          state.version++
          state.etag = `"v${state.version}"`
          throw new PreconditionFailedError('stale', { status: 412 })
        }
        if (options.ifMatch !== undefined && options.ifMatch !== state.etag) {
          throw new PreconditionFailedError('stale', { status: 412 })
        }
        state.encryption = desc.encryption!
        state.version++
        state.etag = `"v${state.version}"`
        return {
          description: { id: 'c', type: ['Collection'] },
          etag: state.etag
        }
      },
      _state: state
    }
  }

  it('retries on a 412 and lands the recipient', async () => {
    const alice = await makeReader()
    const bob = await makeReader()
    // Seed a marker with one epoch that Alice can unwrap.
    const seed = await mintEpoch()
    const marker: CollectionEncryption = {
      scheme: 'edv',
      epochs: [
        {
          id: seed.epochId,
          recipients: [
            await wrapEpochSecret({
              epochSecret: seed.secret,
              recipient: {
                id: alice.kak.id,
                publicKeyMultibase: alice.publicKeyMultibase
              }
            })
          ]
        }
      ],
      currentEpoch: seed.epochId
    }
    const fake = fakeCollection(marker, 1) // one 412 then success

    const result = await addRecipient({
      collection: fake as unknown as Collection,
      recipient: { id: bob.kak.id, publicKeyMultibase: bob.publicKeyMultibase },
      owner: { keyAgreementKey: alice.kak }
    })
    // Bob is now a recipient of the epoch.
    const kids = result.epochs![0]!.recipients.map(entry => entry.header.kid)
    expect(kids).toContain(bob.kak.id)
    expect(kids).toContain(alice.kak.id)
    // And the escrowed key really is the epoch secret (Bob can unwrap it).
    const bobEntry = result.epochs![0]!.recipients.find(
      entry => entry.header.kid === bob.kak.id
    )!
    const bobSecret = await unwrapEpochSecret({
      entry: bobEntry,
      keyAgreementKey: bob.kak
    })
    expect(
      bobSecret && Buffer.from(bobSecret).equals(Buffer.from(seed.secret))
    ).toBe(true)
  })

  it('surfaces PreconditionFailedError after exhausting retries', async () => {
    const alice = await makeReader()
    const bob = await makeReader()
    const seed = await mintEpoch()
    const marker: CollectionEncryption = {
      scheme: 'edv',
      epochs: [
        {
          id: seed.epochId,
          recipients: [
            await wrapEpochSecret({
              epochSecret: seed.secret,
              recipient: {
                id: alice.kak.id,
                publicKeyMultibase: alice.publicKeyMultibase
              }
            })
          ]
        }
      ],
      currentEpoch: seed.epochId
    }
    const fake = fakeCollection(marker, 99) // always 412
    await expect(
      addRecipient({
        collection: fake as unknown as Collection,
        recipient: {
          id: bob.kak.id,
          publicKeyMultibase: bob.publicKeyMultibase
        },
        owner: { keyAgreementKey: alice.kak }
      })
    ).rejects.toBeInstanceOf(PreconditionFailedError)
  })
})

describe('rotation preserves the blinded-index hmac reference', () => {
  it('addRecipient and removeRecipient keep an unrelated marker field (e.g. hmac)', async () => {
    const alice = await makeReader()
    const bob = await makeReader()
    const seed = await mintEpoch()
    // A marker carrying a blinded-index `hmac` reference (an opaque extra field
    // the recipient ops must not disturb -- the hmac deliberately does NOT
    // rotate with the epoch).
    const marker = {
      scheme: 'edv',
      hmac: { id: 'urn:hmac:demo', type: 'Sha256HmacKey2019' },
      epochs: [
        {
          id: seed.epochId,
          recipients: [
            await wrapEpochSecret({
              epochSecret: seed.secret,
              recipient: {
                id: alice.kak.id,
                publicKeyMultibase: alice.publicKeyMultibase
              }
            })
          ]
        }
      ],
      currentEpoch: seed.epochId
    } as unknown as CollectionEncryption

    const state = { encryption: marker }
    const fake = {
      describeWithEtag: async () => ({
        description: {
          id: 'c',
          type: ['Collection'],
          encryption: state.encryption
        },
        etag: '"v1"'
      }),
      replaceDescription: async (desc: {
        encryption?: CollectionEncryption
      }) => {
        state.encryption = desc.encryption!
        return { description: { id: 'c', type: ['Collection'] }, etag: '"v2"' }
      }
    }

    const afterAdd = await addRecipient({
      collection: fake as unknown as Collection,
      recipient: { id: bob.kak.id, publicKeyMultibase: bob.publicKeyMultibase },
      owner: { keyAgreementKey: alice.kak }
    })
    expect((afterAdd as unknown as { hmac?: unknown }).hmac).toEqual({
      id: 'urn:hmac:demo',
      type: 'Sha256HmacKey2019'
    })

    const fakeSpace = { revoke: async () => undefined }
    const afterRemove = await removeRecipient({
      collection: fake as unknown as Collection,
      space: fakeSpace as unknown as Space,
      recipientId: bob.kak.id,
      revoke: []
    })
    // The epoch rotated (a new currentEpoch), but the hmac is unchanged.
    expect(afterRemove.currentEpoch).not.toBe(seed.epochId)
    expect((afterRemove as unknown as { hmac?: unknown }).hmac).toEqual({
      id: 'urn:hmac:demo',
      type: 'Sha256HmacKey2019'
    })
  })
})

describe('initRecipients', () => {
  it('mints the first epoch and wraps it to each initial reader', async () => {
    const alice = await makeReader()
    const bob = await makeReader()
    const state = { encryption: { scheme: 'edv' } as CollectionEncryption }
    const fake = {
      describeWithEtag: async () => ({
        description: {
          id: 'c',
          type: ['Collection'],
          encryption: state.encryption
        },
        etag: '"v1"'
      }),
      replaceDescription: async (desc: {
        encryption?: CollectionEncryption
      }) => {
        state.encryption = desc.encryption!
        return { description: { id: 'c', type: ['Collection'] }, etag: '"v2"' }
      }
    }
    const marker = await initRecipients({
      collection: fake as unknown as Collection,
      recipients: [
        { id: alice.kak.id, publicKeyMultibase: alice.publicKeyMultibase },
        { id: bob.kak.id, publicKeyMultibase: bob.publicKeyMultibase }
      ]
    })
    expect(marker.epochs!.length).toBe(1)
    expect(marker.currentEpoch).toBe(marker.epochs![0]!.id)
    expect(marker.epochs![0]!.recipients.length).toBe(2)
    // Both readers can resolve their keys from the resulting marker.
    const aliceKeys = await resolveEpochKeys({
      encryption: marker,
      keyAgreementKey: alice.kak
    })
    expect(aliceKeys!.readKeys.length).toBe(1)
  })
})

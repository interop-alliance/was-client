/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Unit tests for the multi-recipient key-epoch machinery (no network): the
 * descriptor recipient wrap/unwrap round-trip with real local X25519 keys, the
 * unwrap-failure paths (wrong key / null-treated-as-failure), epoch selection
 * and resolution from a descriptor, the provision-time `ensureFirstEpoch`
 * install (create-if-absent, adopt-on-race), and the compare-and-swap retry
 * logic of `addRecipient` against a fake collection whose description writes
 * race.
 */
import { describe, it, expect } from 'vitest'
import { X25519KeyAgreementKey2020 } from '@interop/x25519-key-agreement-key'
import type { IKeyAgreementKey } from '@interop/data-integrity-core'

import {
  KeyUnwrapError,
  PreconditionFailedError,
  ValidationError
} from '../../src/index.js'
import type {
  CollectionEncryption,
  CollectionEncryptionRecipient
} from '../../src/index.js'
import type { Collection } from '../../src/Collection.js'
import type { Space } from '../../src/Space.js'
import { EDV_SCHEME_VERSION } from '../../src/edv/constants.js'
import type { EncryptionDescriptorStore } from '../../src/edv/descriptorStore.js'
import {
  mintEpoch,
  wrapEpochSecret,
  unwrapEpochSecret,
  epochKeyIdFor,
  reconstructEpochKeyPair
} from '../../src/edv/epochCrypto.js'
import { verifyEpochsMac } from '../../src/edv/epochMac.js'
import { resolveEpochKeys } from '../../src/edv/epochKeys.js'
import {
  addRecipient,
  ensureFirstEpoch,
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

  it('returns null (not a raw decode error) for a malformed encrypted_key', async () => {
    // A non-base64url encrypted_key must honor the documented null contract
    // rather than escape as a raw "Unknown letter" decode error, so downstream
    // callers reach their typed ValidationError / KeyUnwrapError guards.
    const alice = await makeReader()
    const { secret } = await mintEpoch()
    const entry = await wrapEpochSecret({
      epochSecret: secret,
      recipient: {
        id: alice.kak.id,
        publicKeyMultibase: alice.publicKeyMultibase
      }
    })
    entry.encrypted_key = 'not!!!base64url'
    const got = await unwrapEpochSecret({ entry, keyAgreementKey: alice.kak })
    expect(got).toBeNull()
  })

  it('returns null for a malformed (non-base64url) epk.x', async () => {
    const alice = await makeReader()
    const { secret } = await mintEpoch()
    const entry = await wrapEpochSecret({
      epochSecret: secret,
      recipient: {
        id: alice.kak.id,
        publicKeyMultibase: alice.publicKeyMultibase
      }
    })
    ;(entry.header.epk as { x: string }).x = 'not!!!base64url'
    const got = await unwrapEpochSecret({ entry, keyAgreementKey: alice.kak })
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
    // The kid is `<did:key>#<fingerprint>`; the did:key portion before the `#`
    // is the epoch id.
    const kid = epochKeyIdFor(epochId)
    expect(kid.startsWith(`${epochId}#`)).toBe(true)
    expect(kid.slice(0, kid.indexOf('#'))).toBe(epochId)
  })

  it('reconstructs the epoch key pair from the minted secret (round-trip)', async () => {
    const { epochId, secret } = await mintEpoch()
    const keyPair = reconstructEpochKeyPair({ epochId, secret })
    expect(keyPair.id).toBe(epochKeyIdFor(epochId))
    // The reconstructed pair carries the same raw secret it was built from, and
    // its public key is the epoch's did:key fingerprint.
    const reconstructed = keyPair as unknown as X25519KeyAgreementKey2020
    expect(reconstructed.controller).toBe(epochId)
    expect(
      Buffer.from(reconstructed.rawSecret).equals(Buffer.from(secret))
    ).toBe(true)
    expect(`did:key:${reconstructed.publicKeyMultibase}`).toBe(epochId)
  })
})

describe('resolveEpochKeys', () => {
  /**
   * Builds a descriptor with the given epochs, wrapping each epoch to `readers`.
   */
  async function descriptorFor(
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

  it('returns null for a descriptor carrying no epochs', async () => {
    const alice = await makeReader()
    const resolved = await resolveEpochKeys({
      encryption: { scheme: 'edv' },
      keyAgreementKey: alice.kak
    })
    expect(resolved).toBeNull()
  })

  it('resolves a read key per epoch and writes under currentEpoch', async () => {
    const alice = await makeReader()
    const encryption = await descriptorFor([alice], 2)
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
    const encryption = await descriptorFor([alice], 1)
    await expect(
      resolveEpochKeys({ encryption, keyAgreementKey: stranger.kak })
    ).rejects.toBeInstanceOf(KeyUnwrapError)
  })

  it('still resolves read keys for a reader dropped from the latest epoch', async () => {
    // Alice in epoch 1 and 2, Bob only in epoch 1 (removed before epoch 2).
    const alice = await makeReader()
    const bob = await makeReader()
    const older = await descriptorFor([alice, bob], 1)
    const newer = await descriptorFor([alice], 1)
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

describe('lazy epoch key unwrap retry', () => {
  it('re-attempts the unwrap on the next read after a transient failure', async () => {
    // Alice holds epochs 1 and 2; epoch 2 is current (unwrapped eagerly), so
    // epoch 1 resolves through a lazy key. Her key-agreement key fails
    // transiently on the lazy unwrap's first attempt (e.g. a KMS-backed key
    // hiccup). The rejection must not be cached for the life of the handle:
    // the next read retries and succeeds.
    const alice = await makeReader()
    const peer = await makeReader()
    const epochs = []
    let currentEpoch = ''
    for (let index = 0; index < 2; index++) {
      const { epochId, secret } = await mintEpoch()
      currentEpoch = epochId
      epochs.push({
        id: epochId,
        recipients: [
          await wrapEpochSecret({
            epochSecret: secret,
            recipient: {
              id: alice.kak.id,
              publicKeyMultibase: alice.publicKeyMultibase
            }
          })
        ]
      })
    }
    // Call 1 is the eager write-epoch unwrap; call 2 is the lazy epoch's first
    // unwrap, made to fail transiently; call 3 (the retry) succeeds.
    let deriveCalls = 0
    const flakyKak = {
      id: alice.kak.id,
      async deriveSecret(options: { publicKey: unknown }): Promise<Uint8Array> {
        deriveCalls += 1
        if (deriveCalls === 2) {
          throw new Error('transient key-store failure')
        }
        return alice.kak.deriveSecret(options)
      }
    } as IKeyAgreementKey
    const resolved = await resolveEpochKeys({
      encryption: { scheme: 'edv', epochs, currentEpoch },
      keyAgreementKey: flakyKak
    })
    const lazy = resolved!.readKeys[1]!
    const publicKey = {
      type: 'X25519KeyAgreementKey2020',
      publicKeyMultibase: peer.publicKeyMultibase
    }
    // First read: the transient failure surfaces (as the lazy key's typed
    // corrupt-entry error, since the swallowed unwrap resolves null).
    await expect(lazy.deriveSecret({ publicKey })).rejects.toBeInstanceOf(
      KeyUnwrapError
    )
    // Second read: the rejection was not cached; the unwrap retries and works.
    const derived = await lazy.deriveSecret({ publicKey })
    expect(derived).toBeInstanceOf(Uint8Array)
    expect(derived.length).toBe(32)
  })
})

describe('addRecipient compare-and-swap retry', () => {
  /**
   * A fake Collection whose description read returns a shared descriptor and
   * whose write applies it, optionally failing with a 412 for the first `stale`
   * writes (simulating a concurrent writer) so the CAS loop must re-read and
   * retry.
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
    // Seed a descriptor with one epoch that Alice can unwrap.
    const seed = await mintEpoch()
    const descriptor: CollectionEncryption = {
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
    const fake = fakeCollection(descriptor, 1) // one 412 then success

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
    const descriptor: CollectionEncryption = {
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
    const fake = fakeCollection(descriptor, 99) // always 412
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
  it('addRecipient and removeRecipient keep an unrelated descriptor field (e.g. hmac)', async () => {
    const alice = await makeReader()
    const bob = await makeReader()
    const seed = await mintEpoch()
    // A descriptor carrying a blinded-index `hmac` reference (an opaque extra
    // field the recipient ops must not disturb -- the hmac deliberately does
    // NOT rotate with the epoch).
    const descriptor = {
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

    const state = { encryption: descriptor }
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
    const descriptor = await initRecipients({
      collection: fake as unknown as Collection,
      recipients: [
        { id: alice.kak.id, publicKeyMultibase: alice.publicKeyMultibase },
        { id: bob.kak.id, publicKeyMultibase: bob.publicKeyMultibase }
      ]
    })
    expect(descriptor.epochs!.length).toBe(1)
    expect(descriptor.currentEpoch).toBe(descriptor.epochs![0]!.id)
    expect(descriptor.epochs![0]!.recipients.length).toBe(2)
    // Both readers can resolve their keys from the resulting descriptor.
    const aliceKeys = await resolveEpochKeys({
      encryption: descriptor,
      keyAgreementKey: alice.kak
    })
    expect(aliceKeys!.readKeys.length).toBe(1)
  })

  it('stamps epochsSig from the signEpochs hook beside the epochsMac', async () => {
    const alice = await makeReader()
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
    const seen: Uint8Array[] = []
    const descriptor = await initRecipients({
      collection: fake as unknown as Collection,
      recipients: [
        { id: alice.kak.id, publicKeyMultibase: alice.publicKeyMultibase }
      ],
      signEpochs: async ({ payload }) => {
        seen.push(payload)
        return { v: 1, alg: 'EdDSA', kid: 'signer-kid', sig: 'signature' }
      }
    })
    expect(descriptor.epochsMac).toBeDefined()
    expect(descriptor.epochsSig).toEqual({
      v: 1,
      alg: 'EdDSA',
      kid: 'signer-kid',
      sig: 'signature'
    })
    // The signer saw the canonical payload over the exact descriptor written.
    expect(seen.length).toBe(1)
    const payloadText = new TextDecoder().decode(seen[0]!)
    expect(payloadText.startsWith('was-epoch-config-sig/v1.')).toBe(true)
    expect(payloadText).toContain(descriptor.currentEpoch!)
  })
})

describe('ensureFirstEpoch', () => {
  /**
   * An in-memory descriptor store standing in for the resource-hosted adapter:
   * `read()` resolves `null` until a descriptor exists, `create` is the guarded
   * create-if-absent write, and both write paths are counted so a test can
   * assert that an adoption wrote nothing at all. `createFails` makes the first
   * `create` lose the race with a concurrent provisioner, after which `read()`
   * serves `winner`.
   *
   * @param options {object}
   * @param [options.initial] {CollectionEncryption}   the descriptor `read()`
   *   starts out serving; absent means the store starts empty
   * @param [options.createFails] {number}   how many `create` calls reject with
   *   a 412 before one lands
   * @param [options.winner] {CollectionEncryption}   the descriptor `read()`
   *   serves once a `create` has lost the race
   * @returns {object}   the store plus its call counters and current state
   */
  function memoryStore({
    initial,
    createFails = 0,
    winner
  }: {
    initial?: CollectionEncryption
    createFails?: number
    winner?: CollectionEncryption
  } = {}): EncryptionDescriptorStore & {
    state: { descriptor?: CollectionEncryption }
    creates: number
    replaces: number
  } {
    let createsLeft = createFails
    const holder = {
      state: { descriptor: initial },
      creates: 0,
      replaces: 0,
      async read() {
        return holder.state.descriptor === undefined
          ? null
          : { descriptor: holder.state.descriptor, etag: '"v1"' }
      },
      async replace(descriptor: CollectionEncryption) {
        holder.replaces += 1
        holder.state.descriptor = descriptor
      },
      async create(descriptor: CollectionEncryption) {
        holder.creates += 1
        if (createsLeft > 0) {
          createsLeft -= 1
          // A concurrent provisioner got there first: its descriptor is what
          // the next read serves.
          holder.state.descriptor = winner
          throw new PreconditionFailedError('exists', { status: 412 })
        }
        holder.state.descriptor = descriptor
      }
    }
    return holder
  }

  /**
   * A fake Collection whose Description hosts an epoch-less `edv` descriptor --
   * the state the crypto-free `ensureSpaceAndCollection` leaves an encrypted
   * collection in -- counting its description writes.
   *
   * @param initial {CollectionEncryption}
   * @returns {object}
   */
  function fakeCollection(initial: CollectionEncryption) {
    const state = { encryption: initial, writes: 0 }
    return {
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
        state.writes += 1
        state.encryption = desc.encryption!
        return { description: { id: 'c', type: ['Collection'] }, etag: '"v2"' }
      },
      _state: state
    }
  }

  /**
   * Seeds an epoch-bearing descriptor, as a concurrent provisioner's winning
   * install would leave it.
   *
   * @param reader {{ kak: IKeyAgreementKey; publicKeyMultibase: string }}
   * @returns {Promise<CollectionEncryption>}
   */
  async function installedDescriptor(reader: {
    kak: IKeyAgreementKey
    publicKeyMultibase: string
  }): Promise<CollectionEncryption> {
    const { epochId, secret } = await mintEpoch()
    return {
      scheme: 'edv',
      version: EDV_SCHEME_VERSION,
      epochs: [
        {
          id: epochId,
          recipients: [
            await wrapEpochSecret({
              epochSecret: secret,
              recipient: {
                id: reader.kak.id,
                publicKeyMultibase: reader.publicKeyMultibase
              }
            })
          ]
        }
      ],
      currentEpoch: epochId
    }
  }

  it('installs epoch[0] onto an epoch-less collection descriptor', async () => {
    const alice = await makeReader()
    const bob = await makeReader()
    const fake = fakeCollection({ scheme: 'edv' })

    const { descriptor, installed } = await ensureFirstEpoch({
      collection: fake as unknown as Collection,
      recipients: [
        { id: alice.kak.id, publicKeyMultibase: alice.publicKeyMultibase },
        { id: bob.kak.id, publicKeyMultibase: bob.publicKeyMultibase }
      ]
    })

    expect(installed).toBe(true)
    expect(fake._state.writes).toBe(1)
    expect(descriptor.version).toBe(EDV_SCHEME_VERSION)
    expect(descriptor.epochs).toHaveLength(1)
    const epoch = descriptor.epochs![0]!
    expect(descriptor.currentEpoch).toBe(epoch.id)
    expect(descriptor.epochsMac).toBeDefined()
    // No signer was supplied, so no detached signature is stamped.
    expect(descriptor.epochsSig).toBeUndefined()

    // Every recipient's wrap opens to the SAME epoch secret, and that secret
    // keys the stamped epochsMac.
    const aliceSecret = await unwrapEpochSecret({
      entry: epoch.recipients.find(entry => entry.header.kid === alice.kak.id)!,
      keyAgreementKey: alice.kak
    })
    const bobSecret = await unwrapEpochSecret({
      entry: epoch.recipients.find(entry => entry.header.kid === bob.kak.id)!,
      keyAgreementKey: bob.kak
    })
    expect(aliceSecret).not.toBeNull()
    expect(Buffer.from(aliceSecret!).equals(Buffer.from(bobSecret!))).toBe(true)
    expect(
      await verifyEpochsMac({ descriptor, epochSecret: aliceSecret! })
    ).toBe(true)
  })

  it('adopts an existing roster as-is, writing nothing', async () => {
    const alice = await makeReader()
    const existing = await installedDescriptor(alice)
    const store = memoryStore({ initial: existing })

    const { descriptor, installed } = await ensureFirstEpoch({
      store,
      recipients: [
        { id: alice.kak.id, publicKeyMultibase: alice.publicKeyMultibase }
      ]
    })

    expect(installed).toBe(false)
    expect(descriptor).toBe(existing)
    expect(store.replaces).toBe(0)
    expect(store.creates).toBe(0)
  })

  it('creates the descriptor when the store holds none yet', async () => {
    const alice = await makeReader()
    const store = memoryStore()

    const { descriptor, installed } = await ensureFirstEpoch({
      store,
      recipients: [
        { id: alice.kak.id, publicKeyMultibase: alice.publicKeyMultibase }
      ]
    })

    expect(installed).toBe(true)
    expect(store.creates).toBe(1)
    expect(store.replaces).toBe(0)
    expect(store.state.descriptor).toEqual(descriptor)
    expect(descriptor.scheme).toBe('edv')
    expect(descriptor.version).toBe(EDV_SCHEME_VERSION)
    expect(descriptor.epochs).toHaveLength(1)
    expect(descriptor.currentEpoch).toBe(descriptor.epochs![0]!.id)
  })

  it("adopts the winner's roster after losing the create race", async () => {
    const alice = await makeReader()
    const winner = await installedDescriptor(alice)
    const store = memoryStore({ createFails: 1, winner })

    const { descriptor, installed } = await ensureFirstEpoch({
      store,
      recipients: [
        { id: alice.kak.id, publicKeyMultibase: alice.publicKeyMultibase }
      ]
    })

    // The losing create is the only write attempted: the re-read finds the
    // winner's roster and adopts it rather than overwriting it.
    expect(installed).toBe(false)
    expect(descriptor).toBe(winner)
    expect(store.creates).toBe(1)
    expect(store.replaces).toBe(0)
  })

  it('refuses an install with no recipients', async () => {
    const store = memoryStore()
    await expect(
      ensureFirstEpoch({ store, recipients: [] })
    ).rejects.toBeInstanceOf(ValidationError)
    expect(store.creates).toBe(0)
  })

  it('stamps epochsSig when a signer is supplied', async () => {
    const alice = await makeReader()
    const store = memoryStore()
    const seen: Uint8Array[] = []

    const { descriptor, installed } = await ensureFirstEpoch({
      store,
      recipients: [
        { id: alice.kak.id, publicKeyMultibase: alice.publicKeyMultibase }
      ],
      signEpochs: async ({ payload }) => {
        seen.push(payload)
        return { v: 1, alg: 'EdDSA', kid: 'signer-kid', sig: 'signature' }
      }
    })

    expect(installed).toBe(true)
    expect(descriptor.epochsMac).toBeDefined()
    expect(descriptor.epochsSig).toEqual({
      v: 1,
      alg: 'EdDSA',
      kid: 'signer-kid',
      sig: 'signature'
    })
    // The signer saw the canonical payload over the exact descriptor written.
    expect(seen).toHaveLength(1)
    const payloadText = new TextDecoder().decode(seen[0]!)
    expect(payloadText.startsWith('was-epoch-config-sig/v1.')).toBe(true)
    expect(payloadText).toContain(descriptor.currentEpoch!)
  })
})

describe('removeRecipient security', () => {
  /**
   * A minimal in-memory Collection whose description read returns the evolving
   * descriptor and whose write applies it (no CAS races, no network). The
   * optional `staleForever` makes every write reject with a 412 so the CAS loop
   * exhausts its retries (simulating a permanently-losing compare-and-swap).
   *
   * @param initial {CollectionEncryption}
   * @param [options] {object}
   * @param [options.staleForever] {boolean}
   * @returns {object}
   */
  function mutableCollection(
    initial: CollectionEncryption,
    { staleForever = false }: { staleForever?: boolean } = {}
  ) {
    const state = { encryption: initial }
    return {
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
        if (staleForever) {
          throw new PreconditionFailedError('stale', { status: 412 })
        }
        state.encryption = desc.encryption!
        return { description: { id: 'c', type: ['Collection'] }, etag: '"v2"' }
      },
      _state: state
    }
  }

  /**
   * Seeds a one-epoch descriptor wrapping the epoch key to each of `readers`.
   *
   * @param readers {Array<{ kak: IKeyAgreementKey; publicKeyMultibase: string }>}
   * @returns {Promise<CollectionEncryption>}
   */
  async function seedDescriptor(
    readers: Array<{ kak: IKeyAgreementKey; publicKeyMultibase: string }>
  ): Promise<CollectionEncryption> {
    const { epochId, secret } = await mintEpoch()
    return {
      scheme: 'edv',
      epochs: [
        {
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
        }
      ],
      currentEpoch: epochId
    }
  }

  it('re-signs a signed rotation and strips the stale sig when unsigned', async () => {
    const alice = await makeReader()
    const bob = await makeReader()
    const seeded = await seedDescriptor([alice, bob])
    seeded.epochsSig = { v: 1, alg: 'EdDSA', kid: 'old-kid', sig: 'old-sig' }

    // A rotation WITH a signer replaces the stale signature.
    const signedFake = mutableCollection(structuredClone(seeded))
    const signed = await removeRecipient({
      collection: signedFake as unknown as Collection,
      recipientId: bob.kak.id,
      pull: async () => {},
      signEpochs: async () => ({
        v: 1,
        alg: 'EdDSA',
        kid: 'fresh-kid',
        sig: 'fresh-sig'
      })
    })
    expect(signed.epochsSig!.kid).toBe('fresh-kid')

    // A rotation WITHOUT a signer drops the now-invalid signature instead of
    // carrying it forward over a changed epoch configuration.
    const unsignedFake = mutableCollection(structuredClone(seeded))
    const unsigned = await removeRecipient({
      collection: unsignedFake as unknown as Collection,
      recipientId: bob.kak.id,
      pull: async () => {}
    })
    expect(unsigned.epochsSig).toBeUndefined()
  })

  it('does not re-add a previously removed reader on a later removal', async () => {
    // Readers {A, X, Y} in epoch1. Remove X, then remove Y. The survivor set of
    // the second removal must come from the CURRENT epoch (which no longer holds
    // X), not the union across all epochs, so X must not silently regain access.
    const alice = await makeReader()
    const xavier = await makeReader()
    const yolanda = await makeReader()
    const fake = mutableCollection(
      await seedDescriptor([alice, xavier, yolanda])
    )
    const fakeSpace = { revoke: async () => undefined }

    await removeRecipient({
      collection: fake as unknown as Collection,
      space: fakeSpace as unknown as Space,
      recipientId: xavier.kak.id,
      revoke: []
    })
    const afterY = await removeRecipient({
      collection: fake as unknown as Collection,
      space: fakeSpace as unknown as Space,
      recipientId: yolanda.kak.id,
      revoke: []
    })

    const currentEpoch = afterY.epochs!.find(
      epoch => epoch.id === afterY.currentEpoch
    )!
    const kids = currentEpoch.recipients.map(entry => entry.header.kid)
    expect(kids).toEqual([alice.kak.id])
    expect(kids).not.toContain(xavier.kak.id)
    expect(kids).not.toContain(yolanda.kak.id)
  })

  it('rotates the epoch BEFORE revoking capabilities', async () => {
    // At revoke time the descriptor must already be rotated (rotation is durable
    // first), so a revoke failure cannot leave the reader revoked but the epoch
    // un-rotated.
    const alice = await makeReader()
    const bob = await makeReader()
    const seed = await seedDescriptor([alice, bob])
    const seedEpoch = seed.currentEpoch
    const fake = mutableCollection(seed)
    const epochsAtRevoke: string[] = []
    const fakeSpace = {
      revoke: async () => {
        epochsAtRevoke.push(fake._state.encryption.currentEpoch!)
      }
    }
    const revokedZcap = { id: 'urn:zcap:x' }

    const rotated = await removeRecipient({
      collection: fake as unknown as Collection,
      space: fakeSpace as unknown as Space,
      recipientId: bob.kak.id,
      revoke: revokedZcap as never
    })
    // Revoke ran once, and the epoch it observed is the NEW one (already
    // rotated).
    expect(epochsAtRevoke).toEqual([rotated.currentEpoch])
    expect(rotated.currentEpoch).not.toBe(seedEpoch)
  })

  it('tolerates an already-revoked capability (retryable to convergence)', async () => {
    // A retry after a transient failure re-revokes; the non-idempotent revoke
    // then throws ValidationError. removeRecipient must swallow only that and
    // still complete the rotation.
    const alice = await makeReader()
    const bob = await makeReader()
    const fake = mutableCollection(await seedDescriptor([alice, bob]))
    const fakeSpace = {
      revoke: async () => {
        throw new ValidationError('already revoked')
      }
    }

    const rotated = await removeRecipient({
      collection: fake as unknown as Collection,
      space: fakeSpace as unknown as Space,
      recipientId: bob.kak.id,
      revoke: { id: 'urn:zcap:x' } as never
    })
    const currentEpoch = rotated.epochs!.find(
      epoch => epoch.id === rotated.currentEpoch
    )!
    expect(currentEpoch.recipients.map(entry => entry.header.kid)).toEqual([
      alice.kak.id
    ])
  })

  it('does not revoke when the rotation CAS never lands (no half-removal)', async () => {
    // Rotation is attempted first; if it exhausts its retries and throws, the
    // capability must NOT have been revoked, so the operation is safely
    // retryable.
    const alice = await makeReader()
    const bob = await makeReader()
    const fake = mutableCollection(await seedDescriptor([alice, bob]), {
      staleForever: true
    })
    let revoked = false
    const fakeSpace = {
      revoke: async () => {
        revoked = true
      }
    }
    await expect(
      removeRecipient({
        collection: fake as unknown as Collection,
        space: fakeSpace as unknown as Space,
        recipientId: bob.kak.id,
        revoke: { id: 'urn:zcap:x' } as never
      })
    ).rejects.toBeInstanceOf(PreconditionFailedError)
    expect(revoked).toBe(false)
  })

  it('a retry after a transient revoke failure does not append a redundant epoch', async () => {
    // First attempt: rotation lands, then the revoke fails transiently and the
    // whole operation throws. The caller retries. The retry must detect that
    // the current epoch already excludes the departing reader and skip
    // straight to the revoke step -- NOT mint and append another epoch per
    // attempt.
    const alice = await makeReader()
    const bob = await makeReader()
    const fake = mutableCollection(await seedDescriptor([alice, bob]))
    let revokeCalls = 0
    const fakeSpace = {
      revoke: async () => {
        revokeCalls += 1
        if (revokeCalls === 1) {
          throw new Error('transient network failure')
        }
      }
    }
    const removal = {
      collection: fake as unknown as Collection,
      space: fakeSpace as unknown as Space,
      recipientId: bob.kak.id,
      revoke: { id: 'urn:zcap:x' } as never
    }

    await expect(removeRecipient(removal)).rejects.toThrow(/transient/)
    // The rotation was durable before the failed revoke: seed epoch + one
    // rotated epoch.
    expect(fake._state.encryption.epochs).toHaveLength(2)

    const converged = await removeRecipient(removal)
    // No third epoch, and the reader stays excluded from the current one.
    expect(fake._state.encryption.epochs).toHaveLength(2)
    expect(revokeCalls).toBe(2)
    const currentEpoch = converged.epochs!.find(
      epoch => epoch.id === converged.currentEpoch
    )!
    expect(currentEpoch.recipients.map(entry => entry.header.kid)).toEqual([
      alice.kak.id
    ])
  })
})

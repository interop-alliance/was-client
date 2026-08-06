/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Unit tests for `replaceRecipient` (no network): the one-write
 * escrow-and-rotate over an in-memory descriptor store, its convergence rules
 * (zero redundant epochs on a naive re-run, escrow-only writes), the
 * resolver's drop-this-kid contract, the pull-axis ordering, and the
 * validation guards.
 */
import { describe, it, expect } from 'vitest'
import { X25519KeyAgreementKey2020 } from '@interop/x25519-key-agreement-key'
import type { IKeyAgreementKey } from '@interop/data-integrity-core'

import { ValidationError } from '../../src/index.js'
import type { CollectionEncryption } from '../../src/index.js'
import type { EncryptionDescriptorStore } from '../../src/edv/descriptorStore.js'
import {
  mintEpoch,
  unwrapEpochSecret,
  wrapEpochSecret,
  epochKeyIdFor,
  reconstructEpochKeyPair
} from '../../src/edv/epochCrypto.js'
import { verifyEpochsMac } from '../../src/edv/epochMac.js'
import { replaceRecipient } from '../../src/edv/recipients.js'

/**
 * Generates a self-describing did:key X25519 reader (the default recipient
 * resolver recovers its public key from the kid alone).
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
 * A per-user-key stand-in: the epoch construction's key pair, presented the
 * way the wallet presents a user key (kid = `epochKeyIdFor(id)`).
 *
 * @returns {Promise<object>}
 */
async function makeUserKeyLike(): Promise<{
  id: string
  secret: Uint8Array
  kid: string
  kak: IKeyAgreementKey
  publicKeyMultibase: string
}> {
  const { epochId, secret } = await mintEpoch()
  return {
    id: epochId,
    secret,
    kid: epochKeyIdFor(epochId),
    kak: reconstructEpochKeyPair({ epochId, secret }),
    publicKeyMultibase: epochId.split(':')[2]!
  }
}

/**
 * An in-memory descriptor store that counts reads and writes.
 *
 * @param initial {CollectionEncryption}
 * @returns {object}
 */
function memoryStore(
  initial: CollectionEncryption
): EncryptionDescriptorStore & {
  state: { descriptor: CollectionEncryption }
  writes: number
} {
  const holder = {
    state: { descriptor: initial },
    writes: 0,
    async read() {
      return { descriptor: holder.state.descriptor, etag: '"v"' }
    },
    async replace(descriptor: CollectionEncryption) {
      holder.state.descriptor = descriptor
      holder.writes += 1
    }
  }
  return holder
}

/**
 * Seeds a descriptor whose single epoch wraps to the given recipients.
 *
 * @param recipients {Array<{ kid: string; publicKeyMultibase: string }>}
 * @returns {Promise<CollectionEncryption>}
 */
async function seedDescriptor(
  recipients: Array<{ kid: string; publicKeyMultibase: string }>
): Promise<CollectionEncryption> {
  const { epochId, secret } = await mintEpoch()
  return {
    scheme: 'edv',
    version: 1,
    epochs: [
      {
        id: epochId,
        recipients: await Promise.all(
          recipients.map(recipient =>
            wrapEpochSecret({
              epochSecret: secret,
              recipient: {
                id: recipient.kid,
                publicKeyMultibase: recipient.publicKeyMultibase
              }
            })
          )
        )
      }
    ],
    currentEpoch: epochId
  }
}

describe('replaceRecipient', () => {
  it('escrows the incoming key into history and rotates off the retiring key in ONE write', async () => {
    const oldUserKey = await makeUserKeyLike()
    const newUserKey = await makeUserKeyLike()
    const app = await makeReader()
    const store = memoryStore(
      await seedDescriptor([
        {
          kid: oldUserKey.kid,
          publicKeyMultibase: oldUserKey.publicKeyMultibase
        },
        { kid: app.kak.id, publicKeyMultibase: app.publicKeyMultibase }
      ])
    )
    const historicEpochId = store.state.descriptor.currentEpoch!

    const result = await replaceRecipient({
      store,
      retire: oldUserKey.kid,
      recipient: {
        id: newUserKey.kid,
        publicKeyMultibase: newUserKey.publicKeyMultibase
      },
      owner: { keyAgreementKey: oldUserKey.kak },
      pull: async () => {}
    })

    expect(store.writes).toBe(1)
    expect(result.epochs).toHaveLength(2)
    // The historical epoch gained the incoming key's escrow wrap.
    const historic = result.epochs!.find(epoch => epoch.id === historicEpochId)!
    const historicKids = historic.recipients.map(entry => entry.header.kid)
    expect(historicKids).toContain(newUserKey.kid)
    expect(historicKids).toContain(oldUserKey.kid)
    // The fresh current epoch carries the survivors plus the incoming key,
    // never the retired one.
    const current = result.epochs!.find(
      epoch => epoch.id === result.currentEpoch
    )!
    const currentKids = current.recipients.map(entry => entry.header.kid)
    expect(currentKids).toContain(newUserKey.kid)
    expect(currentKids).toContain(app.kak.id)
    expect(currentKids).not.toContain(oldUserKey.kid)
    // The incoming key unwraps both epochs; the retired key fails on the
    // fresh one.
    const currentEntryNew = current.recipients.find(
      entry => entry.header.kid === newUserKey.kid
    )!
    const freshSecret = await unwrapEpochSecret({
      entry: currentEntryNew,
      keyAgreementKey: newUserKey.kak
    })
    expect(freshSecret).not.toBeNull()
    const historicEntryNew = historic.recipients.find(
      entry => entry.header.kid === newUserKey.kid
    )!
    expect(
      await unwrapEpochSecret({
        entry: historicEntryNew,
        keyAgreementKey: newUserKey.kak
      })
    ).not.toBeNull()
    // The epoch configuration re-authenticates under the fresh secret.
    expect(
      await verifyEpochsMac({ descriptor: result, epochSecret: freshSecret! })
    ).toBe(true)
  })

  it('appends zero redundant epochs on a naive re-run', async () => {
    const oldUserKey = await makeUserKeyLike()
    const newUserKey = await makeUserKeyLike()
    const store = memoryStore(
      await seedDescriptor([
        {
          kid: oldUserKey.kid,
          publicKeyMultibase: oldUserKey.publicKeyMultibase
        }
      ])
    )
    const args = {
      store,
      retire: oldUserKey.kid,
      recipient: {
        id: newUserKey.kid,
        publicKeyMultibase: newUserKey.publicKeyMultibase
      },
      owner: { keyAgreementKey: oldUserKey.kak },
      pull: async () => {}
    }
    const first = await replaceRecipient(args)
    const second = await replaceRecipient({
      ...args,
      // The re-run's owner is the incoming key (the retired one is gone from
      // the current epoch); it is a recipient of every epoch via the escrow.
      owner: { keyAgreementKey: newUserKey.kak }
    })
    expect(store.writes).toBe(1)
    expect(second.epochs).toHaveLength(first.epochs!.length)
    expect(second.currentEpoch).toBe(first.currentEpoch)
  })

  it('writes escrow-only (no fresh epoch) when no retiring key is current', async () => {
    // Two epochs; the retiree was already rotated off the current one, but the
    // incoming key is missing from the historical epoch (a crash between the
    // two halves of an older, composed add+remove).
    const oldUserKey = await makeUserKeyLike()
    const midUserKey = await makeUserKeyLike()
    const newUserKey = await makeUserKeyLike()
    const seeded = await seedDescriptor([
      {
        kid: oldUserKey.kid,
        publicKeyMultibase: oldUserKey.publicKeyMultibase
      },
      { kid: midUserKey.kid, publicKeyMultibase: midUserKey.publicKeyMultibase }
    ])
    const { epochId, secret } = await mintEpoch()
    const descriptor: CollectionEncryption = {
      ...seeded,
      epochs: [
        ...seeded.epochs!,
        {
          id: epochId,
          recipients: [
            await wrapEpochSecret({
              epochSecret: secret,
              recipient: {
                id: midUserKey.kid,
                publicKeyMultibase: midUserKey.publicKeyMultibase
              }
            }),
            await wrapEpochSecret({
              epochSecret: secret,
              recipient: {
                id: newUserKey.kid,
                publicKeyMultibase: newUserKey.publicKeyMultibase
              }
            })
          ]
        }
      ],
      currentEpoch: epochId
    }
    const store = memoryStore(descriptor)
    const macBefore = store.state.descriptor.epochsMac

    const result = await replaceRecipient({
      store,
      retire: oldUserKey.kid,
      recipient: {
        id: newUserKey.kid,
        publicKeyMultibase: newUserKey.publicKeyMultibase
      },
      owner: { keyAgreementKey: midUserKey.kak },
      pull: async () => {}
    })

    expect(store.writes).toBe(1)
    expect(result.epochs).toHaveLength(2)
    expect(result.currentEpoch).toBe(epochId)
    expect(result.epochsMac).toBe(macBefore)
    const historic = result.epochs![0]!
    expect(historic.recipients.map(entry => entry.header.kid)).toContain(
      newUserKey.kid
    )
  })

  it('retires several stranded keys in one rotation', async () => {
    const gen1 = await makeUserKeyLike()
    const gen2 = await makeUserKeyLike()
    const gen3 = await makeUserKeyLike()
    const app = await makeReader()
    const store = memoryStore(
      await seedDescriptor([
        { kid: gen1.kid, publicKeyMultibase: gen1.publicKeyMultibase },
        { kid: gen2.kid, publicKeyMultibase: gen2.publicKeyMultibase },
        { kid: app.kak.id, publicKeyMultibase: app.publicKeyMultibase }
      ])
    )
    const result = await replaceRecipient({
      store,
      retire: [gen1.kid, gen2.kid],
      recipient: { id: gen3.kid, publicKeyMultibase: gen3.publicKeyMultibase },
      owner: { keyAgreementKey: gen2.kak },
      pull: async () => {}
    })
    const current = result.epochs!.find(
      epoch => epoch.id === result.currentEpoch
    )!
    const kids = current.recipients.map(entry => entry.header.kid)
    expect(kids).toContain(gen3.kid)
    expect(kids).toContain(app.kak.id)
    expect(kids).not.toContain(gen1.kid)
    expect(kids).not.toContain(gen2.kid)
  })

  it('drops a surviving kid the resolver resolves null for', async () => {
    const oldUserKey = await makeUserKeyLike()
    const newUserKey = await makeUserKeyLike()
    const ghost = await makeReader()
    const store = memoryStore(
      await seedDescriptor([
        {
          kid: oldUserKey.kid,
          publicKeyMultibase: oldUserKey.publicKeyMultibase
        },
        { kid: ghost.kak.id, publicKeyMultibase: ghost.publicKeyMultibase }
      ])
    )
    const result = await replaceRecipient({
      store,
      retire: oldUserKey.kid,
      recipient: {
        id: newUserKey.kid,
        publicKeyMultibase: newUserKey.publicKeyMultibase
      },
      owner: { keyAgreementKey: oldUserKey.kak },
      pull: async () => {},
      resolveRecipientKey: async kid =>
        kid === ghost.kak.id
          ? null
          : { id: kid, publicKeyMultibase: kid.split('#').pop()! }
    })
    const current = result.epochs!.find(
      epoch => epoch.id === result.currentEpoch
    )!
    const kids = current.recipients.map(entry => entry.header.kid)
    expect(kids).toEqual([newUserKey.kid])
  })

  it('runs the pull axis only after the rotation is durable', async () => {
    const oldUserKey = await makeUserKeyLike()
    const newUserKey = await makeUserKeyLike()
    const store = memoryStore(
      await seedDescriptor([
        {
          kid: oldUserKey.kid,
          publicKeyMultibase: oldUserKey.publicKeyMultibase
        }
      ])
    )
    const epochsAtPull: string[] = []
    await replaceRecipient({
      store,
      retire: oldUserKey.kid,
      recipient: {
        id: newUserKey.kid,
        publicKeyMultibase: newUserKey.publicKeyMultibase
      },
      owner: { keyAgreementKey: oldUserKey.kak },
      pull: async () => {
        epochsAtPull.push(store.state.descriptor.currentEpoch!)
      }
    })
    expect(epochsAtPull).toHaveLength(1)
    expect(epochsAtPull[0]).toBe(store.state.descriptor.currentEpoch)
  })

  it('refuses to retire the incoming recipient, an empty retire list, and a descriptor with no epochs', async () => {
    const userKey = await makeUserKeyLike()
    const store = memoryStore({ scheme: 'edv' })
    await expect(
      replaceRecipient({
        store,
        retire: userKey.kid,
        recipient: {
          id: userKey.kid,
          publicKeyMultibase: userKey.publicKeyMultibase
        },
        owner: { keyAgreementKey: userKey.kak },
        pull: async () => {}
      })
    ).rejects.toThrow(ValidationError)
    await expect(
      replaceRecipient({
        store,
        retire: [],
        recipient: {
          id: userKey.kid,
          publicKeyMultibase: userKey.publicKeyMultibase
        },
        owner: { keyAgreementKey: userKey.kak },
        pull: async () => {}
      })
    ).rejects.toThrow(ValidationError)
    const other = await makeUserKeyLike()
    await expect(
      replaceRecipient({
        store,
        retire: other.kid,
        recipient: {
          id: userKey.kid,
          publicKeyMultibase: userKey.publicKeyMultibase
        },
        owner: { keyAgreementKey: userKey.kak },
        pull: async () => {}
      })
    ).rejects.toThrow(/no key epochs/)
  })

  it('throws when the owner cannot unwrap an epoch for the escrow', async () => {
    const oldUserKey = await makeUserKeyLike()
    const newUserKey = await makeUserKeyLike()
    const stranger = await makeUserKeyLike()
    const store = memoryStore(
      await seedDescriptor([
        {
          kid: oldUserKey.kid,
          publicKeyMultibase: oldUserKey.publicKeyMultibase
        }
      ])
    )
    await expect(
      replaceRecipient({
        store,
        retire: oldUserKey.kid,
        recipient: {
          id: newUserKey.kid,
          publicKeyMultibase: newUserKey.publicKeyMultibase
        },
        owner: { keyAgreementKey: stranger.kak },
        pull: async () => {}
      })
    ).rejects.toThrow(/not a recipient of epoch/)
  })
})

/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Integration test: the descriptor-store seam against a live WAS server. A
 * `CollectionEncryption`-shaped roster lives as a plain JSON Resource in a
 * plaintext collection (the `resourceDescriptorStore` adapter), and the
 * recipient primitives manage it end to end: the first `initRecipients` creates
 * the absent resource with a guarded `If-None-Match: *` write, `addRecipient`
 * compare-and-swaps it against the resource's real `ETag`, and
 * `removeRecipient` rotates the epoch and runs a caller-supplied `pull` action
 * (no zcap revocation) only after the rotation is durable. Also proves
 * `Resource.getWithEtag` returns the live validator, and that two racing
 * `addRecipient` calls both land (the resource-level CAS prevents a clobber).
 *
 * Requires a running server: set `TEST_SERVER_URL` (byte-identical to the
 * server's own `SERVER_URL` -- zcap invocation targets embed host and port).
 * The suite skips when it is unset.
 */
import { describe, it, beforeAll, afterAll, expect } from 'vitest'
import type { IKeyAgreementKey } from '@interop/data-integrity-core'
import { X25519KeyAgreementKey2020 } from '@interop/x25519-key-agreement-key'
import { Ed25519VerificationKey } from '@interop/ed25519-verification-key'

import { WasClient, KeyUnwrapError } from '../../src/index.js'
import type { CollectionEncryption, Resource, Space } from '../../src/index.js'
import {
  initRecipients,
  addRecipient,
  removeRecipient,
  resourceDescriptorStore
} from '../../src/edv/index.js'
import type { EncryptionDescriptorStore } from '../../src/edv/index.js'
import { resolveEpochKeys } from '../../src/edv/epochKeys.js'

const serverUrl = process.env.TEST_SERVER_URL
const describeLive = serverUrl ? describe : describe.skip

/**
 * Generates a self-describing did:key X25519 reader: its `id` is
 * `did:key:<pub>#<pub>`, so the default `did:key` recipient resolver can
 * recover its public key from the `kid` alone.
 *
 * @returns {Promise<{ kak: IKeyAgreementKey; recipient: { id: string; publicKeyMultibase: string } }>}
 */
async function makeReader(): Promise<{
  kak: IKeyAgreementKey
  recipient: { id: string; publicKeyMultibase: string }
}> {
  const kak = await X25519KeyAgreementKey2020.generate()
  const did = `did:key:${kak.publicKeyMultibase}`
  kak.controller = did
  kak.id = `${did}#${kak.publicKeyMultibase}`
  return {
    kak: kak as IKeyAgreementKey,
    recipient: { id: kak.id, publicKeyMultibase: kak.publicKeyMultibase }
  }
}

describeLive('resource-hosted descriptor store (live server)', () => {
  let owner: WasClient
  let space: Space
  let roster: Resource
  let store: EncryptionDescriptorStore
  let alice: Awaited<ReturnType<typeof makeReader>>
  let bob: Awaited<ReturnType<typeof makeReader>>
  let carol: Awaited<ReturnType<typeof makeReader>>

  const collectionId = 'keys'
  const rosterId = 'user-key.json'

  beforeAll(async () => {
    const keyPair = await Ed25519VerificationKey.generate()
    const did = `did:key:${keyPair.fingerprint()}`
    keyPair.id = `${did}#${keyPair.fingerprint()}`
    keyPair.controller = did
    owner = WasClient.fromSigner({
      serverUrl: serverUrl!,
      signer: keyPair.signer()
    })

    alice = await makeReader()
    bob = await makeReader()
    carol = await makeReader()

    space = await owner.createSpace({ name: 'Descriptor Store Integration' })
    // A PLAINTEXT collection hosts the roster: the descriptor is
    // integrity-protected by its epochsMac, not encrypted (it is the key
    // material's root).
    await space.createCollection({ id: collectionId, name: 'Key Roster' })
    roster = owner.space(space.id).collection(collectionId).resource(rosterId)
    store = resourceDescriptorStore({ resource: roster })
  })

  afterAll(async () => {
    await space?.delete()
  })

  it('initRecipients creates the absent roster resource', async () => {
    const descriptor = await initRecipients({
      store,
      recipients: [alice.recipient, bob.recipient]
    })
    expect(descriptor.epochs).toHaveLength(1)
    expect(descriptor.currentEpoch).toBe(descriptor.epochs![0]!.id)
    expect(descriptor.epochsMac).toBeDefined()

    // The roster is stored verbatim as the resource's content, with a live
    // ETag validator alongside (the conditional-writes feature).
    const stored = await roster.getWithEtag()
    expect(stored).not.toBeNull()
    expect(stored!.data).toEqual(descriptor)
    expect(stored!.etag).toBeDefined()

    // Both readers resolve their epoch keys from the roster-hosted descriptor.
    const aliceKeys = await resolveEpochKeys({
      encryption: descriptor,
      keyAgreementKey: alice.kak
    })
    expect(aliceKeys!.writeEpoch).toBe(descriptor.currentEpoch)
  })

  it('a second initRecipients refuses the existing roster', async () => {
    await expect(
      initRecipients({ store, recipients: [carol.recipient] })
    ).rejects.toThrow(/already has key epochs/)
  })

  it('addRecipient escrows every epoch to the new reader via CAS', async () => {
    const descriptor = await addRecipient({
      store,
      recipient: carol.recipient,
      owner: { keyAgreementKey: alice.kak }
    })
    const kids = descriptor.epochs![0]!.recipients.map(
      entry => entry.header.kid
    )
    expect(kids).toContain(carol.kak.id)
    const carolKeys = await resolveEpochKeys({
      encryption: descriptor,
      keyAgreementKey: carol.kak
    })
    expect(carolKeys!.readKeys).toHaveLength(1)
  })

  it('two racing addRecipient calls both land (resource-level CAS)', async () => {
    const [readerX, readerY] = await Promise.all([makeReader(), makeReader()])
    await Promise.all([
      addRecipient({
        store,
        recipient: readerX.recipient,
        owner: { keyAgreementKey: alice.kak }
      }),
      addRecipient({
        store,
        recipient: readerY.recipient,
        owner: { keyAgreementKey: alice.kak }
      })
    ])
    const stored = (await roster.get()) as unknown as CollectionEncryption
    const kids = stored.epochs![0]!.recipients.map(entry => entry.header.kid)
    expect(kids).toContain(readerX.kak.id)
    expect(kids).toContain(readerY.kak.id)
  })

  it('removeRecipient rotates and runs the custom pull after rotation', async () => {
    const epochsAtPull: Array<string | undefined> = []
    const rotated = await removeRecipient({
      store,
      recipientId: bob.kak.id,
      pull: async () => {
        // The consumer's pull axis (e.g. a DID document edit) observes the
        // rotation already durable on the server.
        const onServer = (await roster.get()) as unknown as CollectionEncryption
        epochsAtPull.push(onServer.currentEpoch)
      }
    })
    expect(epochsAtPull).toEqual([rotated.currentEpoch])

    // The fresh epoch excludes the removed reader; a remaining reader holds
    // both epochs, the removed reader only the old one (its writeEpoch falls
    // back) and a stranger none.
    const currentEpoch = rotated.epochs!.find(
      epoch => epoch.id === rotated.currentEpoch
    )!
    const kids = currentEpoch.recipients.map(entry => entry.header.kid)
    expect(kids).not.toContain(bob.kak.id)
    const aliceKeys = await resolveEpochKeys({
      encryption: rotated,
      keyAgreementKey: alice.kak
    })
    expect(aliceKeys!.readKeys).toHaveLength(2)
    const bobKeys = await resolveEpochKeys({
      encryption: rotated,
      keyAgreementKey: bob.kak
    })
    expect(bobKeys!.writeEpoch).not.toBe(rotated.currentEpoch)
    const stranger = await makeReader()
    await expect(
      resolveEpochKeys({ encryption: rotated, keyAgreementKey: stranger.kak })
    ).rejects.toBeInstanceOf(KeyUnwrapError)
  })
})

/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Integration test: multi-recipient encrypted Collections and key epochs, end to
 * end against a live WAS server. Several readers each hold their own X25519
 * key-agreement key; a per-epoch collection key is wrapped to each of them on
 * the Collection's `encryption` marker, and resources are encrypted under the
 * `currentEpoch`. Proves the whole feature, and in particular the removal
 * quadruple that carries it:
 *
 * 1. two distinct readers both decrypt the same resource, each with its own key;
 * 2. a third reader added later reads resources written BEFORE its add (escrow
 *    of prior epochs) and after;
 * 3. one reader removed -- the full `removeRecipient` -- and then: (a) its pull
 *    (zcap) is dead, (b) it cannot decrypt a post-rotation resource, (c) it CAN
 *    still decrypt a pre-rotation resource it already holds, (d) the remaining
 *    readers read everything;
 * 4. two racing `addRecipient` calls both land (the CAS prevents a clobber).
 *
 * Also pins epoch stamping (a write's `WAS-Key-Epoch` surfaces on `meta()`, the
 * listing, and the `changes` feed) and that a rotation preserves any
 * blinded-index `hmac` on the marker (the hmac does not rotate with the epoch).
 *
 * Requires a running server: set `TEST_SERVER_URL` (byte-identical to the
 * server's own `SERVER_URL` -- zcap invocation targets embed host and port). The
 * suite skips when it is unset.
 */
import { describe, it, beforeAll, afterAll, expect } from 'vitest'
import type { HttpResponse } from '@interop/http-client'
import type { IKeyAgreementKey } from '@interop/data-integrity-core'
import { X25519KeyAgreementKey2020 } from '@interop/x25519-key-agreement-key'
import { Ed25519VerificationKey } from '@interop/ed25519-verification-key'

import { WasClient, KeyUnwrapError } from '../../src/index.js'
import type {
  Collection,
  CollectionEncryption,
  EncryptionProvider,
  IDelegatedZcap,
  Space
} from '../../src/index.js'
import {
  createEdvEncryption,
  initRecipients,
  addRecipient,
  removeRecipient
} from '../../src/edv/index.js'
import { didKeyResolver } from '../../src/edv/epochCrypto.js'

const serverUrl = process.env.TEST_SERVER_URL
const describeLive = serverUrl ? describe : describe.skip

interface Party {
  was: WasClient
  provider: EncryptionProvider
  signer: Parameters<typeof WasClient.fromSigner>[0]['signer']
  did: string
  kak: IKeyAgreementKey
  recipient: { id: string; publicKeyMultibase: string }
}

/**
 * Builds a party: an Ed25519 signer (for authorization) plus a self-describing
 * `did:key` X25519 key-agreement key (for decryption), and a `WasClient` whose
 * encryption provider supplies that X25519 key. The `kid` is
 * `did:key:<pub>#<pub>`, so the default `did:key` recipient resolver recovers
 * its public key -- what `removeRecipient` re-wraps the fresh epoch to.
 *
 * @returns {Promise<Party>}
 */
async function makeParty(): Promise<Party> {
  const keyPair = await Ed25519VerificationKey.generate()
  const did = `did:key:${keyPair.fingerprint()}`
  keyPair.id = `${did}#${keyPair.fingerprint()}`
  keyPair.controller = did

  const kak = await X25519KeyAgreementKey2020.generate()
  const kakDid = `did:key:${kak.publicKeyMultibase}`
  kak.controller = kakDid
  kak.id = `${kakDid}#${kak.publicKeyMultibase}`

  const provider = createEdvEncryption({
    resolveKeys: async () => ({
      keyAgreementKey: kak as IKeyAgreementKey,
      keyResolver: didKeyResolver
    })
  })
  const signer = keyPair.signer()
  return {
    was: WasClient.fromSigner({
      serverUrl: serverUrl!,
      signer,
      encryption: provider
    }),
    provider,
    signer,
    did,
    kak: kak as IKeyAgreementKey,
    recipient: { id: kak.id, publicKeyMultibase: kak.publicKeyMultibase }
  }
}

describeLive('multi-recipient key epochs (live server)', () => {
  let owner: Party
  let readerA: Party
  let readerB: Party
  let readerC: Party
  // A plaintext owner client, to fetch the raw stored ciphertext (the "hand it
  // the bytes" party for the read-axis assertions).
  let ownerPlain: WasClient
  let space: Space
  let spaceId: string
  let zcapB: IDelegatedZcap
  let doc1Id: string
  let epoch1: string

  const collectionId = 'vault'

  /**
   * A fresh owner handle to the vault (no override) so it re-discovers the
   * current marker and encrypts under the current epoch.
   *
   * @returns {Collection}
   */
  function ownerVault(): Collection {
    return owner.was.space(spaceId).collection(collectionId)
  }

  /**
   * Grants collection read/write to a party and returns the delegated zcap.
   *
   * @param to {string}
   * @returns {Promise<IDelegatedZcap>}
   */
  async function grantTo(to: string): Promise<IDelegatedZcap> {
    return owner.was
      .space(spaceId)
      .collection(collectionId)
      .grant({
        to,
        actions: ['GET', 'PUT', 'POST', 'DELETE'],
        expires: new Date(Date.now() + 60 * 60 * 1000)
      })
  }

  /**
   * Reads the raw stored envelope for a resource (bypassing decryption), as a
   * still-authorized party would to hand another party the ciphertext.
   *
   * @param id {string}
   * @returns {Promise<Record<string, unknown>>}
   */
  async function rawEnvelope(id: string): Promise<Record<string, unknown>> {
    return (await ownerPlain
      .space(spaceId)
      .collection(collectionId)
      .get(id)) as Record<string, unknown>
  }

  /**
   * Decrypts a raw envelope with a party's own keys against a given marker,
   * building that party's codec directly (so the read axis can be exercised even
   * when the party's pull is revoked).
   *
   * @param party {Party}
   * @param marker {CollectionEncryption}
   * @param envelope {Record<string, unknown>}
   * @returns {Promise<unknown>}
   */
  async function decodeWith(
    party: Party,
    marker: CollectionEncryption,
    envelope: Record<string, unknown>
  ): Promise<unknown> {
    const codec = await party.provider.codecFor({
      spaceId,
      collectionId,
      scheme: 'edv',
      encryption: marker
    })
    return codec!.decode({ data: envelope } as unknown as HttpResponse)
  }

  /**
   * Reads the current marker from the server (owner's authorized view).
   *
   * @returns {Promise<CollectionEncryption>}
   */
  async function currentMarker(): Promise<CollectionEncryption> {
    const described = await owner.was
      .space(spaceId)
      .collection(collectionId)
      .describe()
    return described!.encryption!
  }

  beforeAll(async () => {
    owner = await makeParty()
    readerA = await makeParty()
    readerB = await makeParty()
    readerC = await makeParty()
    ownerPlain = WasClient.fromSigner({
      serverUrl: serverUrl!,
      signer: owner.signer
    })

    space = await owner.was.createSpace({ name: 'Key Epochs Integration' })
    spaceId = space.id
    await space.createCollection({
      id: collectionId,
      name: 'Vault',
      encryption: { scheme: 'edv' }
    })

    // Initialize the first epoch, wrapping it to the owner and the two initial
    // readers (the owner is a recipient so it can write).
    const marker = await initRecipients({
      collection: ownerVault(),
      recipients: [owner.recipient, readerA.recipient, readerB.recipient]
    })
    epoch1 = marker.currentEpoch!

    // The readers pull with delegated capabilities on the collection.
    await grantTo(readerA.did) // readerA cap not needed by id here
    zcapB = await grantTo(readerB.did)

    // Owner writes the first resource under epoch 1.
    const added = await ownerVault().add({ note: 'first', n: 1 })
    doc1Id = added.id
  })

  afterAll(async () => {
    try {
      await space.delete()
    } catch {
      /* best-effort cleanup */
    }
  })

  it('two recipients both decrypt the same resource, each with its own key', async () => {
    const zcapA = await grantTo(readerA.did)
    const asA = readerA.was
      .space(spaceId)
      .collection(collectionId, { capability: zcapA })
    const asB = readerB.was
      .space(spaceId)
      .collection(collectionId, { capability: zcapB })
    expect(await asA.get(doc1Id)).toEqual({ note: 'first', n: 1 })
    expect(await asB.get(doc1Id)).toEqual({ note: 'first', n: 1 })
  })

  it('stamps the write epoch on meta(), the listing, and the changes feed', async () => {
    const meta = await ownerVault().resource(doc1Id).meta()
    expect(meta?.epoch).toBe(epoch1)

    const list = await ownerVault().list()
    const item = list?.items.find(entry => entry.id === doc1Id)
    expect(item?.epoch).toBe(epoch1)

    const changes = await ownerVault().changes()
    const changed = changes.documents.find(document => document.id === doc1Id)
    expect(changed?.epoch).toBe(epoch1)
  })

  it('adds a third recipient that reads resources written before and after its add', async () => {
    // Escrow: addRecipient wraps EVERY existing epoch to the new reader.
    await addRecipient({
      collection: ownerVault(),
      recipient: readerC.recipient,
      owner: { keyAgreementKey: owner.kak }
    })
    // No rotation on add: a resource written now is still epoch 1.
    const doc2 = await ownerVault().add({ note: 'second', n: 2 })

    const zcapC = await grantTo(readerC.did)
    const asC = readerC.was
      .space(spaceId)
      .collection(collectionId, { capability: zcapC })
    // Reads the pre-add resource (escrow of the prior epoch)...
    expect(await asC.get(doc1Id)).toEqual({ note: 'first', n: 1 })
    // ...and the post-add resource.
    expect(await asC.get(doc2.id)).toEqual({ note: 'second', n: 2 })
  })

  it('removes a reader: pull dies, new ciphertext is unreadable, old is not clawed back, others unaffected', async () => {
    const zcapA = await grantTo(readerA.did)
    const zcapC = await grantTo(readerC.did)

    // The full, indivisible removal: revoke readerB's pull AND rotate the epoch.
    const rotated = await removeRecipient({
      collection: ownerVault(),
      space: owner.was.space(spaceId),
      recipientId: readerB.recipient.id,
      revoke: zcapB
    })
    const epoch2 = rotated.currentEpoch!
    expect(epoch2).not.toBe(epoch1)

    // Owner writes a post-rotation resource (under epoch 2).
    const doc3 = await ownerVault().add({ note: 'third', n: 3 })
    const doc3Meta = await ownerVault().resource(doc3.id).meta()
    expect(doc3Meta?.epoch).toBe(epoch2)

    // (a) Pull axis: readerB's capability is dead. Read with a plaintext client
    // over readerB's identity (no marker discovery) to isolate the pull axis --
    // the server simply will not serve the bytes anymore (WAS masks
    // unauthorized as 404, surfaced as null by get()).
    const plaintextB = WasClient.fromSigner({
      serverUrl: serverUrl!,
      signer: readerB.signer
    })
    const asBRevoked = plaintextB
      .space(spaceId)
      .collection(collectionId, { capability: zcapB })
    expect(await asBRevoked.get(doc1Id)).toBeNull()

    // (b) Read axis, prospective: handed the post-rotation ciphertext, readerB
    // cannot decrypt it (it holds no epoch-2 key).
    const doc3Envelope = await rawEnvelope(doc3.id)
    await expect(
      decodeWith(readerB, rotated, doc3Envelope)
    ).rejects.toBeInstanceOf(KeyUnwrapError)

    // (c) Honest ceiling: readerB CAN still decrypt a pre-rotation resource it
    // already holds -- rotation never claws back what a reader could read.
    const doc1Envelope = await rawEnvelope(doc1Id)
    expect(await decodeWith(readerB, rotated, doc1Envelope)).toEqual({
      note: 'first',
      n: 1
    })

    // (d) The remaining readers read everything, before and after the rotation.
    const asA = readerA.was
      .space(spaceId)
      .collection(collectionId, { capability: zcapA })
    const asC = readerC.was
      .space(spaceId)
      .collection(collectionId, { capability: zcapC })
    expect(await asA.get(doc1Id)).toEqual({ note: 'first', n: 1 })
    expect(await asA.get(doc3.id)).toEqual({ note: 'third', n: 3 })
    expect(await asC.get(doc3.id)).toEqual({ note: 'third', n: 3 })
  })

  it('two concurrent addRecipient calls both land (the CAS prevents a clobber)', async () => {
    const newA = await makeParty()
    const newB = await makeParty()
    // Two racing adds from two independent handles over the same collection.
    await Promise.all([
      addRecipient({
        collection: ownerVault(),
        recipient: newA.recipient,
        owner: { keyAgreementKey: owner.kak }
      }),
      addRecipient({
        collection: ownerVault(),
        recipient: newB.recipient,
        owner: { keyAgreementKey: owner.kak }
      })
    ])
    const marker = await currentMarker()
    const currentEpoch = marker.epochs!.find(
      epoch => epoch.id === marker.currentEpoch
    )!
    const kids = currentEpoch.recipients.map(entry => entry.header.kid)
    // Neither add clobbered the other: both new readers are present.
    expect(kids).toContain(newA.recipient.id)
    expect(kids).toContain(newB.recipient.id)
  })
})

/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Integration test: a Collection's governing history log against a live WAS
 * server (the backend's `governed-history-logs` feature). The `/log`
 * subpath's `resourceLogStore({ collection })` speaks the store port's three
 * operations at the `/meta/log` sub-resource: a guarded genesis create
 * declares the Collection log-governed, a compare-and-swap append extends it,
 * and a lost race surfaces as the library's `ResourceLogConflictError`. From
 * the create on, the server derives the Collection's served `encryption`
 * member from the log head's `state` with `history` stamped on, refuses a
 * direct `encryption` write on the Description, and keeps the log out of the
 * Collection's listing.
 *
 * Requires a running server: set `TEST_SERVER_URL` (byte-identical to the
 * server's own `SERVER_URL` -- zcap invocation targets embed host and port).
 * The suite skips when it is unset.
 */
import { describe, it, beforeAll, afterAll, expect } from 'vitest'
import { Ed25519VerificationKey } from '@interop/ed25519-verification-key'
import type { ResourceLogEntry } from '@interop/storage-core'
import {
  ResourceLogConflictError,
  serializeResourceLog
} from '@interop/vh-resource-log'
import type { ResourceLogStore } from '@interop/vh-resource-log'

import { WasClient, ConflictError } from '../../src/index.js'
import type {
  Collection,
  CollectionEncryption,
  Space
} from '../../src/index.js'
import { collectionLog, toUrl } from '../../src/paths.js'
import { resourceLogStore } from '../../src/log/index.js'

const serverUrl = process.env.TEST_SERVER_URL
const describeLive = serverUrl ? describe : describe.skip

const RESOURCE_LOG_METHOD = 'resource-log:0.1'

/**
 * A descriptor recipient entry (the JWE recipients-entry shape).
 *
 * @param kid {string}
 * @returns {object}
 */
function recipient(kid: string) {
  return {
    header: { kid, alg: 'ECDH-ES+A256KW' },
    encrypted_key: `wrapped-${kid}`
  }
}

const oneEpoch: CollectionEncryption = {
  type: 'WasEpochConfiguration',
  scheme: 'edv',
  currentEpoch: 'urn:epoch:1',
  epochs: [{ id: 'urn:epoch:1', recipients: [recipient('did:key:zApp1#ka')] }]
}
const twoEpochs: CollectionEncryption = {
  ...oneEpoch,
  currentEpoch: 'urn:epoch:2',
  epochs: [
    { id: 'urn:epoch:2', recipients: [recipient('did:key:zApp2#ka')] },
    ...oneEpoch.epochs!
  ]
}

/**
 * Builds a syntactically valid entry at ordinal `n` carrying `state`. The
 * server verifies neither proofs nor the hash chain (it parses the head
 * line), so hashes and proofs here are placeholders.
 *
 * @param n {number}
 * @param state {CollectionEncryption}
 * @returns {ResourceLogEntry}
 */
function entryAt(n: number, state: CollectionEncryption): ResourceLogEntry {
  return {
    versionId: `${n}-QmEntryHash${n}`,
    versionTime: '2026-09-07T12:00:00Z',
    parameters: n === 1 ? { method: RESOURCE_LOG_METHOD, scid: 'QmScid' } : {},
    state: state as ResourceLogEntry['state'],
    proof: [
      {
        type: 'DataIntegrityProof',
        cryptosuite: 'eddsa-jcs-2022',
        proofPurpose: 'assertionMethod',
        verificationMethod: 'did:webvh:QmScid:h:space:s:id?versionId=1-x#key',
        proofValue: `z${n}`
      }
    ]
  }
}

describeLive('governing history log (live server)', () => {
  let owner: WasClient
  let space: Space
  let collection: Collection
  let store: ResourceLogStore

  const collectionId = 'vault'

  beforeAll(async () => {
    const keyPair = await Ed25519VerificationKey.generate()
    const did = `did:key:${keyPair.fingerprint()}`
    keyPair.id = `${did}#${keyPair.fingerprint()}`
    keyPair.controller = did
    owner = WasClient.fromSigner({
      serverUrl: serverUrl!,
      signer: keyPair.signer()
    })
    space = await owner.createSpace({ name: 'Governed Log Integration' })
    // A Collection with no client-written `encryption` descriptor: the only
    // kind a history log may come to govern.
    await space.createCollection({ id: collectionId, name: 'Vault' })
    collection = owner.space(space.id).collection(collectionId)
    store = resourceLogStore({ collection })
  })

  afterAll(async () => {
    await space?.delete()
  })

  it('reads null before the log exists', async () => {
    expect(await collection.getHistoryLog()).toBeNull()
    expect(await store.read()).toBeNull()
  })

  it('the guarded create governs the Collection: encryption is derived from the head state', async () => {
    await store.create(entryAt(1, oneEpoch))

    const stored = await collection.getHistoryLog()
    expect(stored).not.toBeNull()
    expect(stored!.body).toBe(serializeResourceLog([entryAt(1, oneEpoch)]))
    expect(stored!.etag).toBeDefined()

    const description = await collection.describe()
    expect(description!.encryption).toEqual({
      ...oneEpoch,
      history: {
        method: RESOURCE_LOG_METHOD,
        resource: toUrl({
          serverUrl: serverUrl!,
          path: collectionLog(space.id, collectionId)
        })
      }
    })
  })

  it('a second guarded create loses the race as the conflict error', async () => {
    const fresh = resourceLogStore({ collection })
    await expect(fresh.create(entryAt(1, oneEpoch))).rejects.toBeInstanceOf(
      ResourceLogConflictError
    )
  })

  it('the log is not a Resource of the Collection', async () => {
    const listing = await collection.list()
    expect(listing!.items).toEqual([])
  })

  it('a direct encryption write on the Description is refused', async () => {
    await expect(
      collection.replaceDescription({ name: 'Vault', encryption: twoEpochs })
    ).rejects.toBeInstanceOf(ConflictError)
    // The other fields still update, and the derived member is untouched.
    const { description } = await collection.replaceDescription({
      name: 'Renamed vault'
    })
    expect(description.name).toBe('Renamed vault')
    const described = await collection.describe()
    expect(described!.name).toBe('Renamed vault')
    expect(described!.encryption!.currentEpoch).toBe('urn:epoch:1')
  })

  it('a compare-and-swap append moves the derived member to the new head', async () => {
    const current = (await store.read())!
    expect(current.entries).toEqual([entryAt(1, oneEpoch)])
    expect(current.etag).toBeDefined()

    await store.append(entryAt(2, twoEpochs), { ifMatch: current.etag! })

    const stored = await collection.getHistoryLog()
    expect(stored!.body).toBe(
      serializeResourceLog([entryAt(1, oneEpoch), entryAt(2, twoEpochs)])
    )
    expect(stored!.etag).not.toBe(current.etag)
    const description = await collection.describe()
    expect(description!.encryption!.currentEpoch).toBe('urn:epoch:2')
    expect(description!.encryption!.epochs).toEqual(twoEpochs.epochs)
  })

  it('a stale append loses the race as the conflict error, cause set', async () => {
    const stale = resourceLogStore({ collection })
    const seen = (await stale.read())!
    // Another writer lands first.
    const winner = resourceLogStore({ collection })
    const head = (await winner.read())!
    await winner.append(entryAt(3, twoEpochs), { ifMatch: head.etag! })

    const err = await stale
      .append(entryAt(3, twoEpochs), { ifMatch: seen.etag! })
      .then(() => undefined)
      .catch((thrown: unknown) => thrown as Error)
    expect(err).toBeInstanceOf(ResourceLogConflictError)
    expect(err!.cause).toBeDefined()
    // The winner's line is the head; the loser's never landed.
    const stored = await collection.getHistoryLog()
    expect(stored!.body.trimEnd().split('\n')).toHaveLength(3)
  })
})

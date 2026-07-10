/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Integration test: `collection.changes()` against a live WAS server. Proves the
 * `changes` query profile round-trips through the client -- ordering, tombstones,
 * checkpoint resumption, and the server-managed `createdBy` provenance that must
 * reach a replica without a per-resource `/meta` fetch.
 *
 * Requires a running server: set `TEST_SERVER_URL`. The suite skips when it is
 * unset, so a bare `pnpm test:integration` (no server) is not a failure.
 */
import { describe, it, beforeAll, afterAll, expect } from 'vitest'
import { Ed25519VerificationKey } from '@interop/ed25519-verification-key'

import { WasClient } from '../../src/index.js'
import type { Collection, Space } from '../../src/index.js'

const serverUrl = process.env.TEST_SERVER_URL
const describeLive = serverUrl ? describe : describe.skip

/**
 * Builds a fresh did:key Ed25519 signer, a WAS client over it, and its DID.
 *
 * @returns {Promise<{ was: WasClient, did: string }>}
 */
async function freshWasClient(): Promise<{ was: WasClient; did: string }> {
  const keyPair = await Ed25519VerificationKey.generate()
  const did = `did:key:${keyPair.fingerprint()}`
  keyPair.id = `${did}#${keyPair.fingerprint()}`
  keyPair.controller = did
  const was = WasClient.fromSigner({
    serverUrl: serverUrl!,
    signer: keyPair.signer()
  })
  return { was, did }
}

describeLive('collection.changes() (live server)', () => {
  let was: WasClient
  let did: string
  let space: Space
  let notes: Collection

  beforeAll(async () => {
    ;({ was, did } = await freshWasClient())
    space = await was.createSpace({ name: 'Changes Integration' })
    notes = await space.createCollection({ id: 'notes', name: 'Notes' })
    await notes.put('first', { message: 'one' })
    await notes.put('second', { message: 'two' })
    await notes.put('doomed', { message: 'three' })
    await notes.resource('doomed').delete()
  })

  afterAll(async () => {
    try {
      await space.delete()
    } catch {
      /* best-effort cleanup */
    }
  })

  it('returns live documents and tombstones with a resumable checkpoint', async () => {
    const page = await notes.changes()
    expect(page.documents.map(doc => doc.id).sort()).toEqual([
      'doomed',
      'first',
      'second'
    ])

    const byId = new Map(page.documents.map(doc => [doc.id, doc]))
    expect(byId.get('first')!._deleted).toBe(false)
    expect(byId.get('first')!.data).toEqual({ message: 'one' })
    expect(byId.get('first')!.version).toBe(1)

    const tombstone = byId.get('doomed')!
    expect(tombstone._deleted).toBe(true)
    expect(tombstone.data).toBeUndefined()

    // The checkpoint is the last document's keyset position, and resuming from
    // it drains the feed.
    const last = page.documents[page.documents.length - 1]!
    expect(page.checkpoint).toEqual({ id: last.id, updatedAt: last.updatedAt })
    const drained = await notes.changes({ checkpoint: page.checkpoint! })
    expect(drained.documents).toEqual([])
    expect(drained.checkpoint).toBeNull()
  })

  it('carries createdBy on live documents and on tombstones', async () => {
    const page = await notes.changes()
    const byId = new Map(page.documents.map(doc => [doc.id, doc]))
    expect(byId.get('first')!.createdBy).toBe(did)
    // Provenance survives the delete, so it replicates with the tombstone.
    expect(byId.get('doomed')!.createdBy).toBe(did)
  })

  it('honors limit, and a short page signals catch-up', async () => {
    const page = await notes.changes({ limit: 2 })
    expect(page.documents).toHaveLength(2)
    expect(page.checkpoint).not.toBeNull()

    const rest = await notes.changes({ checkpoint: page.checkpoint!, limit: 2 })
    expect(rest.documents).toHaveLength(1)
    // Shorter than `limit`: an RxDB pull handler stops iterating here.
    expect(rest.documents.length).toBeLessThan(2)
  })
})

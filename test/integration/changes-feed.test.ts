/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Integration test: `collection.changes()` against a live WAS server. Proves the
 * `changes` query profile round-trips through the client -- ordering, tombstones,
 * checkpoint resumption, the record kinds beside Resources, and the
 * server-managed `createdBy` provenance that must reach a replica without a
 * per-resource `/meta` fetch.
 *
 * Requires a running server: set `TEST_SERVER_URL`. The suite skips when it is
 * unset, so a bare `pnpm test:integration` (no server) is not a failure.
 */
import { describe, it, beforeAll, afterAll, expect } from 'vitest'
import { Ed25519VerificationKey } from '@interop/ed25519-verification-key'
import { isResourceChange } from '@interop/storage-core'

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
  const was = WasClient.fromSigner({
    serverUrl: serverUrl!,
    signer: keyPair.didKeySigner()
  })
  return { was, did: was.controllerDid }
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
    const resources = page.documents.filter(isResourceChange)
    expect(resources.map(doc => doc.id).sort()).toEqual([
      'doomed',
      'first',
      'second'
    ])

    // The Collection's own Metadata object passes through, named by URL.
    const metadata = page.documents.find(
      doc => doc.kind === 'collection-metadata'
    )
    expect(metadata?.id).toMatch(/\/space\/[^/]+\/notes\/meta$/)
    expect(metadata?.deleted).toBe(false)

    const byId = new Map(resources.map(doc => [doc.id, doc]))
    expect(byId.get('first')!.deleted).toBe(false)
    expect(byId.get('first')!.contentType).toMatch(/^application\/json/)
    expect(byId.get('first')!.data).toEqual({ message: 'one' })

    const tombstone = byId.get('doomed')!
    expect(tombstone.deleted).toBe(true)
    expect(tombstone.data).toBeUndefined()

    // Every revision carries the write stamp, a deletion included: a
    // non-negative integer counter and the minting store's id.
    for (const doc of [byId.get('first')!, tombstone]) {
      expect(Number.isInteger(doc.updatedAtCounter)).toBe(true)
      expect(doc.updatedAtCounter).toBeGreaterThanOrEqual(0)
      expect(doc.originId).toMatch(/^[A-Za-z0-9_-]{1,64}$/)
    }

    // The checkpoint is an opaque string equal to the last document's own
    // checkpoint, and resuming from it drains the feed.
    for (const doc of page.documents) {
      expect(typeof doc.checkpoint).toBe('string')
    }
    const last = page.documents[page.documents.length - 1]!
    expect(typeof page.checkpoint).toBe('string')
    expect(page.checkpoint).toBe(last.checkpoint)
    const drained = await notes.changes({ checkpoint: page.checkpoint! })
    expect(drained.documents).toEqual([])
    expect(drained.checkpoint).toBeNull()
  })

  it('carries createdBy on live documents and on tombstones', async () => {
    const page = await notes.changes()
    const byId = new Map(
      page.documents.filter(isResourceChange).map(doc => [doc.id, doc])
    )
    expect(byId.get('first')!.createdBy).toBe(did)
    // Provenance survives the delete, so it replicates with the tombstone.
    expect(byId.get('doomed')!.createdBy).toBe(did)
  })

  it('honors limit, and a short page signals catch-up', async () => {
    // Every record kind counts toward `limit`, so size the pages off the
    // whole feed rather than off the Resources alone.
    const total = (await notes.changes()).documents.length
    const limit = total - 1
    const page = await notes.changes({ limit })
    expect(page.documents).toHaveLength(limit)
    expect(page.checkpoint).not.toBeNull()

    const rest = await notes.changes({ checkpoint: page.checkpoint!, limit })
    expect(rest.documents).toHaveLength(1)
    // Shorter than `limit`: an RxDB pull handler stops iterating here.
    expect(rest.documents.length).toBeLessThan(limit)
  })
})

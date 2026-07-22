/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Unit tests for `ensureSpaceAndCollection`. The module imports the client only
 * as a type, so at runtime it is pure -- all effects flow through an injected
 * `was`. These assert the configure call shapes (the `edv` encryption marker in
 * particular), the world-read grant for a public collection, idempotency (a
 * re-run issues the same upserts), and the labelled-error + `cause` wrapping on
 * failure, without a live server.
 */
import { describe, it, expect } from 'vitest'
import type { WasClient } from '../../src/index.js'
import { ensureSpaceAndCollection } from '../../src/sync/index.js'

interface ConfigureOpts {
  name: string
  controller?: string
  encryption?: { scheme: string }
  force?: boolean
}

class FakeCollection {
  readonly configureCalls: ConfigureOpts[] = []
  setPublicCalls = 0
  constructor(private readonly fail?: Error) {}
  configure = async (opts: ConfigureOpts): Promise<void> => {
    this.configureCalls.push(opts)
    if (this.fail) {
      throw this.fail
    }
  }
  setPublic = async (): Promise<void> => {
    this.setPublicCalls += 1
  }
}

class FakeSpace {
  readonly configureCalls: ConfigureOpts[] = []
  readonly collectionIds: string[] = []
  readonly collectionObj: FakeCollection
  private readonly failSpace?: Error

  constructor(opts: { failSpace?: Error; failCollection?: Error } = {}) {
    this.failSpace = opts.failSpace
    this.collectionObj = new FakeCollection(opts.failCollection)
  }

  configure = async (opts: ConfigureOpts): Promise<void> => {
    this.configureCalls.push(opts)
    if (this.failSpace) {
      throw this.failSpace
    }
  }

  collection = (id: string): FakeCollection => {
    this.collectionIds.push(id)
    return this.collectionObj
  }
}

class FakeWas {
  spaceArg?: string
  constructor(private readonly spaceObj: FakeSpace) {}
  space = (id: string): FakeSpace => {
    this.spaceArg = id
    return this.spaceObj
  }
  asClient(): WasClient {
    return this as unknown as WasClient
  }
}

const DID = 'did:key:zController'
const SPACE = 'space-abc'
const COLL = 'private-credentials'

describe('ensureSpaceAndCollection', () => {
  it('configures the space then the collection with the edv encryption marker', async () => {
    const space = new FakeSpace()
    const was = new FakeWas(space)
    await ensureSpaceAndCollection({
      was: was.asClient(),
      spaceId: SPACE,
      controllerDid: DID,
      collectionId: COLL
    })

    expect(was.spaceArg).toBe(SPACE)
    expect(space.configureCalls).toEqual([
      { name: 'WAS Space', controller: DID }
    ])
    expect(space.collectionIds).toEqual([COLL])
    expect(space.collectionObj.configureCalls).toEqual([
      { name: COLL, encryption: { scheme: 'edv' } }
    ])
    expect(space.collectionObj.setPublicCalls).toBe(0)
  })

  it('configures a plaintext public collection without the marker and grants world read', async () => {
    const space = new FakeSpace()
    const was = new FakeWas(space)
    await ensureSpaceAndCollection({
      was: was.asClient(),
      spaceId: SPACE,
      controllerDid: DID,
      collectionId: 'public-credentials',
      encryption: 'plaintext',
      isPublic: true
    })

    expect(space.collectionObj.configureCalls).toEqual([
      { name: 'public-credentials', force: true }
    ])
    expect(space.collectionObj.setPublicCalls).toBe(1)
  })

  it('is idempotent: a re-run issues the same upserts', async () => {
    const space = new FakeSpace()
    const was = new FakeWas(space)
    const run = () =>
      ensureSpaceAndCollection({
        was: was.asClient(),
        spaceId: SPACE,
        controllerDid: DID,
        collectionId: COLL
      })
    await run()
    await run()
    expect(space.configureCalls).toEqual([
      { name: 'WAS Space', controller: DID },
      { name: 'WAS Space', controller: DID }
    ])
    expect(space.collectionObj.configureCalls).toEqual([
      { name: COLL, encryption: { scheme: 'edv' } },
      { name: COLL, encryption: { scheme: 'edv' } }
    ])
  })

  it('honours a custom space name', async () => {
    const space = new FakeSpace()
    const was = new FakeWas(space)
    await ensureSpaceAndCollection({
      was: was.asClient(),
      spaceId: SPACE,
      controllerDid: DID,
      collectionId: COLL,
      spaceName: 'My Space'
    })
    expect(space.configureCalls[0]!.name).toBe('My Space')
  })

  it('honours a custom collection display name', async () => {
    const space = new FakeSpace()
    const was = new FakeWas(space)
    await ensureSpaceAndCollection({
      was: was.asClient(),
      spaceId: SPACE,
      controllerDid: DID,
      collectionId: COLL,
      collectionName: 'Verifiable Credentials'
    })
    expect(space.collectionObj.configureCalls[0]!.name).toBe(
      'Verifiable Credentials'
    )
  })

  it('wraps a space.configure failure with a labelled error + cause', async () => {
    const cause = new Error('space boom')
    const was = new FakeWas(new FakeSpace({ failSpace: cause }))
    await expect(
      ensureSpaceAndCollection({
        was: was.asClient(),
        spaceId: SPACE,
        controllerDid: DID,
        collectionId: COLL
      })
    ).rejects.toMatchObject({
      message: expect.stringContaining(
        'Failed to configure WAS space "space-abc"'
      ),
      cause
    })
  })

  it('does not attempt the collection when the space configure fails', async () => {
    const space = new FakeSpace({ failSpace: new Error('nope') })
    const was = new FakeWas(space)
    await expect(
      ensureSpaceAndCollection({
        was: was.asClient(),
        spaceId: SPACE,
        controllerDid: DID,
        collectionId: COLL
      })
    ).rejects.toThrow()
    expect(space.collectionIds).toEqual([])
  })

  it('wraps a collection.configure failure with a labelled error + cause', async () => {
    const cause = new Error('collection boom')
    const space = new FakeSpace({ failCollection: cause })
    const was = new FakeWas(space)
    await expect(
      ensureSpaceAndCollection({
        was: was.asClient(),
        spaceId: SPACE,
        controllerDid: DID,
        collectionId: COLL
      })
    ).rejects.toMatchObject({
      message: expect.stringContaining(
        'Failed to configure collection "private-credentials" in space "space-abc"'
      ),
      cause
    })
  })
})

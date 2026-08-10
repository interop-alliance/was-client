/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Unit tests for `ensureSpaceAndCollection`. The module imports the client only
 * as a type, so at runtime it is pure -- all effects flow through an injected
 * `was`. These assert the create-if-absent configure shapes (the `edv`
 * encryption descriptor in particular), the non-clobbering reads-only behavior
 * over an already-provisioned Space (existing Space description, encryption
 * descriptor, and public policy all left untouched), the late in-place
 * encryption declaration, the world-read heal for a public collection, and the
 * labelled-error + `cause` wrapping on failure, without a live server.
 */
import { describe, it, expect } from 'vitest'
import type { WasClient } from '../../src/index.js'
import { ensureSpaceAndCollection } from '../../src/sync/index.js'
import { EDV_SCHEME_VERSION } from '../../src/edv/constants.js'

interface ConfigureOpts {
  name: string
  controller?: string
  encryption?: { scheme: string; version: number }
  force?: boolean
}

interface CollectionDesc {
  name?: string
  encryption?: { scheme: string; version: number }
}

class FakeCollection {
  readonly configureCalls: ConfigureOpts[] = []
  describeCalls = 0
  isPublicCalls = 0
  setPublicCalls = 0
  constructor(
    private readonly opts: {
      current?: CollectionDesc
      alreadyPublic?: boolean
      failConfigure?: Error
      failDescribe?: Error
    } = {}
  ) {}
  describe = async (): Promise<CollectionDesc | null> => {
    this.describeCalls += 1
    if (this.opts.failDescribe) {
      throw this.opts.failDescribe
    }
    return this.opts.current ?? null
  }
  configure = async (opts: ConfigureOpts): Promise<void> => {
    this.configureCalls.push(opts)
    if (this.opts.failConfigure) {
      throw this.opts.failConfigure
    }
  }
  isPublic = async (): Promise<boolean> => {
    this.isPublicCalls += 1
    return this.opts.alreadyPublic ?? false
  }
  setPublic = async (): Promise<void> => {
    this.setPublicCalls += 1
  }
}

class FakeSpace {
  readonly configureCalls: ConfigureOpts[] = []
  readonly collectionIds: string[] = []
  readonly collectionObj: FakeCollection
  describeCalls = 0
  private readonly current: { name?: string; controller?: string } | null
  private readonly failSpace?: Error

  constructor(
    opts: {
      current?: { name?: string; controller?: string } | null
      failSpace?: Error
      collection?: FakeCollection
    } = {}
  ) {
    this.current = opts.current ?? null
    this.failSpace = opts.failSpace
    this.collectionObj = opts.collection ?? new FakeCollection()
  }

  describe = async (): Promise<{ name?: string } | null> => {
    this.describeCalls += 1
    return this.current
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
const EDV = { scheme: 'edv', version: EDV_SCHEME_VERSION }

describe('ensureSpaceAndCollection', () => {
  it('creates the absent space then the collection with the edv encryption descriptor', async () => {
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
      { name: COLL, encryption: EDV }
    ])
    expect(space.collectionObj.setPublicCalls).toBe(0)
  })

  it('creates a plaintext public collection without the descriptor and grants world read', async () => {
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

  it('issues only reads over a fully settled space and collection', async () => {
    const space = new FakeSpace({
      current: { name: 'Wallet Space', controller: 'did:webvh:other' },
      collection: new FakeCollection({
        current: { name: 'Verifiable Credentials', encryption: EDV }
      })
    })
    const was = new FakeWas(space)
    await ensureSpaceAndCollection({
      was: was.asClient(),
      spaceId: SPACE,
      controllerDid: DID,
      collectionId: COLL
    })

    // Neither the existing Space description (its controller in particular)
    // nor the existing encryption descriptor is re-sent.
    expect(space.describeCalls).toBe(1)
    expect(space.configureCalls).toEqual([])
    expect(space.collectionObj.describeCalls).toBe(1)
    expect(space.collectionObj.configureCalls).toEqual([])
  })

  it('declares encryption in place on an existing descriptor-less collection, keeping its name', async () => {
    const space = new FakeSpace({
      current: { name: 'Wallet Space' },
      collection: new FakeCollection({ current: { name: 'Kept Name' } })
    })
    const was = new FakeWas(space)
    await ensureSpaceAndCollection({
      was: was.asClient(),
      spaceId: SPACE,
      controllerDid: DID,
      collectionId: COLL,
      collectionName: 'Ignored On Existing'
    })

    expect(space.collectionObj.configureCalls).toEqual([
      { name: 'Kept Name', encryption: EDV }
    ])
  })

  it('leaves an existing encryption descriptor untouched on re-run', async () => {
    const space = new FakeSpace({
      current: { name: 'Wallet Space' },
      // A descriptor another client appended key epochs to: re-sending the
      // bare descriptor would drop them.
      collection: new FakeCollection({
        current: { name: COLL, encryption: EDV }
      })
    })
    const was = new FakeWas(space)
    await ensureSpaceAndCollection({
      was: was.asClient(),
      spaceId: SPACE,
      controllerDid: DID,
      collectionId: COLL
    })

    expect(space.collectionObj.configureCalls).toEqual([])
  })

  it('heals a missing world-read grant on an existing public collection', async () => {
    const space = new FakeSpace({
      current: { name: 'Wallet Space' },
      collection: new FakeCollection({
        current: { name: 'public-credentials' },
        alreadyPublic: false
      })
    })
    const was = new FakeWas(space)
    await ensureSpaceAndCollection({
      was: was.asClient(),
      spaceId: SPACE,
      controllerDid: DID,
      collectionId: 'public-credentials',
      encryption: 'plaintext',
      isPublic: true
    })

    expect(space.collectionObj.configureCalls).toEqual([])
    expect(space.collectionObj.setPublicCalls).toBe(1)
  })

  it('does not re-grant world read when the policy already says public', async () => {
    const space = new FakeSpace({
      current: { name: 'Wallet Space' },
      collection: new FakeCollection({
        current: { name: 'public-credentials' },
        alreadyPublic: true
      })
    })
    const was = new FakeWas(space)
    await ensureSpaceAndCollection({
      was: was.asClient(),
      spaceId: SPACE,
      controllerDid: DID,
      collectionId: 'public-credentials',
      encryption: 'plaintext',
      isPublic: true
    })

    expect(space.collectionObj.isPublicCalls).toBe(1)
    expect(space.collectionObj.setPublicCalls).toBe(0)
  })

  it('is idempotent: a re-run over what the first run created issues no writes', async () => {
    const freshSpace = new FakeSpace()
    await ensureSpaceAndCollection({
      was: new FakeWas(freshSpace).asClient(),
      spaceId: SPACE,
      controllerDid: DID,
      collectionId: COLL
    })
    expect(freshSpace.configureCalls).toHaveLength(1)

    const settledSpace = new FakeSpace({
      current: { name: 'WAS Space', controller: DID },
      collection: new FakeCollection({
        current: { name: COLL, encryption: EDV }
      })
    })
    await ensureSpaceAndCollection({
      was: new FakeWas(settledSpace).asClient(),
      spaceId: SPACE,
      controllerDid: DID,
      collectionId: COLL
    })
    expect(settledSpace.configureCalls).toEqual([])
    expect(settledSpace.collectionObj.configureCalls).toEqual([])
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
    const space = new FakeSpace({
      collection: new FakeCollection({ failConfigure: cause })
    })
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

  it('wraps a collection.describe failure with a labelled error + cause', async () => {
    const cause = new Error('describe boom')
    const space = new FakeSpace({
      collection: new FakeCollection({ failDescribe: cause })
    })
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

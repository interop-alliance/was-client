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
import { PreconditionFailedError, ValidationError } from '../../src/index.js'
import { ensureSpace, ensureSpaceAndCollection } from '../../src/sync/index.js'
import { EDV_SCHEME_VERSION } from '../../src/edv/constants.js'

interface ConfigureOpts {
  name: string
  controller?: string
  encryption?: { scheme: string; version: number }
  force?: boolean
  current?: unknown
}

interface CollectionDesc {
  name?: string
  backend?: { id: string }
  encryption?: { scheme: string; version: number }
}

class FakeCollection {
  readonly configureCalls: ConfigureOpts[] = []
  readonly replaceCalls: { fields: CollectionDesc; ifMatch?: string }[] = []
  describeCalls = 0
  isPublicCalls = 0
  setPublicCalls = 0
  // The served description and its validator; a replace that matches the
  // validator bumps it, a stale one is refused with a 412 the way the server
  // would, and `collideOnce` lets a test slip a rival write in before ours.
  private state: { current: CollectionDesc | null; version: number }
  constructor(
    private readonly opts: {
      current?: CollectionDesc
      alreadyPublic?: boolean
      failConfigure?: Error
      failDescribe?: Error
      collideOnce?: (state: { current: CollectionDesc | null }) => void
    } = {}
  ) {
    this.state = { current: opts.current ?? null, version: 1 }
  }
  describeWithEtag = async (): Promise<{
    description: CollectionDesc
    etag: string
  } | null> => {
    this.describeCalls += 1
    if (this.opts.failDescribe) {
      throw this.opts.failDescribe
    }
    return this.state.current === null
      ? null
      : { description: this.state.current, etag: `"${this.state.version}"` }
  }
  replaceDescription = async (
    fields: CollectionDesc,
    { ifMatch }: { ifMatch?: string } = {}
  ): Promise<void> => {
    this.replaceCalls.push({ fields, ifMatch })
    if (this.opts.collideOnce) {
      const collide = this.opts.collideOnce
      this.opts.collideOnce = undefined
      collide(this.state)
      this.state.version += 1
    }
    if (ifMatch !== undefined && ifMatch !== `"${this.state.version}"`) {
      throw new PreconditionFailedError('stale description', { status: 412 })
    }
    this.state = { current: fields, version: this.state.version + 1 }
  }
  current(): CollectionDesc | null {
    return this.state.current
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

  configure = async (opts: ConfigureOpts): Promise<unknown> => {
    this.configureCalls.push(opts)
    if (this.failSpace) {
      throw this.failSpace
    }
    return { id: SPACE, name: opts.name, controller: opts.controller }
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
    // The description this ensure read is threaded into its own configure,
    // so the create costs one describe rather than two.
    expect(space.describeCalls).toBe(1)
    expect(space.configureCalls).toEqual([
      { name: 'WAS Space', controller: DID, current: null }
    ])
    expect(space.collectionIds).toEqual([COLL])
    expect(space.collectionObj.describeCalls).toBe(1)
    expect(space.collectionObj.configureCalls).toEqual([
      { name: COLL, encryption: EDV, current: null }
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
      { name: 'public-credentials', force: true, current: null }
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

    // Not `configure`: the declaration is compare-and-swapped against the
    // description's validator, carrying every writable field forward.
    expect(space.collectionObj.configureCalls).toEqual([])
    expect(space.collectionObj.replaceCalls).toEqual([
      {
        fields: { name: 'Kept Name', backend: undefined, encryption: EDV },
        ifMatch: '"1"'
      }
    ])
    expect(space.collectionObj.describeCalls).toBe(1)
  })

  it('carries an existing backend through the in-place declaration', async () => {
    const collection = new FakeCollection({
      current: { name: COLL, backend: { id: 'urn:backend:blob' } }
    })
    const space = new FakeSpace({
      current: { name: 'Wallet Space' },
      collection
    })
    await ensureSpaceAndCollection({
      was: new FakeWas(space).asClient(),
      spaceId: SPACE,
      controllerDid: DID,
      collectionId: COLL
    })
    expect(collection.current()).toEqual({
      name: COLL,
      backend: { id: 'urn:backend:blob' },
      encryption: EDV
    })
  })

  it('adopts a rival declaration that lands between the read and the write', async () => {
    const rivalDescriptor = { scheme: 'edv', version: EDV_SCHEME_VERSION + 1 }
    const collection = new FakeCollection({
      current: { name: COLL },
      collideOnce: state => {
        state.current = { name: COLL, encryption: rivalDescriptor }
      }
    })
    const space = new FakeSpace({
      current: { name: 'Wallet Space' },
      collection
    })
    await ensureSpaceAndCollection({
      was: new FakeWas(space).asClient(),
      spaceId: SPACE,
      controllerDid: DID,
      collectionId: COLL
    })
    // The first write lost the race; the re-read found a descriptor and left
    // it alone (a second write would have tripped `encryption-immutable` or,
    // worse, replaced the rival's roster).
    expect(collection.replaceCalls).toHaveLength(1)
    expect(collection.describeCalls).toBe(2)
    expect(collection.current()!.encryption).toEqual(rivalDescriptor)
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

describe('ensureSpace', () => {
  it('creates the absent space and returns the description it wrote', async () => {
    const space = new FakeSpace()
    const was = new FakeWas(space)
    const description = await ensureSpace({
      was: was.asClient(),
      spaceId: SPACE,
      controllerDid: DID
    })

    expect(space.describeCalls).toBe(1)
    expect(space.configureCalls).toEqual([
      { name: 'WAS Space', controller: DID, current: null }
    ])
    expect(description).toMatchObject({ id: SPACE, controller: DID })
  })

  it('returns an existing description without writing anything', async () => {
    // `id` is not decoration: every server write path stamps it from the URL
    // segment, so a served description always carries it -- and it is what
    // `ensureSpaceAndCollection` checks the threaded description against.
    const current = {
      id: SPACE,
      name: 'Wallet Space',
      controller: 'did:webvh:other'
    }
    const space = new FakeSpace({ current })
    const was = new FakeWas(space)
    const description = await ensureSpace({
      was: was.asClient(),
      spaceId: SPACE,
      controllerDid: DID
    })

    expect(space.describeCalls).toBe(1)
    expect(space.configureCalls).toEqual([])
    expect(description).toBe(current)
  })

  it('wraps a failure with the space-labelled error + cause', async () => {
    const cause = new Error('space boom')
    const space = new FakeSpace({ failSpace: cause })
    const was = new FakeWas(space)
    await expect(
      ensureSpace({ was: was.asClient(), spaceId: SPACE, controllerDid: DID })
    ).rejects.toMatchObject({
      message: expect.stringContaining(
        'Failed to configure WAS space "space-abc"'
      ),
      cause
    })
  })
})

describe('ensureSpaceAndCollection with a supplied space description', () => {
  it('accepts what ensureSpace returned, on both of its paths', async () => {
    // The two functions are halves of one seam, so assert them joined rather
    // than only side by side: whatever `ensureSpace` hands back must satisfy
    // `ensureSpaceAndCollection`'s check. Testing each half against its own
    // hand-written description is what let an id-less fixture pass while the
    // join would have thrown.
    for (const current of [
      null,
      { id: SPACE, name: 'Wallet Space', controller: 'did:webvh:other' }
    ]) {
      const space = new FakeSpace({ current })
      const was = new FakeWas(space)
      const spaceDescription = await ensureSpace({
        was: was.asClient(),
        spaceId: SPACE,
        controllerDid: DID
      })
      await ensureSpaceAndCollection({
        was: was.asClient(),
        spaceId: SPACE,
        controllerDid: DID,
        collectionId: COLL,
        spaceDescription
      })
      // One describe from the ensure, none from the collection branch.
      expect(space.describeCalls).toBe(1)
    }
  })

  it('refuses a description naming another space', async () => {
    const space = new FakeSpace()
    const was = new FakeWas(space)
    await expect(
      ensureSpaceAndCollection({
        was: was.asClient(),
        spaceId: SPACE,
        controllerDid: DID,
        collectionId: COLL,
        spaceDescription: {
          id: 'space-somewhere-else',
          type: ['Space'],
          controller: DID
        } as never
      })
    ).rejects.toMatchObject({
      name: 'ValidationError',
      message: expect.stringContaining('space-somewhere-else')
    })
    expect(space.describeCalls).toBe(0)
  })

  it('skips the space half entirely', async () => {
    const space = new FakeSpace()
    const was = new FakeWas(space)
    await ensureSpaceAndCollection({
      was: was.asClient(),
      spaceId: SPACE,
      controllerDid: DID,
      collectionId: COLL,
      spaceDescription: {
        id: SPACE,
        type: ['Space'],
        controller: DID
      } as never
    })

    // The whole point of threading: an already-ensured Space is neither
    // described nor configured again, however many collections fan out.
    expect(space.describeCalls).toBe(0)
    expect(space.configureCalls).toEqual([])
    expect(space.collectionObj.configureCalls).toEqual([
      { name: COLL, encryption: EDV, current: null }
    ])
  })

  it('rejects a description that names a different space', async () => {
    const space = new FakeSpace()
    const was = new FakeWas(space)
    await expect(
      ensureSpaceAndCollection({
        was: was.asClient(),
        spaceId: SPACE,
        controllerDid: DID,
        collectionId: COLL,
        spaceDescription: {
          id: 'urn:uuid:a-different-space',
          type: ['Space'],
          controller: DID
        } as never
      })
    ).rejects.toThrow(ValidationError)

    // Caught before anything is provisioned: supplying the description skips
    // the Space half, so the mismatch would leave `spaceId` unensured.
    expect(space.describeCalls).toBe(0)
    expect(space.configureCalls).toEqual([])
    expect(space.collectionObj.configureCalls).toEqual([])
  })
})

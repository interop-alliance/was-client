/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Unit tests for `ensureSpaceAndCollection`. The module imports the client only
 * as a type, so at runtime it is pure -- all effects flow through an injected
 * `was`. These assert the guarded create-if-absent shapes (the `edv`
 * encryption descriptor in particular) and the lost-race recovery behind them,
 * the non-clobbering reads-only behavior over an already-provisioned Space
 * (existing Space description, encryption descriptor, and public policy all
 * left untouched), the late in-place encryption declaration, the write-free
 * `'governed'` mode, the world-read heal for a public collection, and the
 * labelled-error + `cause` wrapping on failure, without a live server.
 */
import { describe, it, expect } from 'vitest'
import type { WasClient } from '../../src/index.js'
import {
  ConflictError,
  PreconditionFailedError,
  ValidationError
} from '../../src/index.js'
import { ensureSpace, ensureSpaceAndCollection } from '../../src/sync/index.js'
import { EDV_SCHEME_VERSION } from '../../src/edv/constants.js'

interface CollectionDesc {
  name?: string
  backend?: { id: string }
  encryption?: {
    scheme: string
    version: number
    epochs?: { id: string }[]
    history?: { method: string; resource: string }
  }
  generator?: string
  generatorOrigin?: string
}

class FakeCollection {
  readonly replaceCalls: {
    fields: CollectionDesc
    ifMatch?: string
    ifNoneMatch?: boolean
  }[] = []
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
      failReplace?: Error
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
    { ifMatch, ifNoneMatch }: { ifMatch?: string; ifNoneMatch?: boolean } = {}
  ): Promise<{ description: CollectionDesc; etag: string }> => {
    this.replaceCalls.push({
      fields,
      ...(ifMatch !== undefined && { ifMatch }),
      ...(ifNoneMatch !== undefined && { ifNoneMatch })
    })
    if (this.opts.failReplace) {
      throw this.opts.failReplace
    }
    if (this.opts.collideOnce) {
      const collide = this.opts.collideOnce
      this.opts.collideOnce = undefined
      collide(this.state)
      this.state.version += 1
    }
    // The server checks the encryption-descriptor transition before the
    // precondition, so a create carrying the bare descriptor over a rival
    // that already installed key epochs trips those rules first: a 400 for
    // the missing epochs (append-only) is the case modelled here.
    const existing = this.state.current?.encryption
    if (
      fields.encryption !== undefined &&
      existing?.epochs !== undefined &&
      fields.encryption.epochs === undefined
    ) {
      throw new ValidationError('encryption.epochs is append-only', {
        status: 400
      })
    }
    // The guarded create refuses on any present description, the way the
    // server does under `If-None-Match: *`.
    if (ifNoneMatch && this.state.current !== null) {
      throw new PreconditionFailedError('already exists', { status: 412 })
    }
    if (ifMatch !== undefined && ifMatch !== `"${this.state.version}"`) {
      throw new PreconditionFailedError('stale description', { status: 412 })
    }
    this.state = { current: fields, version: this.state.version + 1 }
    return { description: fields, etag: `"${this.state.version}"` }
  }
  current(): CollectionDesc | null {
    return this.state.current
  }
  isPublic = async (): Promise<boolean> => {
    this.isPublicCalls += 1
    return this.opts.alreadyPublic ?? false
  }
  setPublic = async (): Promise<void> => {
    this.setPublicCalls += 1
  }
}

interface SpaceDesc {
  id?: string
  type?: string[]
  name?: string
  controller?: string
}

class FakeSpace {
  readonly replaceCalls: { fields: SpaceDesc; ifNoneMatch?: boolean }[] = []
  readonly collectionIds: string[] = []
  readonly collectionObj: FakeCollection
  describeCalls = 0
  private current: SpaceDesc | null
  private readonly failSpace?: Error
  private collideOnce?: (state: { current: SpaceDesc | null }) => void

  constructor(
    opts: {
      current?: SpaceDesc | null
      failSpace?: Error
      collection?: FakeCollection
      collideOnce?: (state: { current: SpaceDesc | null }) => void
    } = {}
  ) {
    this.current = opts.current ?? null
    this.failSpace = opts.failSpace
    this.collideOnce = opts.collideOnce
    this.collectionObj = opts.collection ?? new FakeCollection()
  }

  describe = async (): Promise<SpaceDesc | null> => {
    this.describeCalls += 1
    return this.current
  }

  // The guarded create refuses on any present description, the way the
  // server does under `If-None-Match: *`; `collideOnce` lets a test slip a
  // rival create in before ours. A create answers with the description, the
  // way the server's 201 does.
  replaceDescription = async (
    fields: SpaceDesc,
    { ifNoneMatch }: { ifNoneMatch?: boolean } = {}
  ): Promise<{ description?: SpaceDesc }> => {
    this.replaceCalls.push({
      fields,
      ...(ifNoneMatch !== undefined && { ifNoneMatch })
    })
    if (this.failSpace) {
      throw this.failSpace
    }
    if (this.collideOnce) {
      const collide = this.collideOnce
      this.collideOnce = undefined
      const state = { current: this.current }
      collide(state)
      this.current = state.current
    }
    if (ifNoneMatch && this.current !== null) {
      throw new PreconditionFailedError('already exists', { status: 412 })
    }
    this.current = { id: SPACE, type: ['Space'], ...fields }
    return { description: this.current }
  }

  collection = (id: string): FakeCollection => {
    this.collectionIds.push(id)
    return this.collectionObj
  }
}

class FakeWas {
  spaceArg?: string
  // The handle options of every `space()` call, so a test can assert which
  // capability the handle was built with (or that none was).
  readonly spaceOptions: { capability?: unknown }[] = []
  constructor(private readonly spaceObj: FakeSpace) {}
  space = (id: string, options: { capability?: unknown } = {}): FakeSpace => {
    this.spaceArg = id
    this.spaceOptions.push(options)
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
    expect(space.describeCalls).toBe(1)
    // Both creates are guarded (`If-None-Match: *`): the server settles the
    // race, not a client-side re-read and merge.
    expect(space.replaceCalls).toEqual([
      { fields: { name: 'WAS Space', controller: DID }, ifNoneMatch: true }
    ])
    expect(space.collectionIds).toEqual([COLL])
    expect(space.collectionObj.describeCalls).toBe(1)
    expect(space.collectionObj.replaceCalls).toEqual([
      { fields: { name: COLL, encryption: EDV }, ifNoneMatch: true }
    ])
    expect(space.collectionObj.setPublicCalls).toBe(0)
  })

  it('adopts a rival Space create that lands between the read and the guarded PUT', async () => {
    const space = new FakeSpace({
      collideOnce: state => {
        state.current = { id: SPACE, name: 'Rival', controller: DID }
      }
    })
    const was = new FakeWas(space)
    await ensureSpaceAndCollection({
      was: was.asClient(),
      spaceId: SPACE,
      controllerDid: DID,
      collectionId: COLL
    })
    // The lost race is a re-read, not an error, and the winner is kept.
    expect(space.replaceCalls).toHaveLength(1)
    expect(space.describeCalls).toBe(2)
    expect(await space.describe()).toMatchObject({ name: 'Rival' })
    // The collection half still ran.
    expect(space.collectionObj.replaceCalls).toHaveLength(1)
  })

  it('adopts a rival collection create that lands between the read and the guarded PUT', async () => {
    const collection = new FakeCollection({
      collideOnce: state => {
        state.current = { name: 'Rival', backend: { id: 'urn:backend:blob' } }
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
    // The guarded create lost; the re-read found a descriptor-less rival, so
    // the late in-place `edv` declaration ran over it, keeping its fields.
    expect(collection.describeCalls).toBe(2)
    expect(collection.replaceCalls).toHaveLength(2)
    expect(collection.replaceCalls[0]).toEqual({
      fields: { name: COLL, encryption: EDV },
      ifNoneMatch: true
    })
    expect(collection.replaceCalls[1]!.ifMatch).toBeDefined()
    expect(collection.current()).toEqual({
      name: 'Rival',
      backend: { id: 'urn:backend:blob' },
      encryption: EDV
    })
  })

  it('adopts a rival collection create that already installed key epochs', async () => {
    // The rival ran `ensureFirstEpoch` before the loser's PUT arrived, so the
    // server answers the loser's bare descriptor with the epoch-transition
    // 400, not the precondition's 412; the re-read still adopts the winner.
    const rivalDescriptor = {
      scheme: 'edv',
      version: EDV_SCHEME_VERSION,
      epochs: [{ id: 'epoch-0' }]
    }
    const collection = new FakeCollection({
      collideOnce: state => {
        state.current = { name: 'Rival', encryption: rivalDescriptor }
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
    expect(collection.replaceCalls).toHaveLength(1)
    expect(collection.describeCalls).toBe(2)
    expect(collection.current()!.encryption).toEqual(rivalDescriptor)
  })

  it('rethrows a create failure when nothing can be read back', async () => {
    // A failed create with no collection behind it is a genuine failure, not
    // a lost race: the re-read finds nothing and the original error keeps
    // its type.
    const cause = new ConflictError('backend unknown', { status: 409 })
    const collection = new FakeCollection({ failReplace: cause })
    const space = new FakeSpace({
      current: { name: 'Wallet Space' },
      collection
    })
    await expect(
      ensureSpaceAndCollection({
        was: new FakeWas(space).asClient(),
        spaceId: SPACE,
        controllerDid: DID,
        collectionId: COLL
      })
    ).rejects.toBe(cause)
    expect(collection.describeCalls).toBe(2)
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

    expect(space.collectionObj.replaceCalls).toEqual([
      { fields: { name: 'public-credentials' }, ifNoneMatch: true }
    ])
    // A just-created collection has no policy yet, so the read is skipped.
    expect(space.collectionObj.isPublicCalls).toBe(0)
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
    expect(space.replaceCalls).toEqual([])
    expect(space.collectionObj.describeCalls).toBe(1)
    expect(space.collectionObj.replaceCalls).toEqual([])
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

  it('creates a governed collection with no encryption member', async () => {
    const space = new FakeSpace()
    const was = new FakeWas(space)
    await ensureSpaceAndCollection({
      was: was.asClient(),
      spaceId: SPACE,
      controllerDid: DID,
      collectionId: COLL,
      encryption: 'governed'
    })

    // The same descriptor-less create the plaintext branch makes: a governed
    // Collection's `encryption` member is the server's to derive from the
    // history log, so the client declares none.
    expect(space.collectionObj.replaceCalls).toEqual([
      { fields: { name: COLL }, ifNoneMatch: true }
    ])
  })

  it('writes nothing to an existing descriptor-less collection when governed', async () => {
    const collection = new FakeCollection({ current: { name: COLL } })
    const space = new FakeSpace({
      current: { name: 'Wallet Space' },
      collection
    })
    await ensureSpaceAndCollection({
      was: new FakeWas(space).asClient(),
      spaceId: SPACE,
      controllerDid: DID,
      collectionId: COLL,
      encryption: 'governed'
    })

    // The late in-place declaration must not fire: the server refuses to
    // govern a Description that already carries a client-written descriptor.
    expect(collection.replaceCalls).toEqual([])
    expect(collection.describeCalls).toBe(1)
    expect(collection.current()).toEqual({ name: COLL })
  })

  it('refuses to govern a collection carrying a client-written descriptor', async () => {
    // The server keeps a declared descriptor immutable, so the caller's log
    // create would fail with its 409; the misfit is named here instead.
    const collection = new FakeCollection({
      current: { name: COLL, encryption: EDV }
    })
    const space = new FakeSpace({
      current: { name: 'Wallet Space' },
      collection
    })
    await expect(
      ensureSpaceAndCollection({
        was: new FakeWas(space).asClient(),
        spaceId: SPACE,
        controllerDid: DID,
        collectionId: COLL,
        encryption: 'governed'
      })
    ).rejects.toMatchObject({
      name: 'ValidationError',
      message: expect.stringContaining('cannot be governed')
    })
    expect(collection.replaceCalls).toEqual([])
  })

  it('writes nothing to an already governed collection', async () => {
    // The derived form: a served `encryption` naming the governing log.
    const derived = {
      scheme: 'edv',
      version: EDV_SCHEME_VERSION,
      history: { method: 'vh-resource-log', resource: 'https://x/meta/log' }
    }
    const collection = new FakeCollection({
      current: { name: COLL, encryption: derived }
    })
    const space = new FakeSpace({
      current: { name: 'Wallet Space' },
      collection
    })
    await ensureSpaceAndCollection({
      was: new FakeWas(space).asClient(),
      spaceId: SPACE,
      controllerDid: DID,
      collectionId: COLL,
      encryption: 'governed'
    })

    // A Description PUT may not carry the derived member, so nothing is sent.
    expect(collection.replaceCalls).toEqual([])
    expect(collection.current()!.encryption).toBe(derived)
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
    expect(freshSpace.replaceCalls).toHaveLength(1)

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
    expect(settledSpace.replaceCalls).toEqual([])
    expect(settledSpace.collectionObj.replaceCalls).toEqual([])
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
    expect(space.replaceCalls[0]!.fields.name).toBe('My Space')
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
    expect(space.collectionObj.replaceCalls[0]!.fields.name).toBe(
      'Verifiable Credentials'
    )
  })

  it('wraps a space create failure with a labelled error + cause', async () => {
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

  it('does not attempt the collection when the space create fails', async () => {
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

  it('wraps a collection create failure with a labelled error + cause', async () => {
    const cause = new Error('collection boom')
    const space = new FakeSpace({
      collection: new FakeCollection({ failReplace: cause })
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

describe('ensureSpaceAndCollection app attribution', () => {
  const APP = 'did:key:zApp'
  const ORIGIN = 'https://app.example'

  it('stamps the generator pair on the guarded create', async () => {
    const space = new FakeSpace()
    await ensureSpaceAndCollection({
      was: new FakeWas(space).asClient(),
      spaceId: SPACE,
      controllerDid: DID,
      collectionId: COLL,
      generator: APP,
      generatorOrigin: ORIGIN
    })

    expect(space.collectionObj.replaceCalls).toEqual([
      {
        fields: {
          name: COLL,
          encryption: EDV,
          generator: APP,
          generatorOrigin: ORIGIN
        },
        ifNoneMatch: true
      }
    ])
  })

  it('stamps the generator pair on a descriptor-less create', async () => {
    const space = new FakeSpace()
    await ensureSpaceAndCollection({
      was: new FakeWas(space).asClient(),
      spaceId: SPACE,
      controllerDid: DID,
      collectionId: COLL,
      encryption: 'governed',
      generator: APP,
      generatorOrigin: ORIGIN
    })

    expect(space.collectionObj.replaceCalls).toEqual([
      {
        fields: { name: COLL, generator: APP, generatorOrigin: ORIGIN },
        ifNoneMatch: true
      }
    ])
  })

  it('does not send generatorOrigin without a generator', async () => {
    const space = new FakeSpace()
    await ensureSpaceAndCollection({
      was: new FakeWas(space).asClient(),
      spaceId: SPACE,
      controllerDid: DID,
      collectionId: COLL,
      generatorOrigin: ORIGIN
    })

    // The origin says which origin the DID was bound to, so it carries no
    // meaning alone: the create body is the unattributed one.
    expect(space.collectionObj.replaceCalls).toEqual([
      { fields: { name: COLL, encryption: EDV }, ifNoneMatch: true }
    ])
  })

  it('writes nothing when the standing collection already carries the pair', async () => {
    const collection = new FakeCollection({
      current: {
        name: COLL,
        encryption: EDV,
        generator: APP,
        generatorOrigin: ORIGIN
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
      collectionId: COLL,
      generator: APP,
      generatorOrigin: ORIGIN
    })

    expect(collection.replaceCalls).toEqual([])
    expect(collection.describeCalls).toBe(1)
  })

  it("leaves a standing attributed collection's pair unchanged when a different generator is supplied", async () => {
    // Attribution is stamped on the create only: the creator of a standing
    // collection is never renamed by a later ensure.
    const collection = new FakeCollection({
      current: {
        name: COLL,
        encryption: EDV,
        generator: APP,
        generatorOrigin: ORIGIN
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
      collectionId: COLL,
      generator: 'did:key:zOtherApp',
      generatorOrigin: 'https://other.example'
    })

    expect(collection.replaceCalls).toEqual([])
    expect(collection.current()).toMatchObject({
      generator: APP,
      generatorOrigin: ORIGIN
    })
  })

  it('does not backfill the pair onto a standing unattributed collection', async () => {
    const collection = new FakeCollection({
      current: { name: COLL, encryption: EDV }
    })
    const space = new FakeSpace({
      current: { name: 'Wallet Space' },
      collection
    })
    await ensureSpaceAndCollection({
      was: new FakeWas(space).asClient(),
      spaceId: SPACE,
      controllerDid: DID,
      collectionId: COLL,
      generator: APP,
      generatorOrigin: ORIGIN
    })

    expect(collection.replaceCalls).toEqual([])
  })

  it('carries a stored pair through the late encryption declaration', async () => {
    // Replace semantics: a body that omitted the attribution would drop it.
    const collection = new FakeCollection({
      current: { name: COLL, generator: APP, generatorOrigin: ORIGIN }
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

    expect(collection.replaceCalls).toHaveLength(1)
    expect(collection.current()).toEqual({
      name: COLL,
      backend: undefined,
      encryption: EDV,
      generator: APP,
      generatorOrigin: ORIGIN
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
    expect(space.replaceCalls).toEqual([
      { fields: { name: 'WAS Space', controller: DID }, ifNoneMatch: true }
    ])
    expect(description).toMatchObject({ id: SPACE, controller: DID })
  })

  it('returns the rival description when the guarded create loses the race', async () => {
    // The realistic rival is another client of the same controller (the
    // Space id is minted for that DID): a rival under another controller
    // would fail the loser's authorization before the precondition is
    // evaluated, so the server answers that case with no 412.
    const rival = { id: SPACE, name: 'Rival', controller: DID }
    const space = new FakeSpace({
      collideOnce: state => {
        state.current = rival
      }
    })
    const description = await ensureSpace({
      was: new FakeWas(space).asClient(),
      spaceId: SPACE,
      controllerDid: DID
    })
    expect(space.replaceCalls).toHaveLength(1)
    expect(space.describeCalls).toBe(2)
    expect(description).toBe(rival)
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
    expect(space.replaceCalls).toEqual([])
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

describe('ensureSpaceAndCollection with an invocation capability', () => {
  const CAPABILITY = { id: 'urn:zcap:delegated' }

  it('builds every Space handle with the capability, on both ensures', async () => {
    const was = new FakeWas(new FakeSpace())
    await ensureSpaceAndCollection({
      was: was.asClient(),
      spaceId: SPACE,
      controllerDid: DID,
      collectionId: COLL,
      encryption: 'governed',
      capability: CAPABILITY as never
    })
    // One handle for the collection half, one inside `ensureSpace`.
    expect(was.spaceOptions).toHaveLength(2)
    for (const options of was.spaceOptions) {
      expect(options.capability).toBe(CAPABILITY)
    }
  })

  it('rides the capability past a supplied space description', async () => {
    const was = new FakeWas(new FakeSpace({ current: null }))
    await ensureSpaceAndCollection({
      was: was.asClient(),
      spaceId: SPACE,
      controllerDid: DID,
      collectionId: COLL,
      encryption: 'governed',
      spaceDescription: { id: SPACE, type: ['Space'], controller: DID },
      capability: CAPABILITY as never
    })
    expect(was.spaceOptions).toEqual([{ capability: CAPABILITY }])
  })

  it('builds the handle with no capability when none is given', async () => {
    const was = new FakeWas(new FakeSpace())
    await ensureSpace({
      was: was.asClient(),
      spaceId: SPACE,
      controllerDid: DID
    })
    expect(was.spaceOptions).toEqual([{ capability: undefined }])
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
    expect(space.replaceCalls).toEqual([])
    expect(space.collectionObj.replaceCalls).toEqual([
      { fields: { name: COLL, encryption: EDV }, ifNoneMatch: true }
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
  })
})

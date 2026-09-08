/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Unit tests for descriptor acquisition and the unknown-epoch refresh policy
 * (`src/edv/acquire.ts`, `src/edv/refresh.ts`,
 * `src/edv/refreshingDocCipher.ts`): descriptor acquisition (fetch + cache +
 * the cached fallback whenever the description yields no descriptor, thrown or
 * empty, with a resource-log refusal rethrown past the cache), the
 * once-per-collection-per-session unknown-epoch refresh policy, and the
 * self-refreshing EDV document cipher -- the last driven through real EDV
 * codecs over real epoch rosters minted with the recipient primitives, so an
 * envelope written under a rotated descriptor really fails to decrypt under a
 * stale one.
 */
import { describe, expect, it } from 'vitest'
import { X25519KeyAgreementKey2020 } from '@interop/x25519-key-agreement-key'
import type {
  IKeyAgreementKey,
  IKeyResolver
} from '@interop/data-integrity-core'
import {
  ResourceLogContinuityError,
  ResourceLogIntegrityError
} from '@interop/vh-resource-log'
import { PreconditionFailedError } from '../../src/index.js'
import type { CollectionEncryption } from '../../src/index.js'
import {
  acquireDescriptor,
  acquireDescriptors,
  createEdvDocCipher,
  createRefreshingEdvDocCipher,
  DescriptorRefreshPolicy,
  initRecipients,
  ownerRecipient,
  removeRecipient,
  UnknownEpochError,
  type EncryptionDescriptorCache,
  type EncryptionDescriptorSource,
  type EncryptionDescriptorStore
} from '../../src/edv/index.js'

const COLLECTION_ID = 'private-credentials'

/**
 * An in-memory `EncryptionDescriptorCache` with write counting; with
 * `failReads` set, every read throws (the cache seam's errors throw through).
 */
function memoryCache(): EncryptionDescriptorCache & {
  writes: number
  failReads: boolean
  _get(collectionId: string): CollectionEncryption | undefined
  _set(collectionId: string, descriptor: CollectionEncryption): void
} {
  const descriptors = new Map<string, CollectionEncryption>()
  return {
    writes: 0,
    failReads: false,
    async readDescriptor({ collectionId }) {
      if (this.failReads) {
        throw new Error(`descriptor cache unreadable for "${collectionId}"`)
      }
      const descriptor = descriptors.get(collectionId)
      return descriptor ? structuredClone(descriptor) : undefined
    },
    async writeDescriptor({ collectionId, descriptor }) {
      this.writes++
      descriptors.set(collectionId, structuredClone(descriptor))
    },
    _get(collectionId) {
      return descriptors.get(collectionId)
    },
    _set(collectionId, descriptor) {
      descriptors.set(collectionId, descriptor)
    }
  }
}

/**
 * An `EncryptionDescriptorSource` with fetch counting, served from a mutable
 * per-collection map; a collection id in `failing` throws instead.
 */
function memorySource(): EncryptionDescriptorSource & {
  fetches: number
  failing: Set<string>
  _set(collectionId: string, descriptor: CollectionEncryption | undefined): void
} {
  const descriptors = new Map<string, CollectionEncryption | undefined>()
  return {
    fetches: 0,
    failing: new Set<string>(),
    async collectionEncryption({ collectionId }) {
      this.fetches++
      if (this.failing.has(collectionId)) {
        throw new Error(`network down for "${collectionId}"`)
      }
      const descriptor = descriptors.get(collectionId)
      return descriptor ? structuredClone(descriptor) : undefined
    },
    _set(collectionId, descriptor) {
      descriptors.set(collectionId, descriptor)
    }
  }
}

/**
 * The in-memory compare-and-swap `EncryptionDescriptorStore` the was-client
 * recipient primitives (initRecipients / removeRecipient) run their real
 * write path against, to mint real epoch rosters for the cipher tests.
 */
function memoryDescriptorStore(): EncryptionDescriptorStore & {
  _getDescriptor(): CollectionEncryption | null
} {
  let descriptor: CollectionEncryption | null = null
  let version = 0
  return {
    async read() {
      return descriptor
        ? { descriptor: structuredClone(descriptor), etag: `v${version}` }
        : null
    },
    async replace(next, { ifMatch }: { ifMatch?: string }) {
      if (ifMatch !== `v${version}`) {
        throw new PreconditionFailedError('stale descriptor etag')
      }
      descriptor = next
      version++
    },
    async create(next) {
      if (descriptor) {
        throw new PreconditionFailedError('descriptor already exists')
      }
      descriptor = next
      version++
    },
    _getDescriptor() {
      return descriptor ? structuredClone(descriptor) : null
    }
  }
}

/** A reader: an X25519 key-agreement key in did:key form, plus its resolver. */
async function makeReader(): Promise<{
  keyAgreementKey: IKeyAgreementKey
  keyResolver: IKeyResolver
}> {
  const kak = await X25519KeyAgreementKey2020.generate()
  const publicKeyMultibase = kak.publicKeyMultibase as string
  const did = `did:key:${publicKeyMultibase}`
  kak.controller = did
  kak.id = `${did}#${publicKeyMultibase}`
  const keyAgreementKey = kak as unknown as IKeyAgreementKey
  const keyResolver = (async ({ id }: { id?: string }) => {
    if (id !== kak.id) {
      throw new Error(`Unknown key id "${id}".`)
    }
    return {
      id: kak.id,
      type: kak.type,
      publicKeyMultibase: kak.publicKeyMultibase
    }
  }) as unknown as IKeyResolver
  return { keyAgreementKey, keyResolver }
}

/**
 * Mints a real two-epoch history for one owner: `descriptor1` (owner + a
 * second reader), then a rotation that removes the second reader, yielding
 * `descriptor2` whose `currentEpoch` the descriptor1-built cipher has never
 * seen.
 */
async function mintRotatedDescriptors(owner: {
  keyAgreementKey: IKeyAgreementKey
}): Promise<{
  descriptor1: CollectionEncryption
  descriptor2: CollectionEncryption
}> {
  const other = await makeReader()
  const store = memoryDescriptorStore()
  const descriptor1 = await initRecipients({
    store,
    recipients: [
      ownerRecipient({ keyAgreementKey: owner.keyAgreementKey }),
      ownerRecipient({ keyAgreementKey: other.keyAgreementKey })
    ]
  })
  const descriptor2 = await removeRecipient({
    store,
    recipientId: other.keyAgreementKey.id as string,
    pull: async () => {}
  })
  return { descriptor1, descriptor2 }
}

const sampleDescriptor = (): CollectionEncryption => ({
  scheme: 'edv',
  version: 1,
  currentEpoch: 'did:key:z6LSepoch',
  epochs: [{ id: 'did:key:z6LSepoch', recipients: [] }]
})

describe('acquireDescriptor', () => {
  it('caches and returns a fetched descriptor', async () => {
    const source = memorySource()
    const cache = memoryCache()
    const descriptor = sampleDescriptor()
    source._set(COLLECTION_ID, descriptor)

    const acquired = await acquireDescriptor({
      source,
      cache,
      collectionId: COLLECTION_ID
    })
    expect(acquired).toEqual(descriptor)
    expect(cache._get(COLLECTION_ID)).toEqual(descriptor)
    expect(cache.writes).toBe(1)
  })

  it('falls back to the cached copy on an empty description (a masked 404), leaving the cache in place', async () => {
    const source = memorySource()
    const cache = memoryCache()
    const descriptor = sampleDescriptor()
    cache._set(COLLECTION_ID, descriptor)

    // An empty description is ambiguous: WAS serves the same shape for an
    // unauthorized read as for an unencrypted collection.
    const acquired = await acquireDescriptor({
      source,
      cache,
      collectionId: COLLECTION_ID
    })
    expect(acquired).toEqual(descriptor)
    // The cached copy is deliberately not cleared (mirrors the offline path).
    expect(cache._get(COLLECTION_ID)).toBeDefined()
  })

  it('resolves undefined on an empty description with nothing cached', async () => {
    const acquired = await acquireDescriptor({
      source: memorySource(),
      cache: memoryCache(),
      collectionId: COLLECTION_ID
    })
    expect(acquired).toBeUndefined()
  })

  it('falls back to the cached copy when the fetch fails, reporting the error', async () => {
    const source = memorySource()
    const cache = memoryCache()
    const descriptor = sampleDescriptor()
    cache._set(COLLECTION_ID, descriptor)
    source.failing.add(COLLECTION_ID)
    const seen: string[] = []

    const acquired = await acquireDescriptor({
      source,
      cache,
      collectionId: COLLECTION_ID,
      onFetchError: (_err, { collectionId }) => seen.push(collectionId)
    })
    expect(acquired).toEqual(descriptor)
    expect(seen).toEqual([COLLECTION_ID])
  })

  it('resolves undefined when the fetch fails and nothing is cached', async () => {
    const source = memorySource()
    source.failing.add(COLLECTION_ID)
    const acquired = await acquireDescriptor({
      source,
      cache: memoryCache(),
      collectionId: COLLECTION_ID
    })
    expect(acquired).toBeUndefined()
  })

  it('reads the cache alone when no source is supplied', async () => {
    const cache = memoryCache()
    const descriptor = sampleDescriptor()
    cache._set(COLLECTION_ID, descriptor)
    const acquired = await acquireDescriptor({
      cache,
      collectionId: COLLECTION_ID
    })
    expect(acquired).toEqual(descriptor)
  })

  it('rethrows a log-governed source refusal instead of falling back (matched by name)', async () => {
    const cache = memoryCache()
    cache._set(COLLECTION_ID, sampleDescriptor())
    const onFetchError = () => {
      throw new Error('a refusal must not be observed as a swallowed fetch')
    }
    // A fabricated log, and a fork off the pinned history: security signals
    // a warm cache must not paper over.
    for (const refusal of [
      new ResourceLogIntegrityError('fabricated'),
      new ResourceLogContinuityError({ reason: 'fork', pinnedHead: '2-x' })
    ]) {
      await expect(
        acquireDescriptor({
          source: {
            collectionEncryption: async () => {
              throw refusal
            }
          },
          cache,
          collectionId: COLLECTION_ID,
          onFetchError
        })
      ).rejects.toThrow(refusal.message)
    }
  })

  it('falls back to the cache on a continuity rollback (reconcilable divergence)', async () => {
    const cache = memoryCache()
    const descriptor = sampleDescriptor()
    cache._set(COLLECTION_ID, descriptor)
    const observed: unknown[] = []
    const acquired = await acquireDescriptor({
      source: {
        collectionEncryption: async () => {
          throw new ResourceLogContinuityError({
            reason: 'rollback',
            pinnedHead: '2-x'
          })
        }
      },
      cache,
      collectionId: COLLECTION_ID,
      onFetchError: err => {
        observed.push(err)
      }
    })
    // Nothing rolled-back is adopted and the pin never regressed (the
    // verifier refused before pinning); the cached copy serves meanwhile.
    expect(acquired).toEqual(descriptor)
    expect(observed).toHaveLength(1)
  })
})

describe('acquireDescriptors', () => {
  it('aggregates only the collections that resolve a descriptor', async () => {
    const source = memorySource()
    const cache = memoryCache()
    const descriptor = sampleDescriptor()
    source._set('contacts', descriptor)
    source.failing.add('wallet-activity')
    cache._set('wallet-activity', descriptor)

    const descriptors = await acquireDescriptors({
      source,
      cache,
      collectionIds: ['contacts', 'contacts-history', 'wallet-activity']
    })
    expect(Object.keys(descriptors).sort()).toEqual([
      'contacts',
      'wallet-activity'
    ])
    expect(source.fetches).toBe(3)
  })
})

describe('DescriptorRefreshPolicy', () => {
  it('spends one refresh + one re-read on the first unknown-epoch report', async () => {
    let refreshes = 0
    let reads = 0
    const policy = new DescriptorRefreshPolicy({
      refresh: async () => {
        refreshes++
      }
    })
    const value = await policy.readWithRefresh({
      collectionId: COLLECTION_ID,
      read: async () => {
        reads++
        // The re-read (after the refresh) no longer reports unknown rows.
        return { value: reads, unknownEpoch: reads === 1 }
      }
    })
    expect(value).toBe(2)
    expect(refreshes).toBe(1)
    expect(reads).toBe(2)
  })

  it('never refreshes the same collection twice in one session, but guards per collection', async () => {
    const refreshed: string[] = []
    const policy = new DescriptorRefreshPolicy({
      refresh: async ({ collectionId }) => {
        refreshed.push(collectionId)
      }
    })
    const unknownRead = async () => ({ value: 'v', unknownEpoch: true })

    await policy.readWithRefresh({
      collectionId: COLLECTION_ID,
      read: unknownRead
    })
    await policy.readWithRefresh({
      collectionId: COLLECTION_ID,
      read: unknownRead
    })
    await policy.readWithRefresh({
      collectionId: 'contacts',
      read: unknownRead
    })
    expect(refreshed).toEqual([COLLECTION_ID, 'contacts'])
  })

  it('reset re-arms the guard, for one collection or all', async () => {
    const refreshed: string[] = []
    const policy = new DescriptorRefreshPolicy({
      refresh: async ({ collectionId }) => {
        refreshed.push(collectionId)
      }
    })
    const unknownRead = async () => ({ value: 'v', unknownEpoch: true })

    await policy.readWithRefresh({
      collectionId: COLLECTION_ID,
      read: unknownRead
    })
    policy.reset({ collectionId: COLLECTION_ID })
    await policy.readWithRefresh({
      collectionId: COLLECTION_ID,
      read: unknownRead
    })
    policy.reset()
    await policy.readWithRefresh({
      collectionId: COLLECTION_ID,
      read: unknownRead
    })
    expect(refreshed).toEqual([COLLECTION_ID, COLLECTION_ID, COLLECTION_ID])
  })
})

describe('createRefreshingEdvDocCipher', () => {
  it('refuses to build fail-closed when no descriptor resolves anywhere', async () => {
    // Every encrypted collection's descriptor carries an epoch roster from
    // provisioning; a cipher for a collection whose descriptor resolves
    // nowhere must refuse rather than encrypt straight to a key-agreement key.
    const owner = await makeReader()
    await expect(
      createRefreshingEdvDocCipher({
        ...owner,
        collectionId: COLLECTION_ID,
        source: memorySource(),
        cache: memoryCache()
      })
    ).rejects.toThrow('no encryption descriptor available')
  })

  it('builds from the cached descriptor when the description comes back empty', async () => {
    // A masked 404 (an unauthorized or transient read) is indistinguishable
    // from an unencrypted collection, so the warm cache still serves it --
    // the collection must not go down for the session.
    const owner = await makeReader()
    const { descriptor2 } = await mintRotatedDescriptors(owner)
    const cache = memoryCache()
    cache._set(COLLECTION_ID, descriptor2)

    const cipher = await createRefreshingEdvDocCipher({
      ...owner,
      collectionId: COLLECTION_ID,
      source: memorySource(),
      cache
    })
    const { envelope, epoch } = await cipher.encrypt({ data: { n: 1 } })
    expect(epoch).toBe(descriptor2.currentEpoch)
    expect(await cipher.decrypt({ envelope })).toEqual({ n: 1 })
  })

  it("encrypts under the acquired descriptor's current epoch", async () => {
    const owner = await makeReader()
    const { descriptor1 } = await mintRotatedDescriptors(owner)
    const source = memorySource()
    source._set(COLLECTION_ID, descriptor1)

    const cipher = await createRefreshingEdvDocCipher({
      ...owner,
      collectionId: COLLECTION_ID,
      source,
      cache: memoryCache()
    })
    const { envelope, epoch } = await cipher.encrypt({ data: { n: 1 } })
    expect(epoch).toBe(descriptor1.currentEpoch)
    expect(await cipher.decrypt({ envelope })).toEqual({ n: 1 })
  })

  it('refreshes exactly once on an unknown-epoch decrypt: re-read, swap, retry', async () => {
    const owner = await makeReader()
    const { descriptor1, descriptor2 } = await mintRotatedDescriptors(owner)
    const source = memorySource()
    const cache = memoryCache()
    source._set(COLLECTION_ID, descriptor1)

    const reader = await createRefreshingEdvDocCipher({
      ...owner,
      collectionId: COLLECTION_ID,
      source,
      cache
    })
    expect(source.fetches).toBe(1)

    // Another replica rotates (descriptor2) and writes under the fresh epoch.
    source._set(COLLECTION_ID, descriptor2)
    const writer = await createEdvDocCipher({
      ...owner,
      collectionId: COLLECTION_ID,
      encryption: descriptor2
    })
    const one = await writer.encrypt({ data: { n: 1 } })
    const two = await writer.encrypt({ data: { n: 2 } })
    expect(one.epoch).toBe(descriptor2.currentEpoch)

    // First unknown-epoch decrypt drives the one re-read + swap + retry...
    expect(await reader.decrypt({ envelope: one.envelope })).toEqual({ n: 1 })
    expect(source.fetches).toBe(2)
    expect(cache._get(COLLECTION_ID)).toEqual(descriptor2)
    // ...and later fresh-epoch decrypts ride the swapped cipher, no refetch.
    expect(await reader.decrypt({ envelope: two.envelope })).toEqual({ n: 2 })
    expect(source.fetches).toBe(2)
  })

  it('propagates UnknownEpochError for a foreign envelope without a second re-read', async () => {
    const owner = await makeReader()
    const { descriptor1 } = await mintRotatedDescriptors(owner)
    const source = memorySource()
    source._set(COLLECTION_ID, descriptor1)

    const reader = await createRefreshingEdvDocCipher({
      ...owner,
      collectionId: COLLECTION_ID,
      source,
      cache: memoryCache()
    })
    // A stranger writing under its own independently minted epoch roster --
    // an epoch the reader's descriptor (current or refetched) never carries.
    const stranger = await makeReader()
    const foreignDescriptor = await initRecipients({
      store: memoryDescriptorStore(),
      recipients: [
        ownerRecipient({ keyAgreementKey: stranger.keyAgreementKey })
      ]
    })
    const foreign = await createEdvDocCipher({
      ...stranger,
      collectionId: COLLECTION_ID,
      encryption: foreignDescriptor
    })
    const { envelope } = await foreign.encrypt({ data: { n: 1 } })

    // The first foreign envelope spends the one refresh (the descriptor is
    // unchanged, so the retry fails the same way)...
    await expect(reader.decrypt({ envelope })).rejects.toThrow(
      UnknownEpochError
    )
    expect(source.fetches).toBe(2)
    // ...and a later one neither refetches nor loops.
    await expect(reader.decrypt({ envelope })).rejects.toThrow(
      UnknownEpochError
    )
    expect(source.fetches).toBe(2)
  })

  it('rethrows the original UnknownEpochError when the refresh itself fails, and retries later', async () => {
    const owner = await makeReader()
    const { descriptor1, descriptor2 } = await mintRotatedDescriptors(owner)
    const source = memorySource()
    const cache = memoryCache()
    source._set(COLLECTION_ID, descriptor1)

    const reader = await createRefreshingEdvDocCipher({
      ...owner,
      collectionId: COLLECTION_ID,
      source,
      cache
    })
    const writer = await createEdvDocCipher({
      ...owner,
      collectionId: COLLECTION_ID,
      encryption: descriptor2
    })
    const { envelope } = await writer.encrypt({ data: { n: 1 } })

    // Nothing answers the re-read: the description is unreachable and the
    // cache cannot be read either, so the rebuild rejects.
    source.failing.add(COLLECTION_ID)
    cache.failReads = true
    await expect(reader.decrypt({ envelope })).rejects.toThrow(
      UnknownEpochError
    )
    expect(source.fetches).toBe(2)

    // A failed refresh is not spent: once the description is reachable again
    // the next unknown-epoch decrypt refreshes and routes the envelope.
    source.failing.delete(COLLECTION_ID)
    cache.failReads = false
    source._set(COLLECTION_ID, descriptor2)
    expect(await reader.decrypt({ envelope })).toEqual({ n: 1 })
    expect(source.fetches).toBe(3)
  })

  it('builds from the cached descriptor when the description cannot be fetched', async () => {
    const owner = await makeReader()
    const { descriptor2 } = await mintRotatedDescriptors(owner)
    const source = memorySource()
    source.failing.add(COLLECTION_ID)
    const cache = memoryCache()
    cache._set(COLLECTION_ID, descriptor2)
    const errors: unknown[] = []

    const cipher = await createRefreshingEdvDocCipher({
      ...owner,
      collectionId: COLLECTION_ID,
      source,
      cache,
      onFetchError: err => errors.push(err)
    })
    // Offline, the previously-shared collection keeps encrypting under its
    // current epoch (the cached descriptor).
    const { envelope, epoch } = await cipher.encrypt({ data: { n: 1 } })
    expect(epoch).toBe(descriptor2.currentEpoch)
    expect(await cipher.decrypt({ envelope })).toEqual({ n: 1 })
    expect(errors).toHaveLength(1)
  })

  it('is inert (no refresh) without a source: an unknown-epoch decrypt propagates', async () => {
    const owner = await makeReader()
    const { descriptor1, descriptor2 } = await mintRotatedDescriptors(owner)
    const cache = memoryCache()
    cache._set(COLLECTION_ID, descriptor1)

    const reader = await createRefreshingEdvDocCipher({
      ...owner,
      collectionId: COLLECTION_ID,
      cache
    })
    const writer = await createEdvDocCipher({
      ...owner,
      collectionId: COLLECTION_ID,
      encryption: descriptor2
    })
    const { envelope } = await writer.encrypt({ data: { n: 1 } })
    await expect(reader.decrypt({ envelope })).rejects.toThrow(
      UnknownEpochError
    )
  })

  it('supports the in-place update path through the wrapper', async () => {
    const owner = await makeReader()
    const { descriptor1 } = await mintRotatedDescriptors(owner)
    const source = memorySource()
    source._set(COLLECTION_ID, descriptor1)

    const cipher = await createRefreshingEdvDocCipher({
      ...owner,
      collectionId: 'contacts',
      idDerivation: 'random',
      source: (() => {
        const s = memorySource()
        s._set('contacts', descriptor1)
        return s
      })(),
      cache: memoryCache()
    })
    const created = await cipher.encrypt({ data: { name: 'Ada' } })
    if (!cipher.encryptUpdate) {
      throw new Error('wrapper lost encryptUpdate')
    }
    const updated = await cipher.encryptUpdate({
      id: created.id,
      data: { name: 'Ada Lovelace' },
      current: created.envelope
    })
    expect(updated.id).toBe(created.id)
    expect(await cipher.decrypt({ envelope: updated.envelope })).toEqual({
      name: 'Ada Lovelace'
    })
  })
})

/**
 * `isKeyUnwrapError` (`src/descriptors/errors.ts`): the not-a-recipient half
 * of what an injected cipher throws. Matched by name, since the cipher may
 * come from a second copy of `@interop/was-client` -- and a scan that misses
 * the class drops a real, permanently-unreadable row into the undecryptable
 * bucket a host is entitled to purge.
 */

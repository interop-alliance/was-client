/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Unit tests for the log-governed descriptor store (no network): the
 * `EncryptionDescriptorStore` over a Collection whose served `encryption`
 * member is the point-state projection of its governing history log. Covers
 * the plain-descriptor passthrough (a projection without `history` behaves
 * as the Collection Description adapter does), the governed lifecycle driven
 * by the recipient primitives (genesis create, verified read, signed append,
 * chain-head pin), the read-only store, the forwarded seal, and the refusals:
 * `history.method` and `history.resource` mismatches before any fetch, a
 * projection that does not match the verified head (a stale one is the port's
 * conflict, a forged one an integrity refusal), a head of the wrong state
 * type, an absent log under a projection, and the library's own integrity and
 * continuity refusals passing through unwrapped.
 */
import { describe, it, expect } from 'vitest'
import { Ed25519VerificationKey } from '@interop/ed25519-verification-key'
import { X25519KeyAgreementKey2020 } from '@interop/x25519-key-agreement-key'
import type { IKeyAgreementKey } from '@interop/data-integrity-core'
import { RESOURCE_LOG_METHOD } from '@interop/storage-core'
import type { ResourceLogEntry } from '@interop/storage-core'
import {
  memoryResourceLogPinStore,
  parseResourceLog,
  serializeResourceLog,
  type ResourceLogController,
  type ResourceLogSigner
} from '@interop/vh-resource-log'
import {
  fakeController,
  memoryLogStore
} from '@interop/vh-resource-log/testing'

import { PreconditionFailedError, ValidationError } from '../../src/index.js'
import type { CollectionEncryption } from '../../src/index.js'
import type { Collection } from '../../src/Collection.js'
import {
  EPOCH_CONFIGURATION_STATE_TYPE,
  logGovernedCollectionDescriptorStore,
  logGovernedDescriptorStore,
  toEpochConfigurationState
} from '../../src/edv/logGovernedDescriptorStore.js'
import { addRecipient, initRecipients } from '../../src/edv/recipients.js'
import type { RecipientPublicKey } from '../../src/edv/recipients.js'

const LOG_URL = 'https://was.example/space/s1/vault/meta/log'
const LOG_ID = 'space/s1/vault/meta/log'

/**
 * The format identifier a genesis entry's `parameters` carry (absent on a
 * non-genesis entry's parameters shape).
 *
 * @param entry {ResourceLogEntry}
 * @returns {string | undefined}
 */
function genesisMethod(entry: ResourceLogEntry): string | undefined {
  const parameters = entry.parameters as { method?: string } | undefined
  return parameters?.method
}

/**
 * A self-describing did:key X25519 reader (see descriptor-store.test.ts).
 *
 * @returns {Promise<{ kak: IKeyAgreementKey; recipient: RecipientPublicKey }>}
 */
async function makeReader(): Promise<{
  kak: IKeyAgreementKey
  recipient: RecipientPublicKey
}> {
  const kak = await X25519KeyAgreementKey2020.generate()
  const publicKeyMultibase = kak.publicKeyMultibase
  const did = `did:key:${publicKeyMultibase}`
  kak.controller = did
  kak.id = `${did}#${publicKeyMultibase}`
  return {
    kak: kak as IKeyAgreementKey,
    recipient: { id: kak.id, publicKeyMultibase }
  }
}

/**
 * An Ed25519 log signer plus a one-version controller view that lists it.
 *
 * @returns {Promise<{ signer: ResourceLogSigner; controller: ResourceLogController }>}
 */
async function makeWriter(): Promise<{
  signer: ResourceLogSigner
  controller: ResourceLogController
}> {
  const signingKey = await Ed25519VerificationKey.generate()
  const keyMultibase = signingKey.publicKeyMultibase as string
  const did = `did:key:${keyMultibase}`
  signingKey.controller = did
  signingKey.id = `${did}#${keyMultibase}`
  const keySigner = signingKey.signer()
  const signer: ResourceLogSigner = {
    keyMultibase,
    async sign({ data }) {
      return keySigner.sign({ data })
    }
  }
  const controller = fakeController({
    versions: [{ versionId: '1-a', keys: [keyMultibase] }]
  })
  return { signer, controller }
}

/**
 * An in-memory fake of the Collection surface the governed store drives. The
 * served Description's `encryption` member is derived the way the server
 * derives it: the log head's `state` with `history` stamped on, or the
 * point-state descriptor when the collection is not log-governed. Control
 * seams let a test serve a tampered projection or rewrite the stored log.
 *
 * @param [options] {object}
 * @param [options.encryption] {CollectionEncryption}   a point-state
 *   descriptor for a collection that is not log-governed
 * @returns {object}
 */
function fakeGovernedCollection(
  options: { encryption?: CollectionEncryption } = {}
) {
  const state = {
    body: undefined as string | undefined,
    version: 0,
    encryption: options.encryption,
    projection: undefined as CollectionEncryption | undefined,
    logReads: 0,
    descriptionPuts: [] as Array<{
      description: Record<string, unknown>
      ifMatch?: string
    }>,
    logPuts: [] as Array<{ ifMatch?: string; ifNoneMatch?: boolean }>
  }
  const etag = () => `"v${state.version}"`
  function served(): CollectionEncryption | undefined {
    if (state.projection !== undefined) {
      return state.projection
    }
    if (state.body === undefined) {
      return state.encryption
    }
    const entries = parseResourceLog(state.body)
    const head = entries[entries.length - 1]!
    const method = genesisMethod(entries[0]!)
    return {
      ...(head.state as unknown as CollectionEncryption),
      ...(method !== undefined && { history: { method, resource: LOG_URL } })
    }
  }
  const collection = {
    id: 'vault',
    spaceId: 's1',
    historyLogUrl: LOG_URL,
    describeWithEtag: async () => ({
      description: {
        type: ['Collection'],
        name: 'Vault',
        generator: 'did:key:zApp',
        generatorOrigin: 'https://app.example',
        encryption: served()
      },
      etag: etag()
    }),
    replaceDescription: async (
      description: Record<string, unknown>,
      options: { ifMatch?: string } = {}
    ) => {
      state.descriptionPuts.push({ description, ifMatch: options.ifMatch })
      if (options.ifMatch !== undefined && options.ifMatch !== etag()) {
        throw new PreconditionFailedError('stale', { status: 412 })
      }
      state.encryption = description.encryption as CollectionEncryption
      state.version += 1
      return { description, etag: etag() }
    },
    getHistoryLog: async () => {
      state.logReads += 1
      return state.body === undefined
        ? null
        : { body: state.body, etag: etag() }
    },
    putHistoryLog: async (
      body: string,
      options: { ifMatch?: string; ifNoneMatch?: boolean } = {}
    ) => {
      state.logPuts.push(options)
      if (options.ifNoneMatch && state.body !== undefined) {
        throw new PreconditionFailedError('exists', { status: 412 })
      }
      if (options.ifMatch !== undefined && options.ifMatch !== etag()) {
        throw new PreconditionFailedError('stale', { status: 412 })
      }
      state.body = body
      state.version += 1
      return { etag: etag() }
    },
    _entries: () =>
      state.body === undefined ? [] : parseResourceLog(state.body),
    _setEntries: (entries: ResourceLogEntry[]) => {
      state.body = serializeResourceLog(entries)
      state.version += 1
    },
    _state: state
  }
  return { collection: collection as unknown as Collection, fake: collection }
}

/**
 * A governed collection carrying a one-epoch log for `reader`, plus the
 * writer and pin store that produced it, and a fresh store over it.
 *
 * @returns {Promise<object>}
 */
async function governedFixture() {
  const reader = await makeReader()
  const writer = await makeWriter()
  const pinStore = memoryResourceLogPinStore()
  const { collection, fake } = fakeGovernedCollection()
  const storeOptions = {
    collection,
    resolveController: async () => writer.controller,
    pinStore,
    logId: LOG_ID
  }
  const descriptor = await initRecipients({
    store: logGovernedCollectionDescriptorStore({
      ...storeOptions,
      signer: writer.signer
    }),
    recipients: [reader.recipient]
  })
  return {
    reader,
    writer,
    pinStore,
    collection,
    fake,
    storeOptions,
    descriptor
  }
}

describe('logGovernedCollectionDescriptorStore over a plain descriptor', () => {
  it('reads the point-state descriptor and writes the description', async () => {
    const reader = await makeReader()
    const initial: CollectionEncryption = {
      scheme: 'edv',
      epochs: [],
      currentEpoch: undefined
    }
    const { collection, fake } = fakeGovernedCollection({
      encryption: initial
    })
    const writer = await makeWriter()
    const store = logGovernedCollectionDescriptorStore({
      collection,
      resolveController: async () => writer.controller,
      pinStore: memoryResourceLogPinStore(),
      logId: LOG_ID
    })
    const current = await store.read()
    expect(current).toEqual({ descriptor: initial, etag: '"v0"' })
    const next = await addRecipient({
      store,
      recipient: reader.recipient,
      owner: { keyAgreementKey: reader.kak }
    }).catch(err => err)
    // No epochs yet: the primitive refuses, but the read path is the
    // description's, never the log's.
    expect(next).toBeInstanceOf(ValidationError)
    expect(fake._state.logReads).toBe(0)

    await store.replace({ ...initial, currentEpoch: 'e1' }, { ifMatch: '"v0"' })
    // The sibling fields ride along: the server's replace semantics would
    // otherwise drop the app attribution on a key rotation.
    expect(fake._state.descriptionPuts).toEqual([
      {
        description: {
          name: 'Vault',
          backend: undefined,
          generator: 'did:key:zApp',
          generatorOrigin: 'https://app.example',
          encryption: { ...initial, currentEpoch: 'e1' }
        },
        ifMatch: '"v0"'
      }
    ])
    expect(fake._state.logReads).toBe(0)
    expect(store.create).toBeUndefined()
  })

  it('reads a null encryption member as no descriptor', async () => {
    const { collection } = fakeGovernedCollection({
      encryption: null as unknown as CollectionEncryption
    })
    const writer = await makeWriter()
    const store = logGovernedCollectionDescriptorStore({
      collection,
      resolveController: async () => writer.controller,
      pinStore: memoryResourceLogPinStore(),
      logId: LOG_ID
    })
    expect(await store.read()).toBeNull()
  })
})

describe('logGovernedCollectionDescriptorStore over a governed collection', () => {
  it('creates the genesis, then reads the verified head as the descriptor', async () => {
    const { fake, pinStore, storeOptions, descriptor } = await governedFixture()
    expect(fake._state.logPuts).toEqual([{ ifNoneMatch: true }])
    const entries = fake._entries()
    expect(entries).toHaveLength(1)
    expect(genesisMethod(entries[0]!)).toBe(RESOURCE_LOG_METHOD)
    expect(entries[0]!.state.type).toBe(EPOCH_CONFIGURATION_STATE_TYPE)
    expect(entries[0]!.state).not.toHaveProperty('history')
    expect(await pinStore.read({ logId: LOG_ID })).toMatchObject({
      method: RESOURCE_LOG_METHOD,
      head: entries[0]!.versionId
    })

    const store = logGovernedCollectionDescriptorStore(storeOptions)
    const current = await store.read()
    expect(current?.etag).toBe('"v1"')
    expect(current?.descriptor).toEqual({
      ...toEpochConfigurationState(descriptor),
      history: { method: RESOURCE_LOG_METHOD, resource: LOG_URL }
    })
  })

  it('appends a signed entry on replace, pinned to the read etag', async () => {
    const { reader, writer, fake, pinStore, storeOptions } =
      await governedFixture()
    const other = await makeReader()
    const store = logGovernedCollectionDescriptorStore({
      ...storeOptions,
      signer: writer.signer
    })
    const next = await addRecipient({
      store,
      recipient: other.recipient,
      owner: { keyAgreementKey: reader.kak }
    })
    expect(next.epochs?.[0]?.recipients).toHaveLength(2)
    expect(fake._state.logPuts).toEqual([
      { ifNoneMatch: true },
      { ifMatch: '"v1"' }
    ])
    const entries = fake._entries()
    expect(entries).toHaveLength(2)
    expect(entries[1]!.state).toEqual(toEpochConfigurationState(next))
    expect(await pinStore.read({ logId: LOG_ID })).toMatchObject({
      head: entries[1]!.versionId
    })
  })

  it('takes the governed write path on a replace right after its own create', async () => {
    const reader = await makeReader()
    const writer = await makeWriter()
    const { fake, collection } = fakeGovernedCollection()
    const store = logGovernedCollectionDescriptorStore({
      collection,
      resolveController: async () => writer.controller,
      pinStore: memoryResourceLogPinStore(),
      logId: LOG_ID,
      signer: writer.signer
    })
    // initRecipients reads (no descriptor yet) and then creates the genesis.
    const descriptor = await initRecipients({
      store,
      recipients: [reader.recipient]
    })
    // No read in between: the store must not act on the pre-create
    // description it observed, which named no governing log.
    await store.replace(descriptor, { ifMatch: '"v1"' })
    expect(fake._state.descriptionPuts).toEqual([])
    expect(fake._state.logPuts).toEqual([
      { ifNoneMatch: true },
      { ifMatch: '"v1"' }
    ])
    expect(fake._entries()).toHaveLength(2)
  })

  it('reports a projection behind the verified head as the port conflict class', async () => {
    const { reader, writer, fake, storeOptions } = await governedFixture()
    const other = await makeReader()
    await addRecipient({
      store: logGovernedCollectionDescriptorStore({
        ...storeOptions,
        signer: writer.signer
      }),
      recipient: other.recipient,
      owner: { keyAgreementKey: reader.kak }
    })
    // The Description was read at the genesis head, then a concurrent append
    // landed before the log read: the projection equals the earlier entry's
    // state, a lost race rather than a forgery.
    const [genesis] = fake._entries()
    fake._state.projection = {
      ...(genesis!.state as unknown as CollectionEncryption),
      history: { method: RESOURCE_LOG_METHOD, resource: LOG_URL }
    }
    const err = await logGovernedCollectionDescriptorStore(storeOptions)
      .read()
      .catch(err => err)
    expect(err).toBeInstanceOf(PreconditionFailedError)
    expect((err as Error).message).toMatch(/behind the verified head/)
  })

  it('forwards seal() to the generic store', async () => {
    const { writer, storeOptions } = await governedFixture()
    const store = logGovernedCollectionDescriptorStore({
      ...storeOptions,
      signer: writer.signer
    })
    // Nothing to seal against a one-version controller.
    expect(await store.seal()).toBe('noop')
    await expect(
      logGovernedCollectionDescriptorStore(storeOptions).seal()
    ).rejects.toBeInstanceOf(ValidationError)
  })

  it('reports a stale validator on replace as the port conflict class', async () => {
    const { writer, fake, storeOptions, descriptor } = await governedFixture()
    const store = logGovernedCollectionDescriptorStore({
      ...storeOptions,
      signer: writer.signer
    })
    await store.read()
    // A concurrent writer moved the log on: the held head is stale.
    fake._setEntries(fake._entries())
    const err = await store
      .replace(descriptor, { ifMatch: '"v1"' })
      .catch(err => err)
    expect(err).toBeInstanceOf(PreconditionFailedError)
    expect((err as Error).cause).toMatchObject({
      name: 'ResourceLogConflictError'
    })
  })

  it('is read-only without a signer', async () => {
    const { storeOptions, descriptor } = await governedFixture()
    const store = logGovernedCollectionDescriptorStore(storeOptions)
    expect(store.create).toBeUndefined()
    await store.read()
    await expect(
      store.replace(descriptor, { ifMatch: '"v1"' })
    ).rejects.toBeInstanceOf(ValidationError)
  })

  it('refuses a history.method mismatch before any fetch', async () => {
    const { fake, storeOptions } = await governedFixture()
    const readsBefore = fake._state.logReads
    fake._state.projection = {
      ...(await fake.describeWithEtag()).description.encryption!,
      history: { method: 'resource-log:9.9', resource: LOG_URL }
    }
    const err = await logGovernedCollectionDescriptorStore(storeOptions)
      .read()
      .catch(err => err)
    expect((err as Error).name).toBe('ResourceLogIntegrityError')
    expect((err as Error).message).toMatch(/resource-log:9\.9/)
    expect(fake._state.logReads).toBe(readsBefore)
  })

  it('refuses a history.resource that is not this collection log', async () => {
    const { fake, storeOptions } = await governedFixture()
    const readsBefore = fake._state.logReads
    fake._state.projection = {
      ...(await fake.describeWithEtag()).description.encryption!,
      history: {
        method: RESOURCE_LOG_METHOD,
        resource: 'https://was.example/space/s1/key-map/vault.jsonl'
      }
    }
    const err = await logGovernedCollectionDescriptorStore(storeOptions)
      .read()
      .catch(err => err)
    expect((err as Error).name).toBe('ResourceLogIntegrityError')
    expect(fake._state.logReads).toBe(readsBefore)
  })

  it('refuses a projection that does not match the verified head', async () => {
    const { fake, storeOptions } = await governedFixture()
    const projection = (await fake.describeWithEtag()).description.encryption!
    fake._state.projection = { ...projection, currentEpoch: 'forged' }
    const err = await logGovernedCollectionDescriptorStore(storeOptions)
      .read()
      .catch(err => err)
    expect((err as Error).name).toBe('ResourceLogIntegrityError')
    expect((err as Error).message).toMatch(/does not match the verified head/)
  })

  it('refuses a projection whose log the collection does not serve', async () => {
    const { fake, storeOptions } = await governedFixture()
    fake._state.projection = (
      await fake.describeWithEtag()
    ).description.encryption!
    fake._state.body = undefined
    const err = await logGovernedCollectionDescriptorStore({
      ...storeOptions,
      pinStore: memoryResourceLogPinStore()
    })
      .read()
      .catch(err => err)
    expect((err as Error).name).toBe('ResourceLogIntegrityError')
    expect((err as Error).message).toMatch(/serves none/)
  })

  it('refuses a verified head whose state is not an epoch configuration', async () => {
    const { fake, storeOptions } = await governedFixture()
    const [genesis] = fake._entries()
    fake._setEntries([
      { ...genesis!, state: { ...genesis!.state, type: 'SomethingElse' } }
    ])
    // The projection mirrors the (tampered) head, so only the type rule can
    // refuse it; the entry hash no longer matches either, and the library's
    // integrity check runs first.
    const err = await logGovernedCollectionDescriptorStore({
      ...storeOptions,
      pinStore: memoryResourceLogPinStore()
    })
      .read()
      .catch(err => err)
    expect((err as Error).name).toBe('ResourceLogIntegrityError')
  })

  it('passes the library integrity refusal through unwrapped', async () => {
    const { fake, storeOptions } = await governedFixture()
    const [genesis] = fake._entries()
    fake._setEntries([
      { ...genesis!, versionId: genesis!.versionId.replace(/.$/, 'x') }
    ])
    const err = await logGovernedCollectionDescriptorStore({
      ...storeOptions,
      pinStore: memoryResourceLogPinStore()
    })
      .read()
      .catch(err => err)
    expect((err as Error).name).toBe('ResourceLogIntegrityError')
    expect(err).not.toBeInstanceOf(PreconditionFailedError)
    expect(err).not.toBeInstanceOf(ValidationError)
  })

  it('passes the library continuity refusal through unwrapped', async () => {
    const { reader, writer, fake, storeOptions } = await governedFixture()
    const other = await makeReader()
    await addRecipient({
      store: logGovernedCollectionDescriptorStore({
        ...storeOptions,
        signer: writer.signer
      }),
      recipient: other.recipient,
      owner: { keyAgreementKey: reader.kak }
    })
    // The pin now names the second entry; a host serving only the genesis is
    // a truncated log behind the pin.
    fake._setEntries(fake._entries().slice(0, 1))
    const err = await logGovernedCollectionDescriptorStore(storeOptions)
      .read()
      .catch(err => err)
    expect((err as Error).name).toBe('ResourceLogContinuityError')
  })
})

describe('logGovernedDescriptorStore over any resource log', () => {
  async function genericFixture() {
    const reader = await makeReader()
    const writer = await makeWriter()
    const pinStore = memoryResourceLogPinStore()
    const log = memoryLogStore()
    const options = {
      log,
      resolveController: async () => writer.controller,
      pinStore,
      logId: 'space/s1/key-map/vault.jsonl'
    }
    return { reader, writer, pinStore, log, options }
  }

  it('reads null before genesis, creates, reads the head state, appends', async () => {
    const { reader, writer, pinStore, log, options } = await genericFixture()
    const store = logGovernedDescriptorStore({
      ...options,
      signer: writer.signer
    })
    expect(await store.read()).toBeNull()
    const descriptor = await initRecipients({
      store,
      recipients: [reader.recipient]
    })
    const current = await store.read()
    expect(current?.descriptor).toEqual(toEpochConfigurationState(descriptor))
    expect(current?.etag).toBe('v1')
    const other = await makeReader()
    const next = await addRecipient({
      store,
      recipient: other.recipient,
      owner: { keyAgreementKey: reader.kak }
    })
    expect(log._getEntries()).toHaveLength(2)
    expect(log._getEntries()![1]!.state).toEqual(
      toEpochConfigurationState(next)
    )
    expect(await pinStore.read({ logId: options.logId })).toMatchObject({
      head: log._getEntries()![1]!.versionId
    })
    // Nothing to seal against a one-version controller.
    expect(await store.seal()).toBe('noop')
  })

  it('refuses an unconditional replace', async () => {
    const { reader, writer, options } = await genericFixture()
    const store = logGovernedDescriptorStore({
      ...options,
      signer: writer.signer
    })
    const descriptor = await initRecipients({
      store,
      recipients: [reader.recipient]
    })
    await expect(store.replace(descriptor, {})).rejects.toThrow(
      /forbids an unconditional write/
    )
  })

  it('translates a lost create race into the port conflict class', async () => {
    const { reader, writer, options } = await genericFixture()
    const winner = logGovernedDescriptorStore({
      ...options,
      signer: writer.signer
    })
    const descriptor = await initRecipients({
      store: winner,
      recipients: [reader.recipient]
    })
    const loser = logGovernedDescriptorStore({
      ...options,
      pinStore: memoryResourceLogPinStore(),
      signer: writer.signer
    })
    const err = await loser.create!(descriptor).catch(err => err)
    expect(err).toBeInstanceOf(PreconditionFailedError)
  })

  it('is read-only without a signer: no create, replace and seal refuse', async () => {
    const { reader, writer, options } = await genericFixture()
    const descriptor = await initRecipients({
      store: logGovernedDescriptorStore({ ...options, signer: writer.signer }),
      recipients: [reader.recipient]
    })
    const store = logGovernedDescriptorStore(options)
    expect(store.create).toBeUndefined()
    await expect(
      store.replace(descriptor, { ifMatch: 'v1' })
    ).rejects.toBeInstanceOf(ValidationError)
    await expect(store.seal()).rejects.toBeInstanceOf(ValidationError)
  })
})

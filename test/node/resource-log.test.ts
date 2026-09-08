/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Tests for the `/log` subpath: the WAS adapter of
 * `@interop/vh-resource-log`'s store port (read-with-etag, CAS append,
 * guarded genesis create, and the 412-to-conflict-error translation) --
 * against an in-memory fake Resource and an in-memory fake Collection whose
 * governing history log is the target (no network). The codec,
 * `confirmAppend`, and verification suites live in the library.
 */
import { describe, expect, it } from 'vitest'
import type { ResourceLogEntry } from '@interop/storage-core'
import {
  ResourceLogConflictError,
  serializeResourceLog
} from '@interop/vh-resource-log'
import type { Collection } from '../../src/Collection.js'
import type { Resource } from '../../src/Resource.js'
import { PreconditionFailedError, ValidationError } from '../../src/errors.js'
import { LOG_CONTENT_TYPE, resourceLogStore } from '../../src/log/index.js'

/**
 * Builds a minimal syntactically valid entry at ordinal `n`. The wire types
 * only constrain shapes -- hashes and proofs here are placeholders, since the
 * transport layer under test never verifies them.
 *
 * @param n {number}
 * @returns {ResourceLogEntry}
 */
function entryAt(n: number): ResourceLogEntry {
  return {
    versionId: `${n}-QmEntryHash${n}`,
    versionTime: '2026-08-10T12:00:00Z',
    parameters: n === 1 ? { method: 'resource-log:0.1', scid: 'QmScid' } : {},
    state: { type: 'WasEpochConfiguration', currentEpoch: `epoch-${n}` },
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

/**
 * An in-memory fake of the WAS Resource surface the log store drives:
 * `getWithEtag({ as: 'text' })` serves the stored body as text with a
 * version-counter ETag, and `put` records its options and enforces the
 * `ifMatch` / `ifNoneMatch` preconditions like the server would.
 *
 * @param [initialBody] {string}   the stored log body; absent = no resource
 * @returns {object}
 */
function fakeLogResource(initialBody?: string) {
  const state = {
    body: initialBody,
    version: initialBody === undefined ? 0 : 1,
    puts: [] as Array<{
      contentType?: string
      ifMatch?: string
      ifNoneMatch?: boolean
    }>
  }
  const resource = {
    id: 'user-key.jsonl',
    getWithEtag: async (options?: { as?: 'text' }) => {
      expect(options).toEqual({ as: 'text' })
      return state.body === undefined
        ? null
        : { data: state.body, etag: `"v${state.version}"` }
    },
    put: async (
      data: Uint8Array,
      options: {
        contentType?: string
        ifMatch?: string
        ifNoneMatch?: boolean
      } = {}
    ) => {
      state.puts.push(options)
      if (options.ifNoneMatch && state.body !== undefined) {
        throw new PreconditionFailedError('exists', { status: 412 })
      }
      if (
        options.ifMatch !== undefined &&
        options.ifMatch !== `"v${state.version}"`
      ) {
        throw new PreconditionFailedError('stale', { status: 412 })
      }
      state.body = new TextDecoder().decode(data)
      state.version += 1
      return { etag: `"v${state.version}"` }
    }
  }
  return { resource: resource as unknown as Resource, state }
}

/**
 * An in-memory fake of the Collection surface the collection-hosted store
 * drives: `getHistoryLog` serves the stored body as text with a
 * version-counter ETag, and `putHistoryLog` records its options and enforces
 * the `ifMatch` / `ifNoneMatch` preconditions like the server would.
 *
 * @param [initialBody] {string}   the stored log body; absent = no log yet
 * @returns {object}
 */
function fakeLogCollection(initialBody?: string) {
  const state = {
    body: initialBody,
    version: initialBody === undefined ? 0 : 1,
    puts: [] as Array<{ ifMatch?: string; ifNoneMatch?: boolean }>
  }
  const collection = {
    id: 'vault',
    getHistoryLog: async () =>
      state.body === undefined
        ? null
        : { body: state.body, etag: `"v${state.version}"` },
    putHistoryLog: async (
      body: string,
      options: { ifMatch?: string; ifNoneMatch?: boolean } = {}
    ) => {
      state.puts.push(options)
      if (options.ifNoneMatch && state.body !== undefined) {
        throw new PreconditionFailedError('exists', { status: 412 })
      }
      if (
        options.ifMatch !== undefined &&
        options.ifMatch !== `"v${state.version}"`
      ) {
        throw new PreconditionFailedError('stale', { status: 412 })
      }
      state.body = body
      state.version += 1
      return { etag: `"v${state.version}"` }
    }
  }
  return { collection: collection as unknown as Collection, state }
}

describe('resourceLogStore', () => {
  it('reads null for an absent log, and creates the genesis guarded', async () => {
    const { resource, state } = fakeLogResource()
    const store = resourceLogStore({ resource })
    expect(await store.read()).toBeNull()

    await store.create(entryAt(1))
    expect(state.puts[0]).toEqual({
      contentType: LOG_CONTENT_TYPE,
      ifNoneMatch: true
    })
    expect(state.body).toBe(serializeResourceLog([entryAt(1)]))
  })

  it('reads entries with the etag and appends conditioned on it', async () => {
    const { resource, state } = fakeLogResource(
      serializeResourceLog([entryAt(1)])
    )
    const store = resourceLogStore({ resource })
    const current = (await store.read())!
    expect(current.entries).toEqual([entryAt(1)])
    expect(current.etag).toBe('"v1"')

    await store.append(entryAt(2), { ifMatch: current.etag! })
    expect(state.puts[0]).toEqual({
      contentType: LOG_CONTENT_TYPE,
      ifMatch: '"v1"'
    })
    // The prior line's bytes are carried forward verbatim, one line appended.
    expect(state.body).toBe(serializeResourceLog([entryAt(1), entryAt(2)]))
  })

  it('rethrows a stale-validator 412 as the conflict error, cause set', async () => {
    const { resource } = fakeLogResource(serializeResourceLog([entryAt(1)]))
    const store = resourceLogStore({ resource })
    await store.read()
    const err = await store
      .append(entryAt(2), { ifMatch: '"v0"' })
      .then(() => undefined)
      .catch((thrown: unknown) => thrown as Error)
    expect(err).toBeInstanceOf(ResourceLogConflictError)
    expect(err!.name).toBe('ResourceLogConflictError')
    expect(err!.cause).toBeInstanceOf(PreconditionFailedError)
  })

  it('rethrows a lost guarded-create race as the conflict error', async () => {
    const { resource } = fakeLogResource(serializeResourceLog([entryAt(1)]))
    const store = resourceLogStore({ resource })
    const err = await store
      .create(entryAt(1))
      .then(() => undefined)
      .catch((thrown: unknown) => thrown as Error)
    expect(err).toBeInstanceOf(ResourceLogConflictError)
    expect(err!.cause).toBeInstanceOf(PreconditionFailedError)
  })

  it('refuses an append with no prior read on this store instance', async () => {
    const { resource } = fakeLogResource(serializeResourceLog([entryAt(1)]))
    const store = resourceLogStore({ resource })
    await expect(
      store.append(entryAt(2), { ifMatch: '"v1"' })
    ).rejects.toBeInstanceOf(ValidationError)
  })

  it('the subpath exposes exactly the adapter and its content type', async () => {
    // Invariant: one owner per name -- the subpath re-exports nothing from
    // the library or storage-core.
    const subpath = await import('../../src/log/index.js')
    expect(Object.keys(subpath).sort()).toEqual([
      'LOG_CONTENT_TYPE',
      'resourceLogStore'
    ])
  })
})

describe('resourceLogStore over a Collection history log', () => {
  it('reads null for an absent log, and creates the genesis guarded', async () => {
    const { collection, state } = fakeLogCollection()
    const store = resourceLogStore({ collection })
    expect(await store.read()).toBeNull()

    await store.create(entryAt(1))
    expect(state.puts[0]).toEqual({ ifNoneMatch: true })
    expect(state.body).toBe(serializeResourceLog([entryAt(1)]))
  })

  it('reads an empty served body as an absent log', async () => {
    const { collection } = fakeLogCollection('')
    expect(await resourceLogStore({ collection }).read()).toBeNull()
  })

  it('refuses neither host or both hosts at construction', async () => {
    const { collection } = fakeLogCollection()
    const { resource } = fakeLogResource()
    expect(() =>
      resourceLogStore({} as unknown as { collection: Collection })
    ).toThrow(ValidationError)
    expect(() =>
      resourceLogStore({ collection, resource } as unknown as {
        collection: Collection
      })
    ).toThrow(ValidationError)
  })

  it('reads entries with the etag and appends the prior bytes plus one line', async () => {
    const { collection, state } = fakeLogCollection(
      serializeResourceLog([entryAt(1)])
    )
    const store = resourceLogStore({ collection })
    const current = (await store.read())!
    expect(current.entries).toEqual([entryAt(1)])
    expect(current.etag).toBe('"v1"')

    await store.append(entryAt(2), { ifMatch: current.etag! })
    expect(state.puts[0]).toEqual({ ifMatch: '"v1"' })
    expect(state.body).toBe(serializeResourceLog([entryAt(1), entryAt(2)]))
  })

  it('rethrows a lost race as the conflict error on both writes', async () => {
    const { collection } = fakeLogCollection(serializeResourceLog([entryAt(1)]))
    const store = resourceLogStore({ collection })
    await store.read()
    await expect(
      store.append(entryAt(2), { ifMatch: '"v0"' })
    ).rejects.toBeInstanceOf(ResourceLogConflictError)
    await expect(store.create(entryAt(1))).rejects.toBeInstanceOf(
      ResourceLogConflictError
    )
  })
})

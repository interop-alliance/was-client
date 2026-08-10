/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Tests for the `/log` subpath: strict JSON Lines parse/serialize, the
 * resource-log store adapter (read-with-etag, CAS append, guarded genesis
 * create), the read-back `confirmAppend`, and the point-state projection
 * write -- all against an in-memory fake Resource (no network).
 */
import { describe, expect, it } from 'vitest'
import type { ResourceLogEntry } from '@interop/storage-core'
import type { Resource } from '../../src/Resource.js'
import {
  LogNotConfirmedError,
  PreconditionFailedError,
  ValidationError
} from '../../src/errors.js'
import {
  LOG_CONTENT_TYPE,
  confirmAppend,
  parseResourceLog,
  resourceLogStore,
  serializeResourceLog,
  serializeResourceLogEntry,
  writeLogProjection
} from '../../src/log/index.js'

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
    parameters:
      n === 1 ? { method: 'was-resource-log:0.1', scid: 'QmScid' } : {},
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
 * `getWithEtag` serves the stored body as a `Blob` (the shape a `text/jsonl`
 * read decodes to) with a version-counter ETag, and `put` records its options
 * and enforces the `ifMatch` / `ifNoneMatch` preconditions like the server
 * would.
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
    getWithEtag: async () =>
      state.body === undefined
        ? null
        : {
            data: new Blob([state.body], { type: LOG_CONTENT_TYPE }),
            etag: `"v${state.version}"`
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

describe('parseResourceLog / serializeResourceLog', () => {
  it('round-trips a serialized log, with the terminating newline', () => {
    const entries = [entryAt(1), entryAt(2)]
    const text = serializeResourceLog(entries)
    expect(text.endsWith('\n')).toBe(true)
    expect(text).toBe(
      serializeResourceLogEntry(entries[0]!) +
        '\n' +
        serializeResourceLogEntry(entries[1]!) +
        '\n'
    )
    expect(parseResourceLog(text)).toEqual(entries)
  })

  it('parses a body without a trailing newline', () => {
    const text = serializeResourceLogEntry(entryAt(1))
    expect(parseResourceLog(text)).toEqual([entryAt(1)])
  })

  it('fails the whole parse on a non-object line, not a skip', () => {
    const good = serializeResourceLogEntry(entryAt(1))
    for (const bad of ['[1,2]', '"text"', 'null', '42', 'not json', '']) {
      expect(() => parseResourceLog(`${good}\n${bad}\n`)).toThrow(
        ValidationError
      )
    }
  })

  it('rejects an empty body (a log has at least its genesis entry)', () => {
    expect(() => parseResourceLog('')).toThrow(ValidationError)
    expect(() => parseResourceLog('\n')).toThrow(ValidationError)
    expect(() => serializeResourceLog([])).toThrow(ValidationError)
  })
})

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

  it('surfaces a stale-validator append as PreconditionFailedError', async () => {
    const { resource } = fakeLogResource(serializeResourceLog([entryAt(1)]))
    const store = resourceLogStore({ resource })
    await store.read()
    await expect(
      store.append(entryAt(2), { ifMatch: '"v0"' })
    ).rejects.toBeInstanceOf(PreconditionFailedError)
  })

  it('refuses an append with no prior read on this store instance', async () => {
    const { resource } = fakeLogResource(serializeResourceLog([entryAt(1)]))
    const store = resourceLogStore({ resource })
    await expect(
      store.append(entryAt(2), { ifMatch: '"v1"' })
    ).rejects.toBeInstanceOf(ValidationError)
  })

  it('refuses a resource that does not hold a text body', async () => {
    const resource = {
      id: 'r',
      getWithEtag: async () => ({ data: { not: 'a log' }, etag: '"v1"' })
    } as unknown as Resource
    const store = resourceLogStore({ resource })
    await expect(store.read()).rejects.toBeInstanceOf(ValidationError)
  })
})

describe('confirmAppend', () => {
  it('returns the read-back log containing the entry at its ordinal', async () => {
    const { resource } = fakeLogResource(
      serializeResourceLog([entryAt(1), entryAt(2)])
    )
    const store = resourceLogStore({ resource })
    const confirmed = await confirmAppend({ store, entry: entryAt(2) })
    expect(confirmed.entries).toHaveLength(2)
  })

  it('throws LogNotConfirmedError when the served log is too short', async () => {
    const { resource } = fakeLogResource(serializeResourceLog([entryAt(1)]))
    const store = resourceLogStore({ resource })
    await expect(
      confirmAppend({ store, entry: entryAt(2) })
    ).rejects.toBeInstanceOf(LogNotConfirmedError)
  })

  it('throws LogNotConfirmedError on a different entry at the ordinal', async () => {
    const other = { ...entryAt(2), versionTime: '2026-08-11T00:00:00Z' }
    const { resource } = fakeLogResource(
      serializeResourceLog([entryAt(1), other])
    )
    const store = resourceLogStore({ resource })
    await expect(
      confirmAppend({ store, entry: entryAt(2) })
    ).rejects.toBeInstanceOf(LogNotConfirmedError)
  })

  it('throws LogNotConfirmedError when the log vanished', async () => {
    const { resource } = fakeLogResource()
    const store = resourceLogStore({ resource })
    await expect(
      confirmAppend({ store, entry: entryAt(1) })
    ).rejects.toBeInstanceOf(LogNotConfirmedError)
  })

  it('refuses an entry whose versionId has no ordinal', async () => {
    const { resource } = fakeLogResource(serializeResourceLog([entryAt(1)]))
    const store = resourceLogStore({ resource })
    const bad = { ...entryAt(1), versionId: 'Qm-no-ordinal' }
    await expect(confirmAppend({ store, entry: bad })).rejects.toBeInstanceOf(
      ValidationError
    )
  })
})

describe('writeLogProjection', () => {
  it('writes the head state with the history dispatch hint added', async () => {
    const writes: unknown[] = []
    const resource = {
      id: 'user-key.json',
      put: async (data: unknown) => {
        writes.push(data)
        return {}
      }
    } as unknown as Resource
    const history = {
      method: 'was-resource-log:0.1',
      resource: 'https://h.example/space/s/key-map/user-key.jsonl'
    }
    await writeLogProjection({ resource, state: entryAt(2).state, history })
    expect(writes).toEqual([{ ...entryAt(2).state, history }])
  })

  it('refuses a state that already carries a history member', async () => {
    const resource = { id: 'r', put: async () => ({}) } as unknown as Resource
    await expect(
      writeLogProjection({
        resource,
        state: { type: 'T', history: {} },
        history: { method: 'm', resource: 'r' }
      })
    ).rejects.toBeInstanceOf(ValidationError)
  })
})

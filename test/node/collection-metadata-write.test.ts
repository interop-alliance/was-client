/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Unit tests for the one compose path behind every Collection Metadata write:
 * the merge runs against the read the write is pinned to, an unreadable object
 * is refused instead of upserted over, members this client does not model are
 * carried forward, a write that declares encryption re-seals the stored
 * `custom`, and the guarded create takes its codec from the body rather than
 * from stored state. A stub `ZcapClient` answers every request, so no signer or
 * server is involved.
 */
import { describe, it, expect } from 'vitest'

import type { HttpResponse } from '@interop/http-client'

import { WasClient, NotFoundError } from '../../src/index.js'
import type {
  CollectionMetadata,
  EncryptionProvider,
  ResourceCodec
} from '../../src/index.js'
import type { RequestArgs } from '../helpers/stubClient.js'
import { jsonResponse } from '../helpers/stubClient.js'

/**
 * Builds a `WasClient` whose stub answers each request through `handler`,
 * recording every call.
 *
 * @param handler {function}   the canned answer for one request
 * @param [encryption] {EncryptionProvider}   the client's keystore, when the
 *   test needs an encryption-capable client
 * @returns {object} { client, calls }
 */
function clientWith(
  handler: (args: RequestArgs) => HttpResponse,
  encryption?: EncryptionProvider
): { client: WasClient; calls: RequestArgs[] } {
  const calls: RequestArgs[] = []
  const zcapClient = {
    invocationSigner: { id: 'did:example:alice#key-1' },
    async request(args: RequestArgs) {
      // Recorded before the answer, so a call the handler fails (a 412 rebase,
      // a masked 404) still shows up in the log.
      calls.push(args)
      return handler(args)
    }
  } as unknown as ConstructorParameters<typeof WasClient>[0]['zcapClient']
  const client = new WasClient({
    serverUrl: 'https://was.example',
    zcapClient,
    ...(encryption !== undefined && { encryption })
  })
  return { client, calls }
}

/**
 * A stored Collection Metadata object served with its validator.
 *
 * @param metadata {Record<string, unknown>}
 * @param etag {string}
 * @returns {HttpResponse}
 */
function served(metadata: Record<string, unknown>, etag: string): HttpResponse {
  return jsonResponse({ data: metadata, status: 200, headers: { etag } })
}

/**
 * Throws the stub error shape `mapError` reads a status off.
 *
 * @param status {number}
 * @returns {never}
 */
function failWith(status: number): never {
  throw { status, response: { status } }
}

describe('the merge runs against the version the write pins to', () => {
  it('re-merges over a rival configuration change on a 412 rebase', async () => {
    // Client A renames while client B declares a `generator`. A's first
    // attempt is pinned to the version it read and loses; the rebase re-reads
    // AND re-merges, so B's member survives instead of being re-cleared by a
    // merge frozen before B landed.
    let version = 1
    const { client, calls } = clientWith(args => {
      if (args.method === 'GET') {
        return version === 1
          ? served({ id: 'c', type: ['Collection'], name: 'Old' }, '"1"')
          : served(
              {
                id: 'c',
                type: ['Collection'],
                name: 'Old',
                generator: 'did:example:app'
              },
              '"2"'
            )
      }
      if (version === 1) {
        version = 2
        failWith(412)
      }
      return jsonResponse({ status: 204, headers: { etag: '"3"' } })
    })
    await client
      .space('s')
      .collection('c')
      .configure({ name: 'Renamed', force: true })
    const writes = calls.filter(call => call.method === 'PUT')
    expect(writes).toHaveLength(2)
    expect(writes[0]?.json).toMatchObject({ name: 'Renamed' })
    expect(writes[0]?.json).not.toHaveProperty('generator')
    // The rebased write carries the rival's member forward.
    expect(writes[1]?.json).toMatchObject({
      name: 'Renamed',
      generator: 'did:example:app'
    })
    expect(writes[1]?.headers?.['if-match']).toBe('"2"')
  })

  it('composes the write against the read the caller just made', async () => {
    // `describe()` and the write that follows it are one GET plus one PUT: the
    // read carries the validator the write pins to, so it is the baseline
    // rather than a second GET of the same object.
    const { client, calls } = clientWith(args =>
      args.method === 'GET'
        ? served({ id: 'c', type: ['Collection'], name: 'Old' }, '"1"')
        : jsonResponse({ status: 204, headers: { etag: '"2"' } })
    )
    const collection = client.space('s').collection('c')
    await collection.describe()
    await collection.configure({ name: 'Renamed', force: true })
    expect(calls.map(call => call.method)).toEqual(['GET', 'PUT'])
    expect(calls[1]?.headers?.['if-match']).toBe('"1"')
  })
})

describe('an annotation write on an unreadable Collection', () => {
  it('refuses setMeta rather than upserting a configuration-less Collection', async () => {
    const { client, calls } = clientWith(args =>
      args.method === 'GET' ? failWith(404) : jsonResponse({ status: 204 })
    )
    await expect(
      client
        .space('s')
        .collection('c')
        .setMeta({ custom: { name: 'x' } })
    ).rejects.toBeInstanceOf(NotFoundError)
    expect(calls.some(call => call.method === 'PUT')).toBe(false)
  })

  it('refuses setName on a Collection that is absent or not visible', async () => {
    const { client, calls } = clientWith(args =>
      args.method === 'GET' ? failWith(404) : jsonResponse({ status: 204 })
    )
    await expect(
      client.space('s').collection('c').setName('x')
    ).rejects.toBeInstanceOf(NotFoundError)
    expect(calls.some(call => call.method === 'PUT')).toBe(false)
  })

  it('refuses a write pinned to a validator when the object is gone', async () => {
    const { client } = clientWith(args =>
      args.method === 'GET' ? failWith(404) : jsonResponse({ status: 204 })
    )
    await expect(
      client
        .space('s')
        .collection('c')
        .setMeta({ custom: {} }, { ifMatch: '"1"' })
    ).rejects.toBeInstanceOf(NotFoundError)
  })

  it('still creates under `ifNoneMatch`, which states its own absence', async () => {
    const { client, calls } = clientWith(() =>
      jsonResponse({ status: 201, headers: { etag: '"1"' } })
    )
    await client
      .space('s')
      .collection('c')
      .setMeta({ custom: { name: 'x' } }, { ifNoneMatch: true })
    expect(calls).toHaveLength(1)
    expect(calls[0]?.method).toBe('PUT')
    expect(calls[0]?.headers?.['if-none-match']).toBe('*')
    expect(calls[0]?.json).toEqual({ id: 'c', custom: { name: 'x' } })
  })
})

/**
 * A codec that seals `custom` into a marker envelope and refuses to open one
 * it did not write, standing in for the EDV codec's behavior at the metadata
 * slot.
 *
 * @returns {ResourceCodec}
 */
function sealingCodec(): ResourceCodec {
  return {
    async encode({ id, data }) {
      return { id, json: data as object }
    },
    async decode() {
      return null
    },
    async encodeMeta({ custom }) {
      return { custom: { jwe: custom }, epoch: 'epoch-1' }
    },
    async decodeMeta(stored: { custom?: unknown }) {
      const envelope = stored.custom as { jwe?: object } | undefined
      if (envelope?.jwe === undefined) {
        throw new Error('not an envelope this reader can open')
      }
      return envelope.jwe
    }
  } as ResourceCodec
}

describe('a write that declares encryption', () => {
  const descriptor = { scheme: 'edv', version: 1 } as const

  it('re-seals the stored plaintext custom under the incoming descriptor', async () => {
    // The server validates `custom` against the INCOMING descriptor, so a
    // plaintext `custom` cannot travel beside a newly declared one.
    const { client, calls } = clientWith(
      args =>
        args.method === 'GET'
          ? served(
              {
                id: 'c',
                type: ['Collection'],
                name: 'Docs',
                custom: { name: 'Notes' }
              },
              '"1"'
            )
          : jsonResponse({ status: 204, headers: { etag: '"2"' } }),
      {
        async codecFor() {
          return sealingCodec()
        }
      }
    )
    await client
      .space('s')
      .collection('c')
      .replaceDescription({ name: 'Docs', encryption: descriptor })
    const write = calls.find(call => call.method === 'PUT')
    expect(write?.json).toMatchObject({
      encryption: descriptor,
      custom: { jwe: { name: 'Notes' } },
      epoch: 'epoch-1'
    })
  })

  it('drops the custom when this client cannot build the incoming codec', async () => {
    // A plaintext-only client has no keystore, so there is no codec to re-seal
    // under: the envelope is dropped rather than sent as plaintext beside the
    // descriptor (which the server refuses, 422).
    const { client, calls } = clientWith(args =>
      args.method === 'GET'
        ? served(
            {
              id: 'c',
              type: ['Collection'],
              custom: { name: 'Notes' }
            },
            '"1"'
          )
        : jsonResponse({ status: 204, headers: { etag: '"2"' } })
    )
    await client
      .space('s')
      .collection('c')
      .replaceDescription({ encryption: descriptor })
    const write = calls.find(call => call.method === 'PUT')
    expect(write?.json).toMatchObject({ encryption: descriptor })
    expect(write?.json).not.toHaveProperty('custom')
    expect(write?.json).not.toHaveProperty('epoch')
  })

  it('leaves the stored envelope alone when the scheme does not change', async () => {
    // An epoch rotation CASes the same descriptor's roster: the envelope stays
    // sealed under the epoch its stamp names.
    const stored = {
      id: 'c',
      type: ['Collection'],
      encryption: descriptor,
      custom: { jwe: { name: 'Notes' } },
      epoch: 'epoch-1'
    }
    const { client, calls } = clientWith(
      args =>
        args.method === 'GET'
          ? served(stored, '"1"')
          : jsonResponse({ status: 204, headers: { etag: '"2"' } }),
      {
        async codecFor() {
          return sealingCodec()
        }
      }
    )
    await client
      .space('s')
      .collection('c')
      .replaceDescription({ encryption: { ...descriptor, currentEpoch: 'e2' } })
    const write = calls.find(call => call.method === 'PUT')
    expect(write?.json).toMatchObject({
      custom: { jwe: { name: 'Notes' } },
      epoch: 'epoch-1'
    })
  })

  it('creates with the plaintext codec, without discovering a descriptor', async () => {
    // An encryption-capable client would otherwise fail closed on the masked
    // 404 of the object it is about to create.
    const { client, calls } = clientWith(
      args => {
        if (args.method === 'GET') {
          throw new Error('the guarded create must not read stored state')
        }
        return jsonResponse({ status: 201, headers: { etag: '"1"' } })
      },
      {
        async codecFor() {
          throw new Error('no keys for a Collection that does not exist yet')
        }
      }
    )
    await client
      .space('s')
      .collection('c')
      .setMeta({ custom: { name: 'x' } }, { ifNoneMatch: true })
    expect(calls[0]?.json).toEqual({ id: 'c', custom: { name: 'x' } })
  })
})

describe('members this client does not model', () => {
  it('carries them forward through an annotation write', async () => {
    const { client, calls } = clientWith(args =>
      args.method === 'GET'
        ? served(
            {
              id: 'c',
              type: ['Collection'],
              url: 'https://was.example/space/s/c/',
              linkset: 'https://was.example/space/s/c/linkset',
              createdAt: '2026-01-01T00:00:00Z',
              updatedAt: '2026-01-02T00:00:00Z',
              createdBy: 'did:example:alice',
              name: 'Docs',
              plaintext: { indexes: ['title'] },
              somethingNewer: { kept: true }
            },
            '"1"'
          )
        : jsonResponse({ status: 204, headers: { etag: '"2"' } })
    )
    await client
      .space('s')
      .collection('c')
      .setMeta({ custom: { name: 'x' } })
    const write = calls.find(call => call.method === 'PUT')
    expect(write?.json).toEqual({
      id: 'c',
      name: 'Docs',
      plaintext: { indexes: ['title'] },
      somethingNewer: { kept: true },
      custom: { name: 'x' }
    })
  })

  it('carries them forward through a configuration write', async () => {
    const { client, calls } = clientWith(args =>
      args.method === 'GET'
        ? served(
            {
              id: 'c',
              type: ['Collection'],
              name: 'Docs',
              plaintext: { indexes: ['title'] },
              custom: { name: 'Notes' }
            },
            '"1"'
          )
        : jsonResponse({ status: 204, headers: { etag: '"2"' } })
    )
    await client.space('s').collection('c').replaceDescription({ name: 'New' })
    const write = calls.find(call => call.method === 'PUT')
    expect(write?.json).toEqual({
      id: 'c',
      name: 'New',
      plaintext: { indexes: ['title'] },
      custom: { name: 'Notes' }
    })
  })

  it('never echoes the etag a describe() projection carried', async () => {
    const { client, calls } = clientWith(args =>
      args.method === 'GET'
        ? served({ id: 'c', type: ['Collection'], name: 'Docs' }, '"1"')
        : jsonResponse({ status: 204, headers: { etag: '"2"' } })
    )
    const collection = client.space('s').collection('c')
    const current = await collection.describe()
    await collection.configure({
      name: 'Renamed',
      current: current as CollectionMetadata & { etag?: string }
    })
    const write = calls.find(call => call.method === 'PUT')
    expect(write?.json).not.toHaveProperty('etag')
    expect(write?.headers?.['if-match']).toBe('"1"')
  })
})

describe('a custom this reader cannot open', () => {
  it('does not brick the operations that do not need it', async () => {
    // Codec resolution decodes the same read's `custom` for the index schema.
    // A reader removed from the collection cannot open it, which must not fail
    // every get/put on the handle -- only the calls that want the annotations.
    const { client } = clientWith(
      args => {
        if (args.url?.endsWith('/meta')) {
          return served(
            {
              id: 'c',
              type: ['Collection'],
              encryption: { scheme: 'edv', version: 1 } as const,
              custom: { foreign: 'envelope' }
            },
            '"1"'
          )
        }
        return jsonResponse({ data: { ok: true }, status: 200 })
      },
      {
        async codecFor() {
          return sealingCodec()
        }
      }
    )
    const collection = client.space('s').collection('c')
    await expect(collection.put('r', { a: 1 })).resolves.toBeDefined()
    await expect(collection.meta()).rejects.toThrow(
      'not an envelope this reader can open'
    )
  })
})

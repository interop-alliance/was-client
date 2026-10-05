/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Unit tests for the replica registration API on `Space`
 * (`registerReplica` / `replicas` / `replica` / `deregisterReplica` /
 * `replicaStatus`), the `replicas` member of the Space Metadata object, the
 * server-managed `created` stamp on the Collection Metadata object, and the
 * read-only `GET` form of the `changes` query. A stub `ZcapClient` captures
 * the request args and returns canned `HttpResponse`s, so no signer or server
 * is involved.
 */
import { describe, it, expect } from 'vitest'

import type {
  ReplicaRegistration,
  ReplicaStatus,
  Space,
  SpaceMetadata
} from '../../src/index.js'
import {
  ConflictError,
  NotFoundError,
  ProblemTypes,
  ValidationError,
  WasServerError
} from '../../src/index.js'
import {
  clientWithRequestSpy,
  clientWithStub,
  jsonResponse
} from '../helpers/stubClient.js'

const registration = {
  id: 'peer',
  fromSpace: 'https://source.example/space/reg-src/',
  toSpace: 'https://was.example/space/s/',
  capability: {
    '@context': 'https://w3id.org/zcap/v1',
    id: 'urn:uuid:1',
    parentCapability: 'urn:zcap:root:x',
    invocationTarget: 'https://source.example/space/reg-src/',
    controller: 'did:key:z6MkServer',
    allowedAction: ['GET'],
    proof: {}
  },
  role: 'source'
} as unknown as ReplicaRegistration

/**
 * A thrown `@interop/http-client` error carrying a `problem+json` body of the
 * given type, as the stub's `request` rejects with.
 */
function problem({ status, type }: { status: number; type: string }): object {
  return {
    status,
    response: { status },
    data: { type, title: 'refused', errors: [{ detail: 'why' }] }
  }
}

describe('space.registerReplica()', () => {
  it('POSTs the registration and returns the stored record', async () => {
    const { client, calls } = clientWithRequestSpy({
      data: registration,
      etag: '"1"'
    })
    const result = await client.space('s').registerReplica(registration)
    expect(calls[0]?.url).toBe('https://was.example/space/s/replicas')
    expect(calls[0]?.method).toBe('POST')
    expect(calls[0]?.json).toEqual(registration)
    expect(result).toEqual(registration)
  })

  it.each([
    [409, ProblemTypes.REPLICA_REFUSED, ConflictError],
    [409, ProblemTypes.ID_CONFLICT, ConflictError],
    [400, ProblemTypes.INVALID_REQUEST_BODY, ValidationError]
  ])(
    'surfaces a %i %s as a %p told apart by its problem type',
    async (status, type, errorClass) => {
      const client = clientWithStub(() => {
        throw problem({ status, type })
      })
      const attempt = client.space('s').registerReplica(registration)
      await expect(attempt).rejects.toBeInstanceOf(errorClass)
      await expect(attempt).rejects.toMatchObject({ status, type })
    }
  )
})

describe('replica calls on a 2xx with no JSON body', () => {
  it.each([
    ['registerReplica', (space: Space) => space.registerReplica(registration)],
    ['replicas', (space: Space) => space.replicas()],
    ['replica', (space: Space) => space.replica('peer')],
    ['replicaStatus', (space: Space) => space.replicaStatus('peer')]
  ])(
    '%s throws WasServerError naming the content type instead of reading it as null',
    async (_name, call) => {
      const client = clientWithStub(() =>
        jsonResponse({ status: 200, headers: { 'content-type': 'text/plain' } })
      )
      const attempt = call(client.space('s'))
      await expect(attempt).rejects.toBeInstanceOf(WasServerError)
      await expect(attempt).rejects.toThrow(/text\/plain/)
    }
  )
})

describe('space.replicas()', () => {
  it('GETs the listing and returns it unshaped', async () => {
    const listing = {
      url: '/space/s/replicas',
      totalItems: 1,
      items: [registration]
    }
    const { client, calls } = clientWithRequestSpy({ data: listing })
    const result = await client.space('s').replicas()
    expect(calls[0]?.url).toBe('https://was.example/space/s/replicas')
    expect(calls[0]?.method).toBe('GET')
    expect(result).toEqual(listing)
  })

  it('returns null when the space is missing or the caller is not its controller (404)', async () => {
    const { client } = clientWithRequestSpy({ fail: 404 })
    expect(await client.space('s').replicas()).toBeNull()
  })
})

describe('space.replica()', () => {
  it('GETs the per-id path and returns the record', async () => {
    const { client, calls } = clientWithRequestSpy({ data: registration })
    const result = await client.space('s').replica('peer')
    expect(calls[0]?.url).toBe('https://was.example/space/s/replicas/peer')
    expect(calls[0]?.method).toBe('GET')
    expect(result).toEqual(registration)
  })

  it('percent-encodes the replica id', async () => {
    const { client, calls } = clientWithRequestSpy({ data: registration })
    await client.space('s').replica('a b')
    expect(calls[0]?.url).toBe('https://was.example/space/s/replicas/a%20b')
  })

  it('returns null when the registration is absent (404)', async () => {
    const { client } = clientWithRequestSpy({ fail: 404 })
    expect(await client.space('s').replica('missing')).toBeNull()
  })
})

describe('space.deregisterReplica()', () => {
  it('DELETEs the per-id path and reports the removal', async () => {
    const { client, calls } = clientWithRequestSpy()
    const result = await client.space('s').deregisterReplica('peer')
    expect(calls[0]?.url).toBe('https://was.example/space/s/replicas/peer')
    expect(calls[0]?.method).toBe('DELETE')
    expect(result).toEqual({ outcome: 'deleted' })
  })

  it("reports 'not-found' on the masked 404 instead of resolving as success", async () => {
    const { client } = clientWithRequestSpy({ fail: 404 })
    await expect(
      client.space('s').deregisterReplica('missing')
    ).resolves.toEqual({ outcome: 'not-found' })
  })

  it('surfaces the replica-refused removal as a ConflictError', async () => {
    const client = clientWithStub(() => {
      throw problem({ status: 409, type: ProblemTypes.REPLICA_REFUSED })
    })
    await expect(
      client.space('s').deregisterReplica('peer')
    ).rejects.toMatchObject({ type: ProblemTypes.REPLICA_REFUSED })
  })
})

describe('space.replicaStatus()', () => {
  it('GETs the status sub-resource and exposes stall.reason', async () => {
    const status: ReplicaStatus = {
      state: 'stalled',
      lastPullAt: '2026-10-05T00:00:00Z',
      collections: [
        { id: 'notes', state: 'synced', lastAppliedAt: '2026-10-05T00:00:00Z' },
        {
          id: 'photos',
          state: 'stalled',
          stall: { reason: 'clock-bound', since: '2026-10-05T00:00:01Z' }
        }
      ]
    }
    const { client, calls } = clientWithRequestSpy({ data: status })
    const result = await client.space('s').replicaStatus('peer')
    expect(calls[0]?.url).toBe(
      'https://was.example/space/s/replicas/peer/status'
    )
    expect(calls[0]?.method).toBe('GET')
    expect(result).toEqual(status)
    expect(result?.collections[1]?.stall?.reason).toBe('clock-bound')
  })

  it('returns null when the registration is absent (404)', async () => {
    const { client } = clientWithRequestSpy({ fail: 404 })
    expect(await client.space('s').replicaStatus('missing')).toBeNull()
  })
})

describe('space.describe() replicas member', () => {
  it('surfaces the server-derived replicas summaries without shaping', async () => {
    const description: SpaceMetadata = {
      id: 's',
      type: ['Space'],
      controller: 'did:example:alice' as SpaceMetadata['controller'],
      replicas: [
        {
          fromSpace: 'https://source.example/space/reg-src/',
          toSpace: 'https://was.example/space/s/',
          role: 'source'
        }
      ]
    }
    const { client } = clientWithRequestSpy({ data: description })
    const result = await client.space('s').describe()
    expect(result?.replicas).toEqual(description.replicas)
  })
})

describe('collection.meta() created stamp', () => {
  const created = {
    updatedAt: '2026-10-01T00:00:00Z',
    updatedAtCounter: 3,
    originId: 'srv-1'
  }

  it('surfaces the server-managed created stamp', async () => {
    const { client } = clientWithRequestSpy({
      data: { id: 'c', created, custom: {} },
      etag: '"1"'
    })
    const result = await client.space('s').collection('c').meta()
    expect(result?.created).toEqual(created)
  })

  it('sends none of the server-managed stamp members the read served', async () => {
    const { client, calls } = clientWithRequestSpy({
      data: {
        id: 'c',
        name: 'Docs',
        createdAt: '2026-10-01T00:00:00Z',
        created,
        updatedAt: '2026-10-02T00:00:00Z',
        updatedAtCounter: 7,
        originId: 'srv-1',
        custom: { name: 'Docs' }
      },
      etag: '"1"'
    })
    const collection = client.space('s').collection('c')
    await collection.setMeta({ custom: { name: 'x' } })
    await collection.configure({ name: 'Renamed' })
    const writes = calls.filter(call => call.method === 'PUT')
    expect(writes).toHaveLength(2)
    const stamped = [
      'createdAt',
      'created',
      'updatedAt',
      'updatedAtCounter',
      'originId'
    ]
    for (const write of writes) {
      for (const member of stamped) {
        expect(write.json).not.toHaveProperty(member)
      }
    }
  })
})

describe('collection.changes({ method: "GET" })', () => {
  const page = { documents: [], checkpoint: null }
  // allowedAction: ['GET']
  const getOnlyCapability = registration.capability

  it('GETs the query endpoint with the parameters in the query string', async () => {
    const { client, calls } = clientWithRequestSpy({ data: page })
    const result = await client
      .space('s')
      .collection('notes')
      .changes({ method: 'GET', checkpoint: 'cp/1+=', limit: 10 })
    expect(calls[0]?.method).toBe('GET')
    expect(calls[0]?.url).toBe(
      'https://was.example/space/s/notes/query?profile=changes&checkpoint=cp%2F1%2B%3D&limit=10'
    )
    expect(calls[0]?.json).toBeUndefined()
    expect(result).toEqual(page)
  })

  it('sends only profile=changes when no checkpoint or limit is given', async () => {
    const { client, calls } = clientWithRequestSpy({ data: page })
    await client.space('s').collection('notes').changes({ method: 'GET' })
    expect(calls[0]?.url).toBe(
      'https://was.example/space/s/notes/query?profile=changes'
    )
  })

  it('keeps the POST form by default', async () => {
    const { client, calls } = clientWithRequestSpy({ data: page })
    await client.space('s').collection('notes').changes({ limit: 5 })
    expect(calls[0]?.method).toBe('POST')
    expect(calls[0]?.url).toBe('https://was.example/space/s/notes/query')
    expect(calls[0]?.json).toEqual({ profile: 'changes', limit: 5 })
  })

  it('derives the GET form from a bound capability that excludes POST', async () => {
    const { client, calls } = clientWithRequestSpy({ data: page })
    await client
      .space('s')
      .collection('notes', { capability: getOnlyCapability })
      .changes({ limit: 5 })
    expect(calls[0]?.method).toBe('GET')
    expect(calls[0]?.url).toBe(
      'https://was.example/space/s/notes/query?profile=changes&limit=5'
    )
  })

  it('keeps POST under a capability whose actions include POST', async () => {
    const { client, calls } = clientWithRequestSpy({ data: page })
    const capability = { ...getOnlyCapability, allowedAction: 'POST' }
    await client.space('s').collection('notes', { capability }).changes()
    expect(calls[0]?.method).toBe('POST')
  })

  it('walks resourceChanges() in the derived GET form', async () => {
    const { client, calls } = clientWithRequestSpy({ data: page })
    const walk = client
      .space('s')
      .collection('notes', { capability: getOnlyCapability })
      .resourceChanges()
    for await (const _entry of walk) {
      // drain
    }
    expect(calls[0]?.method).toBe('GET')
  })

  it('throws (no null-on-404) when the collection is not visible', async () => {
    const { client } = clientWithRequestSpy({ fail: 404 })
    await expect(
      client.space('s').collection('notes').changes({ method: 'GET' })
    ).rejects.toBeInstanceOf(NotFoundError)
  })
})

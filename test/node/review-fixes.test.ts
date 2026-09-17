/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Unit tests for two whole-codebase-review fixes whose natural test homes are
 * off-limits to this change: `fromCapability` on a sub-path-mounted server (it
 * must strip `serverUrl`'s base path via `parseSpaceTarget`, not classify the
 * raw pathname), and the deterministic write-epoch selection in
 * `resolveEpochKeys` (currentEpoch by id lookup, refusing a descriptor that
 * omits it or names an unlisted epoch).
 */
import { describe, it, expect } from 'vitest'
import { X25519KeyAgreementKey2020 } from '@interop/x25519-key-agreement-key'
import type { IKeyAgreementKey } from '@interop/data-integrity-core'

import {
  WasClient,
  ValidationError,
  WasServerError,
  EncryptionError,
  EncryptOnlyCipherError,
  NotFoundError,
  NotSupportedError,
  PreconditionFailedError
} from '../../src/index.js'
import type { CollectionEncryption, IZcap } from '../../src/index.js'
import { Space } from '../../src/Space.js'
import { Collection } from '../../src/Collection.js'
import { Resource } from '../../src/Resource.js'
import {
  mintEpoch,
  wrapEpochSecret,
  epochKeyIdFor
} from '../../src/edv/epochCrypto.js'
import { resolveEpochKeys } from '../../src/edv/epochKeys.js'
import { DescriptorRefreshPolicy } from '../../src/edv/refresh.js'
import { compareAndSwap } from '../../src/internal/cas.js'
import { createdResource } from '../../src/internal/content.js'
import {
  clientWithStub,
  jsonResponse,
  serviceDescriptionFor
} from '../helpers/stubClient.js'

/**
 * Builds a `WasClient` over a stub `ZcapClient` (no signer, no I/O -- only the
 * `invocationSigner.id` `fromCapability` needs for its context).
 *
 * @param serverUrl {string}
 * @returns {WasClient}
 */
function clientFor(serverUrl: string): WasClient {
  const zcapClient = {
    invocationSigner: { id: 'did:example:alice#key-1' }
  } as unknown as ConstructorParameters<typeof WasClient>[0]['zcapClient']
  return new WasClient({
    serverUrl,
    zcapClient,
    serviceDescription: serviceDescriptionFor(serverUrl)
  })
}

describe('fromCapability on a sub-path-mounted server', () => {
  it('derives a resource handle under a base-path prefix', () => {
    const client = clientFor('https://host/was/')
    const handle = client.fromCapability({
      invocationTarget: 'https://host/was/space/s/c/r'
    } as never)
    expect(handle).toBeInstanceOf(Resource)
    const resource = handle as Resource
    expect(resource.spaceId).toBe('s')
    expect(resource.collectionId).toBe('c')
    expect(resource.id).toBe('r')
  })

  it('derives a collection handle under a base-path prefix', () => {
    const client = clientFor('https://host/was')
    const handle = client.fromCapability({
      invocationTarget: 'https://host/was/space/s/c'
    } as never)
    expect(handle).toBeInstanceOf(Collection)
  })

  it('derives a space handle under a base-path prefix', () => {
    const client = clientFor('https://host/was/')
    const handle = client.fromCapability({
      invocationTarget: 'https://host/was/space/s'
    } as never)
    expect(handle).toBeInstanceOf(Space)
    expect((handle as Space).id).toBe('s')
  })

  it('rejects a target on a different base path or origin', () => {
    const client = clientFor('https://host/was/')
    // Right origin, wrong base path (no `/was/` prefix).
    expect(() =>
      client.fromCapability({
        invocationTarget: 'https://host/space/s'
      } as never)
    ).toThrow(ValidationError)
    // Different origin entirely.
    expect(() =>
      client.fromCapability({
        invocationTarget: 'https://other/was/space/s'
      } as never)
    ).toThrow(ValidationError)
  })
})

/**
 * Generates a self-describing did:key X25519 reader (its `id` is
 * `did:key:<pub>#<pub>`, matching what a recipient entry's `kid` carries).
 *
 * @returns {Promise<{ kak: IKeyAgreementKey; publicKeyMultibase: string }>}
 */
async function makeReader(): Promise<{
  kak: IKeyAgreementKey
  publicKeyMultibase: string
}> {
  const kak = await X25519KeyAgreementKey2020.generate()
  const publicKeyMultibase = kak.publicKeyMultibase
  const did = `did:key:${publicKeyMultibase}`
  kak.controller = did
  kak.id = `${did}#${publicKeyMultibase}`
  return { kak: kak as IKeyAgreementKey, publicKeyMultibase }
}

/**
 * Mints an epoch and wraps its secret to each reader, producing a descriptor
 * epoch entry alongside the epoch id (so a test can order epochs and pick a
 * `currentEpoch` independently of array position).
 *
 * @param readers {Array<{ kak: IKeyAgreementKey; publicKeyMultibase: string }>}
 * @returns {Promise<{ id: string; recipients: object[] }>}
 */
async function epochEntryFor(
  readers: Array<{ kak: IKeyAgreementKey; publicKeyMultibase: string }>
): Promise<{ id: string; recipients: unknown[]; secret: Uint8Array }> {
  const { epochId, secret } = await mintEpoch()
  const recipients = await Promise.all(
    readers.map(reader =>
      wrapEpochSecret({
        epochSecret: secret,
        recipient: {
          id: reader.kak.id,
          publicKeyMultibase: reader.publicKeyMultibase
        }
      })
    )
  )
  return { id: epochId, recipients, secret }
}

describe('resolveEpochKeys write-epoch selection', () => {
  it('selects currentEpoch by id even when it is not the array-last epoch', async () => {
    const alice = await makeReader()
    const first = await epochEntryFor([alice])
    const second = await epochEntryFor([alice])
    // List `second` before `first`, but point `currentEpoch` at `first`: the
    // write epoch must come from the id lookup, never the array position.
    const encryption = {
      scheme: 'edv',
      epochs: [second, first],
      currentEpoch: first.id
    } as unknown as CollectionEncryption
    const resolved = await resolveEpochKeys({
      encryption,
      keyAgreementKey: alice.kak
    })
    expect(resolved!.writeEpoch).toBe(first.id)
    expect(resolved!.writeKey.id).toBe(epochKeyIdFor(first.id))
    expect(resolved!.readKeys.length).toBe(2)
  })

  it('writes to currentEpoch through a stand-in when rotated off it', async () => {
    const bob = await makeReader()
    const inX = await epochEntryFor([bob])
    const inY = await epochEntryFor([bob])
    const notInZ = await epochEntryFor([await makeReader()])
    // Bob is a recipient of X and Y but not of the current epoch Z. He must
    // NOT fall back to Y: writing under an epoch he was rotated off of would
    // seal fresh plaintext to a key every removed recipient of Y still holds.
    // The write epoch stays Z, sealed through a public-only stand-in.
    const encryption = {
      scheme: 'edv',
      epochs: [inX, inY, notInZ],
      currentEpoch: notInZ.id
    } as unknown as CollectionEncryption
    const resolved = await resolveEpochKeys({
      encryption,
      keyAgreementKey: bob.kak
    })
    expect(resolved!.writeEpoch).toBe(notInZ.id)
    expect(resolved!.writeKey.id).toBe(epochKeyIdFor(notInZ.id))
    expect(resolved!.namedInWriteEpoch).toBe(false)
    // The stand-in seals to Z and unseals nothing under it.
    await expect(
      resolved!.writeKey.deriveSecret({
        publicKey: { type: 'X25519KeyAgreementKey2020' }
      } as never)
    ).rejects.toThrow(EncryptOnlyCipherError)
    // Bob's history stays readable: X and Y, and never Z.
    expect(resolved!.readKeys.map(key => key.id).sort()).toEqual(
      [epochKeyIdFor(inX.id), epochKeyIdFor(inY.id)].sort()
    )
  })

  it('refuses a descriptor that declares no currentEpoch', async () => {
    const alice = await makeReader()
    const older = await epochEntryFor([alice])
    const newer = await epochEntryFor([alice])
    // Listed newest-first with no `currentEpoch`: a last-entry fallback would
    // seal writes to `older`, whose key a reader removed at the rotation to
    // `newer` still holds.
    const encryption = {
      scheme: 'edv',
      epochs: [newer, older]
    } as unknown as CollectionEncryption
    await expect(
      resolveEpochKeys({ encryption, keyAgreementKey: alice.kak })
    ).rejects.toThrow(EncryptionError)
  })

  it('refuses a currentEpoch the roster does not list', async () => {
    const alice = await makeReader()
    const listed = await epochEntryFor([alice])
    const encryption = {
      scheme: 'edv',
      epochs: [listed],
      currentEpoch: 'urn:epoch:never-listed'
    } as unknown as CollectionEncryption
    await expect(
      resolveEpochKeys({ encryption, keyAgreementKey: alice.kak })
    ).rejects.toThrow(EncryptionError)
  })
})

describe('compareAndSwap on an absent store', () => {
  it('creates the seed even when mutate reports nothing to change', async () => {
    // `null` from `mutate` means "already in the desired state". On the
    // replace path that value is stored; on the absent path nothing is, so
    // returning the seed unwritten would resolve a value that exists nowhere.
    const stored: string[] = []
    const written = await compareAndSwap<string>({
      store: {
        async read() {
          return null
        },
        async create(value: string) {
          stored.push(value)
        },
        async replace() {
          throw new Error('not reached')
        }
      },
      mutate: () => null,
      operation: 'Seed',
      onAbsent: () => 'seed'
    })
    expect(written).toBe('seed')
    expect(stored).toEqual(['seed'])
  })
})

describe('compareAndSwap on a read with no validator', () => {
  const unversioned = (
    replaced: Array<{ value: string; ifMatch?: string }>
  ) => ({
    async read() {
      return { value: 'current' }
    },
    async replace(value: string, { ifMatch }: { ifMatch?: string }) {
      replaced.push({ value, ifMatch })
    }
  })

  it('refuses the unconditional replace before writing', async () => {
    const replaced: Array<{ value: string; ifMatch?: string }> = []
    const failure = await compareAndSwap<string>({
      store: unversioned(replaced),
      mutate: () => 'next',
      operation: 'Index declaration'
    }).catch((err: unknown) => err)
    expect(failure).toBeInstanceOf(NotSupportedError)
    expect((failure as Error).message).toMatch(
      /^Index declaration was refused: the read it is pinned to returned no ETag/
    )
    expect(replaced).toEqual([])
  })

  it('writes nothing and refuses nothing when mutate reports no change', async () => {
    const replaced: Array<{ value: string; ifMatch?: string }> = []
    const result = await compareAndSwap<string>({
      store: unversioned(replaced),
      mutate: () => null,
      operation: 'Index declaration'
    })
    expect(result).toBe('current')
    expect(replaced).toEqual([])
  })
})

describe('compareAndSwap on a 412 raised by read()', () => {
  it('rebases the read the same way as a stale replace', async () => {
    // A store's read can observe a concurrent write mid-read (the governed
    // store's projection behind its log). That is a lost race, so the loop
    // re-reads instead of surfacing the conflict.
    let reads = 0
    const written: string[] = []
    const result = await compareAndSwap<string>({
      store: {
        async read() {
          reads += 1
          if (reads === 1) {
            throw new PreconditionFailedError('behind the log', { status: 412 })
          }
          return { value: 'fresh', etag: '"v2"' }
        },
        async replace(value: string) {
          written.push(value)
        }
      },
      mutate: value => `${value}+change`,
      operation: 'Read rebase'
    })
    expect(reads).toBe(2)
    expect(result).toBe('fresh+change')
    expect(written).toEqual(['fresh+change'])
  })

  it('surfaces the exhaustion error when every read keeps losing', async () => {
    const conflict = new PreconditionFailedError('behind the log', {
      status: 412
    })
    await expect(
      compareAndSwap<string>({
        store: {
          async read() {
            throw conflict
          },
          async replace() {
            throw new Error('not reached')
          }
        },
        mutate: value => value,
        operation: 'Read rebase',
        maxAttempts: 2
      })
    ).rejects.toMatchObject({
      name: 'PreconditionFailedError',
      cause: conflict
    })
  })
})

describe('createdResource with a malformed Location', () => {
  it('reports a bad percent escape as a server fault, not a URIError', () => {
    const response = {
      headers: new Headers({ location: '/space/s/c/bad%zz' }),
      url: 'https://was.example/space/s/c'
    } as unknown as Parameters<typeof createdResource>[0]
    let thrown: unknown
    try {
      createdResource(response)
    } catch (err) {
      thrown = err
    }
    expect(thrown).toBeInstanceOf(WasServerError)
    expect((thrown as Error).message).toContain('percent-encoding')
    expect((thrown as Error).cause).toBeInstanceOf(URIError)
  })
})

describe('DescriptorRefreshPolicy', () => {
  it('does not spend the refresh when the refresh itself fails', async () => {
    let attempts = 0
    const policy = new DescriptorRefreshPolicy({
      refresh: async () => {
        attempts += 1
        if (attempts === 1) {
          throw new Error('transient descriptor re-read failure')
        }
      }
    })
    const read = async (): Promise<{ value: string; unknownEpoch: boolean }> =>
      Promise.resolve({ value: 'rows', unknownEpoch: true })
    // The failed refresh returns the read that DID succeed, and leaves the
    // collection's one refresh unspent.
    await expect(
      policy.readWithRefresh({ collectionId: 'c', read })
    ).resolves.toBe('rows')
    expect(policy.shouldRefresh({ collectionId: 'c' })).toBe(true)
    // The next unknown-epoch read retries it, and that one sticks.
    await policy.readWithRefresh({ collectionId: 'c', read })
    expect(attempts).toBe(2)
    expect(policy.shouldRefresh({ collectionId: 'c' })).toBe(false)
  })
})

describe('listSpaces against a body that is not a listing', () => {
  it('reports a server fault rather than destructuring null', async () => {
    const client = clientWithStub(() => jsonResponse({ status: 200 }))
    await expect(client.listSpaces()).rejects.toThrow(WasServerError)
  })
})

describe('changes feed shape guards', () => {
  it('refuses a page whose documents member is not an array', async () => {
    const client = clientWithStub(() =>
      jsonResponse({ data: { checkpoint: null } })
    )
    await expect(client.space('s').collection('c').changes()).rejects.toThrow(
      WasServerError
    )
  })

  it('refuses a page with a non-object entry in its documents array', async () => {
    // `[null]` passes the `Array.isArray` guard, so the per-entry check is
    // what keeps this a `WasServerError` rather than a raw `TypeError`.
    const client = clientWithStub(() =>
      jsonResponse({ data: { documents: [null], checkpoint: null } })
    )
    await expect(client.space('s').collection('c').changes()).rejects.toThrow(
      WasServerError
    )
  })

  it('treats an omitted checkpoint as the end of the walk', async () => {
    // A terminal page that omits `checkpoint` entirely rather than sending an
    // explicit `null` must end the walk, not throw a TypeError.
    const client = clientWithStub(() =>
      jsonResponse({ data: { documents: [{ id: 'a', data: { x: 1 } }] } })
    )
    const documents = await client.space('s').collection('c').documents()
    expect(documents?.map(doc => doc.id)).toEqual(['a'])
  })
})

describe('Resource conditional writes', () => {
  /**
   * A plaintext collection that serves a validator on every read and ack. The
   * `unreadable` variant answers the Collection Metadata read with the 404 WAS
   * masks an unauthorized read as. Records every request's method and URL.
   *
   * @param [readable] {boolean}   whether the Collection Metadata object reads
   * @returns {object}
   */
  function plaintextClient(readable = true) {
    const calls: Array<{ method?: string; url?: string }> = []
    const client = clientWithStub(({ method, url }) => {
      calls.push({ method, url })
      if (method === 'GET') {
        if (!readable) {
          throw Object.assign(new Error('HTTP 404'), { status: 404 })
        }
        return jsonResponse({
          data: { id: 'c', type: ['Collection'], name: 'Plain' },
          headers: { etag: '"g.1"' }
        })
      }
      return jsonResponse({ headers: { etag: '"g.2"' } })
    })
    return { client, calls }
  }

  /**
   * The handle a plain `space().collection().resource()` walk produces.
   *
   * @returns {object}
   */
  function walkedResource() {
    const { client, calls } = plaintextClient()
    return { resource: client.space('s').collection('c').resource('r'), calls }
  }

  it('sends a guarded put with no descriptor read of its own', async () => {
    const { resource, calls } = walkedResource()
    await resource.put({ a: 1 }, { ifMatch: '"g.1"' })
    expect(calls.filter(call => call.url?.endsWith('/backend'))).toEqual([])
    expect(calls.filter(call => call.method === 'PUT')).toHaveLength(1)
  })

  it('sends an unguarded put', async () => {
    const { resource, calls } = walkedResource()
    await resource.put({ a: 1 })
    expect(calls.filter(call => call.method === 'PUT')).toHaveLength(1)
  })

  it('sends a guarded and an unguarded delete', async () => {
    const { resource, calls } = walkedResource()
    await resource.delete({ ifMatch: '"g.1"' })
    await resource.delete()
    expect(calls.filter(call => call.method === 'DELETE')).toHaveLength(2)
  })

  it('sends a setMeta naming ifMatch', async () => {
    const { resource, calls } = walkedResource()
    await resource.setMeta({ custom: { name: 'A' } }, { ifMatch: '"m.1"' })
    expect(calls.filter(call => call.method === 'PUT')).toHaveLength(1)
  })

  it('pins setName to the validator its own read returned', async () => {
    const { resource, calls } = walkedResource()
    await resource.setName('New')
    expect(calls.filter(call => call.method === 'PUT')).toHaveLength(1)
  })

  it('refuses setName when the metadata cannot be read', async () => {
    // A masked 404 must not turn a rename into a create of a metadata document
    // over one this capability simply cannot see.
    const { client } = plaintextClient(false)
    await expect(
      client.space('s').collection('c').resource('r').setName('New')
    ).rejects.toThrow(NotFoundError)
  })

  it('sends a guarded put and delete under a resource-scoped capability', async () => {
    const { client, calls } = plaintextClient()
    const capability = {
      '@context': 'https://w3id.org/zcap/v1',
      id: 'urn:zcap:scoped',
      invocationTarget: 'https://was.example/space/s/c/r'
    } as unknown as IZcap
    const resource = client.fromCapability(capability) as Resource

    await resource.put({ a: 1 }, { ifMatch: '"g.1"' })
    await resource.delete({ ifMatch: '"g.1"' })
    expect(calls.filter(call => call.method === 'PUT')).toHaveLength(1)
    expect(calls.filter(call => call.method === 'DELETE')).toHaveLength(1)
  })
})

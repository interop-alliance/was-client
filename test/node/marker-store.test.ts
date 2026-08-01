/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Unit tests for the marker-store seam (no network): the recipient primitives
 * generalized over a `MarkerStore`. Exercises the plain-JSON-Resource adapter
 * (create-if-absent on the first `initRecipients`, the CAS write path, the
 * absent-marker and malformed-content refusals), the parameterized pull axis
 * of `removeRecipient` (a caller-supplied action in place of the zcap
 * revocation, still fused rotate-first/pull-second), the drop-this-kid skip
 * contract on `resolveRecipientKey`, and the `collection` / `store` argument
 * validation.
 */
import { describe, it, expect } from 'vitest'
import { X25519KeyAgreementKey2020 } from '@interop/x25519-key-agreement-key'
import type { IKeyAgreementKey } from '@interop/data-integrity-core'

import { PreconditionFailedError, ValidationError } from '../../src/index.js'
import type { CollectionEncryption, JsonObject } from '../../src/index.js'
import type { Collection } from '../../src/Collection.js'
import type { Resource } from '../../src/Resource.js'
import { mintEpoch, wrapEpochSecret } from '../../src/edv/epochCrypto.js'
import { resolveEpochKeys } from '../../src/edv/epochKeys.js'
import {
  addRecipient,
  initRecipients,
  removeRecipient
} from '../../src/edv/recipients.js'
import type { RecipientPublicKey } from '../../src/edv/recipients.js'
import { resourceMarkerStore } from '../../src/edv/markerStore.js'

/**
 * Generates a self-describing did:key X25519 reader (see key-epochs.test.ts):
 * its `id` is `did:key:<pub>#<pub>`, so the default `did:key` recipient
 * resolver can recover its public key from the `kid` alone.
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
 * The `RecipientPublicKey` for a generated reader.
 *
 * @param reader {{ kak: IKeyAgreementKey; publicKeyMultibase: string }}
 * @returns {RecipientPublicKey}
 */
function recipientOf(reader: {
  kak: IKeyAgreementKey
  publicKeyMultibase: string
}): RecipientPublicKey {
  return { id: reader.kak.id, publicKeyMultibase: reader.publicKeyMultibase }
}

/**
 * A fake roster Resource for `resourceMarkerStore`: an in-memory versioned
 * JSON document honoring the `ifMatch` / `ifNoneMatch` preconditions (a 412
 * for a stale validator or a guarded create of an existing document), and
 * recording each put's precondition so tests can pin what was sent.
 *
 * @param [initial] {CollectionEncryption | JsonObject}   the starting content
 *   (absent resource when omitted)
 * @returns {object}
 */
function fakeRosterResource(initial?: CollectionEncryption | JsonObject) {
  const state = {
    content: (initial ?? null) as JsonObject | null,
    version: 1,
    puts: [] as Array<{ ifMatch?: string; ifNoneMatch?: boolean }>
  }
  const etag = () => `"v${state.version}"`
  const resource = {
    id: 'puk.json',
    getWithEtag: async () =>
      state.content === null ? null : { data: state.content, etag: etag() },
    put: async (
      data: JsonObject,
      options: { ifMatch?: string; ifNoneMatch?: boolean } = {}
    ) => {
      state.puts.push({
        ifMatch: options.ifMatch,
        ifNoneMatch: options.ifNoneMatch
      })
      if (options.ifNoneMatch && state.content !== null) {
        throw new PreconditionFailedError('exists', { status: 412 })
      }
      if (options.ifMatch !== undefined && options.ifMatch !== etag()) {
        throw new PreconditionFailedError('stale', { status: 412 })
      }
      state.content = data
      state.version++
      return { etag: etag() }
    },
    _state: state
  }
  return resource
}

/**
 * Seeds a one-epoch marker wrapping the epoch key to each of `readers`.
 *
 * @param readers {Array<{ kak: IKeyAgreementKey; publicKeyMultibase: string }>}
 * @returns {Promise<CollectionEncryption>}
 */
async function seedMarker(
  readers: Array<{ kak: IKeyAgreementKey; publicKeyMultibase: string }>
): Promise<CollectionEncryption> {
  const { epochId, secret } = await mintEpoch()
  return {
    scheme: 'edv',
    epochs: [
      {
        id: epochId,
        recipients: await Promise.all(
          readers.map(reader =>
            wrapEpochSecret({
              epochSecret: secret,
              recipient: recipientOf(reader)
            })
          )
        )
      }
    ],
    currentEpoch: epochId
  }
}

describe('resourceMarkerStore', () => {
  it('initRecipients creates an absent roster with If-None-Match', async () => {
    const alice = await makeReader()
    const bob = await makeReader()
    const roster = fakeRosterResource()
    const store = resourceMarkerStore({
      resource: roster as unknown as Resource
    })

    const marker = await initRecipients({
      store,
      recipients: [recipientOf(alice), recipientOf(bob)]
    })
    // The first write was the guarded create, not a blind put.
    expect(roster._state.puts).toEqual([
      { ifMatch: undefined, ifNoneMatch: true }
    ])
    expect(marker.scheme).toBe('edv')
    expect(marker.version).toBe(1)
    expect(marker.epochs).toHaveLength(1)
    expect(marker.currentEpoch).toBe(marker.epochs![0]!.id)
    expect(marker.epochsMac).toBeDefined()
    // The stored roster is the marker verbatim, and a reader resolves keys
    // from it exactly as from a Description-hosted marker.
    expect(roster._state.content).toEqual(marker)
    const keys = await resolveEpochKeys({
      encryption: marker,
      keyAgreementKey: alice.kak
    })
    expect(keys!.readKeys).toHaveLength(1)
  })

  it('a lost create race converges on the already-initialized error', async () => {
    // The roster reads absent, but a concurrent writer creates it before this
    // caller's guarded create lands (412). The retry re-reads the now-present
    // marker and surfaces initRecipients' already-has-epochs refusal instead
    // of clobbering the other writer's roster.
    const alice = await makeReader()
    const bob = await makeReader()
    const roster = fakeRosterResource()
    let readsSeen = 0
    const racing = {
      ...roster,
      getWithEtag: async () => {
        readsSeen++
        if (readsSeen === 1) {
          // Simulate the concurrent writer landing right after this read.
          roster._state.content = (await seedMarker([
            bob
          ])) as unknown as JsonObject
          return null
        }
        return roster.getWithEtag()
      }
    }
    await expect(
      initRecipients({
        store: resourceMarkerStore({ resource: racing as unknown as Resource }),
        recipients: [recipientOf(alice)]
      })
    ).rejects.toThrow(/already has key epochs/)
    // The loser's create never replaced the winner's roster.
    const kids = (
      roster._state.content as unknown as CollectionEncryption
    ).epochs![0]!.recipients.map(entry => entry.header.kid)
    expect(kids).toEqual([bob.kak.id])
  })

  it('addRecipient CAS-updates the roster resource (If-Match)', async () => {
    const alice = await makeReader()
    const bob = await makeReader()
    const roster = fakeRosterResource(
      (await seedMarker([alice])) as unknown as JsonObject
    )
    const marker = await addRecipient({
      store: resourceMarkerStore({ resource: roster as unknown as Resource }),
      recipient: recipientOf(bob),
      owner: { keyAgreementKey: alice.kak }
    })
    expect(roster._state.puts).toEqual([
      { ifMatch: '"v1"', ifNoneMatch: undefined }
    ])
    const kids = marker.epochs![0]!.recipients.map(entry => entry.header.kid)
    expect(kids).toContain(bob.kak.id)
    // Bob resolves his keys from the roster-hosted marker.
    const keys = await resolveEpochKeys({
      encryption: marker,
      keyAgreementKey: bob.kak
    })
    expect(keys!.readKeys).toHaveLength(1)
  })

  it('addRecipient / removeRecipient refuse an absent roster', async () => {
    const alice = await makeReader()
    const bob = await makeReader()
    const store = resourceMarkerStore({
      resource: fakeRosterResource() as unknown as Resource
    })
    await expect(
      addRecipient({
        store,
        recipient: recipientOf(bob),
        owner: { keyAgreementKey: alice.kak }
      })
    ).rejects.toThrow(/Call initRecipients first/)
    await expect(
      removeRecipient({
        store,
        recipientId: bob.kak.id,
        pull: async () => undefined
      })
    ).rejects.toThrow(/Call initRecipients first/)
  })

  it('refuses a resource that does not hold an edv marker', async () => {
    const alice = await makeReader()
    const bob = await makeReader()
    const store = resourceMarkerStore({
      resource: fakeRosterResource({ hello: 'world' }) as unknown as Resource
    })
    await expect(
      addRecipient({
        store,
        recipient: recipientOf(bob),
        owner: { keyAgreementKey: alice.kak }
      })
    ).rejects.toBeInstanceOf(ValidationError)
  })
})

describe('removeRecipient pull axis', () => {
  it('runs a caller-supplied pull action after the rotation is durable', async () => {
    const alice = await makeReader()
    const bob = await makeReader()
    const roster = fakeRosterResource(
      (await seedMarker([alice, bob])) as unknown as JsonObject
    )
    const epochsAtPull: Array<string | undefined> = []
    const rotated = await removeRecipient({
      store: resourceMarkerStore({ resource: roster as unknown as Resource }),
      recipientId: bob.kak.id,
      pull: async () => {
        epochsAtPull.push(
          (roster._state.content as unknown as CollectionEncryption)
            .currentEpoch
        )
      }
    })
    // The pull observed the already-rotated marker (rotate-first is preserved).
    expect(epochsAtPull).toEqual([rotated.currentEpoch])
    const currentEpoch = rotated.epochs!.find(
      epoch => epoch.id === rotated.currentEpoch
    )!
    expect(currentEpoch.recipients.map(entry => entry.header.kid)).toEqual([
      alice.kak.id
    ])
  })

  it('does not pull when the rotation CAS never lands', async () => {
    const alice = await makeReader()
    const bob = await makeReader()
    const roster = fakeRosterResource(
      (await seedMarker([alice, bob])) as unknown as JsonObject
    )
    const staleRoster = {
      ...roster,
      put: async () => {
        throw new PreconditionFailedError('stale', { status: 412 })
      }
    }
    let pulled = false
    await expect(
      removeRecipient({
        store: resourceMarkerStore({
          resource: staleRoster as unknown as Resource
        }),
        recipientId: bob.kak.id,
        pull: async () => {
          pulled = true
        }
      })
    ).rejects.toBeInstanceOf(PreconditionFailedError)
    expect(pulled).toBe(false)
  })

  it('refuses both a custom pull and the default space/revoke axis', async () => {
    const bob = await makeReader()
    const store = resourceMarkerStore({
      resource: fakeRosterResource() as unknown as Resource
    })
    await expect(
      removeRecipient({
        store,
        recipientId: bob.kak.id,
        revoke: [],
        pull: async () => undefined
      })
    ).rejects.toThrow(/not both/)
  })

  it('refuses a call with no pull axis at all', async () => {
    const bob = await makeReader()
    const store = resourceMarkerStore({
      resource: fakeRosterResource() as unknown as Resource
    })
    await expect(
      removeRecipient({ store, recipientId: bob.kak.id })
    ).rejects.toThrow(/pull axis/)
  })
})

describe('resolveRecipientKey drop-this-kid contract', () => {
  it('a null resolution excludes the entry from the fresh epoch', async () => {
    // Readers {alice, bob, carol}; carol is removed, and the resolver drops
    // bob (his kid no longer resolves). The fresh epoch holds only alice --
    // no throw -- and history epochs are untouched.
    const alice = await makeReader()
    const bob = await makeReader()
    const carol = await makeReader()
    const roster = fakeRosterResource(
      (await seedMarker([alice, bob, carol])) as unknown as JsonObject
    )
    const rotated = await removeRecipient({
      store: resourceMarkerStore({ resource: roster as unknown as Resource }),
      recipientId: carol.kak.id,
      pull: async () => undefined,
      resolveRecipientKey: async kid =>
        kid === bob.kak.id ? null : recipientOf(alice)
    })
    const currentEpoch = rotated.epochs!.find(
      epoch => epoch.id === rotated.currentEpoch
    )!
    expect(currentEpoch.recipients.map(entry => entry.header.kid)).toEqual([
      alice.kak.id
    ])
    // The prior epoch still names all three (history is never edited).
    expect(rotated.epochs![0]!.recipients).toHaveLength(3)
  })

  it('keeps the no-recipients-remaining guard when every entry is dropped', async () => {
    const alice = await makeReader()
    const bob = await makeReader()
    const roster = fakeRosterResource(
      (await seedMarker([alice, bob])) as unknown as JsonObject
    )
    await expect(
      removeRecipient({
        store: resourceMarkerStore({ resource: roster as unknown as Resource }),
        recipientId: bob.kak.id,
        pull: async () => undefined,
        resolveRecipientKey: async () => null
      })
    ).rejects.toThrow(/no recipients would remain/)
    // Nothing was written: the roster still holds the seed marker only.
    expect(
      (roster._state.content as unknown as CollectionEncryption).epochs
    ).toHaveLength(1)
  })
})

describe('marker host argument validation', () => {
  it('refuses both collection and store, and neither', async () => {
    const alice = await makeReader()
    const store = resourceMarkerStore({
      resource: fakeRosterResource() as unknown as Resource
    })
    await expect(
      initRecipients({
        collection: {} as unknown as Collection,
        store,
        recipients: [recipientOf(alice)]
      })
    ).rejects.toThrow(/not both/)
    await expect(
      initRecipients({ recipients: [recipientOf(alice)] })
    ).rejects.toThrow(/pass `collection` or `store`/)
  })
})

describe('collectionMarkerStore description-field forwarding', () => {
  it('forwards name/backend observed by the read into the CAS write', async () => {
    // The description hosts more than the marker; the replace-semantics PUT
    // must carry the sibling fields forward or the server would drop them.
    const alice = await makeReader()
    const bob = await makeReader()
    const written: Array<{ name?: string; backend?: unknown }> = []
    const state = { encryption: await seedMarker([alice]) }
    const fake = {
      describeWithEtag: async () => ({
        description: {
          id: 'c',
          type: ['Collection'],
          name: 'My Roster',
          backend: { id: 'urn:backend:demo' },
          encryption: state.encryption
        },
        etag: '"v1"'
      }),
      replaceDescription: async (desc: {
        name?: string
        backend?: unknown
        encryption?: CollectionEncryption
      }) => {
        written.push({ name: desc.name, backend: desc.backend })
        state.encryption = desc.encryption!
        return { description: { id: 'c', type: ['Collection'] }, etag: '"v2"' }
      }
    }
    await addRecipient({
      collection: fake as unknown as Collection,
      recipient: recipientOf(bob),
      owner: { keyAgreementKey: alice.kak }
    })
    expect(written).toEqual([
      { name: 'My Roster', backend: { id: 'urn:backend:demo' } }
    ])
  })
})

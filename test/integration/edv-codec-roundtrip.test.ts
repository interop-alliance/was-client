/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Integration test: encrypted collections through the unified handle seam,
 * end to end against a live WAS server (e.g. was-teaching-server's
 * filesystem backend). A `WasClient` constructed with an `encryption` provider
 * transparently encrypts `collection.add()` / `put()` and decrypts `get()` -- the
 * same plain Collection/Resource API as a plaintext collection, with no EdvClient
 * in sight. Encryption is gated purely on the client holding keys for the
 * collection (the `encryption` provider returning a codec), not on any backend
 * feature.
 *
 * Proves: the value round-trips decrypted; what the server stores is an opaque
 * JWE envelope (the raw `getBytes()` escape hatch shows ciphertext, no
 * cleartext); a small blob round-trips; user metadata (`setName`/`setTags`) is
 * likewise encrypted -- round-tripping decrypted for a keyed reader but opaque at
 * rest -- with its own `/meta` ETag; and the stricter contract holds
 * (human-readable `put()` ids are rejected on an encrypted collection).
 *
 * Requires a running server: set `TEST_SERVER_URL`. The suite skips when it is
 * unset, so a bare `pnpm test:integration` (no server) is not a failure.
 */
import { describe, it, beforeAll, afterAll, expect } from 'vitest'
import type { IKeyAgreementKey } from '@interop/data-integrity-core'
import { X25519KeyAgreementKey2020 } from '@interop/x25519-key-agreement-key'
import { Ed25519VerificationKey } from '@interop/ed25519-verification-key'

import {
  WasClient,
  ValidationError,
  PreconditionFailedError,
  EncryptionError
} from '../../src/index.js'
import type { Space, Collection } from '../../src/index.js'
import { createEdvEncryption } from '../../src/edv/index.js'

const serverUrl = process.env.TEST_SERVER_URL
const describeLive = serverUrl ? describe : describe.skip

/**
 * Builds two WAS clients over the SAME signer: one with an `encryption` provider
 * (encrypts for a single vault-per-collection X25519 key) and one plaintext (no
 * codec). The plaintext client reads what the server actually stores -- a JWE
 * envelope -- to prove ciphertext at rest. The key never leaves the client.
 *
 * Also returns a `keyless` client: encryption-capable (it has an EDV provider)
 * but whose keystore holds no keys, to prove the fail-closed path -- reading a
 * collection declared encrypted throws rather than returning ciphertext.
 *
 * @returns {Promise<{ encrypted: WasClient, plaintext: WasClient, keyless: WasClient }>}
 */
async function freshClients(): Promise<{
  encrypted: WasClient
  plaintext: WasClient
  keyless: WasClient
}> {
  const keyPair = await Ed25519VerificationKey.generate()
  const did = `did:key:${keyPair.fingerprint()}`
  keyPair.id = `${did}#${keyPair.fingerprint()}`
  keyPair.controller = did

  const kak = await X25519KeyAgreementKey2020.generate({ controller: did })
  const keyResolver = async ({ id }: { id?: string }) => {
    if (id !== kak.id) {
      throw new Error(`Unknown key id "${id}".`)
    }
    return {
      id: kak.id,
      type: kak.type,
      publicKeyMultibase: kak.publicKeyMultibase
    }
  }
  const encryption = createEdvEncryption({
    resolveKeys: async () => ({
      keyAgreementKey: kak as IKeyAgreementKey,
      keyResolver
    })
  })
  return {
    encrypted: WasClient.fromSigner({
      serverUrl: serverUrl!,
      signer: keyPair.signer(),
      encryption
    }),
    plaintext: WasClient.fromSigner({
      serverUrl: serverUrl!,
      signer: keyPair.signer()
    }),
    keyless: WasClient.fromSigner({
      serverUrl: serverUrl!,
      signer: keyPair.signer(),
      encryption: createEdvEncryption({ resolveKeys: async () => null })
    })
  }
}

describeLive('encrypted collection via the codec seam (live server)', () => {
  let was: WasClient
  let plaintext: WasClient
  let keyless: WasClient
  let space: Space
  let collection: Collection

  beforeAll(async () => {
    ;({ encrypted: was, plaintext, keyless } = await freshClients())
    space = await was.createSpace({ name: 'EDV Codec Integration' })
    // Declare the collection encrypted: the marker lets any authorized reader
    // discover it (the returned handle is pre-seeded so the first write needs no
    // round-trip), and the keystore supplies the keys.
    collection = await space.createCollection({
      id: 'vault',
      name: 'Vault',
      encryption: { scheme: 'edv' }
    })
  })

  afterAll(async () => {
    try {
      await space.delete()
    } catch {
      /* best-effort cleanup */
    }
  })

  it('add() then get() transparently round-trips the cleartext', async () => {
    const content = { message: 'hello codec seam', n: 7 }
    const { id } = await collection.add(content)
    // The minted id is an EDV multibase value used verbatim as the WAS id.
    expect(id).toMatch(/^z/)

    const got = await collection.get(id)
    expect(got).toEqual(content)
  })

  it('a fresh handle (no pre-seed) discovers the marker and decrypts', async () => {
    const { id } = await collection.add({ via: 'marker discovery' })
    // A brand-new handle for the same collection, with no encryption override:
    // it must read the Collection Description, see the `encryption` marker, and
    // decrypt with the keystore's keys -- the delegated-consumer discovery path.
    const rediscovered = was.space(space.id).collection('vault')
    expect(await rediscovered.get(id)).toEqual({ via: 'marker discovery' })
  })

  it('fails closed: an encryption-capable client with no keys throws, not ciphertext', async () => {
    const { id } = await collection.add({ secret: 'still safe' })
    // The keyless client discovers the marker (encrypted) but its keystore holds
    // no keys, so reading throws EncryptionError rather than leaking the JWE.
    await expect(
      keyless.space(space.id).collection('vault').get(id)
    ).rejects.toThrow(EncryptionError)
  })

  it('stores an opaque JWE envelope (a plaintext client sees ciphertext)', async () => {
    const { id } = await collection.add({ secret: 'do not leak' })

    // A client with no codec (but the same authorization) reads exactly what the
    // server stored: a JWE envelope, never the cleartext.
    const stored = (await plaintext
      .space(space.id)
      .collection('vault')
      .get(id)) as Record<string, unknown>
    expect(stored.jwe).toBeTruthy()
    expect(stored.content).toBeUndefined()
    expect(JSON.stringify(stored)).not.toContain('do not leak')
  })

  it('put() to a minted EDV id updates the document', async () => {
    const { id } = await collection.add({ v: 1 })
    await collection.put(id, { v: 2 })
    expect(await collection.get(id)).toEqual({ v: 2 })
  })

  it('chains sequential updates (the enforced sequence advances each write)', async () => {
    const { id } = await collection.add({ v: 0 })
    // Each put pre-reads the current envelope and writes previous+1 under
    // If-Match, so a straight-line series of updates all succeed.
    await collection.put(id, { v: 1 })
    await collection.put(id, { v: 2 })
    await collection.put(id, { v: 3 })
    expect(await collection.get(id)).toEqual({ v: 3 })
  })

  it('enforces the sequence: a stale concurrent update is rejected (412)', async () => {
    const { id } = await collection.add({ v: 0 })

    // Two updates race off the same prior version. The server evaluates the
    // EDV-sequence-derived If-Match atomically under its per-resource lock, so
    // exactly one wins and the other gets a PreconditionFailedError -- the EDV
    // sequence is now enforced (lost-update-safe), not advisory.
    const results = await Promise.allSettled([
      collection.put(id, { v: 1 }),
      collection.put(id, { v: 2 })
    ])
    const fulfilled = results.filter(result => result.status === 'fulfilled')
    const rejected = results.filter(result => result.status === 'rejected')
    expect(fulfilled.length).toBe(1)
    expect(rejected.length).toBe(1)
    expect((rejected[0] as PromiseRejectedResult).reason).toBeInstanceOf(
      PreconditionFailedError
    )

    // The winner persists, and a fresh (re-read) update still succeeds.
    expect([{ v: 1 }, { v: 2 }]).toContainEqual(await collection.get(id))
    await collection.put(id, { v: 9 })
    expect(await collection.get(id)).toEqual({ v: 9 })
  })

  it('round-trips a small binary blob', async () => {
    const bytes = new Uint8Array([0, 1, 2, 250, 255])
    const { id } = await collection.add(bytes, {
      contentType: 'application/octet-stream'
    })
    const got = await collection.get(id)
    expect(got).toBeInstanceOf(Blob)
    const out = new Uint8Array(await (got as Blob).arrayBuffer())
    expect(out).toEqual(bytes)
  })

  it('round-trips a text/html resource as a Blob', async () => {
    const html = '<!doctype html><h1>héllo</h1>'
    const { id, contentType } = await collection.add(
      new Blob([html], { type: 'text/html' })
    )
    expect(contentType).toBe('text/html')
    const got = await collection.get(id)
    expect(got).toBeInstanceOf(Blob)
    expect((got as Blob).type).toBe('text/html')
    expect(await (got as Blob).text()).toBe(html)
  })

  it('rejects a human-readable id on put()', async () => {
    await expect(collection.put('2020-01-01-hello', { a: 1 })).rejects.toThrow(
      ValidationError
    )
  })

  it('encrypts setName/setTags metadata: decrypted round-trip, opaque at rest', async () => {
    const { id } = await collection.add({ a: 1 })
    const resource = collection.resource(id)

    // setName / setTags now succeed on an encrypted collection (they no longer
    // throw): the codec encrypts `custom` into an envelope before it is sent.
    await resource.setName('My Secret Label')
    await resource.setTags({ project: 'demo' })

    // The keyed client reads the metadata back decrypted.
    const meta = await resource.meta()
    expect(meta?.custom).toEqual({
      name: 'My Secret Label',
      tags: { project: 'demo' }
    })
    // The /meta ETag (the server's `metaVersion`) is surfaced.
    expect(meta?.etag).toBeTruthy()

    // At rest the server stores an opaque envelope: a plaintext client (same
    // authorization, no keys) reading `/meta` sees a `custom` envelope carrying a
    // `jwe`, never the cleartext name.
    const rawMeta = await plaintext
      .space(space.id)
      .collection('vault')
      .resource(id)
      .meta()
    expect((rawMeta?.custom as { jwe?: unknown }).jwe).toBeTruthy()
    expect(JSON.stringify(rawMeta?.custom)).not.toContain('My Secret Label')
  })

  it('conditional metadata write: stale If-Match on /meta is rejected (412)', async () => {
    const { id } = await collection.add({ a: 1 })
    const resource = collection.resource(id)
    const first = await resource.setMeta({ custom: { name: 'v1' } })
    expect(first.etag).toBeTruthy()

    // A second write with the now-stale /meta ETag is a lost-update 412.
    await resource.setMeta({ custom: { name: 'v2' } }, { ifMatch: first.etag })
    await expect(
      resource.setMeta({ custom: { name: 'v3' } }, { ifMatch: first.etag })
    ).rejects.toBeInstanceOf(PreconditionFailedError)
    expect((await resource.meta())?.custom).toEqual({ name: 'v2' })
  })
})

describeLive('plaintext conditional writes (live server)', () => {
  let was: WasClient
  let space: Space
  let collection: Collection

  beforeAll(async () => {
    // A plaintext client (no encryption provider): conditional writes are the
    // explicit ifMatch / ifNoneMatch options on the handles.
    ;({ plaintext: was } = await freshClients())
    space = await was.createSpace({ name: 'Conditional Writes Integration' })
    collection = await space.createCollection({ id: 'docs', name: 'Docs' })
  })

  afterAll(async () => {
    try {
      await space.delete()
    } catch {
      /* best-effort cleanup */
    }
  })

  it('surfaces the content ETag on write, advancing on each write', async () => {
    const first = await collection.put('etag-doc', { v: 1 })
    expect(first.etag).toBeTruthy()

    const second = await collection.put('etag-doc', { v: 2 })
    expect(second.etag).toBeTruthy()
    expect(second.etag).not.toBe(first.etag)
  })

  it('meta() carries an independent /meta ETag (metaVersion), not the content ETag', async () => {
    // V2 metadata versioning: `/meta` has its own ETag (`metaVersion`),
    // independent of the content `version` -- absent until a metadata write, and
    // NOT advanced by a content write.
    await collection.put('meta-etag-doc', { v: 1 })
    const before = await collection.resource('meta-etag-doc').meta()
    expect(before?.etag).toBeUndefined() // no metadata written yet

    const set = await collection
      .resource('meta-etag-doc')
      .setMeta({ custom: { name: 'labeled' } })
    expect(set.etag).toBeTruthy()
    expect((await collection.resource('meta-etag-doc').meta())?.etag).toBe(
      set.etag
    )

    // A subsequent CONTENT write advances the content ETag but leaves the /meta
    // ETag untouched -- proving the two versions are independent.
    const contentWrite = await collection.put('meta-etag-doc', { v: 2 })
    const afterContent = await collection.resource('meta-etag-doc').meta()
    expect(afterContent?.etag).toBe(set.etag) // metaVersion unchanged
    expect(contentWrite.etag).not.toBe(afterContent?.etag) // content ETag diverged
  })

  it('an ifMatch update succeeds when current and 412s when stale', async () => {
    const created = await collection.put('ifmatch-doc', { v: 1 })
    const staleEtag = created.etag!

    // Update-if-unchanged against the current ETag succeeds and advances it.
    const updated = await collection.put(
      'ifmatch-doc',
      { v: 2 },
      { ifMatch: staleEtag }
    )
    expect(updated.etag).not.toBe(staleEtag)

    // Re-using the now-stale ETag is rejected (the lost-update guard).
    await expect(
      collection.put('ifmatch-doc', { v: 3 }, { ifMatch: staleEtag })
    ).rejects.toBeInstanceOf(PreconditionFailedError)
    // The clobbering write did not land.
    expect(await collection.get('ifmatch-doc')).toEqual({ v: 2 })
  })

  it('ifNoneMatch creates when absent and 412s when the target exists', async () => {
    const created = await collection.put(
      'create-once',
      { v: 1 },
      { ifNoneMatch: true }
    )
    expect(created.etag).toBeTruthy()

    await expect(
      collection.put('create-once', { v: 2 }, { ifNoneMatch: true })
    ).rejects.toBeInstanceOf(PreconditionFailedError)
    expect(await collection.get('create-once')).toEqual({ v: 1 })
  })

  it('delete honors ifMatch: stale 412s, current succeeds', async () => {
    const created = await collection.put('del-doc', { v: 1 })
    await expect(
      collection.resource('del-doc').delete({ ifMatch: '"999"' })
    ).rejects.toBeInstanceOf(PreconditionFailedError)

    await collection.resource('del-doc').delete({ ifMatch: created.etag! })
    expect(await collection.get('del-doc')).toBeNull()
  })
})

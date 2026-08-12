/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Integration test: encrypted collections through the unified handle seam, end
 * to end against a live WAS server (e.g. was-teaching-server's filesystem
 * backend). A `WasClient` constructed with an `encryption` provider
 * transparently encrypts `collection.add()` / `put()` and decrypts `get()` --
 * the same plain Collection/Resource API as a plaintext collection, with no
 * EdvClient in sight. Encryption is gated purely on the client holding keys for
 * the collection (the `encryption` provider returning a codec), not on any
 * backend feature.
 *
 * Provisioning is the two steps every encrypted collection takes: declare the
 * collection encrypted, then install its key epoch[0] with `ensureFirstEpoch`
 * (epoch-from-birth -- a descriptor with no epoch roster is refused
 * fail-closed, so nothing reads or writes before the install).
 *
 * Proves: the value round-trips decrypted; what the server stores is an opaque
 * JWE envelope (the raw `getBytes()` escape hatch shows ciphertext, no
 * cleartext); a small blob round-trips; user metadata (`setName`/`setTags`) is
 * likewise encrypted -- round-tripping decrypted for a keyed reader but opaque
 * at rest -- with its own `/meta` ETag; the same holds for the Collection's own
 * metadata (`collection.setName`/`setTags`), whose key epoch is stamped in the
 * `/meta` body; and the stricter contract holds (human-readable `put()` ids are
 * rejected on an encrypted collection).
 *
 * A second suite plays the tampering server against the metadata slots, moving
 * a stored envelope between slots with a plaintext client (which writes what it
 * is handed, verbatim) and proving the keyed reader refuses each swap on the
 * envelope's AEAD-bound slot marker rather than decoding it.
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
  EncryptionError,
  IntegrityError
} from '../../src/index.js'
import type {
  Space,
  Collection,
  ResourceMetadataCustom
} from '../../src/index.js'
import {
  createEdvEncryption,
  ensureFirstEpoch,
  ownerRecipient
} from '../../src/edv/index.js'

const serverUrl = process.env.TEST_SERVER_URL
const describeLive = serverUrl ? describe : describe.skip

/**
 * Retypes a stored `custom` value read back off the wire so it can be written
 * to another slot through the plaintext client's `setMeta`, whose signature
 * describes the plaintext `{ name, tags }` shape rather than the ciphertext
 * envelope a tampering server would move between slots.
 *
 * @param custom {unknown}
 * @returns {ResourceMetadataCustom}
 */
function asStoredCustom(custom: unknown): ResourceMetadataCustom {
  return custom as ResourceMetadataCustom
}

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
 * The keyed client's own key-agreement key comes back too: it is the recipient
 * the collection's first key epoch is wrapped to at provision time.
 *
 * @returns {Promise<{ encrypted: WasClient, plaintext: WasClient,
 *   keyless: WasClient, kak: IKeyAgreementKey }>}
 */
async function freshClients(): Promise<{
  encrypted: WasClient
  plaintext: WasClient
  keyless: WasClient
  kak: IKeyAgreementKey
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
    }),
    kak: kak as IKeyAgreementKey
  }
}

describeLive('encrypted collection via the codec seam (live server)', () => {
  let was: WasClient
  let plaintext: WasClient
  let keyless: WasClient
  let space: Space
  let collection: Collection

  beforeAll(async () => {
    let kak: IKeyAgreementKey
    ;({ encrypted: was, plaintext, keyless, kak } = await freshClients())
    space = await was.createSpace({ name: 'EDV Codec Integration' })
    // Step 1: declare the collection encrypted, so any authorized reader can
    // discover it from the descriptor.
    const declared = await space.createCollection({
      id: 'vault',
      name: 'Vault',
      encryption: { scheme: 'edv' }
    })
    // Step 2: install key epoch[0], wrapped to this client's own key-agreement
    // key. Every encrypted collection carries an epoch roster from birth, and
    // reads/writes are refused fail-closed until it is installed.
    await ensureFirstEpoch({
      collection: declared,
      recipients: [ownerRecipient({ keyAgreementKey: kak })]
    })
    // A fresh handle (the one the tests drive): the handle returned by
    // createCollection is pre-seeded with the pre-install `{ scheme: 'edv' }`
    // override, so discovery -- not that stale override -- must supply the
    // epoch-bearing descriptor.
    collection = was.space(space.id).collection('vault')
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

  it('a fresh handle (no pre-seed) discovers the descriptor and decrypts', async () => {
    const { id } = await collection.add({ via: 'descriptor discovery' })
    // A brand-new handle for the same collection, with no encryption override:
    // it must read the Collection Description, see the `encryption` descriptor,
    // and decrypt with the keystore's keys -- the delegated-consumer discovery
    // path.
    const rediscovered = was.space(space.id).collection('vault')
    expect(await rediscovered.get(id)).toEqual({ via: 'descriptor discovery' })
  })

  it('fails closed: an encryption-capable client with no keys throws, not ciphertext', async () => {
    const { id } = await collection.add({ secret: 'still safe' })
    // The keyless client discovers the descriptor (encrypted) but its keystore
    // holds no keys, so reading throws EncryptionError rather than leaking the
    // JWE.
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
    // authorization, no keys) reading `/meta` sees a `custom` envelope carrying
    // a `jwe`, never the cleartext name.
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

  it('encrypts Collection-level setName/setTags: decrypted round-trip, opaque at rest', async () => {
    await collection.setName('My Secret Collection')
    await collection.setTags({ project: 'demo' })

    const meta = await collection.meta()
    expect(meta?.custom).toEqual({
      name: 'My Secret Collection',
      tags: { project: 'demo' }
    })
    expect(meta?.etag).toBeTruthy()

    // A plaintext client (same authorization, no keys) sees the opaque
    // envelope the server stored, never the cleartext name.
    const rawMeta = await plaintext.space(space.id).collection('vault').meta()
    expect((rawMeta?.custom as { jwe?: unknown }).jwe).toBeTruthy()
    expect(JSON.stringify(rawMeta?.custom)).not.toContain(
      'My Secret Collection'
    )
  })

  it("stamps the writing codec's key epoch as the /meta body's top-level epoch", async () => {
    await collection.setMeta({ custom: { name: 'epoch-stamped' } })
    // The Collection metadata epoch travels in the PUT body (not the
    // `Key-Epoch` header), so the server echoes it as a top-level GET member.
    const description = await collection.describe()
    const currentEpoch = description?.encryption?.currentEpoch
    expect(currentEpoch).toBeTruthy()
    const rawMeta = await plaintext.space(space.id).collection('vault').meta()
    expect(rawMeta?.epoch).toBe(currentEpoch)
  })
})

describeLive('metadata slot bindings against a tampering server (live)', () => {
  let was: WasClient
  let plaintext: WasClient
  let space: Space
  let collection: Collection
  let twin: Collection

  beforeAll(async () => {
    let kak: IKeyAgreementKey
    ;({ encrypted: was, plaintext, kak } = await freshClients())
    space = await was.createSpace({ name: 'EDV Metadata Bindings' })
    const declared = await space.createCollection({
      id: 'vault',
      name: 'Vault',
      encryption: { scheme: 'edv' }
    })
    await ensureFirstEpoch({
      collection: declared,
      recipients: [ownerRecipient({ keyAgreementKey: kak })]
    })
    collection = was.space(space.id).collection('vault')
    // A second encrypted collection carrying the SAME epoch roster (the same
    // reader, the same epoch secret), so a cross-collection swap of metadata
    // envelopes is caught by the `was.collection` binding rather than by a key
    // miss -- keys alone cannot separate two collections a client can read.
    const description = await collection.describe()
    const twinDeclared = await space.createCollection({
      id: 'vault-twin',
      name: 'Vault Twin'
    })
    await twinDeclared.replaceDescription({
      name: 'Vault Twin',
      encryption: description!.encryption
    })
    twin = was.space(space.id).collection('vault-twin')
  })

  afterAll(async () => {
    try {
      await space.delete()
    } catch {
      /* best-effort cleanup */
    }
  })

  it("refuses a resource's metadata envelope served in the Collection slot", async () => {
    const { id } = await collection.add({ a: 1 })
    await collection.resource(id).setName('Resource Label')
    const raw = plaintext.space(space.id).collection('vault')
    const stored = (await raw.resource(id).meta())?.custom
    // The tampering server: the resource's envelope now sits in the
    // Collection's own `/meta` slot, which belongs to no resource.
    await raw.setMeta({ custom: asStoredCustom(stored) })
    await expect(collection.meta()).rejects.toBeInstanceOf(IntegrityError)
  })

  it("refuses the Collection's metadata envelope served in a resource slot", async () => {
    // `setMeta` (a full replacement) rather than `setName`: a sibling test may
    // have left a foreign envelope in this slot, and `setName` would read it.
    await collection.setMeta({ custom: { name: 'Collection Label' } })
    const { id } = await collection.add({ b: 2 })
    const raw = plaintext.space(space.id).collection('vault')
    const stored = (await raw.meta())?.custom
    await raw.resource(id).setMeta({ custom: asStoredCustom(stored) })
    await expect(collection.resource(id).meta()).rejects.toBeInstanceOf(
      IntegrityError
    )
  })

  it("refuses one Collection's metadata envelope served as another's", async () => {
    await collection.setMeta({ custom: { name: 'Only For Vault' } })
    const stored = (await plaintext.space(space.id).collection('vault').meta())
      ?.custom
    await plaintext
      .space(space.id)
      .collection('vault-twin')
      .setMeta({ custom: asStoredCustom(stored) })
    // The twin's reader holds the very same epoch key, so the envelope
    // decrypts; only the `was.collection` binding separates the two.
    await expect(twin.meta()).rejects.toBeInstanceOf(IntegrityError)
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

  it('collection meta() / setMeta() round-trips and advances its own etag', async () => {
    // Before any metadata write the server answers 200 with no ETag.
    const before = await collection.meta()
    expect(before?.custom).toEqual({})
    expect(before?.etag).toBeUndefined()

    const first = await collection.setMeta({
      custom: { name: 'Docs Label', tags: { project: 'demo' } }
    })
    expect(first.etag).toBeTruthy()
    const read = await collection.meta()
    expect(read?.custom).toEqual({
      name: 'Docs Label',
      tags: { project: 'demo' }
    })
    expect(read?.etag).toBe(first.etag)

    const second = await collection.setMeta({ custom: { name: 'Renamed' } })
    expect(second.etag).not.toBe(first.etag)
    // Full replacement: the omitted `tags` are cleared, not merged forward.
    expect((await collection.meta())?.custom).toEqual({ name: 'Renamed' })
  })

  it('collection setMeta: a stale ifMatch on /meta is rejected (412)', async () => {
    const first = await collection.setMeta({ custom: { name: 'cv1' } })
    await collection.setMeta(
      { custom: { name: 'cv2' } },
      { ifMatch: first.etag }
    )
    await expect(
      collection.setMeta({ custom: { name: 'cv3' } }, { ifMatch: first.etag })
    ).rejects.toBeInstanceOf(PreconditionFailedError)
    expect((await collection.meta())?.custom).toEqual({ name: 'cv2' })
  })

  it('the collection /meta ETag is independent of the description ETag', async () => {
    const beforeDescription = await collection.describeWithEtag()
    const metaWrite = await collection.setMeta({
      custom: { name: 'independent' }
    })
    // A metadata write leaves `descriptionVersion` untouched...
    const afterDescription = await collection.describeWithEtag()
    expect(afterDescription?.etag).toBe(beforeDescription?.etag)

    // ...and a description write leaves `metaVersion` untouched.
    await collection.replaceDescription(
      { name: 'Docs (renamed)' },
      { ifMatch: afterDescription?.etag }
    )
    expect((await collection.meta())?.etag).toBe(metaWrite.etag)
    expect((await collection.describeWithEtag())?.etag).not.toBe(
      afterDescription?.etag
    )
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

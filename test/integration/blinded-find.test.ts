/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Integration test: content search on an encrypted collection, end to end
 * against a live WAS server. The collection is provisioned with a blinded-index
 * key, an attribute is declared searchable, documents are written through the
 * ordinary `add()` path, and `find()` matches them -- with the server comparing
 * only opaque tokens, never learning the attribute names or the values.
 *
 * Proves: the index schema is persisted encrypted and discovered by a second
 * handle that never declared it; a write emits blinded index entries a
 * plaintext client can see but not read; `find()` returns decrypted documents;
 * `count` returns just the tally; declarations are prospective (a document
 * written before the declaration does not match until it is rewritten); and
 * searching an undeclared attribute is refused client-side rather than
 * silently matching nothing.
 *
 * Requires a running server whose backend advertises `blinded-index-query`: set
 * `TEST_SERVER_URL`. The suite skips when it is unset, so a bare
 * `pnpm test:integration` (no server) is not a failure.
 */
import { describe, it, beforeAll, afterAll, expect } from 'vitest'
import type {
  IKeyAgreementKey,
  IKeyResolver
} from '@interop/data-integrity-core'
import { X25519KeyAgreementKey2020 } from '@interop/x25519-key-agreement-key'
import { Ed25519VerificationKey } from '@interop/ed25519-verification-key'

import { WasClient, ValidationError } from '../../src/index.js'
import type { Collection, FindPage, Space } from '../../src/index.js'
import {
  createEdvDocCipher,
  createEdvEncryption,
  ensureFirstEpoch,
  ownerRecipient
} from '../../src/edv/index.js'
import { createWasSyncPort } from '../../src/sync/index.js'

const serverUrl = process.env.TEST_SERVER_URL
const describeLive = serverUrl ? describe : describe.skip

/**
 * Builds an encryption-capable client plus a plaintext one over the same
 * signer, and returns the key-agreement key the collection's first epoch (and
 * its blinding key) will be wrapped to.
 *
 * @returns {Promise<{ encrypted: WasClient, plaintext: WasClient,
 *   kak: IKeyAgreementKey, keyResolver: IKeyResolver }>}
 */
async function freshClients(): Promise<{
  encrypted: WasClient
  plaintext: WasClient
  kak: IKeyAgreementKey
  keyResolver: IKeyResolver
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
    kak: kak as IKeyAgreementKey,
    keyResolver: keyResolver as unknown as IKeyResolver
  }
}

describeLive('blinded content search on an encrypted collection', () => {
  let was: WasClient
  let plaintext: WasClient
  let space: Space
  let collection: Collection
  let beforeDeclarationId: string
  let kak: IKeyAgreementKey
  let keyResolver: IKeyResolver

  beforeAll(async () => {
    ;({ encrypted: was, plaintext, kak, keyResolver } = await freshClients())
    space = await was.createSpace({ name: 'Blinded Find Integration' })
    const declared = await space.createCollection({
      id: 'vault',
      name: 'Searchable Vault',
      encryption: { scheme: 'edv' }
    })
    // The blinding key is installed with epoch[0] or never, so a searchable
    // collection is a property fixed at birth.
    await ensureFirstEpoch({
      collection: declared,
      recipients: [ownerRecipient({ keyAgreementKey: kak })],
      blindedIndex: true
    })
    collection = was.space(space.id).collection('vault')

    // Written BEFORE any declaration: it carries no index token, so it must not
    // match later searches (declarations are prospective).
    ;({ id: beforeDeclarationId } = await collection.add({
      type: 'note',
      title: 'written first'
    }))

    await collection.declareIndex({ attribute: 'content.type' })
    await collection.add({ type: 'note', title: 'alpha' })
    await collection.add({ type: 'note', title: 'beta' })
    await collection.add({ type: 'task', title: 'gamma' })
  })

  afterAll(async () => {
    try {
      await space.delete()
    } catch {
      /* best-effort cleanup */
    }
  })

  it('finds the documents written after the declaration, decrypted', async () => {
    const page = (await collection.find({
      equals: { 'content.type': 'note' }
    })) as FindPage
    const titles = page.items
      .map(item => (item.data as { title: string }).title)
      .sort()
    expect(titles).toEqual(['alpha', 'beta'])
    expect(page.items.map(item => item.id)).not.toContain(beforeDeclarationId)
  })

  it('counts matches without returning documents', async () => {
    await expect(
      collection.find({ equals: { 'content.type': 'task' }, count: true })
    ).resolves.toEqual({ count: 1 })
  })

  it('matches on attribute presence with `has`', async () => {
    const page = (await collection.find({ has: 'content.type' })) as FindPage
    expect(page.items.length).toBe(3)
  })

  it('persists the schema encrypted and discoverable by a second handle', async () => {
    // A fresh handle that never declared anything learns what is searchable
    // from the collection itself -- the access-grant flow.
    const second = was.space(space.id).collection('vault')
    expect(await second.indexes()).toEqual([
      { attribute: 'content.type', addedIn: 1 }
    ])
    const page = (await second.find({
      equals: { 'content.type': 'task' }
    })) as FindPage
    expect(page.items.length).toBe(1)

    // A client without the keys sees only an opaque envelope where the schema
    // lives -- the attribute names never reach the server as plaintext.
    const stored = await plaintext.space(space.id).collection('vault').meta()
    expect(JSON.stringify(stored?.custom)).not.toContain('content.type')
  })

  it('stores blinded index entries alongside the ciphertext', async () => {
    const { id } = await collection.add({ type: 'note', title: 'delta' })
    const raw = await plaintext
      .space(space.id)
      .collection('vault')
      .resource(id)
      .get()
    const envelope = raw as {
      indexed?: Array<{ attributes: Array<{ name: string; value: string }> }>
    }
    expect(envelope.indexed?.[0]?.attributes.length).toBeGreaterThan(0)
    expect(JSON.stringify(envelope.indexed)).not.toContain('content.type')
    expect(JSON.stringify(envelope.indexed)).not.toContain('note')
  })

  it('refuses a search on an attribute nobody declared', async () => {
    await expect(
      collection.find({ equals: { 'content.title': 'alpha' } })
    ).rejects.toBeInstanceOf(ValidationError)
  })

  // Runs last on purpose: it adds another `content.type: note` document, which
  // would change the counts the earlier tests assert.
  it('finds a document pushed through the sync path', async () => {
    // What a replica holds: the collection's descriptor and its stored `/meta`
    // (whose `custom` is the opaque metadata envelope -- the plaintext client
    // passes it through raw).
    const description = await was.space(space.id).collection('vault').describe()
    const stored = await plaintext.space(space.id).collection('vault').meta()
    const cipher = await createEdvDocCipher({
      keyAgreementKey: kak,
      keyResolver,
      collectionId: 'vault',
      encryption: description!.encryption!,
      meta: { custom: stored?.custom }
    })

    // The sync push: the port ships the envelope verbatim, no codec involved.
    const { id, envelope, epoch } = await cipher.encrypt({
      data: { type: 'note', title: 'pushed-by-sync' }
    })
    const port = createWasSyncPort({
      was,
      spaceId: space.id,
      collectionId: 'vault'
    })
    await port.putContent({ id, data: envelope, ifNoneMatch: true, epoch })

    const page = (await collection.find({
      equals: { 'content.type': 'note' }
    })) as FindPage
    const pushed = page.items.find(item => item.id === id)
    expect(pushed?.data).toEqual({ type: 'note', title: 'pushed-by-sync' })
  })
})

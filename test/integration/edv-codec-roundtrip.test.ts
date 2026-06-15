/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Integration test: encrypted collections through the unified handle seam
 * (Increment 2), end to end against a live WAS server (e.g. was-teaching-server's
 * filesystem backend). A `WasClient` constructed with an `encryption` provider
 * transparently encrypts `collection.add()` / `put()` and decrypts `get()` -- the
 * same plain Collection/Resource API as a plaintext collection, with no EdvClient
 * in sight. Encryption is gated purely on the client holding keys for the
 * collection (the `encryption` provider returning a codec), not on any backend
 * feature.
 *
 * Proves: the value round-trips decrypted; what the server stores is an opaque
 * JWE envelope (the raw `getBytes()` escape hatch shows ciphertext, no
 * cleartext); a small blob round-trips; and the stricter contract holds
 * (human-readable `put()` ids and `setName` are rejected on an encrypted
 * collection).
 *
 * Requires a running server: set `TEST_SERVER_URL`. The suite skips when it is
 * unset, so a bare `pnpm test:integration` (no server) is not a failure.
 */
import { describe, it, beforeAll, afterAll, expect } from 'vitest'
import type { IKeyAgreementKey } from '@interop/data-integrity-core'
import { X25519KeyAgreementKey2020 } from '@interop/x25519-key-agreement-key'
import { Ed25519VerificationKey } from '@interop/ed25519-verification-key'

import { WasClient, ValidationError } from '../../src/index.js'
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
 * @returns {Promise<{ encrypted: WasClient, plaintext: WasClient }>}
 */
async function freshClients(): Promise<{
  encrypted: WasClient
  plaintext: WasClient
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
    })
  }
}

describeLive('encrypted collection via the codec seam (live server)', () => {
  let was: WasClient
  let plaintext: WasClient
  let space: Space
  let collection: Collection

  beforeAll(async () => {
    ;({ encrypted: was, plaintext } = await freshClients())
    space = await was.createSpace({ name: 'EDV Codec Integration' })
    collection = await space.createCollection({ id: 'vault', name: 'Vault' })
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

  it('rejects a human-readable id on put()', async () => {
    await expect(collection.put('2020-01-01-hello', { a: 1 })).rejects.toThrow(
      ValidationError
    )
  })

  it('forbids setName() on an encrypted collection', async () => {
    const { id } = await collection.add({ a: 1 })
    await expect(
      collection.resource(id).setName('a-plaintext-name')
    ).rejects.toThrow(ValidationError)
  })
})

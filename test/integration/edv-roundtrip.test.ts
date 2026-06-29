/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Integration test: the EDV-over-WAS layout profile, end to end, against a live
 * WAS server (e.g. a was-teaching-server filesystem backend). Proves that a
 * document encrypted client-side with `EdvClientCore` can be written through
 * `WasTransport` as an ordinary WAS resource, read back, and decrypted -- and
 * that what the server stores is opaque ciphertext (a JWE envelope, no
 * cleartext).
 *
 * Requires a running server: set `TEST_SERVER_URL`. The suite skips when it is
 * unset, so a bare `pnpm test:integration` (no server) is not a failure. Start
 * a server yourself (e.g. in was-teaching-server) and point `TEST_SERVER_URL`
 * at it.
 */
import { describe, it, beforeAll, afterAll, expect } from 'vitest'
import { EdvClientCore } from '@interop/edv-client'
import type { IKeyAgreementKey } from '@interop/data-integrity-core'
import { X25519KeyAgreementKey2020 } from '@interop/x25519-key-agreement-key'
import { Ed25519VerificationKey } from '@interop/ed25519-verification-key'

import { WasClient } from '../../src/index.js'
import type { Space, Collection } from '../../src/index.js'
import { WasTransport, JOSE_CONTENT_TYPE } from '../../src/edv/index.js'

const serverUrl = process.env.TEST_SERVER_URL
const describeLive = serverUrl ? describe : describe.skip

/**
 * Builds a fresh did:key Ed25519 signer and a WAS client over it.
 *
 * @returns {Promise<WasClient>}
 */
async function freshWasClient(): Promise<WasClient> {
  const keyPair = await Ed25519VerificationKey.generate()
  const did = `did:key:${keyPair.fingerprint()}`
  keyPair.id = `${did}#${keyPair.fingerprint()}`
  keyPair.controller = did
  return WasClient.fromSigner({
    serverUrl: serverUrl!,
    signer: keyPair.signer()
  })
}

describeLive('EDV-over-WAS round trip (live server)', () => {
  let was: WasClient
  let space: Space
  let collection: Collection
  let edv: EdvClientCore
  let transport: WasTransport

  beforeAll(async () => {
    was = await freshWasClient()
    space = await was.createSpace({ name: 'EDV Integration' })
    collection = await space.createCollection({ id: 'vault', name: 'Vault' })

    // Vault-per-collection: one client-side X25519 key set; keys never reach
    // the server. The key id is the recipient `kid` and the decrypt key id.
    const kak = await X25519KeyAgreementKey2020.generate({
      controller: was.controllerDid
    })
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
    // `generate({ controller })` always derives an `id`, so `kak` satisfies the
    // `IKeyAgreementKey` contract whose `id` is required (the class types it as
    // optional).
    edv = new EdvClientCore({
      keyAgreementKey: kak as IKeyAgreementKey,
      keyResolver
    })
    transport = new WasTransport({
      was,
      spaceId: space.id,
      collectionId: collection.id
    })
  })

  afterAll(async () => {
    try {
      await space.delete()
    } catch {
      /* best-effort cleanup */
    }
  })

  it('encrypts, writes, reads back, and decrypts a document', async () => {
    const content = { message: 'hello edv-over-was', n: 42 }
    const inserted = await edv.insert({ doc: { content }, transport })

    // The id is an EDV 128-bit multibase value, used verbatim as the WAS
    // resource id (restrict-mode mapping).
    expect(inserted.id).toMatch(/^z/)
    expect(inserted.sequence).toBe(0)

    const fetched = await edv.get({ id: inserted.id, transport })
    expect(fetched.content).toEqual(content)
  })

  it('stores opaque ciphertext (application/json envelope)', async () => {
    const inserted = await edv.insert({
      doc: { content: { secret: 'do not leak' } },
      transport
    })

    // Read the raw stored resource through the plaintext WAS client: the server
    // sees only the JWE envelope, never the cleartext.
    const stored = (await collection.get(inserted.id)) as Record<
      string,
      unknown
    >
    expect(stored.jwe).toBeTruthy()
    expect(stored.content).toBeUndefined()
    expect(JSON.stringify(stored)).not.toContain('do not leak')

    // Stored as application/json (the zero-server-change default). The
    // preferred `application/jose+json` marker needs a server-side parser.
    const meta = await collection.resource(inserted.id).meta()
    expect(meta?.contentType).toMatch(/application\/json/)
  })

  it('updates a document, incrementing its advisory sequence', async () => {
    const inserted = await edv.insert({
      doc: { content: { v: 1 } },
      transport
    })
    const fetched = await edv.get({ id: inserted.id, transport })

    const updated = await edv.update({
      doc: { ...fetched, content: { v: 2 } },
      transport
    })
    expect(updated.sequence).toBe(1)

    const refetched = await edv.get({ id: inserted.id, transport })
    expect(refetched.content).toEqual({ v: 2 })
  })

  it('can store the preferred application/jose+json marker', async () => {
    // A server that registers an `application/*+json` content-type parser (the
    // reference server does) accepts the preferred EDV marker.
    const edvTransport = new WasTransport({
      was,
      spaceId: space.id,
      collectionId: collection.id,
      contentType: JOSE_CONTENT_TYPE
    })
    const inserted = await edv.insert({
      doc: { content: { marked: true } },
      transport: edvTransport
    })

    const fetched = await edv.get({ id: inserted.id, transport: edvTransport })
    expect(fetched.content).toEqual({ marked: true })

    const meta = await collection.resource(inserted.id).meta()
    expect(meta?.contentType).toMatch(/application\/jose\+json/)
  })

  it('throws NotFoundError reading a missing document', async () => {
    await expect(
      edv.get({ id: 'zMissingDoc', transport })
    ).rejects.toMatchObject({ name: 'NotFoundError' })
  })
})

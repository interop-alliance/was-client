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
import { SHA256HMACKey } from '@interop/data-integrity-core'
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

/**
 * The decrypted shape of a stored EDV document, as returned by
 * `EdvClientCore.find` / `.get`: the client-side cipher re-attaches the
 * plaintext `content` after decrypting the JWE envelope.
 */
interface DecryptedDoc {
  id: string
  content: Record<string, unknown>
}

describeLive('EDV-over-WAS blinded-index query (live server)', () => {
  let was: WasClient
  let space: Space
  let collection: Collection
  let edv: EdvClientCore
  let transport: WasTransport
  let hmac: SHA256HMACKey

  beforeAll(async () => {
    was = await freshWasClient()
    space = await was.createSpace({ name: 'EDV Query Integration' })
    // A dedicated collection keeps document counts deterministic, independent
    // of the round-trip suite above; queries below stay disjoint by using a
    // distinct indexed attribute value (or a distinct attribute name) per test.
    collection = await space.createCollection({
      id: 'vault-indexed',
      name: 'Indexed Vault'
    })

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
    // A real `Sha256HmacKey2019` HMAC (the reference `IHMAC` implementation
    // exported by `@interop/data-integrity-core`): it blinds the indexable
    // attribute names and values client-side, so the server indexes and
    // queries opaque HMAC tags -- never the plaintext the tests search on.
    hmac = await SHA256HMACKey.generate({ id: 'urn:hmac:edv-integration-1' })
    edv = new EdvClientCore({
      hmac,
      keyAgreementKey: kak as IKeyAgreementKey,
      keyResolver
    })
    // Register the indexed attributes once, up front: `ensureIndex` is what
    // makes an attribute carry a blinded `indexed` entry on every subsequent
    // `insert`. `content.serialNumber` is unique, so two live documents may not
    // both claim the same blinded value.
    edv.ensureIndex({ attribute: 'content.category' })
    edv.ensureIndex({ attribute: 'content.section' })
    edv.ensureIndex({ attribute: 'content.serialNumber', unique: true })

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

  it('finds documents by an attribute the server never saw in plaintext', async () => {
    // Two documents share the plaintext value 'alpha'; a third does not.
    // Distinct generated ids and no unique attributes, so the inserts are
    // order-independent and safe to run in parallel.
    await Promise.all([
      edv.insert({
        doc: { content: { category: 'alpha', label: 'a1' } },
        transport
      }),
      edv.insert({
        doc: { content: { category: 'alpha', label: 'a2' } },
        transport
      }),
      edv.insert({
        doc: { content: { category: 'beta', label: 'b1' } },
        transport
      })
    ])

    const { documents } = (await edv.find({
      equals: { 'content.category': 'alpha' },
      transport
    })) as { documents: DecryptedDoc[] }

    // Exactly the two 'alpha' documents come back, decrypted to plaintext --
    // located by a value the server only ever indexed as a blinded HMAC tag.
    expect(documents).toHaveLength(2)
    const labels = documents.map(doc => doc.content.label).sort()
    expect(labels).toEqual(['a1', 'a2'])
    for (const doc of documents) {
      expect(doc.content.category).toBe('alpha')
    }

    // A value no document holds matches nothing.
    const miss = (await edv.find({
      equals: { 'content.category': 'no-such-value' },
      transport
    })) as { documents: DecryptedDoc[] }
    expect(miss.documents).toHaveLength(0)
  })

  it('finds all documents possessing an attribute (has query)', async () => {
    // A distinct attribute name so this query is disjoint from the others.
    // Order-independent inserts, run in parallel.
    await Promise.all([
      edv.insert({
        doc: { content: { section: 'x', label: 'sec1' } },
        transport
      }),
      edv.insert({
        doc: { content: { section: 'y', label: 'sec2' } },
        transport
      }),
      edv.insert({
        doc: { content: { section: 'z', label: 'sec3' } },
        transport
      })
    ])

    const { documents } = (await edv.find({
      has: 'content.section',
      transport
    })) as { documents: DecryptedDoc[] }

    expect(documents).toHaveLength(3)
    const labels = documents.map(doc => doc.content.label).sort()
    expect(labels).toEqual(['sec1', 'sec2', 'sec3'])
  })

  it('counts matching documents without returning them', async () => {
    await edv.insert({
      doc: { content: { category: 'countable', label: 'c1' } },
      transport
    })
    await edv.insert({
      doc: { content: { category: 'countable', label: 'c2' } },
      transport
    })

    const result = (await edv.find({
      equals: { 'content.category': 'countable' },
      count: true,
      transport
    })) as { count: number }
    expect(result).toEqual({ count: 2 })
  })

  it('paginates matches natively, walking the cursor through EdvClientCore', async () => {
    // Five documents share one indexed value; page them two at a time.
    // Order-independent inserts, run in parallel.
    await Promise.all(
      [1, 2, 3, 4, 5].map(index =>
        edv.insert({
          doc: { content: { category: 'paged', label: `p${index}` } },
          transport
        })
      )
    )

    // `EdvClientCore.find` now accepts a `cursor` and surfaces the server's
    // `cursor` on its result, so pagination walks entirely through the client
    // -- no direct `transport.find` calls, and every page is decrypted.
    const firstPage = (await edv.find({
      equals: { 'content.category': 'paged' },
      limit: 2,
      transport
    })) as { documents: DecryptedDoc[]; hasMore: boolean; cursor?: string }
    expect(firstPage.documents).toHaveLength(2)
    expect(firstPage.hasMore).toBe(true)
    expect(firstPage.cursor).toBeTruthy()

    // Walk every page by feeding the previous page's cursor back in. Assert on
    // decrypted labels (available now), not raw ids.
    const seenLabels: string[] = []
    let pageCount = 0
    let cursor: string | undefined = firstPage.cursor
    let page = firstPage
    for (;;) {
      pageCount++
      for (const doc of page.documents) {
        seenLabels.push(doc.content.label as string)
      }
      if (!page.hasMore) {
        expect(page.cursor).toBeUndefined()
        break
      }
      expect(page.cursor).toBeTruthy()
      if (pageCount > 10) {
        throw new Error('pagination failed to terminate')
      }
      page = (await edv.find({
        equals: { 'content.category': 'paged' },
        limit: 2,
        cursor,
        transport
      })) as { documents: DecryptedDoc[]; hasMore: boolean; cursor?: string }
      cursor = page.cursor
    }

    // Pages are disjoint (each label counted exactly once) and together cover
    // all five: three pages of 2 + 2 + 1.
    expect(seenLabels).toHaveLength(5)
    expect([...seenLabels].sort()).toEqual(['p1', 'p2', 'p3', 'p4', 'p5'])
    expect(pageCount).toBe(3)
  })

  it('rejects a second document claiming a held unique attribute', async () => {
    await edv.insert({
      doc: { content: { serialNumber: 'SN-1', label: 'first' } },
      transport
    })

    // A different document (its own generated id) claiming the same unique
    // blinded serial value is a server-side 409, which the insert path maps to
    // `DuplicateError` (the name `EdvClientCore` dispatches on).
    await expect(
      edv.insert({
        doc: { content: { serialNumber: 'SN-1', label: 'second' } },
        transport
      })
    ).rejects.toMatchObject({ name: 'DuplicateError' })
  })
})

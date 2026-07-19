/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Integration test: chunked encrypted blobs over WAS, end to end, against a
 * live WAS server whose backend advertises the `chunked-streams` feature.
 * Proves two things:
 *
 * 1. Transport-level `WasTransport.storeChunk` / `getChunk` round-trip an
 *    opaque EDV chunk object through the reserved `.../chunks/{n}` sub-segment.
 * 2. A blob larger than one chunk, driven through
 *    `EdvClientCore.insert({ stream })` and read back with `getStream`,
 *    encrypts client-side, stores as N opaque chunks over WAS, and decrypts
 *    byte-for-byte -- reusing minimal-cipher's proven encrypt/decrypt with no
 *    server change (the server stores ciphertext fragments it never parses).
 *
 * Requires a running server: set `TEST_SERVER_URL`. The suite skips when it is
 * unset, so a bare `pnpm test:integration` (no server) is not a failure.
 */
import { describe, it, beforeAll, afterAll, expect } from 'vitest'
import { EdvClientCore } from '@interop/edv-client'
import type { IEDVChunk, IKeyAgreementKey } from '@interop/data-integrity-core'
import { X25519KeyAgreementKey2020 } from '@interop/x25519-key-agreement-key'
import { Ed25519VerificationKey } from '@interop/ed25519-verification-key'

import { WasClient } from '../../src/index.js'
import type { Space, Collection } from '../../src/index.js'
import { WasTransport } from '../../src/edv/index.js'

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

/**
 * Wraps a byte array in a WHATWG `ReadableStream`, enqueuing it in fixed-size
 * slices so `EdvClientCore` sees a genuinely multi-part source.
 *
 * @param bytes {Uint8Array}
 * @param sliceSize {number}
 * @returns {ReadableStream<Uint8Array>}
 */
function streamOf(bytes: Uint8Array, sliceSize: number): ReadableStream {
  let offset = 0
  return new ReadableStream({
    pull(controller) {
      if (offset >= bytes.length) {
        controller.close()
        return
      }
      const end = Math.min(offset + sliceSize, bytes.length)
      controller.enqueue(bytes.subarray(offset, end))
      offset = end
    }
  })
}

/**
 * Drains a `ReadableStream` of `Uint8Array` chunks into one contiguous array.
 *
 * @param stream {ReadableStream<Uint8Array>}
 * @returns {Promise<Uint8Array>}
 */
async function drain(stream: ReadableStream): Promise<Uint8Array> {
  const reader = (stream as ReadableStream<Uint8Array>).getReader()
  const parts: Uint8Array[] = []
  let total = 0
  for (;;) {
    const { value, done } = await reader.read()
    if (done) {
      break
    }
    parts.push(value)
    total += value.length
  }
  const out = new Uint8Array(total)
  let offset = 0
  for (const part of parts) {
    out.set(part, offset)
    offset += part.length
  }
  return out
}

describeLive('chunked encrypted blobs over WAS (live server)', () => {
  let was: WasClient
  let space: Space
  let collection: Collection
  let edv: EdvClientCore
  let transport: WasTransport

  beforeAll(async () => {
    was = await freshWasClient()
    space = await was.createSpace({ name: 'EDV Chunk Integration' })
    collection = await space.createCollection({ id: 'vault', name: 'Vault' })

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

  it('round-trips an opaque EDV chunk via storeChunk/getChunk', async () => {
    // The parent Resource must exist before its chunks (the server rejects an
    // orphan chunk with 404), so create a document first.
    const inserted = await edv.insert({
      doc: { content: { note: 'parent of a hand-written chunk' } },
      transport
    })

    const chunk = {
      sequence: 0,
      index: 0,
      offset: 0,
      // The server stores the chunk opaquely, so any JSON `jwe` round-trips.
      jwe: {
        protected: 'eyJlbmMiOiJYQzIwUCJ9',
        iv: 'abc',
        ciphertext: 'def',
        tag: 'ghi'
      }
    } as unknown as IEDVChunk
    await transport.storeChunk({ docId: inserted.id, chunk })

    const read = await transport.getChunk({
      docId: inserted.id,
      chunkIndex: 0
    })
    expect(read).toEqual(chunk)
  })

  it('surfaces a missing chunk as NotFoundError', async () => {
    const inserted = await edv.insert({
      doc: { content: { note: 'no chunks written' } },
      transport
    })
    await expect(
      transport.getChunk({ docId: inserted.id, chunkIndex: 7 })
    ).rejects.toMatchObject({ name: 'NotFoundError' })
  })

  it('rejects a chunk whose parent document is absent', async () => {
    await expect(
      transport.storeChunk({
        docId: 'zNonexistentDocumentId000000000000',
        chunk: {
          sequence: 0,
          index: 0,
          offset: 0,
          jwe: { ciphertext: 'x' }
        } as unknown as IEDVChunk
      })
    ).rejects.toMatchObject({ name: 'NotFoundError' })
  })

  it('encrypts, chunks, stores, and reassembles a >1 chunk blob', async () => {
    // 2.5 MiB of deterministic pseudo-random bytes -- larger than the 1 MiB
    // default chunk size, so it is split into multiple stored chunks.
    const size = Math.floor(2.5 * 1024 * 1024)
    const plaintext = new Uint8Array(size)
    for (let index = 0; index < size; index++) {
      plaintext[index] = (index * 31 + 7) & 0xff
    }

    const inserted = await edv.insert({
      doc: { content: { label: 'big-blob' } },
      stream: streamOf(plaintext, 256 * 1024),
      transport
    })

    // The document now records the chunk count the reader reassembles from.
    expect(inserted.stream?.chunks).toBeGreaterThan(1)

    const outStream = await edv.getStream({ doc: inserted, transport })
    const roundTripped = await drain(outStream)
    expect(roundTripped.length).toBe(plaintext.length)
    expect(Buffer.from(roundTripped).equals(Buffer.from(plaintext))).toBe(true)
  })
})

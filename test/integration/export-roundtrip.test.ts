/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Integration test: the three whole-space export shapes against a live WAS
 * server. Proves that `export()`, `exportBlob()`, and a fully-drained
 * `exportStream()` produce byte-identical tar archives for the same space, and
 * that `spaceB.import(await spaceA.exportBlob())` round-trips the resources.
 *
 * Requires a running server: set `TEST_SERVER_URL`. The suite skips when it is
 * unset, so a bare `pnpm test:integration` (no server) is not a failure.
 */
import { describe, it, beforeAll, afterAll, expect } from 'vitest'
import { Ed25519VerificationKey } from '@interop/ed25519-verification-key'

import { WasClient } from '../../src/index.js'
import type { Space } from '../../src/index.js'

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
 * Drains a `ReadableStream<Uint8Array>` into a single concatenated array.
 *
 * @param stream {ReadableStream<Uint8Array>}
 * @returns {Promise<Uint8Array>}
 */
async function drain(stream: ReadableStream<Uint8Array>): Promise<Uint8Array> {
  const chunks: Uint8Array[] = []
  const reader = stream.getReader()
  for (;;) {
    const { done, value } = await reader.read()
    if (done) {
      break
    }
    chunks.push(value)
  }
  const total = chunks.reduce((sum, chunk) => sum + chunk.byteLength, 0)
  const out = new Uint8Array(total)
  let offset = 0
  for (const chunk of chunks) {
    out.set(chunk, offset)
    offset += chunk.byteLength
  }
  return out
}

describeLive('whole-space export shapes (live server)', () => {
  let was: WasClient
  let source: Space

  beforeAll(async () => {
    was = await freshWasClient()
    source = await was.createSpace({ name: 'Export Integration' })
    const notes = await source.createCollection({ id: 'notes', name: 'Notes' })
    await notes.put('first', { message: 'hello export' })
    await notes.put('second', { message: 'and again' })
  })

  afterAll(async () => {
    try {
      await source.delete()
    } catch {
      /* best-effort cleanup */
    }
  })

  it('export(), exportBlob(), and a drained exportStream() agree byte-for-byte', async () => {
    const fromExport = await source.export()
    const fromBlob = new Uint8Array(
      await (await source.exportBlob()).arrayBuffer()
    )
    const fromStream = await drain(await source.exportStream())

    // Every archive is non-empty and the three shapes carry identical bytes.
    expect(fromExport.byteLength).toBeGreaterThan(0)
    expect(fromBlob).toEqual(fromExport)
    expect(fromStream).toEqual(fromExport)
  })

  it('exportBlob() is typed application/x-tar and round-trips through import()', async () => {
    const blob = await source.exportBlob()
    expect(blob.type).toBe('application/x-tar')

    const target = await was.createSpace({ name: 'Export Target' })
    try {
      const stats = await target.import(blob)
      expect(stats.collectionsCreated).toBeGreaterThan(0)
      expect(stats.resourcesCreated).toBeGreaterThanOrEqual(2)

      const copied = await target.collection('notes').get('first')
      expect(copied).toMatchObject({ message: 'hello export' })
    } finally {
      try {
        await target.delete()
      } catch {
        /* best-effort cleanup */
      }
    }
  })
})

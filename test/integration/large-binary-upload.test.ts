/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Integration test: a large binary `Blob` written to a plaintext Collection,
 * via both `Resource.put()` and `Collection.add()`, against a live WAS server.
 * The signed request's `Digest` is computed by hashing the Blob incrementally,
 * and the same Blob is the request body. The server verifies that digest over
 * the streamed body before it commits the Resource, so a successful write
 * followed by a byte-exact read proves the two agree.
 *
 * Requires a running server: set `TEST_SERVER_URL`. The suite skips when it is
 * unset, so a bare `pnpm test:integration` (no server) is not a failure.
 */
import { describe, it, beforeAll, afterAll, expect } from 'vitest'
import { sha256 } from '@noble/hashes/sha2.js'
import { Ed25519VerificationKey } from '@interop/ed25519-verification-key'

import { WasClient } from '../../src/index.js'
import type { Space, Collection } from '../../src/index.js'

const serverUrl = process.env.TEST_SERVER_URL
const describeLive = serverUrl ? describe : describe.skip

/**
 * Well past the server's 1 MiB buffered-body default and the size at which a
 * whole-body hash would be noticeable, while staying under the server's
 * default 64 MiB per-upload cap.
 */
const LARGE_BODY_BYTES = 40 * 1024 * 1024 + 13

/**
 * A deterministic pseudo-random body, so the digest comparison is meaningful.
 *
 * @param size {number}
 * @returns {Uint8Array}
 */
function bytesOf(size: number): Uint8Array<ArrayBuffer> {
  const bytes = new Uint8Array(size)
  for (let index = 0; index < size; index++) {
    bytes[index] = (index * 31 + (index >> 8) * 17) % 256
  }
  return bytes
}

/**
 * Hex SHA-256 of a Blob's bytes, for comparing a large read-back without an
 * element-wise array diff.
 *
 * @param blob {Blob}
 * @returns {Promise<string>}
 */
async function hexDigestOf(blob: Blob): Promise<string> {
  return Buffer.from(sha256(await blob.bytes())).toString('hex')
}

describeLive(
  'large binary upload to a plaintext collection (live server)',
  () => {
    let space: Space
    let collection: Collection
    let body: Blob
    let expectedDigest: string

    beforeAll(async () => {
      const keyPair = await Ed25519VerificationKey.generate()
      const was = WasClient.fromSigner({
        serverUrl: serverUrl!,
        signer: keyPair.didKeySigner()
      })
      space = await was.createSpace({ name: 'Large Binary Upload Integration' })
      collection = await space.createCollection({ id: 'files', name: 'Files' })
      body = new Blob([bytesOf(LARGE_BODY_BYTES)], {
        type: 'application/octet-stream'
      })
      expectedDigest = await hexDigestOf(body)
    })

    afterAll(async () => {
      try {
        await space.delete()
      } catch {
        /* best-effort cleanup */
      }
    })

    it('accepts a large Blob via Resource.put() and reads it back', async () => {
      await collection.resource('large.bin').put(body)
      const read = await collection.get('large.bin')
      expect(read).toBeInstanceOf(Blob)
      expect((read as Blob).size).toBe(LARGE_BODY_BYTES)
      expect(await hexDigestOf(read as Blob)).toBe(expectedDigest)
    })

    it('accepts a large Blob via Collection.add() and reads it back', async () => {
      const { id } = await collection.add(body)
      const read = await collection.get(id)
      expect((read as Blob).size).toBe(LARGE_BODY_BYTES)
      expect(await hexDigestOf(read as Blob)).toBe(expectedDigest)
    })
  }
)

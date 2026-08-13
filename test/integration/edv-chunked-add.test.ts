/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Integration test: `collection.add(bigBlob)` auto-routing, end to end against
 * a live WAS server whose backend advertises the `chunked-streams` feature. A
 * binary payload over the codec's `maxBlobBytes` threshold is written as one
 * EDV document plus its chunk resources, and the ordinary `get()` handle reads
 * it back byte-exact -- no `EdvClientCore` or `WasTransport` in the caller's
 * code. The threshold is set small here so the blob need not exceed the 512 KiB
 * default.
 *
 * Requires a running server: set `TEST_SERVER_URL`. The suite skips when it is
 * unset, so a bare `pnpm test:integration` (no server) is not a failure.
 */
import { describe, it, beforeAll, afterAll, expect } from 'vitest'
import type { IKeyAgreementKey } from '@interop/data-integrity-core'
import { X25519KeyAgreementKey2020 } from '@interop/x25519-key-agreement-key'
import { Ed25519VerificationKey } from '@interop/ed25519-verification-key'

import { WasClient } from '../../src/index.js'
import type { Space, Collection } from '../../src/index.js'
import {
  createEdvEncryption,
  ensureFirstEpoch,
  ownerRecipient
} from '../../src/edv/index.js'

const serverUrl = process.env.TEST_SERVER_URL
const describeLive = serverUrl ? describe : describe.skip

/**
 * The routing threshold and chunk size these tests provision the codec with,
 * both far below the defaults so a modest blob exercises the multi-chunk path.
 */
const MAX_BLOB_BYTES = 4 * 1024
const CHUNK_SIZE = 8 * 1024

/**
 * Builds a WAS client whose EDV provider routes anything over
 * {@link MAX_BLOB_BYTES} to the chunked-stream path, plus the key-agreement key
 * the collection's first epoch is wrapped to.
 *
 * @returns {Promise<{ was: WasClient; kak: IKeyAgreementKey }>}
 */
async function freshClient(): Promise<{
  was: WasClient
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
    }),
    maxBlobBytes: MAX_BLOB_BYTES,
    chunkSize: CHUNK_SIZE
  })
  return {
    was: WasClient.fromSigner({
      serverUrl: serverUrl!,
      signer: keyPair.signer(),
      encryption
    }),
    kak: kak as IKeyAgreementKey
  }
}

/**
 * A deterministic pseudo-random blob, so a byte-exact comparison is meaningful
 * (a run of zeros would round-trip even through a broken reassembly).
 *
 * @param size {number}
 * @returns {Uint8Array}
 */
function blobOf(size: number): Uint8Array {
  const bytes = new Uint8Array(size)
  for (let index = 0; index < size; index++) {
    bytes[index] = (index * 31 + (index >> 8) * 17) % 256
  }
  return bytes
}

describeLive('collection.add(bigBlob) auto-routing (live server)', () => {
  let was: WasClient
  let space: Space
  let collection: Collection

  beforeAll(async () => {
    let kak: IKeyAgreementKey
    ;({ was, kak } = await freshClient())
    space = await was.createSpace({ name: 'EDV Chunked Add Integration' })
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
  })

  afterAll(async () => {
    try {
      await space.delete()
    } catch {
      /* best-effort cleanup */
    }
  })

  it('routes a blob over the threshold to chunks and reads it back byte-exact', async () => {
    const bytes = blobOf(MAX_BLOB_BYTES * 5 + 123)
    const added = await collection.add(bytes, {
      contentType: 'application/octet-stream'
    })
    expect(added.id).toMatch(/^z/)
    expect(added.contentType).toBe('application/octet-stream')

    const read = await collection.get(added.id)
    expect(read).toBeInstanceOf(Blob)
    const out = new Uint8Array(await (read as Blob).arrayBuffer())
    expect(out.length).toBe(bytes.length)
    expect(out).toEqual(bytes)
  })

  it('keeps a blob under the threshold on the single-document path', async () => {
    const bytes = blobOf(MAX_BLOB_BYTES - 1)
    const { id } = await collection.add(bytes, {
      contentType: 'application/octet-stream'
    })
    const read = await collection.get(id)
    expect(new Uint8Array(await (read as Blob).arrayBuffer())).toEqual(bytes)
  })
})

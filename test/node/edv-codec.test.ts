/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Unit tests for the EDV codec (Increment 2, Phase 2). These use real X25519
 * keys and the real `EdvClientCore` cipher (no network) to prove that the codec
 * genuinely encrypts/decrypts at the seam: `encode` produces an opaque JWE
 * envelope (no plaintext leak) and `decode` round-trips it back. Also covers the
 * documents-only contract decisions: minted EDV ids on add, human ids rejected
 * on put, small binary as a single JWE, oversized binary rejected, and the
 * provider's null (no-keys) path.
 */
import { describe, it, expect } from 'vitest'
import { X25519KeyAgreementKey2020 } from '@interop/x25519-key-agreement-key'

import { ValidationError } from '../../src/index.js'
import type { ResourceCodec } from '../../src/index.js'
import { createEdvEncryption, EDV_CONTENT_TYPE } from '../../src/edv/index.js'

/**
 * Builds an EDV codec over a fresh real X25519 key (so encrypt/decrypt actually
 * run), via the public `createEdvEncryption` provider.
 *
 * @param [options] {object}
 * @param [options.contentType] {string}
 * @param [options.maxBlobBytes] {number}
 * @returns {Promise<ResourceCodec>}
 */
async function makeCodec(
  options: {
    contentType?: string
    maxBlobBytes?: number
  } = {}
): Promise<ResourceCodec> {
  const kak = await X25519KeyAgreementKey2020.generate({
    controller: 'did:example:alice'
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
  const provider = createEdvEncryption({
    resolveKeys: async () => ({ keyAgreementKey: kak, keyResolver }),
    ...options
  })
  const codec = await provider.resolveCodec({ spaceId: 's', collectionId: 'c' })
  if (!codec) {
    throw new Error('expected a codec')
  }
  return codec
}

/**
 * Wraps an encoded write's body bytes as a minimal read response the codec's
 * `decode` accepts (mirroring how core hands the GET response back).
 *
 * @param body {Uint8Array}
 * @returns {object}
 */
function responseFrom(body?: Uint8Array | Blob): {
  data: unknown
  json(): Promise<unknown>
} {
  const envelope = JSON.parse(new TextDecoder().decode(body as Uint8Array))
  return {
    data: envelope,
    async json() {
      return envelope
    }
  }
}

describe('EdvCodec: JSON round trip', () => {
  it('encrypts on encode (no plaintext leak) and decrypts on decode', async () => {
    const codec = await makeCodec()
    const encoded = await codec.encode({
      data: { secret: 'do not leak', n: 42 }
    })

    // add(): a fresh EDV multibase id is minted and the body is an opaque JWE.
    expect(encoded.id).toMatch(/^z/)
    expect(encoded.contentType).toBe('application/json')
    const json = new TextDecoder().decode(encoded.body as Uint8Array)
    expect(json).not.toContain('do not leak')
    const envelope = JSON.parse(json)
    expect(envelope.jwe).toBeTruthy()
    expect(envelope.content).toBeUndefined()

    const decoded = await codec.decode(responseFrom(encoded.body))
    expect(decoded).toEqual({ secret: 'do not leak', n: 42 })
  })

  it('honors an opted-in application/edv+json content type', async () => {
    const codec = await makeCodec({ contentType: EDV_CONTENT_TYPE })
    const encoded = await codec.encode({ data: { a: 1 } })
    expect(encoded.contentType).toBe('application/edv+json')
  })
})

describe('EdvCodec: id strategy', () => {
  it('rejects a human-readable id on put', async () => {
    const codec = await makeCodec()
    await expect(
      codec.encode({ id: '2020-01-01-hello', data: { a: 1 } })
    ).rejects.toThrow(ValidationError)
  })

  it('accepts a (re-used) EDV-format id on put', async () => {
    const codec = await makeCodec()
    const minted = (await codec.encode({ data: { v: 1 } })).id as string
    const updated = await codec.encode({ id: minted, data: { v: 2 } })
    expect(updated.id).toBe(minted)
    const decoded = await codec.decode(responseFrom(updated.body))
    expect(decoded).toEqual({ v: 2 })
  })
})

describe('EdvCodec: binary', () => {
  it('round-trips a small blob as a single JWE document', async () => {
    const codec = await makeCodec()
    const bytes = new Uint8Array([1, 2, 3, 4, 250])
    const encoded = await codec.encode({
      data: bytes,
      contentType: 'application/octet-stream'
    })
    const decoded = await codec.decode(responseFrom(encoded.body))
    expect(decoded).toBeInstanceOf(Blob)
    const out = new Uint8Array(await (decoded as Blob).arrayBuffer())
    expect(out).toEqual(bytes)
    expect((decoded as Blob).type).toBe('application/octet-stream')
  })

  it('rejects an oversized binary write', async () => {
    const codec = await makeCodec({ maxBlobBytes: 4 })
    await expect(
      codec.encode({ data: new Uint8Array([1, 2, 3, 4, 5]) })
    ).rejects.toThrow(ValidationError)
  })

  it('rejects a bare primitive', async () => {
    const codec = await makeCodec()
    await expect(codec.encode({ data: 'just a string' })).rejects.toThrow(
      ValidationError
    )
  })
})

describe('createEdvEncryption: provider', () => {
  it('resolves null when resolveKeys yields no keys (plaintext)', async () => {
    const provider = createEdvEncryption({ resolveKeys: async () => null })
    const codec = await provider.resolveCodec({
      spaceId: 's',
      collectionId: 'c'
    })
    expect(codec).toBeNull()
  })
})

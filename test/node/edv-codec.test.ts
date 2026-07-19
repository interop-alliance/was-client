/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Unit tests for the EDV codec. These use real X25519
 * keys and the real `EdvClientCore` cipher (no network) to prove that the codec
 * genuinely encrypts/decrypts at the seam: `encode` produces an opaque JWE
 * envelope (no plaintext leak) and `decode` round-trips it back. Also covers the
 * documents-only contract decisions: minted EDV ids on add (random by default,
 * content-derived with `idDerivation: 'content'`), human ids rejected on put,
 * small binary as a single JWE, oversized binary rejected, and the provider's
 * null (no-keys) path.
 */
import { describe, it, expect } from 'vitest'
import { X25519KeyAgreementKey2020 } from '@interop/x25519-key-agreement-key'
import { EdvClientCore, EdvDocumentCipher } from '@interop/edv-client'
import type {
  IEDVDocument,
  IKeyAgreementKey,
  IKeyResolver
} from '@interop/data-integrity-core'
import type { HttpResponse } from '@interop/http-client'

import {
  EncryptionError,
  IntegrityError,
  KeyUnwrapError,
  ValidationError
} from '../../src/index.js'
import type { ResourceCodec } from '../../src/index.js'
import {
  createEdvEncryption,
  EdvCodec,
  JOSE_CONTENT_TYPE
} from '../../src/edv/index.js'

/**
 * Generates a fresh real X25519 key agreement key and a matching resolver, so
 * the codec's encrypt/decrypt actually run.
 *
 * @returns {Promise<{ kak: IKeyAgreementKey; keyResolver: function }>}
 */
async function makeKeys(): Promise<{
  kak: IKeyAgreementKey
  keyResolver: IKeyResolver
}> {
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
  // `X25519KeyAgreementKey2020.id` is typed optional, but a key generated with a
  // `controller` always derives one, so narrow it to the `IKeyAgreementKey`
  // contract the EDV keystore expects.
  return { kak: kak as IKeyAgreementKey, keyResolver }
}

/**
 * Builds an EDV codec over a fresh real X25519 key, via the public
 * `createEdvEncryption` provider.
 *
 * @param [options] {object}
 * @param [options.contentType] {string}
 * @param [options.maxBlobBytes] {number}
 * @param [options.idDerivation] {string}
 * @returns {Promise<ResourceCodec>}
 */
async function makeCodec(
  options: {
    contentType?: string
    maxBlobBytes?: number
    idDerivation?: 'random' | 'content'
  } = {}
): Promise<ResourceCodec> {
  const { kak, keyResolver } = await makeKeys()
  const provider = createEdvEncryption({
    resolveKeys: async () => ({ keyAgreementKey: kak, keyResolver }),
    ...options
  })
  // Core decides policy (marker/override) and then asks the provider to build
  // the codec for the declared scheme; mirror that here.
  const codec = await provider.codecFor({
    spaceId: 's',
    collectionId: 'c',
    scheme: 'edv'
  })
  if (!codec) {
    throw new Error('expected a codec')
  }
  return codec
}

/**
 * Builds a codec plus a `decrypt` helper that unseals an encoded envelope back
 * to its decrypted `{ content, meta }`, so a test can assert the on-the-wire
 * inner document (e.g. that text is stored verbatim, not base64).
 *
 * @param [options] {object}
 * @param [options.maxBlobBytes] {number}
 * @returns {Promise<{ codec: ResourceCodec; decrypt: function }>}
 */
async function makeInspectableCodec(
  options: { maxBlobBytes?: number } = {}
): Promise<{
  codec: ResourceCodec
  decrypt: (body: Uint8Array | Blob | undefined) => Promise<IEDVDocument>
}> {
  const { kak, keyResolver } = await makeKeys()
  const provider = createEdvEncryption({
    resolveKeys: async () => ({ keyAgreementKey: kak, keyResolver }),
    ...options
  })
  const codec = await provider.codecFor({
    spaceId: 's',
    collectionId: 'c',
    scheme: 'edv'
  })
  if (!codec) {
    throw new Error('expected a codec')
  }
  const edv = new EdvClientCore({ keyAgreementKey: kak, keyResolver })
  const decrypt = async (
    body: Uint8Array | Blob | undefined
  ): Promise<IEDVDocument> => {
    const encryptedDoc = JSON.parse(
      new TextDecoder().decode(body as Uint8Array)
    )
    return edv.documentCipher.decrypt({ encryptedDoc, keyAgreementKey: kak })
  }
  return { codec, decrypt }
}

/**
 * Wraps an encoded write's body bytes as a minimal read response the codec's
 * `decode` accepts (mirroring how core hands the GET response back).
 *
 * @param body {Uint8Array}
 * @returns {object}
 */
function responseFrom(body?: Uint8Array | Blob): HttpResponse {
  const envelope = JSON.parse(new TextDecoder().decode(body as Uint8Array))
  return {
    data: envelope,
    async json() {
      return envelope
    }
  } as unknown as HttpResponse
}

describe('EdvCodec: JSON round trip', () => {
  it('encrypts on encode (no plaintext leak) and decrypts on decode', async () => {
    const codec = await makeCodec()
    const encoded = await codec.encode({
      data: { secret: 'do not leak', n: 42 }
    })

    // add(): a fresh EDV multibase id is minted and the body is an opaque JWE.
    expect(encoded.id).toMatch(/^z/)
    // The wire type is the opaque envelope; the resource type is the plaintext.
    expect(encoded.contentType).toBe('application/json')
    expect(encoded.resourceContentType).toBe('application/json')
    const json = new TextDecoder().decode(encoded.body as Uint8Array)
    expect(json).not.toContain('do not leak')
    const envelope = JSON.parse(json)
    expect(envelope.jwe).toBeTruthy()
    expect(envelope.content).toBeUndefined()

    const decoded = await codec.decode(responseFrom(encoded.body))
    expect(decoded).toEqual({ secret: 'do not leak', n: 42 })
  })

  it('stores JSON content verbatim and typed application/json in meta', async () => {
    const { codec, decrypt } = await makeInspectableCodec()
    const value = { type: ['VerifiableCredential'], claim: 'legible' }
    const encoded = await codec.encode({ data: value })

    // Inside the JWE: content is the value verbatim (no wrapper), meta carries
    // the JSON content type and NO encoding discriminator.
    const doc = await decrypt(encoded.body)
    expect(doc.content).toEqual(value)
    expect(doc.meta).toEqual({ contentType: 'application/json' })
    expect(doc.meta?.encoding).toBeUndefined()
  })

  it('honors an opted-in application/jose+json content type', async () => {
    const codec = await makeCodec({ contentType: JOSE_CONTENT_TYPE })
    const encoded = await codec.encode({ data: { a: 1 } })
    expect(encoded.contentType).toBe('application/jose+json')
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

describe("EdvCodec: content-derived ids (idDerivation: 'content')", () => {
  it("derives the add() id from the envelope's JWE ciphertext and stamps it", async () => {
    const codec = await makeCodec({ idDerivation: 'content' })
    const encoded = await codec.encode({ data: { secret: 'addressed' } })
    const envelope = JSON.parse(
      new TextDecoder().decode(encoded.body as Uint8Array)
    )
    // The write id IS the stamped envelope id, in the standard EDV format...
    expect(encoded.id).toMatch(/^z[1-9A-HJ-NP-Za-km-z]{21,}$/)
    expect(envelope.id).toBe(encoded.id)
    // ...and recomputes from the ciphertext (content-derived, not random).
    await expect(
      EdvDocumentCipher.deriveId({ jwe: envelope.jwe })
    ).resolves.toBe(encoded.id)
  })

  it('guards the content-derived insert with If-None-Match: * and round-trips', async () => {
    const codec = await makeCodec({ idDerivation: 'content' })
    const encoded = await codec.encode({ data: { v: 1 } })
    expect(encoded.ifNoneMatch).toBe(true)
    expect(encoded.ifMatch).toBeUndefined()
    // The stamped id satisfies the cipher's decrypt-side id assertion.
    const decoded = await codec.decode(responseFrom(encoded.body))
    expect(decoded).toEqual({ v: 1 })
  })

  it('accepts an explicit EDV-format id and still rejects a human-readable one', async () => {
    const codec = await makeCodec({ idDerivation: 'content' })
    const derived = (await codec.encode({ data: { v: 1 } })).id as string
    const rewrite = await codec.encode({ id: derived, data: { v: 1 } })
    expect(rewrite.id).toBe(derived)
    await expect(
      codec.encode({ id: '2020-01-01-hello', data: { a: 1 } })
    ).rejects.toThrow(ValidationError)
  })

  it("default 'random' mode does not content-derive the id", async () => {
    const codec = await makeCodec()
    const encoded = await codec.encode({ data: { v: 1 } })
    const envelope = JSON.parse(
      new TextDecoder().decode(encoded.body as Uint8Array)
    )
    const derived = await EdvDocumentCipher.deriveId({ jwe: envelope.jwe })
    expect(encoded.id).not.toBe(derived)
  })
})

describe('EdvCodec: binary', () => {
  it('round-trips a small blob as base64 in a single JWE document', async () => {
    const { codec, decrypt } = await makeInspectableCodec()
    const bytes = new Uint8Array([1, 2, 3, 4, 250])
    const encoded = await codec.encode({
      data: bytes,
      contentType: 'application/octet-stream'
    })
    // Stored inline as base64 under `content.bytes`, typed in meta.
    const doc = await decrypt(encoded.body)
    expect(doc.meta).toEqual({
      contentType: 'application/octet-stream',
      encoding: 'base64'
    })
    expect(typeof (doc.content as { bytes?: unknown }).bytes).toBe('string')
    expect(encoded.resourceContentType).toBe('application/octet-stream')

    const decoded = await codec.decode(responseFrom(encoded.body))
    expect(decoded).toBeInstanceOf(Blob)
    const out = new Uint8Array(await (decoded as Blob).arrayBuffer())
    expect(out).toEqual(bytes)
    expect((decoded as Blob).type).toBe('application/octet-stream')
  })

  it('surfaces the resolved content type of a typed blob', async () => {
    const codec = await makeCodec()
    const png = new Blob([new Uint8Array([137, 80, 78, 71])], {
      type: 'image/png'
    })
    const encoded = await codec.encode({ data: png })
    // Finding 15: add() reports the plaintext type, not the envelope type.
    expect(encoded.contentType).toBe('application/json')
    expect(encoded.resourceContentType).toBe('image/png')
  })

  it('rejects an oversized binary write', async () => {
    const codec = await makeCodec({ maxBlobBytes: 4 })
    await expect(
      codec.encode({ data: new Uint8Array([1, 2, 3, 4, 5]) })
    ).rejects.toThrow(ValidationError)
  })

  it('rejects a write above the 512 KiB default cap with chunked-path guidance', async () => {
    // The default single-document cap must stay under what the transport can
    // actually deliver: the envelope rides through the server's ~1 MiB JSON
    // body parser, and a binary payload inflates ~1.78x (base64 in the
    // document, base64url again in the JWE). A payload that would pass a lax
    // cap but die at the server as an opaque 413 must instead get the codec's
    // clear guidance toward the chunked-stream path.
    const codec = await makeCodec()
    const big = new Uint8Array(512 * 1024 + 1)
    await expect(
      codec.encode({ data: big, contentType: 'application/octet-stream' })
    ).rejects.toThrow(/single-document limit/)
  })

  it('rejects a bare primitive', async () => {
    const codec = await makeCodec()
    await expect(
      // A bare string is excluded by the `ResourceData` type; cast to prove the
      // runtime guard still rejects it.
      codec.encode({ data: 'just a string' as unknown as Uint8Array })
    ).rejects.toThrow(ValidationError)
  })
})

describe('EdvCodec: text', () => {
  it('stores text as a legible UTF-8 string (no base64) and reads a Blob', async () => {
    const { codec, decrypt } = await makeInspectableCodec()
    const html = '<!doctype html><h1>héllo</h1>'
    const encoded = await codec.encode({
      data: new Blob([html], { type: 'text/html' })
    })
    expect(encoded.resourceContentType).toBe('text/html')

    // Stored verbatim under `content.text` with `encoding: 'utf-8'` -- legible,
    // not base64.
    const doc = await decrypt(encoded.body)
    expect(doc.meta).toEqual({ contentType: 'text/html', encoding: 'utf-8' })
    expect((doc.content as { text?: unknown }).text).toBe(html)

    // Reads back as a Blob typed text/html whose .text() matches.
    const decoded = await codec.decode(responseFrom(encoded.body))
    expect(decoded).toBeInstanceOf(Blob)
    expect((decoded as Blob).type).toBe('text/html')
    expect(await (decoded as Blob).text()).toBe(html)
  })

  it('falls back to base64 for a text-typed blob carrying invalid UTF-8', async () => {
    const { codec, decrypt } = await makeInspectableCodec()
    // 0xff is not valid UTF-8; the text gate must reject it and store base64.
    const encoded = await codec.encode({
      data: new Blob([new Uint8Array([0xff, 0xfe, 0x00])], {
        type: 'text/plain'
      })
    })
    const doc = await decrypt(encoded.body)
    expect(doc.meta).toEqual({ contentType: 'text/plain', encoding: 'base64' })
    expect(typeof (doc.content as { bytes?: unknown }).bytes).toBe('string')
  })

  it('preserves a leading UTF-8 BOM through the text round trip', async () => {
    // BOM-prefixed UTF-8 is valid UTF-8, so the text gate stores it as a
    // string -- and the decoder must not strip the BOM (`ignoreBOM: true`), or
    // the round-tripped bytes come back 3 bytes short, corrupting any hash or
    // signature over the original file.
    const { codec, decrypt } = await makeInspectableCodec()
    const bytes = new Uint8Array([
      0xef,
      0xbb,
      0xbf,
      ...new TextEncoder().encode('hello')
    ])
    const encoded = await codec.encode({
      data: bytes,
      contentType: 'text/plain'
    })
    const doc = await decrypt(encoded.body)
    expect(doc.meta).toEqual({ contentType: 'text/plain', encoding: 'utf-8' })

    const decoded = await codec.decode(responseFrom(encoded.body))
    const roundTripped = new Uint8Array(await (decoded as Blob).arrayBuffer())
    expect(roundTripped).toEqual(bytes)
  })
})

describe('EdvCodec: caller-data collision (no in-band marker)', () => {
  it('round-trips a JSON object shaped like the binary container as itself', async () => {
    const codec = await makeCodec()
    const value = { bytes: 'aGk=' }
    const encoded = await codec.encode({ data: value })
    const decoded = await codec.decode(responseFrom(encoded.body))
    // No `meta.encoding`, so it is JSON -- returned verbatim, not a Blob.
    expect(decoded).not.toBeInstanceOf(Blob)
    expect(decoded).toEqual(value)
  })

  it('round-trips a JSON object shaped like the text container as itself', async () => {
    const codec = await makeCodec()
    const value = { text: 'hi' }
    const encoded = await codec.encode({ data: value })
    const decoded = await codec.decode(responseFrom(encoded.body))
    expect(decoded).not.toBeInstanceOf(Blob)
    expect(decoded).toEqual(value)
  })
})

describe('EdvCodec: malformed inner document', () => {
  /**
   * Encrypts an arbitrary `{ content, meta }` under a fresh key and returns a
   * `{ codec, response }` pair so `decode` can be exercised against a
   * deliberately malformed inner shape.
   *
   * @param content {Record<string, unknown>}
   * @param meta {Record<string, unknown>}
   * @returns {Promise<{ codec: ResourceCodec; response: HttpResponse }>}
   */
  async function encodedDocWith(
    content: Record<string, unknown>,
    meta: Record<string, unknown>
  ): Promise<{ codec: ResourceCodec; response: HttpResponse }> {
    const { kak, keyResolver } = await makeKeys()
    const provider = createEdvEncryption({
      resolveKeys: async () => ({ keyAgreementKey: kak, keyResolver })
    })
    const codec = (await provider.codecFor({
      spaceId: 's',
      collectionId: 'c',
      scheme: 'edv'
    })) as ResourceCodec
    const edv = new EdvClientCore({ keyAgreementKey: kak, keyResolver })
    const recipients = edv.documentCipher.createDefaultRecipients(kak)
    const encrypted = await edv.documentCipher.encrypt({
      doc: { id: 'z' + 'A'.repeat(21), content, meta },
      recipients,
      keyResolver,
      update: false
    })
    return {
      codec,
      response: responseFrom(
        new TextEncoder().encode(JSON.stringify(encrypted))
      )
    }
  }

  it('throws EncryptionError when encoding is base64 but content.bytes is not a string', async () => {
    const { codec, response } = await encodedDocWith(
      { bytes: 123 },
      { contentType: 'image/png', encoding: 'base64' }
    )
    await expect(codec.decode(response)).rejects.toThrow(EncryptionError)
  })

  it('throws EncryptionError when encoding is utf-8 but content.text is not a string', async () => {
    const { codec, response } = await encodedDocWith(
      { text: 42 },
      { contentType: 'text/html', encoding: 'utf-8' }
    )
    await expect(codec.decode(response)).rejects.toThrow(EncryptionError)
  })
})

describe('EdvCodec: non-envelope guard', () => {
  /**
   * A read response carrying an arbitrary JSON document (mirroring how core
   * hands a GET response back), used to simulate a plaintext/foreign resource
   * stored in an encrypted collection.
   *
   * @param doc {unknown}
   * @returns {HttpResponse}
   */
  function jsonResponse(doc: unknown): HttpResponse {
    return {
      data: doc,
      async json() {
        return doc
      },
      headers: {
        get: () => '"1"'
      }
    } as unknown as HttpResponse
  }

  it('throws a typed EncryptionError when decoding a non-envelope body', async () => {
    const codec = await makeCodec()
    await expect(
      codec.decode(jsonResponse({ hello: 'plaintext, no jwe' }))
    ).rejects.toThrow(EncryptionError)
  })

  it('throws a typed EncryptionError when updating over a non-envelope prior doc', async () => {
    const codec = await makeCodec()
    const minted = (await codec.encode({ data: { v: 1 } })).id as string
    await expect(
      codec.encode({
        id: minted,
        data: { v: 2 },
        current: jsonResponse({ hello: 'plaintext, no jwe' })
      })
    ).rejects.toThrow(EncryptionError)
  })

  it('throws a typed EncryptionError when the prior envelope has no sequence', async () => {
    // A foreign `{ id, jwe }` envelope without a `sequence`: spreading its
    // undefined `sequence` onto the update doc would make the cipher's
    // `'sequence' in encrypted` check throw a raw untyped Error.
    const codec = await makeCodec()
    const first = await codec.encode({ data: { v: 1 } })
    const envelope = JSON.parse(
      new TextDecoder().decode(first.body as Uint8Array)
    ) as { sequence?: number }
    delete envelope.sequence
    const failure = await codec
      .encode({
        id: first.id as string,
        data: { v: 2 },
        current: jsonResponse(envelope)
      })
      .catch((err: unknown) => err)
    expect(failure).toBeInstanceOf(EncryptionError)
    expect((failure as Error).message).toMatch(/sequence/)
  })

  it('throws a typed EncryptionError for a malformed prior sequence', async () => {
    const codec = await makeCodec()
    const first = await codec.encode({ data: { v: 1 } })
    const envelope = JSON.parse(
      new TextDecoder().decode(first.body as Uint8Array)
    ) as { sequence?: unknown }
    envelope.sequence = 'not-a-number'
    await expect(
      codec.encode({
        id: first.id as string,
        data: { v: 2 },
        current: jsonResponse(envelope)
      })
    ).rejects.toThrow(EncryptionError)
  })
})

describe('EdvCodec: conditional writes (sequence enforcement)', () => {
  /**
   * A read response the codec's `encode` accepts as `current`: the prior
   * envelope plus an `ETag` header (the server's conditional-writes validator).
   *
   * @param body {Uint8Array | Blob}   the prior encoded envelope bytes
   * @param etag {string | null}       the prior ETag (null to simulate a backend
   *   without the conditional-writes feature)
   * @returns {object}
   */
  function currentFrom(
    body: Uint8Array | Blob | undefined,
    etag: string | null
  ): HttpResponse {
    const envelope = JSON.parse(new TextDecoder().decode(body as Uint8Array))
    return {
      data: envelope,
      async json() {
        return envelope
      },
      headers: {
        get: (name: string) => (name.toLowerCase() === 'etag' ? etag : null)
      }
    } as unknown as HttpResponse
  }

  function sequenceOf(body: Uint8Array | Blob | undefined): number {
    return JSON.parse(new TextDecoder().decode(body as Uint8Array)).sequence
  }

  it('marks the codec as driving conditional writes', async () => {
    const codec = await makeCodec()
    expect(codec.conditionalWrites).toBe(true)
  })

  it('a fresh insert is sequence 0 guarded by If-None-Match', async () => {
    const codec = await makeCodec()
    const minted = await codec.encode({ data: { v: 1 } })
    expect(sequenceOf(minted.body)).toBe(0)
    expect(minted.ifNoneMatch).toBe(true)
    expect(minted.ifMatch).toBeUndefined()
  })

  it('an update advances the sequence and pins If-Match to the current ETag', async () => {
    const codec = await makeCodec()
    const first = await codec.encode({ data: { v: 1 } })
    const id = first.id as string
    expect(sequenceOf(first.body)).toBe(0)

    const second = await codec.encode({
      id,
      data: { v: 2 },
      current: currentFrom(first.body, '"1"')
    })
    expect(sequenceOf(second.body)).toBe(1)
    expect(second.ifMatch).toBe('"1"')
    expect(second.ifNoneMatch).toBeUndefined()
    expect(await codec.decode(responseFrom(second.body))).toEqual({ v: 2 })

    // A third update advances again from the prior envelope.
    const third = await codec.encode({
      id,
      data: { v: 3 },
      current: currentFrom(second.body, '"2"')
    })
    expect(sequenceOf(third.body)).toBe(2)
    expect(third.ifMatch).toBe('"2"')
  })

  it('degrades to advisory (no If-Match) when the backend sends no ETag', async () => {
    const codec = await makeCodec()
    const first = await codec.encode({ data: { v: 1 } })
    const second = await codec.encode({
      id: first.id as string,
      data: { v: 2 },
      current: currentFrom(first.body, null)
    })
    // The sequence still advances, but with no validator there is no precondition.
    expect(sequenceOf(second.body)).toBe(1)
    expect(second.ifMatch).toBeUndefined()
    expect(second.ifNoneMatch).toBeUndefined()
  })
})

describe('EdvCodec: decrypt failure discrimination', () => {
  /**
   * Re-serializes an encoded envelope after mutating its parsed form, returning
   * a read response the codec's `decode` accepts. Used to tamper with a real
   * JWE's ciphertext/tag before reading it back.
   *
   * @param body {Uint8Array | Blob}   the encoded envelope bytes
   * @param mutate {function}          mutates the parsed envelope in place
   * @returns {HttpResponse}
   */
  function tamperedResponse(
    body: Uint8Array | Blob | undefined,
    mutate: (envelope: { jwe: { ciphertext: string; tag: string } }) => void
  ): HttpResponse {
    const envelope = JSON.parse(new TextDecoder().decode(body as Uint8Array))
    mutate(envelope)
    const bytes = new TextEncoder().encode(JSON.stringify(envelope))
    return responseFrom(bytes)
  }

  /**
   * Flips the last character of a base64url string to a different one, so the
   * value stays well-formed base64url but decodes to different bytes.
   *
   * @param value {string}
   * @returns {string}
   */
  function flipLast(value: string): string {
    const last = value.slice(-1)
    return value.slice(0, -1) + (last === 'A' ? 'B' : 'A')
  }

  it('throws IntegrityError (not KeyUnwrapError) on a tampered ciphertext read by a legitimate recipient', async () => {
    const codec = await makeCodec()
    const encoded = await codec.encode({ data: { secret: 'authentic' } })
    // The reader holds the recipient key, but the sealed content is corrupted:
    // the AEAD tag must fail and surface as an integrity failure, NOT as a
    // membership/KeyUnwrapError.
    const response = tamperedResponse(encoded.body, envelope => {
      envelope.jwe.ciphertext = flipLast(envelope.jwe.ciphertext)
    })
    const failure = await codec.decode(response).catch((err: unknown) => err)
    expect(failure).toBeInstanceOf(IntegrityError)
    expect(failure).not.toBeInstanceOf(KeyUnwrapError)
    // Still under the EncryptionError umbrella (fail-closed handling catches it).
    expect(failure).toBeInstanceOf(EncryptionError)
  })

  it('throws IntegrityError on a tampered AEAD tag read by a legitimate recipient', async () => {
    const codec = await makeCodec()
    const encoded = await codec.encode({ data: { secret: 'authentic' } })
    const response = tamperedResponse(encoded.body, envelope => {
      envelope.jwe.tag = flipLast(envelope.jwe.tag)
    })
    await expect(codec.decode(response)).rejects.toThrow(IntegrityError)
  })

  it('throws KeyUnwrapError (not IntegrityError) when no candidate key is a recipient', async () => {
    // Encode under one key, then read with a codec built over an unrelated key:
    // the reader is not a recipient of the envelope, so decryption never reaches
    // the AEAD stage and must fail as a key/membership miss.
    const writer = await makeCodec()
    const encoded = await writer.encode({
      data: { secret: 'for someone else' }
    })
    const reader = await makeCodec()
    const failure = await reader
      .decode(responseFrom(encoded.body))
      .catch((err: unknown) => err)
    expect(failure).toBeInstanceOf(KeyUnwrapError)
    expect(failure).not.toBeInstanceOf(IntegrityError)
  })

  it('treats a candidate throwing KeyUnwrapError as a key miss and tries the next key', async () => {
    // A lazy epoch key whose recipient entry is corrupt raises KeyUnwrapError
    // from its own deriveSecret when a decrypt first forces the unwrap. That
    // says nothing about the stored envelope, so the loop must move on to the
    // next candidate (which decrypts fine) instead of misreporting tampering.
    const { kak, keyResolver } = await makeKeys()
    const edv = new EdvClientCore({ keyAgreementKey: kak, keyResolver })
    const corrupt = {
      // Same kid as the envelope recipient, so this candidate is tried first.
      id: kak.id,
      async deriveSecret(): Promise<Uint8Array> {
        throw new KeyUnwrapError(
          'This reader\'s recipient entry for epoch "did:key:zFake" did ' +
            'not unwrap (a corrupt entry).'
        )
      }
    } as IKeyAgreementKey
    const codec = new EdvCodec({
      edv,
      keyAgreementKey: kak,
      readKeys: [corrupt, kak],
      contentType: 'application/json',
      maxBlobBytes: 512 * 1024,
      idDerivation: 'random'
    })
    const encoded = await codec.encode({ data: { secret: 'still readable' } })
    await expect(codec.decode(responseFrom(encoded.body))).resolves.toEqual({
      secret: 'still readable'
    })
  })
})

describe('createEdvEncryption: provider (keystore)', () => {
  it('returns null when resolveKeys yields no keys (core then fails closed)', async () => {
    const provider = createEdvEncryption({ resolveKeys: async () => null })
    const codec = await provider.codecFor({
      spaceId: 's',
      collectionId: 'c',
      scheme: 'edv'
    })
    // Null no longer means "plaintext" -- policy already said encrypted, so core
    // turns this into a fail-closed EncryptionError rather than a codec.
    expect(codec).toBeNull()
  })

  it('returns null for a scheme it does not handle', async () => {
    const kak = await X25519KeyAgreementKey2020.generate({
      controller: 'did:example:alice'
    })
    const provider = createEdvEncryption({
      resolveKeys: async () => ({
        keyAgreementKey: kak as IKeyAgreementKey,
        keyResolver: async () => ({
          id: kak.id,
          type: kak.type,
          publicKeyMultibase: kak.publicKeyMultibase
        })
      })
    })
    const codec = await provider.codecFor({
      spaceId: 's',
      collectionId: 'c',
      scheme: 'age'
    })
    expect(codec).toBeNull()
  })

  it('uses override-supplied keys instead of the keystore', async () => {
    const kak = await X25519KeyAgreementKey2020.generate({
      controller: 'did:example:alice'
    })
    const keyResolver = async () => ({
      id: kak.id,
      type: kak.type,
      publicKeyMultibase: kak.publicKeyMultibase
    })
    let keystoreCalls = 0
    const provider = createEdvEncryption({
      resolveKeys: async () => {
        keystoreCalls++
        return null
      }
    })
    const codec = await provider.codecFor({
      spaceId: 's',
      collectionId: 'c',
      scheme: 'edv',
      keys: { keyAgreementKey: kak, keyResolver }
    })
    expect(codec).not.toBeNull()
    expect(keystoreCalls).toBe(0)
  })
})

describe('EdvCodec: metadata (encodeMeta / decodeMeta)', () => {
  it('encrypts custom into an EDV Document envelope (no plaintext leak)', async () => {
    const codec = await makeCodec()
    const { custom } = await codec.encodeMeta({
      custom: { name: 'Secret Name', tags: { project: 'x' } }
    })
    // The stored `custom` is an EDV Document envelope (`{ jwe, ... }`), not the
    // plaintext name/tags.
    expect((custom as { jwe?: unknown }).jwe).toBeTruthy()
    expect(JSON.stringify(custom)).not.toContain('Secret Name')
  })

  it('round-trips custom through encodeMeta then decodeMeta', async () => {
    const codec = await makeCodec()
    const original = { name: 'Hello', tags: { a: 'b', c: 'd' } }
    const { custom } = await codec.encodeMeta({ custom: original })
    expect(await codec.decodeMeta({ custom })).toEqual(original)
  })

  it('round-trips an empty custom (envelope on the wire, {} decoded)', async () => {
    const codec = await makeCodec()
    const { custom } = await codec.encodeMeta({ custom: {} })
    expect((custom as { jwe?: unknown }).jwe).toBeTruthy()
    expect(await codec.decodeMeta({ custom })).toEqual({})
  })

  it('decodeMeta returns {} for an absent custom (no metadata written)', async () => {
    const codec = await makeCodec()
    expect(await codec.decodeMeta({})).toEqual({})
    expect(await codec.decodeMeta({ custom: undefined })).toEqual({})
  })

  it('decodeMeta fails closed on a foreign plaintext custom (no `jwe`)', async () => {
    const codec = await makeCodec()
    await expect(
      codec.decodeMeta({ custom: { name: 'plaintext' } })
    ).rejects.toThrow(EncryptionError)
  })
})

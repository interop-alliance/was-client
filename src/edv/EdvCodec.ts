/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The EDV (Encrypted Data Vault) resource codec and its `EncryptionProvider`
 * factory -- the encrypting half of the codec seam. Bound to an
 * encrypted collection, it encrypts a caller's value into an EDV envelope
 * (`{ id, sequence, indexed, jwe }`) on write and decrypts it on read, so
 * `collection.put(id, obj)` / `collection.get(id)` transparently round-trip
 * ciphertext. Keys live in the wallet and are supplied per-collection by the
 * app's `resolveKeys`; they never reach the server, which stores only opaque
 * JWE envelopes.
 *
 * This reuses `EdvClientCore`'s transport-free `documentCipher` (its public
 * `EdvDocumentCipher` -- the same JWE machinery as the standalone
 * `WasTransport`), but here the WAS Resource CRUD -- the transport role -- is
 * played by core was-client's `Collection`/`Resource` I/O, so the codec is a
 * pure encode/decode transform and needs no transport of its own.
 *
 * Scope (documents-only):
 *
 * - **Restrict-mode ids.** `add()` mints a 128-bit multibase EDV id; the WAS
 *   resource id IS that EDV id. `put(id, ...)` accepts only an EDV-format id --
 *   a human-readable id is rejected (it would leak onto the URL). Carry a
 *   human-readable label inside the encrypted content instead. (Blind-derived
 *   ids are a deferred future item.)
 * - **Inline non-JSON as a single JWE.** A `Blob`/`Uint8Array` under the size cap
 *   is encrypted as one document -- stored as a legible UTF-8 string for a
 *   text-family type (else base64) -- with the plaintext content type and the
 *   encoding carried in the document `meta`. An oversized one is
 *   rejected (large chunked encrypted blobs need the server's `chunked-streams`
 *   affordance).
 * - **Enforced sequence (conditional writes).** The codec sets
 *   `conditionalWrites`, so the write path pre-reads the current envelope and
 *   hands it to `encode`: an update advances `sequence` from its prior value and
 *   pins the write to the server's current ETag via `If-Match`, while a fresh
 *   insert (`sequence: 0`) is guarded by `If-None-Match: *`. A stale write
 *   surfaces as a `PreconditionFailedError` (412) -- the lost-update guard --
 *   rather than the old advisory last-writer-wins. Against a backend that does
 *   not advertise `conditional-writes` (no ETag) it degrades to advisory.
 * - **No server-visible metadata.** `allowsServerMetadata` is `false`, so
 *   `setName`/`setTags` throw on an encrypted collection (the core seam enforces
 *   this).
 */
import { EdvClientCore } from '@interop/edv-client'
import type { HttpResponse } from '@interop/http-client'
import type {
  IEncryptedDocument,
  IKeyAgreementKey,
  IKeyResolver
} from '@interop/data-integrity-core'
import type {
  EncodedWrite,
  EncryptionProvider,
  ResourceCodec
} from '../codec.js'
import { EncryptionError, ValidationError } from '../errors.js'
import {
  guessContentTypeFromId,
  isBlob,
  isTextContentType,
  readJsonData
} from '../internal/content.js'
import type { Json, ResourceData } from '../types.js'
import { DEFAULT_CONTENT_TYPE, ENCODER } from './constants.js'

/**
 * Default ceiling for a single-document (unchunked) encrypted binary or text
 * write, measured in raw (pre-base64) bytes. Past this a `Blob`/`Uint8Array` is
 * rejected until chunked encrypted blobs are supported. 5 MiB; binary inflates
 * ~33% under base64, text is stored verbatim.
 */
const DEFAULT_MAX_BLOB_BYTES = 5 * 1024 * 1024

/**
 * A shared strict UTF-8 decoder used to test whether a non-JSON payload is
 * valid UTF-8 (so it can be stored legibly as text rather than base64).
 * `fatal: true` makes `decode` throw on malformed input; the decoder is
 * stateless across non-streaming calls, so one instance is reused.
 */
const UTF8_DECODER = new TextDecoder('utf-8', { fatal: true })

/**
 * Heuristic for an EDV document id: multibase base58btc (leading `z`) of a
 * 128-bit value. Used to reject human-readable ids on `put()`. Deliberately a
 * loose, dependency-free check (base58 charset, leading `z`, minimum length) --
 * it rejects ids with human separators (`.`/`-`/`_`/spaces) and is not a full
 * decode-and-length verification.
 */
const EDV_DOC_ID = /^z[1-9A-HJ-NP-Za-km-z]{21,}$/

/**
 * Encodes bytes to standard base64 using the platform `btoa` (present in modern
 * Node and browsers), via a binary string.
 *
 * @param bytes {Uint8Array}
 * @returns {string}
 */
function bytesToBase64(bytes: Uint8Array): string {
  let binary = ''
  for (const byte of bytes) {
    binary += String.fromCharCode(byte)
  }
  return btoa(binary)
}

/**
 * Decodes standard base64 to bytes using the platform `atob`.
 *
 * @param base64 {string}
 * @returns {Uint8Array}
 */
function base64ToBytes(base64: string): Uint8Array {
  const binary = atob(base64)
  const bytes = new Uint8Array(binary.length)
  for (let index = 0; index < binary.length; index++) {
    bytes[index] = binary.charCodeAt(index)
  }
  return bytes
}

/**
 * A {@link ResourceCodec} that encrypts on write and decrypts on read using an
 * `EdvClientCore`'s public `documentCipher`. One instance is bound per encrypted
 * collection handle.
 */
export class EdvCodec implements ResourceCodec {
  readonly allowsServerMetadata = false
  readonly conditionalWrites = true

  private readonly _edv: EdvClientCore
  private readonly _keyAgreementKey: IKeyAgreementKey
  private readonly _contentType: string
  private readonly _maxBlobBytes: number

  /**
   * @param options {object}
   * @param options.edv {EdvClientCore}             holds the cipher + key resolver
   * @param options.keyAgreementKey {IKeyAgreementKey}   the recipient/decrypt key
   * @param options.contentType {string}            stored envelope content type
   * @param options.maxBlobBytes {number}           single-document binary cap
   */
  constructor({
    edv,
    keyAgreementKey,
    contentType,
    maxBlobBytes
  }: {
    edv: EdvClientCore
    keyAgreementKey: IKeyAgreementKey
    contentType: string
    maxBlobBytes: number
  }) {
    this._edv = edv
    this._keyAgreementKey = keyAgreementKey
    this._contentType = contentType
    this._maxBlobBytes = maxBlobBytes
  }

  /**
   * @inheritdoc
   */
  async encode({
    id,
    data,
    contentType,
    current
  }: {
    id?: string
    data: ResourceData
    contentType?: string
    current?: HttpResponse | null
  }): Promise<EncodedWrite> {
    if (id !== undefined && !EDV_DOC_ID.test(id)) {
      throw new ValidationError(
        `Cannot write a human-readable id "${id}" to an encrypted collection ` +
          '-- it would leak onto the URL. Use add() to mint an EDV document ' +
          'id, or carry the human-readable label inside the encrypted content.'
      )
    }
    const docId = id ?? ((await this._edv.generateId()) as string)
    const { content, meta } = await this._toDocument(data, contentType, docId)

    // When the write path pre-read a current envelope, advance `sequence` from
    // its prior value (`encrypt({ update: true })` increments it) and pin the
    // write to the server's current ETag with `If-Match`. With no prior envelope
    // this is a fresh insert (`sequence: 0`) guarded by `If-None-Match: *`
    // (create-if-absent), so a concurrent first writer cannot be clobbered.
    let priorDoc: IEncryptedDocument | null = null
    if (current) {
      const read = await readJsonData(
        current as Parameters<typeof readJsonData>[0]
      )
      this._assertEnvelope(read, 'update')
      priorDoc = read
    }

    const { documentCipher } = this._edv
    const recipients = documentCipher.createDefaultRecipients(
      this._keyAgreementKey
    )
    const encrypted = await documentCipher.encrypt({
      doc: {
        id: docId,
        content,
        // `content` and `meta` are both sealed inside the JWE; `meta` carries the
        // plaintext content type and the inline-encoding discriminator, taken
        // fresh from this write (the new type/encoding wins on update).
        meta,
        ...(priorDoc && { sequence: priorDoc.sequence })
      },
      recipients,
      keyResolver: this._edv.keyResolver,
      hmac: undefined,
      update: priorDoc !== null
    })
    return {
      id: docId,
      body: ENCODER.encode(JSON.stringify(encrypted)),
      contentType: this._contentType,
      // Surface the plaintext content type (the server-opaque envelope type stays
      // `contentType`) so `add()` reports the real resource type.
      resourceContentType: meta.contentType as string,
      // Pin an update to the server's current ETag; guard a fresh insert with
      // create-if-absent. An update's `If-Match` carries a server-provided ETag,
      // so it degrades to an advisory write against a backend without the
      // conditional-writes feature (the ETag is absent). A fresh insert's
      // `If-None-Match: *` needs no server-provided validator and so is emitted
      // unconditionally by design -- it expresses the insert's intent
      // (create-only-if-absent); a backend that does not honor it simply ignores
      // it, leaving the write harmless rather than degraded.
      ...(priorDoc
        ? { ifMatch: current!.headers.get('etag') ?? undefined }
        : { ifNoneMatch: true })
    }
  }

  /**
   * @inheritdoc
   */
  async decode(response: {
    data?: unknown
    json(): Promise<unknown>
  }): Promise<Json | Blob> {
    const encryptedDoc = await readJsonData(
      response as Parameters<typeof readJsonData>[0]
    )
    this._assertEnvelope(encryptedDoc, 'read')
    const decrypted = await this._edv.documentCipher.decrypt({
      encryptedDoc,
      keyAgreementKey: this._keyAgreementKey
    })
    return this._fromDocument(decrypted.content, decrypted.meta)
  }

  /**
   * Asserts that a document read from an encrypted collection is an EDV envelope
   * (`{ jwe, ... }`) before it is handed to the cipher. A plaintext or foreign
   * resource -- one written without this codec -- carries no `jwe`, which would
   * otherwise make the EDV core throw a raw `TypeError`. Surfacing a typed
   * `EncryptionError` keeps the fail-closed contract legible to callers.
   *
   * @param doc {unknown}
   * @param context {string}   the operation in progress (`read` / `update`),
   *   for the message
   * @returns {asserts doc is IEncryptedDocument}
   */
  private _assertEnvelope(
    doc: unknown,
    context: string
  ): asserts doc is IEncryptedDocument {
    const jwe =
      doc !== null && typeof doc === 'object'
        ? (doc as { jwe?: unknown }).jwe
        : undefined
    if (jwe === null || typeof jwe !== 'object') {
      throw new EncryptionError(
        `Cannot ${context} an encrypted resource: the stored document is not ` +
          'an EDV envelope (it carries no `jwe` field). It was likely written ' +
          'as plaintext, or by a writer that did not use this encrypted ' +
          'collection.'
      )
    }
  }

  /**
   * Splits a caller value into a decrypted EDV document `{ content, meta }`,
   * carrying the plaintext content type and inline-encoding discriminator in
   * `meta`. Three cases:
   *
   * 1. JSON object/array to `content` verbatim, `meta = { contentType }` (no
   *   `encoding`); the shape of `content` is never inspected on read, so a
   *   caller object shaped like `{ text }` / `{ bytes }` round-trips as itself.
   * 2. Text (`Blob`/`Uint8Array` of a text-family type that is valid UTF-8)
   *   to `content = { text }`, `meta = { contentType, encoding: 'utf-8' }`;
   *   stored legibly with no base64 inflation.
   * 3. Binary (any other `Blob`/`Uint8Array`) to `content = { bytes: base64 }`,
   *   `meta = { contentType, encoding: 'base64' }`.
   *
   * A bare primitive is rejected (mirroring the plaintext `prepareBody`
   * contract). The binary/text content type resolves as
   * `contentType || blob.type || guessContentTypeFromId(id) || octet-stream`,
   * mirroring `prepareBody`.
   *
   * @param data {ResourceData}
   * @param [contentType] {string}   caller-supplied content type
   * @param [id] {string}            resource id, for the extension guess
   * @returns {Promise<{ content: Record<string, unknown>; meta:
   *   Record<string, unknown> }>}
   */
  private async _toDocument(
    data: ResourceData,
    contentType?: string,
    id?: string
  ): Promise<{
    content: Record<string, unknown>
    meta: Record<string, unknown>
  }> {
    let bytes: Uint8Array | undefined
    let resolvedType: string | undefined
    if (isBlob(data)) {
      bytes = new Uint8Array(await data.arrayBuffer())
      resolvedType =
        contentType ||
        data.type ||
        guessContentTypeFromId(id ?? '') ||
        'application/octet-stream'
    } else if (data instanceof Uint8Array) {
      bytes = data
      resolvedType =
        contentType ||
        guessContentTypeFromId(id ?? '') ||
        'application/octet-stream'
    }

    if (bytes !== undefined && resolvedType !== undefined) {
      if (bytes.length > this._maxBlobBytes) {
        throw new ValidationError(
          `Encrypted binary write of ${bytes.length} bytes exceeds the ` +
            `single-document limit of ${this._maxBlobBytes} bytes. Chunked ` +
            "encrypted blobs need the server's chunked-streams affordance " +
            '(not yet available).'
        )
      }
      // Text-family AND valid UTF-8 to store as a legible string. The UTF-8 gate
      // guarantees the bytes survive the string round-trip exactly; anything
      // else falls through to base64, which is always byte-safe.
      if (isTextContentType(resolvedType)) {
        const text = decodeUtf8(bytes)
        if (text !== null) {
          return {
            content: { text },
            meta: { contentType: resolvedType, encoding: 'utf-8' }
          }
        }
      }
      return {
        content: { bytes: bytesToBase64(bytes) },
        meta: { contentType: resolvedType, encoding: 'base64' }
      }
    }

    if (data !== null && typeof data === 'object') {
      // JSON object/array: content verbatim, no encoding (the read side treats an
      // absent `meta.encoding` as JSON). EDV models `content` as an object
      // record; a JSON array is also a valid encrypted value here, so widen it.
      return {
        content: data as Record<string, unknown>,
        meta: { contentType: contentType ?? 'application/json' }
      }
    }

    throw new ValidationError(
      'Encrypted resource data must be a plain object/array (JSON) or a ' +
        'Blob/Uint8Array (binary).'
    )
  }

  /**
   * Reconstructs a caller value from a decrypted EDV document, discriminating
   * on `meta.encoding`:
   *
   * - `'utf-8'` to a `Blob` typed `meta.contentType` from `content.text`.
   * - `'base64'` to a `Blob` typed `meta.contentType` from `content.bytes`.
   * - absent (or `meta` absent) to `content` returned verbatim as JSON.
   *
   * A malformed inner shape (an encoding that does not match its container key's
   * type) throws {@link EncryptionError} -- the decrypted-document analogue of
   * `_assertEnvelope`'s outer guard.
   *
   * @param content {unknown}
   * @param [meta] {Record<string, unknown>}
   * @returns {Json | Blob}
   */
  private _fromDocument(
    content: unknown,
    meta?: Record<string, unknown>
  ): Json | Blob {
    const encoding = meta?.encoding
    const contentType =
      typeof meta?.contentType === 'string' ? meta.contentType : undefined
    if (encoding === 'utf-8') {
      const text = (content as { text?: unknown } | null)?.text
      if (typeof text !== 'string') {
        throw new EncryptionError(
          'Malformed encrypted text document: meta.encoding is "utf-8" but ' +
            'content.text is not a string.'
        )
      }
      return new Blob([ENCODER.encode(text) as BlobPart], { type: contentType })
    }
    if (encoding === 'base64') {
      const base64 = (content as { bytes?: unknown } | null)?.bytes
      if (typeof base64 !== 'string') {
        throw new EncryptionError(
          'Malformed encrypted binary document: meta.encoding is "base64" but ' +
            'content.bytes is not a string.'
        )
      }
      return new Blob([base64ToBytes(base64) as BlobPart], {
        type: contentType
      })
    }
    return content as Json
  }
}

/**
 * Decodes bytes as strict UTF-8, returning `null` when they are not valid UTF-8
 * (so the caller can fall back to base64). Uses the shared fatal decoder.
 *
 * @param bytes {Uint8Array}
 * @returns {string | null}
 */
function decodeUtf8(bytes: Uint8Array): string | null {
  try {
    return UTF8_DECODER.decode(bytes)
  } catch {
    return null
  }
}

/**
 * The EDV scheme tag this provider handles (matches the Collection marker).
 */
const EDV_SCHEME = 'edv'

/**
 * The per-collection key material an EDV codec is built from.
 */
export interface EdvKeys {
  keyAgreementKey: IKeyAgreementKey
  keyResolver: IKeyResolver
}

/**
 * Builds an {@link EncryptionProvider} for the `edv` scheme: a pure **keystore**
 * that turns a collection's keys into an {@link EdvCodec}. Pass the result as
 * `WasClient`'s `encryption` option.
 *
 * It does **not** decide which collections are encrypted -- that policy is the
 * Collection's `encryption` marker (or a per-handle override). Core calls
 * `codecFor` only for a collection already known to be encrypted; this provider
 * then supplies the keys: the override-supplied `keys` when present, else
 * `resolveKeys({ spaceId, collectionId })`. `resolveKeys` returning `null` means
 * "I hold no keys for this collection", so core fails closed (it does **not**
 * mean plaintext -- the marker/override already decided that). A non-`edv`
 * scheme yields `null` (this provider does not handle it).
 *
 * @param options {object}
 * @param options.resolveKeys {function}   the keystore: returns the collection's
 *   `{ keyAgreementKey, keyResolver }`, or `null` if this client holds no keys
 *   for it (fail-closed -- not a plaintext signal)
 * @param [options.contentType] {string}   stored envelope content type;
 *   defaults to `application/json`. Pass `JOSE_CONTENT_TYPE`
 *   (`application/jose+json`) against a server that registers an
 *   `application/*+json` parser.
 * @param [options.maxBlobBytes] {number}   single-document binary cap (default
 *   1 MiB)
 * @returns {EncryptionProvider}
 */
export function createEdvEncryption({
  resolveKeys,
  contentType = DEFAULT_CONTENT_TYPE,
  maxBlobBytes = DEFAULT_MAX_BLOB_BYTES
}: {
  resolveKeys: (ref: {
    spaceId: string
    collectionId: string
  }) => Promise<EdvKeys | null>
  contentType?: string
  maxBlobBytes?: number
}): EncryptionProvider {
  return {
    async codecFor({ spaceId, collectionId, scheme, keys }) {
      if (scheme !== EDV_SCHEME) {
        return null
      }
      // Prefer override-supplied keys; otherwise consult the keystore.
      const resolved =
        (keys as EdvKeys | undefined) ??
        (await resolveKeys({ spaceId, collectionId }))
      if (!resolved) {
        return null
      }
      const edv = new EdvClientCore({
        keyAgreementKey: resolved.keyAgreementKey,
        keyResolver: resolved.keyResolver
      })
      return new EdvCodec({
        edv,
        keyAgreementKey: resolved.keyAgreementKey,
        contentType,
        maxBlobBytes
      })
    }
  }
}

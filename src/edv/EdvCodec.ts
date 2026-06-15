/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The EDV (Encrypted Data Vault) resource codec and its `EncryptionProvider`
 * factory -- the encrypting half of the codec seam (Increment 2). Bound to an
 * encrypted collection, it encrypts a caller's value into an EDV envelope
 * (`{ id, sequence, indexed, jwe }`) on write and decrypts it on read, so
 * `collection.put(id, obj)` / `collection.get(id)` transparently round-trip
 * ciphertext. Keys live in the wallet and are supplied per-collection by the
 * app's `resolveKeys`; they never reach the server, which stores only opaque
 * JWE envelopes.
 *
 * This reuses `EdvClientCore`'s encrypt/decrypt primitives (the same JWE
 * machinery as the standalone `WasTransport`), but here the WAS Resource CRUD --
 * the transport role -- is played by core was-client's `Collection`/`Resource`
 * I/O, so the codec is a pure encode/decode transform and needs no transport of
 * its own.
 *
 * Scope (documents-only):
 *
 * - **Restrict-mode ids.** `add()` mints a 128-bit multibase EDV id; the WAS
 *   resource id IS that EDV id. `put(id, ...)` accepts only an EDV-format id --
 *   a human-readable id is rejected (it would leak onto the URL). Carry a
 *   human-readable label inside the encrypted content instead. (Blind-derived
 *   ids are a deferred future item.)
 * - **Small binary as a single JWE.** A `Blob`/`Uint8Array` under the size cap
 *   is wrapped and encrypted as one document; an oversized one is rejected
 *   (chunked encrypted blobs need the server's `chunked-streams` affordance).
 * - **Advisory sequence.** Without server-side conditional writes, every write
 *   is `sequence: 0` (last-writer-wins), as in the standalone transport.
 * - **No server-visible metadata.** `allowsServerMetadata` is `false`, so
 *   `setName`/`setTags` throw on an encrypted collection (the core seam enforces
 *   this).
 */
import { EdvClientCore } from '@interop/edv-client'
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
import { ValidationError } from '../errors.js'
import { readJsonData } from '../internal/content.js'
import type { Json } from '../types.js'
import { EDV_CONTENT_TYPE } from './WasTransport.js'

/**
 * Default ceiling for a single-document (unchunked) encrypted binary write.
 * Past this a `Blob`/`Uint8Array` is rejected until chunked encrypted blobs are
 * supported. 1 MiB before the ~33% base64 inflation.
 */
const DEFAULT_MAX_BLOB_BYTES = 1024 * 1024

/**
 * The default stored content type. Plain JSON keeps the codec portable across
 * any document-capable server (the envelope is still self-identifying by its
 * `jwe` field). Pass `contentType: EDV_CONTENT_TYPE`
 * (`application/edv+json`) against a server that registers an
 * `application/*+json` parser to mark envelopes distinctly in listings.
 */
const DEFAULT_CONTENT_TYPE = 'application/json'

/**
 * Marker property tagging an encrypted document whose decrypted content is a
 * binary blob (rather than a JSON value), so `decode` can reconstruct a `Blob`.
 * Namespaced to avoid colliding with caller JSON.
 */
const BLOB_MARKER = '@interop/was-client:edvBlob'

/**
 * Heuristic for an EDV document id: multibase base58btc (leading `z`) of a
 * 128-bit value. Used to reject human-readable ids on `put()`. Deliberately a
 * loose, dependency-free check (base58 charset, leading `z`, minimum length) --
 * it rejects ids with human separators (`.`/`-`/`_`/spaces) and is not a full
 * decode-and-length verification.
 */
const EDV_DOC_ID = /^z[1-9A-HJ-NP-Za-km-z]{21,}$/

const ENCODER = new TextEncoder()

function isBlob(value: unknown): value is Blob {
  return typeof Blob !== 'undefined' && value instanceof Blob
}

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
 * `EdvClientCore`'s JWE primitives. One instance is bound per encrypted
 * collection handle.
 */
export class EdvCodec implements ResourceCodec {
  readonly allowsServerMetadata = false

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
    contentType
  }: {
    id?: string
    data: Json | Blob | Uint8Array
    contentType?: string
  }): Promise<EncodedWrite> {
    if (id !== undefined && !EDV_DOC_ID.test(id)) {
      throw new ValidationError(
        `Cannot write a human-readable id "${id}" to an encrypted collection ` +
          '-- it would leak onto the URL. Use add() to mint an EDV document ' +
          'id, or carry the human-readable label inside the encrypted content.'
      )
    }
    const docId = id ?? ((await this._edv.generateId()) as string)
    const content = await this._toContent(data, contentType)
    const recipients = this._edv._createDefaultRecipients(this._keyAgreementKey)
    const encrypted = await this._edv._encrypt({
      doc: { id: docId, content },
      recipients,
      keyResolver: this._edv.keyResolver,
      hmac: undefined,
      update: false
    })
    return {
      id: docId,
      body: ENCODER.encode(JSON.stringify(encrypted)),
      contentType: this._contentType
    }
  }

  /**
   * @inheritdoc
   */
  async decode(response: {
    data?: unknown
    json(): Promise<unknown>
  }): Promise<Json | Blob> {
    const encryptedDoc = (await readJsonData(
      response as Parameters<typeof readJsonData>[0]
    )) as IEncryptedDocument
    const decrypted = await this._edv._decrypt({
      encryptedDoc,
      keyAgreementKey: this._keyAgreementKey
    })
    return this._fromContent(decrypted.content)
  }

  /**
   * Resolves a caller value to the EDV document `content`: a JSON object/array
   * passes through; a `Blob`/`Uint8Array` (under the cap) is wrapped as a
   * base64 blob record; a bare primitive is rejected (mirroring the plaintext
   * `prepareBody` contract).
   *
   * @param data {Json | Blob | Uint8Array}
   * @param [contentType] {string}
   * @returns {Promise<object>}
   */
  private async _toContent(
    data: Json | Blob | Uint8Array,
    contentType?: string
  ): Promise<object> {
    if (isBlob(data)) {
      const bytes = new Uint8Array(await data.arrayBuffer())
      return this._blobContent(
        bytes,
        contentType || data.type || 'application/octet-stream'
      )
    }
    if (data instanceof Uint8Array) {
      return this._blobContent(data, contentType || 'application/octet-stream')
    }
    if (data !== null && typeof data === 'object') {
      return data
    }
    throw new ValidationError(
      'Encrypted resource data must be a plain object/array (JSON) or a ' +
        'Blob/Uint8Array (binary).'
    )
  }

  /**
   * Wraps binary bytes as an EDV document content record, enforcing the
   * single-document size cap.
   *
   * @param bytes {Uint8Array}
   * @param contentType {string}
   * @returns {object}
   */
  private _blobContent(bytes: Uint8Array, contentType: string): object {
    if (bytes.length > this._maxBlobBytes) {
      throw new ValidationError(
        `Encrypted binary write of ${bytes.length} bytes exceeds the ` +
          `single-document limit of ${this._maxBlobBytes} bytes. Chunked ` +
          "encrypted blobs need the server's chunked-streams affordance " +
          '(not yet available).'
      )
    }
    return { [BLOB_MARKER]: true, contentType, base64: bytesToBase64(bytes) }
  }

  /**
   * Reconstructs a caller value from decrypted EDV document content: a `Blob`
   * for a wrapped blob record, otherwise the JSON content verbatim.
   *
   * @param content {unknown}
   * @returns {Json | Blob}
   */
  private _fromContent(content: unknown): Json | Blob {
    if (
      content !== null &&
      typeof content === 'object' &&
      (content as Record<string, unknown>)[BLOB_MARKER] === true
    ) {
      const record = content as { contentType?: string; base64: string }
      return new Blob([base64ToBytes(record.base64) as BlobPart], {
        type: record.contentType
      })
    }
    return content as Json
  }
}

/**
 * Builds an {@link EncryptionProvider} that encrypts the collections the client
 * holds keys for, wiring the per-collection keys (from `resolveKeys`) into an
 * {@link EdvCodec}. Pass the result as `WasClient`'s `encryption` option; core
 * resolves a codec for a collection exactly when `resolveKeys` returns keys for
 * it (the switch is keys alone -- encryption is not a backend feature).
 *
 * @param options {object}
 * @param options.resolveKeys {function}   returns the collection's
 *   `{ keyAgreementKey, keyResolver }`, or `null` to read/write it as plaintext
 * @param [options.contentType] {string}   stored envelope content type;
 *   defaults to `application/json`. Pass `EDV_CONTENT_TYPE`
 *   (`application/edv+json`) against a server that registers an
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
  resolveKeys: (ref: { spaceId: string; collectionId: string }) => Promise<{
    keyAgreementKey: IKeyAgreementKey
    keyResolver: IKeyResolver
  } | null>
  contentType?: string
  maxBlobBytes?: number
}): EncryptionProvider {
  return {
    async resolveCodec({ spaceId, collectionId }) {
      const keys = await resolveKeys({ spaceId, collectionId })
      if (!keys) {
        return null
      }
      const edv = new EdvClientCore({
        keyAgreementKey: keys.keyAgreementKey,
        keyResolver: keys.keyResolver
      })
      return new EdvCodec({
        edv,
        keyAgreementKey: keys.keyAgreementKey,
        contentType,
        maxBlobBytes
      })
    }
  }
}

export { EDV_CONTENT_TYPE }

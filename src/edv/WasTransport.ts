/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * An `@interop/edv-client` `Transport` that maps Encrypted Data Vault (EDV)
 * document operations onto ordinary WAS Resource CRUD -- the "EDV-over-WAS"
 * layout profile (Layer 1). It is paired with `EdvClientCore`, which does all
 * encryption, decryption, and index blinding client-side; this transport only
 * moves opaque JWE documents to and from a WAS server, reusing the client's
 * zcap-signed request layer (`WasClient.request()`). Keys never reach the
 * server.
 *
 * Profile decisions encoded here:
 *
 * - **Vault per Collection.** The WAS Collection is the EDV vault; each
 *   encrypted document is one WAS Resource.
 * - **Restrict-mode ids.** The WAS resource id IS the EDV document id (the
 *   128-bit multibase value `EdvClientCore.generateId()` produces), which is
 *   URL-safe and never a reserved segment.
 * - **Encrypted content type.** Documents are stored as `application/json` by
 *   default, so the profile works against an unmodified WAS server. The
 *   preferred type is `application/jose+json` (exported as
 *   `JOSE_CONTENT_TYPE`), which distinguishes EDV envelopes from plaintext
 *   application JSON in listings and metadata -- but the server must register
 *   an `application/*+json` content-type parser to accept it (the reference
 *   was-teaching-server does; a server that does not will reject it with 415).
 *   Pass `contentType: JOSE_CONTENT_TYPE` to opt into it where the server
 *   supports it.
 *
 * Scope: documents (`insert` / `update` / `get`, plus `deleteDocument`, which
 * is not part of the EDV `Transport` contract but lets a driver undo a
 * half-finished multi-request write) plus blinded-index content
 * query (`find`, the `blinded-index` profile of the reserved Collection
 * `POST .../query` endpoint). `updateIndex` throws: in this profile the `indexed` array rides
 * inside the stored document envelope, so `update()` IS the re-index
 * operation and no separate index endpoint exists. Chunked streams
 * (`storeChunk` / `getChunk`) map each EDV chunk onto the reserved
 * `/{id}/chunks/{n}` sub-segment, storing the chunk object as an opaque JSON
 * body -- so `EdvClientCore.insert({
 * stream })` / `getStream` drive chunked encrypted blobs over a WAS server
 * unchanged. The chunk endpoints and the blinded-index query profile are
 * conformance requirements of the server profiles that serve them, so neither
 * carries a client-side gate: a server that does not implement one answers
 * `501`.
 * `insert` is an atomic `If-None-Match: *` create, and the EDV `sequence` is
 * enforced by the server's conditional writes.
 */
import { Transport } from '@interop/edv-client'
import type { HttpResponse } from '@interop/http-client'
import type {
  IEDVChunk,
  IEDVQuery,
  IEncryptedDocument
} from '@interop/data-integrity-core'
import type { WasClient } from '../WasClient.js'
import { httpStatus, NotSupportedError } from '../errors.js'
import { readJsonData } from '../internal/content.js'
import { readEtag, writeHeaders } from '../internal/conditional.js'
import {
  collectionQuery,
  resourceChunkPath,
  resourcePath
} from '../internal/paths.js'
import { DEFAULT_CONTENT_TYPE, envelopeBytes } from './constants.js'

/**
 * The content type a serialized EDV chunk is stored under. Deliberately an
 * opaque binary type (not `application/json`): the chunk is `PUT` as raw bytes
 * so the server routes it through its streaming binary write path (bounded by
 * the backend's `maxUploadBytes`, tens of MiB) rather than the in-memory JSON
 * body parser (a ~1 MiB cap that a full encrypted chunk would exceed). The
 * body is still JSON text -- the server stores it verbatim and never parses it,
 * so `getChunk` decodes and parses it back client-side.
 */
const CHUNK_CONTENT_TYPE = 'application/octet-stream'

/**
 * The message for the EDV unique-attribute collision (HTTP 409): a
 * `unique: true` blinded attribute value already held by another document.
 * Shared by every write method that can trip it.
 */
const DUPLICATE_ATTRIBUTE_MESSAGE =
  'A unique indexed attribute value is already held by another document in ' +
  'this collection.'

/**
 * The subset of `WasClient` this transport depends on: the signed-request
 * escape hatch. Declared structurally so tests can supply a lightweight stub.
 */
type WasRequester = Pick<WasClient, 'request'>

/**
 * Builds an `Error` carrying the `name` that `EdvClientCore` (and the reference
 * `HttpsTransport`) dispatch on -- `DuplicateError`, `InvalidStateError`,
 * `NotFoundError`.
 *
 * @param options {object}
 * @param options.name {string}        the error name to set
 * @param options.message {string}     the human-readable message
 * @param [options.cause] {unknown}    the underlying error, if any
 * @returns {Error}
 */
function namedError({
  name,
  message,
  cause
}: {
  name: string
  message: string
  cause?: unknown
}): Error {
  const err = new Error(message)
  err.name = name
  if (cause !== undefined) {
    err.cause = cause
  }
  return err
}

/**
 * Rethrows a caught transport error as the named error `EdvClientCore`
 * dispatches on, selected by the error's HTTP status from `mapping`; an
 * unmapped status (or a non-HTTP error) is rethrown verbatim. The single
 * status-to-named-error funnel every transport method's catch goes through.
 *
 * @param err {unknown}   the caught error
 * @param mapping {object}   HTTP status to `{ name, message }` of the named
 *   error to throw in its place (the original error becomes its `cause`)
 * @returns {never}
 */
function mapTransportError(
  err: unknown,
  mapping: Record<number, { name: string; message: string }>
): never {
  const status = httpStatus(err)
  const entry = status === undefined ? undefined : mapping[status]
  if (entry) {
    throw namedError({ ...entry, cause: err })
  }
  throw err
}

export class WasTransport extends Transport {
  readonly spaceId: string
  readonly collectionId: string
  readonly contentType: string

  readonly #was: WasRequester
  /**
   * Extra headers stamped on every document write (never on a chunk write).
   */
  readonly #documentHeaders: Record<string, string>
  /**
   * The last document write this transport completed, or `undefined` while it
   * has written none. `EdvClientCore` owns the write sequence and discards the
   * responses, so a driver (the codec's chunked-write plan) reads the outcome
   * of the document write here instead of inspecting requests: whether a
   * document was written at all, and the `ETag` validator the server acked it
   * with. Chunk writes never touch it.
   */
  #lastDocumentWrite?: { id: string; etag?: string }

  /**
   * @param options {object}
   * @param options.was {WasClient}          a WAS client holding the signer
   * @param options.spaceId {string}         the vault's Space id
   * @param options.collectionId {string}    the vault Collection id
   * @param [options.contentType] {string}   content type for stored envelopes;
   *   defaults to `application/json` (accepted by an unmodified server). Pass
   *   `JOSE_CONTENT_TYPE` against a server that registers an
   *   `application/*+json` parser.
   * @param [options.documentHeaders] {Record<string, string>}   extra headers
   *   sent with every document write, for a caller that needs the WAS-level
   *   stamps the codec seam applies (notably `Key-Epoch`). Chunk writes do not
   *   carry them -- a chunk is an opaque body, not a resource with metadata.
   */
  constructor({
    was,
    spaceId,
    collectionId,
    contentType = DEFAULT_CONTENT_TYPE,
    documentHeaders
  }: {
    was: WasRequester
    spaceId: string
    collectionId: string
    contentType?: string
    documentHeaders?: Record<string, string>
  }) {
    super()
    this.#was = was
    this.#documentHeaders = documentHeaders ?? {}
    this.spaceId = spaceId
    this.collectionId = collectionId
    this.contentType = contentType
  }

  /**
   * The last document write this transport completed: its id and, where one
   * reached the client, the `ETag` validator. `undefined` until the first
   * document write succeeds, so a driver can tell "nothing was written" from
   * "written, but no validator came back".
   *
   * @returns {{ id: string; etag?: string } | undefined}
   */
  get lastDocumentWrite(): { id: string; etag?: string } | undefined {
    return this.#lastDocumentWrite
  }

  /**
   * The WAS resource path for a document id, delegating to was-client's
   * internal `resourcePath` builder so the percent-encoding and trailing-slash
   * rules stay defined in one place (no trailing slash -- get/put/delete by
   * id).
   *
   * @param id {string}   the EDV document id (= WAS resource id)
   * @returns {string}
   */
  #resourcePath(id: string): string {
    return resourcePath(this.spaceId, this.collectionId, id)
  }

  /**
   * Writes an encrypted document to its WAS resource path as
   * `application/jose+json` (the envelope serialized to bytes so the stored
   * content type is exact).
   *
   * @param id {string}
   * @param encrypted {IEncryptedDocument}
   * @param [headers] {Record<string, string>}   extra request headers (e.g. a
   *   conditional-write precondition)
   * @returns {Promise<HttpResponse>}
   */
  async #put(
    id: string,
    encrypted: IEncryptedDocument,
    headers: Record<string, string> = {}
  ): Promise<HttpResponse> {
    const body = envelopeBytes(encrypted)
    const response = await this.#was.request({
      path: this.#resourcePath(id),
      method: 'PUT',
      body,
      headers: {
        'content-type': this.contentType,
        ...this.#documentHeaders,
        ...headers
      }
    })
    // Record the acked write for a driver that needs its outcome: the core
    // swallows this response, and this is the only place that knows a document
    // (not a chunk) was written.
    const etag = readEtag(response)
    this.#lastDocumentWrite = { id, ...(etag !== undefined && { etag }) }
    return response
  }

  /**
   * Deletes a document resource. Not part of the EDV `Transport` contract (the
   * EDV core never deletes) -- it is the compensating action a driver needs
   * when a multi-request write fails partway and the document it already wrote
   * would otherwise be orphaned.
   *
   * @param options {object}
   * @param options.id {string}   the document id (= WAS resource id)
   * @returns {Promise<void>}
   */
  async deleteDocument({ id }: { id: string }): Promise<void> {
    await this.#was.request({ path: this.#resourcePath(id), method: 'DELETE' })
  }

  /**
   * @inheritdoc
   *
   * Inserts a new encrypted document. WAS `PUT` is an upsert, so EDV insert
   * semantics (`DuplicateError` if the id already exists) need a guard: the
   * insert is a single atomic `PUT` with `If-None-Match: *`, and the server's
   * 412 maps to `DuplicateError`. A 409 (a `unique: true` blinded attribute
   * already held by another document) likewise maps to `DuplicateError`.
   *
   * @param options {object}
   * @param options.encrypted {IEncryptedDocument}   the document to insert
   * @returns {Promise<void>}
   */
  override async insert({
    encrypted
  }: { encrypted?: IEncryptedDocument } = {}): Promise<void> {
    if (!encrypted) {
      throw new TypeError('"encrypted" is required.')
    }
    const duplicateId = {
      name: 'DuplicateError',
      message: `A document with id "${encrypted.id}" already exists.`
    }
    try {
      await this.#put(
        encrypted.id,
        encrypted,
        writeHeaders({ precondition: { ifNoneMatch: true } })
      )
    } catch (err) {
      mapTransportError(err, {
        // The `If-None-Match: *` precondition failing IS "the document
        // already exists".
        412: duplicateId,
        409: { name: 'DuplicateError', message: DUPLICATE_ATTRIBUTE_MESSAGE }
      })
    }
  }

  /**
   * @inheritdoc
   *
   * Updates (upserts) an encrypted document.
   *
   * Two write-time conflicts are mapped to the names `EdvClientCore` dispatches
   * on. A stale/sequence conflict is rejected with 412
   * (precondition-failed), which surfaces as `InvalidStateError` -- the
   * recoverable case, by re-fetching the current document and retrying. A 409
   * is the EDV unique-attribute collision (a
   * `unique: true` blinded attribute already held by another document), which
   * is NOT recoverable by re-fetch-and-retry; it surfaces as `DuplicateError`.
   *
   * @param options {object}
   * @param options.encrypted {IEncryptedDocument}   the document to update
   * @returns {Promise<void>}
   */
  override async update({
    encrypted
  }: { encrypted?: IEncryptedDocument } = {}): Promise<void> {
    if (!encrypted) {
      throw new TypeError('"encrypted" is required.')
    }
    try {
      await this.#put(encrypted.id, encrypted)
    } catch (err) {
      mapTransportError(err, {
        412: {
          name: 'InvalidStateError',
          message:
            'Document update conflict: the stored document changed since it ' +
            'was read. Re-fetch the current document and retry.'
        },
        409: { name: 'DuplicateError', message: DUPLICATE_ATTRIBUTE_MESSAGE }
      })
    }
  }

  /**
   * @inheritdoc
   *
   * Reads an encrypted document by id. Throws a `NotFoundError` (the name
   * `EdvClientCore` expects) when the resource is missing or not visible.
   *
   * @param options {object}
   * @param options.id {string}   the document id to read
   * @returns {Promise<IEncryptedDocument>}
   */
  override async get({
    id
  }: { id?: string } = {}): Promise<IEncryptedDocument> {
    if (!id) {
      throw new TypeError('"id" is required.')
    }
    let response: HttpResponse
    try {
      response = await this.#was.request({
        path: this.#resourcePath(id),
        method: 'GET'
      })
    } catch (err) {
      mapTransportError(err, {
        404: { name: 'NotFoundError', message: 'Document not found.' }
      })
    }
    return (await readJsonData(response)) as IEncryptedDocument
  }

  /**
   * @inheritdoc
   *
   * Runs a blinded-index content query: a signed `POST` of
   * `{ profile: 'blinded-index', ...query }` to the Collection's reserved
   * `/query` endpoint. Serving the profile is a conformance requirement of a
   * server that offers it, so there is no client-side gate: one that does not
   * implement it answers `501`. The server evaluates the
   * blinded `equals` / `has` filters against the `indexed` entries of stored
   * documents (opaque string comparison -- it does no crypto) and returns
   * `{ documents, hasMore, cursor? }` (the encrypted envelopes verbatim, in
   * ascending resource-id order, with `cursor` present iff `hasMore`), or a
   * bare `{ count }` when `query.count` is `true`. The body is returned
   * untouched: `EdvClientCore.find` decrypts `documents` and passes
   * `hasMore` / `cursor` through.
   *
   * @param options {object}
   * @param options.query {IEDVQuery}   the blinded query (`index` plus one of
   *   `equals` / `has`, and optional `count` / `limit` / `cursor`), as built
   *   by `EdvClientCore`'s `IndexHelper.buildQuery`
   * @returns {Promise<object>}   the server's response body verbatim
   */
  override async find({ query }: { query?: IEDVQuery } = {}): Promise<object> {
    if (!query) {
      throw new TypeError('"query" is required.')
    }
    // `returnDocuments` is a first-class `IEDVQuery` field, but the WAS profile
    // has no ids-only mode, so it is dropped (whatever its value) and full
    // documents come back -- the best-effort degradation `EdvClientCore.find`
    // documents for this option.
    const { returnDocuments: _returnDocuments, ...blindedQuery } = query
    let response: HttpResponse
    try {
      response = await this.#was.request({
        path: collectionQuery(this.spaceId, this.collectionId),
        method: 'POST',
        json: { profile: 'blinded-index', ...blindedQuery }
      })
    } catch (err) {
      mapTransportError(err, {
        404: { name: 'NotFoundError', message: 'Collection not found.' }
      })
    }
    const result = await readJsonData(response)
    if (result === null || typeof result !== 'object') {
      throw new Error('Malformed blinded-index query response.')
    }
    return result
  }

  /**
   * @inheritdoc
   *
   * Not supported, deliberately: in the EDV-over-WAS profile, index entries
   * are not a separate server-side resource -- the `indexed` array rides
   * inside the stored document envelope, and every `insert` / `update`
   * already carries it. Re-indexing a document is therefore an ordinary
   * `update()` of the full envelope; there is no `/{id}/index` endpoint to
   * bind this to.
   */
  override async updateIndex(): Promise<never> {
    throw new NotSupportedError(
      '"updateIndex" is not supported by the EDV-over-WAS profile: index ' +
        'entries ride inside the stored document envelope, so re-index a ' +
        'document with an ordinary "update()" of the full document.'
    )
  }

  /**
   * The WAS path of one chunk of a document, delegating to the internal
   * `resourceChunkPath` builder (member form, no trailing slash --
   * put/get/delete one chunk by index).
   *
   * @param docId {string}       the EDV document id (= WAS resource id)
   * @param chunkIndex {number}   the chunk's non-negative ordinal index
   * @returns {string}
   */
  #chunkPath(docId: string, chunkIndex: number): string {
    return resourceChunkPath(this.spaceId, this.collectionId, docId, chunkIndex)
  }

  /**
   * @inheritdoc
   *
   * Stores one encrypted chunk of a document's data stream. The EDV chunk
   * object (`{ sequence, index, jwe, offset }`) is serialized to JSON and
   * `PUT` as an opaque binary body ({@link CHUNK_CONTENT_TYPE}) to the chunk's
   * own URL (`.../chunks/{index}`), signed like every other write. The server
   * stores the bytes verbatim -- it never parses the chunk -- so any
   * client-side crypto framing is transparent to it. The parent Resource must
   * already exist
   * (`EdvClientCore.insert`/`update` writes the document envelope before
   * draining the stream), so a 404 here surfaces as a `NotFoundError`.
   *
   * @param options {object}
   * @param options.docId {string}     the owning document id (= WAS resource id)
   * @param options.chunk {IEDVChunk}   the encrypted chunk to store
   * @returns {Promise<void>}
   */
  override async storeChunk({
    docId,
    chunk
  }: { docId?: string; chunk?: IEDVChunk } = {}): Promise<void> {
    if (!docId) {
      throw new TypeError('"docId" is required.')
    }
    if (!chunk) {
      throw new TypeError('"chunk" is required.')
    }
    try {
      await this.#was.request({
        path: this.#chunkPath(docId, chunk.index),
        method: 'PUT',
        body: envelopeBytes(chunk),
        headers: { 'content-type': CHUNK_CONTENT_TYPE }
      })
    } catch (err) {
      mapTransportError(err, {
        404: {
          name: 'NotFoundError',
          message:
            `Cannot store chunk ${chunk.index}: the parent document ` +
            `"${docId}" does not exist. Write the document before its chunks.`
        }
      })
    }
  }

  /**
   * @inheritdoc
   *
   * Reads one encrypted chunk back by index, `GET`ting the chunk's own URL and
   * parsing the opaque body (stored as raw bytes, so parsed client-side) back
   * into the EDV chunk object the decrypt stream consumes. A missing chunk
   * (404) surfaces as a `NotFoundError` (the name
   * `EdvClientCore` expects), so a reassembling reader can distinguish it.
   *
   * @param options {object}
   * @param options.docId {string}        the owning document id
   * @param options.chunkIndex {number}   the chunk's ordinal index
   * @returns {Promise<IEDVChunk>}
   */
  override async getChunk({
    docId,
    chunkIndex
  }: { docId?: string; chunkIndex?: number } = {}): Promise<IEDVChunk> {
    if (!docId) {
      throw new TypeError('"docId" is required.')
    }
    if (chunkIndex === undefined) {
      throw new TypeError('"chunkIndex" is required.')
    }
    let response: HttpResponse
    try {
      response = await this.#was.request({
        path: this.#chunkPath(docId, chunkIndex),
        method: 'GET'
      })
    } catch (err) {
      mapTransportError(err, {
        404: {
          name: 'NotFoundError',
          message: `Chunk ${chunkIndex} of document "${docId}" not found.`
        }
      })
    }
    // The chunk was stored as opaque bytes, so the http-client did not
    // pre-parse it: decode the body text and parse the EDV chunk object back.
    return JSON.parse(await response.text()) as IEDVChunk
  }
}

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
 *   preferred marker is `application/jose+json` (exported as `JOSE_CONTENT_TYPE`),
 *   which distinguishes EDV envelopes from plaintext application JSON in
 *   listings and metadata -- but the server must register an `application/*+json`
 *   content-type parser to accept it (the reference was-teaching-server does; a
 *   server that does not will reject it with 415). Pass `contentType:
 *   JOSE_CONTENT_TYPE` to opt into it where the server supports it.
 *
 * Scope: documents (`insert` / `update` / `get`) plus blinded-index content
 * query (`find`, the `blinded-index` profile of the reserved Collection
 * `POST .../query` endpoint -- the server's `blinded-index-query` backend
 * feature). `updateIndex` throws: in this profile the `indexed` array rides
 * inside the stored document envelope, so `update()` IS the re-index
 * operation and no separate index endpoint exists. Chunked streams
 * (`storeChunk` / `getChunk`) still require the server's `chunked-streams`
 * affordance (the reserved `/{id}/chunks/{n}` sub-segment), which neither
 * reference backend provides, so they throw.
 * `insert` uses an atomic `If-None-Match: *` create when the backend
 * advertises the optional `conditional-writes` feature; otherwise (and for
 * `update`) writes are advisory -- the EDV `sequence` is not enforced
 * (last-writer-wins on `update`).
 */
import { Transport } from '@interop/edv-client'
import type { HttpResponse } from '@interop/http-client'
import type {
  IEDVQuery,
  IEncryptedDocument
} from '@interop/data-integrity-core'
import type { WasClient } from '../WasClient.js'
import { httpStatus } from '../errors.js'
import { readJsonData } from '../internal/content.js'
import {
  collectionBackend,
  collectionQuery,
  resourcePath
} from '../internal/paths.js'
import {
  DEFAULT_CONTENT_TYPE,
  envelopeBytes,
  JOSE_CONTENT_TYPE
} from './constants.js'

export { JOSE_CONTENT_TYPE }

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

export class WasTransport extends Transport {
  readonly spaceId: string
  readonly collectionId: string
  readonly contentType: string

  private readonly _was: WasRequester
  private _backendFeaturesPromise?: Promise<string[]>

  /**
   * @param options {object}
   * @param options.was {WasClient}          a WAS client holding the signer
   * @param options.spaceId {string}         the vault's Space id
   * @param options.collectionId {string}    the vault Collection id
   * @param [options.contentType] {string}   content type for stored envelopes;
   *   defaults to `application/json` (accepted by an unmodified server). Pass
   *   `JOSE_CONTENT_TYPE` against a server that registers an `application/*+json`
   *   parser.
   */
  constructor({
    was,
    spaceId,
    collectionId,
    contentType = DEFAULT_CONTENT_TYPE
  }: {
    was: WasRequester
    spaceId: string
    collectionId: string
    contentType?: string
  }) {
    super()
    this._was = was
    this.spaceId = spaceId
    this.collectionId = collectionId
    this.contentType = contentType
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
  private _resourcePath(id: string): string {
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
  private async _put(
    id: string,
    encrypted: IEncryptedDocument,
    headers: Record<string, string> = {}
  ): Promise<HttpResponse> {
    const body = envelopeBytes(encrypted)
    return this._was.request({
      path: this._resourcePath(id),
      method: 'PUT',
      body,
      headers: { 'content-type': this.contentType, ...headers }
    })
  }

  /**
   * The feature tokens the collection's backend advertises in its "Collection
   * Backend Selected" descriptor (e.g. `conditional-writes`,
   * `blinded-index-query`). Read once and memoized for the transport's
   * lifetime; any failure to read the descriptor (404, 501 on a server without
   * backend support, network error) resolves `[]`, so every affordance gate
   * falls closed.
   *
   * @returns {Promise<string[]>}
   */
  private _backendFeatures(): Promise<string[]> {
    this._backendFeaturesPromise ??= (async () => {
      try {
        const response = await this._was.request({
          path: collectionBackend(this.spaceId, this.collectionId),
          method: 'GET'
        })
        const descriptor = (await readJsonData(response)) as {
          features?: unknown
        } | null
        return Array.isArray(descriptor?.features)
          ? descriptor.features.filter(
              (feature): feature is string => typeof feature === 'string'
            )
          : []
      } catch {
        return []
      }
    })()
    return this._backendFeaturesPromise
  }

  /**
   * Whether the collection's backend advertises the optional
   * `conditional-writes` feature, so `insert` can use an atomic
   * `If-None-Match: *` create instead of the advisory existence-check path.
   *
   * @returns {Promise<boolean>}
   */
  private async _conditionalWrites(): Promise<boolean> {
    return (await this._backendFeatures()).includes('conditional-writes')
  }

  /**
   * @inheritdoc
   *
   * Inserts a new encrypted document. WAS `PUT` is an upsert, so EDV insert
   * semantics (`DuplicateError` if the id already exists) need a guard. When
   * the backend advertises `conditional-writes`, the insert is a single atomic
   * `PUT` with `If-None-Match: *`, and the server's 412 maps to
   * `DuplicateError`. Otherwise it degrades to a bodiless existence check
   * (`HEAD`) before the `PUT` -- advisory and non-atomic, but no longer
   * downloading the whole stored envelope just to discard it. In either path a
   * 409 (a `unique: true` blinded attribute already held by another document)
   * likewise maps to `DuplicateError`.
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
    if (await this._conditionalWrites()) {
      try {
        await this._put(encrypted.id, encrypted, { 'if-none-match': '*' })
      } catch (err) {
        if (httpStatus(err) === 412) {
          throw namedError({
            name: 'DuplicateError',
            message: `A document with id "${encrypted.id}" already exists.`,
            cause: err
          })
        }
        if (httpStatus(err) === 409) {
          throw namedError({
            name: 'DuplicateError',
            message:
              'A unique indexed attribute value is already held by another ' +
              'document in this collection.',
            cause: err
          })
        }
        throw err
      }
      return
    }
    if (await this._exists(encrypted.id)) {
      throw namedError({
        name: 'DuplicateError',
        message: `A document with id "${encrypted.id}" already exists.`
      })
    }
    try {
      await this._put(encrypted.id, encrypted)
    } catch (err) {
      if (httpStatus(err) === 409) {
        throw namedError({
          name: 'DuplicateError',
          message:
            'A unique indexed attribute value is already held by another ' +
            'document in this collection.',
          cause: err
        })
      }
      throw err
    }
  }

  /**
   * @inheritdoc
   *
   * Updates (upserts) an encrypted document. The EDV `sequence` is advisory
   * here -- without server-side conditional writes, a stale write is not
   * rejected (last-writer-wins).
   *
   * Two write-time conflicts are mapped to the names `EdvClientCore` dispatches
   * on. A server enforcing conditional writes rejects a stale/sequence
   * conflict with 412 (precondition-failed), which surfaces as
   * `InvalidStateError` -- the recoverable case, by re-fetching the current
   * document and retrying. A 409 is the EDV unique-attribute collision (a
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
      await this._put(encrypted.id, encrypted)
    } catch (err) {
      if (httpStatus(err) === 412) {
        throw namedError({
          name: 'InvalidStateError',
          message:
            'Document update conflict: the stored document changed since it ' +
            'was read. Re-fetch the current document and retry.',
          cause: err
        })
      }
      if (httpStatus(err) === 409) {
        throw namedError({
          name: 'DuplicateError',
          message:
            'A unique indexed attribute value is already held by another ' +
            'document in this collection.',
          cause: err
        })
      }
      throw err
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
      response = await this._was.request({
        path: this._resourcePath(id),
        method: 'GET'
      })
    } catch (err) {
      if (httpStatus(err) === 404) {
        throw namedError({
          name: 'NotFoundError',
          message: 'Document not found.',
          cause: err
        })
      }
      throw err
    }
    return (await readJsonData(response)) as IEncryptedDocument
  }

  /**
   * Resolves to `true` if a resource exists at the document's path, via a
   * bodiless `HEAD` (the stored envelope is not needed, only its existence). A
   * 404 resolves to `false`; any other error propagates.
   *
   * @param id {string}
   * @returns {Promise<boolean>}
   */
  private async _exists(id: string): Promise<boolean> {
    try {
      await this._was.request({ path: this._resourcePath(id), method: 'HEAD' })
      return true
    } catch (err) {
      if (httpStatus(err) === 404) {
        return false
      }
      throw err
    }
  }

  /**
   * @inheritdoc
   *
   * Runs a blinded-index content query: a signed `POST` of
   * `{ profile: 'blinded-index', ...query }` to the Collection's reserved
   * `/query` endpoint. Requires the backend's `blinded-index-query` affordance
   * (throws `NotSupportedError` when it is absent). The server evaluates the
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
    if (!(await this._backendFeatures()).includes('blinded-index-query')) {
      throw namedError({
        name: 'NotSupportedError',
        message:
          "Blinded-index query is not supported: the collection's backend " +
          'does not advertise the "blinded-index-query" affordance.'
      })
    }
    // `returnDocuments` is a first-class `IEDVQuery` field, but the WAS profile
    // has no ids-only mode, so it is dropped (whatever its value) and full
    // documents come back -- the best-effort degradation `EdvClientCore.find`
    // documents for this option.
    const { returnDocuments: _returnDocuments, ...blindedQuery } = query
    let response: HttpResponse
    try {
      response = await this._was.request({
        path: collectionQuery(this.spaceId, this.collectionId),
        method: 'POST',
        json: { profile: 'blinded-index', ...blindedQuery }
      })
    } catch (err) {
      if (httpStatus(err) === 404) {
        throw namedError({
          name: 'NotFoundError',
          message: 'Collection not found.',
          cause: err
        })
      }
      throw err
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
    throw namedError({
      name: 'NotSupportedError',
      message:
        '"updateIndex" is not supported by the EDV-over-WAS profile: index ' +
        'entries ride inside the stored document envelope, so re-index a ' +
        'document with an ordinary "update()" of the full document.'
    })
  }

  /**
   * @inheritdoc
   *
   * Chunked streams need the reserved `/{id}/chunks/{n}` sub-segment.
   */
  override async storeChunk(): Promise<never> {
    return this._unsupported('storeChunk (chunked streams)')
  }

  /**
   * @inheritdoc
   *
   * Chunked streams need the reserved `/{id}/chunks/{n}` sub-segment.
   */
  override async getChunk(): Promise<never> {
    return this._unsupported('getChunk (chunked streams)')
  }

  /**
   * Throws a uniform "not supported in this profile" error for the chunked-
   * stream operations, which depend on a server-side affordance (the reserved
   * `/{id}/chunks/{n}` sub-segment, the `chunked-streams` backend feature)
   * that neither reference backend provides yet.
   *
   * @param operation {string}
   * @returns {never}
   */
  private _unsupported(operation: string): never {
    throw namedError({
      name: 'NotSupportedError',
      message:
        `"${operation}" is not supported by the EDV-over-WAS profile ` +
        '(requires the server\'s "chunked-streams" affordance).'
    })
  }
}

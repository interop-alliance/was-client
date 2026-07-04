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
 * Scope: documents only (`insert` / `update` / `get`). Blinded `find` / `count`
 * / `updateIndex` and chunked streams (`storeChunk` / `getChunk`) require
 * server-side EDV affordances (blinded `/query`, the `/{id}/chunks/{n}`
 * sub-segment) that a plaintext WAS server does not yet provide, so they throw
 * here. `insert` uses an atomic `If-None-Match: *` create when the backend
 * advertises the optional `conditional-writes` feature; otherwise (and for
 * `update`) writes are advisory -- the EDV `sequence` is not enforced
 * (last-writer-wins on `update`).
 */
import { Transport } from '@interop/edv-client'
import type { HttpResponse } from '@interop/http-client'
import type { IEncryptedDocument } from '@interop/data-integrity-core'
import type { WasClient } from '../WasClient.js'
import { httpStatus } from '../errors.js'
import { readJsonData } from '../internal/content.js'
import { collectionBackend, resourcePath } from '../internal/paths.js'
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
  private _conditionalWritesPromise?: Promise<boolean>

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
   * Whether the collection's backend advertises the `conditional-writes`
   * feature. Read once from the "Collection Backend Selected" descriptor and
   * memoized for the transport's lifetime; any failure to read the descriptor
   * (404, 501 on a server without backend support, network error) resolves
   * `false`, so the caller falls back to the advisory path.
   *
   * @returns {Promise<boolean>}
   */
  private _conditionalWrites(): Promise<boolean> {
    this._conditionalWritesPromise ??= (async () => {
      try {
        const response = await this._was.request({
          path: collectionBackend(this.spaceId, this.collectionId),
          method: 'GET'
        })
        const descriptor = (await readJsonData(response)) as {
          features?: unknown
        } | null
        return (
          Array.isArray(descriptor?.features) &&
          descriptor.features.includes('conditional-writes')
        )
      } catch {
        return false
      }
    })()
    return this._conditionalWritesPromise
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
   * downloading the whole stored envelope just to discard it.
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
    await this._put(encrypted.id, encrypted)
  }

  /**
   * @inheritdoc
   *
   * Updates (upserts) an encrypted document. The EDV `sequence` is advisory
   * here -- without server-side conditional writes, a stale write is not
   * rejected (last-writer-wins).
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
      // A server that DOES enforce conditional writes signals a stale update
      // with 409; surface it the way `EdvClientCore` expects.
      if (httpStatus(err) === 409) {
        throw namedError({
          name: 'InvalidStateError',
          message: 'Conflict error.',
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
   * Blinded-index query is not part of the documents-only EDV-over-WAS profile;
   * it needs the server's `/query` affordance.
   */
  override async find(): Promise<never> {
    return this._unsupported('find (blinded-index query)')
  }

  /**
   * @inheritdoc
   *
   * Index updates need the server's `/{id}/index` affordance.
   */
  override async updateIndex(): Promise<never> {
    return this._unsupported('updateIndex')
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
   * Throws a uniform "not supported in this profile" error for EDV operations
   * that depend on server-side affordances absent from a plaintext WAS server.
   *
   * @param operation {string}
   * @returns {never}
   */
  private _unsupported(operation: string): never {
    throw namedError({
      name: 'NotSupportedError',
      message:
        `"${operation}" is not supported by the documents-only ` +
        'EDV-over-WAS profile (requires server-side EDV affordances).'
    })
  }
}

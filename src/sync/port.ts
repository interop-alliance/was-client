/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * `createWasSyncPort`: the {@link WasSyncPort} implementation over a signed
 * {@link WasClient}, bound to one Space + Collection.
 *
 * Writes and single-resource reads ride the raw, signed `was.request()` escape
 * hatch, which moves the stored body VERBATIM (bypassing the encryption codec).
 * The change feed already ships opaque stored bodies -- plaintext for a
 * plaintext collection, the EDV envelope for an encrypted one -- and push must
 * write those same bytes back unchanged; running them through `resource.put()`
 * would re-encrypt an already-encrypted envelope. Encrypt/decrypt therefore
 * stays a read/write-time concern above the port, and the port itself is
 * collection-agnostic and never touches keys.
 *
 * The pull path rides the client's `Collection.changes()` feed, bound to the
 * same Space + Collection, which produces the byte-identical signed
 * `POST /space/:s/:c/query` (profile `changes`) as a root invocation and, like
 * the raw writes, ships the stored bodies verbatim without decrypting. The
 * port moves JSON documents, so it keeps only the feed's `kind: 'resource'`
 * entries with a JSON content type, and renames the feed's `deleted` to the
 * `_deleted` its consumers read.
 *
 * Conditional writes ride the server's `ETag`, an opaque quoted strong
 * validator, enforced uniformly for plaintext and encrypted resources, so
 * there is no plaintext-vs-encrypted fork. `putContent`/`deleteContent`
 * return the server-acked {@link WriteAck}: the write's raw `etag`, which the
 * port never parses. A caller records the acked `etag` immediately and echoes
 * it back verbatim as a later write's `ifMatch`. Conditional writes are a
 * baseline server requirement, so a write carrying `ifMatch` or `ifNoneMatch`
 * goes out as given and the server answers a lost race with a `412`.
 *
 * Bypassing the codec is not bypassing the error mapper. Every failure caught
 * here goes through the client's own `mapError` first, so the port's signals
 * carry the server's `problem+json` fields and a `cause`, and a status the
 * port has no signal for still leaves this subpath as a typed `WasError`.
 */
import type { WasClient } from '../WasClient.js'
import type { HttpResponse } from '@interop/http-client'
import {
  assertWriterId,
  KEY_EPOCH_HEADER,
  readEtag,
  writeHeaders,
  WRITER_ID_HEADER
} from '../internal/conditional.js'
import { resourceMeta, resourcePath } from '../internal/paths.js'
import {
  isJsonResourceChange,
  isMetaStamp,
  isWriteStamp,
  ProblemTypes
} from '@interop/storage-core'
import type {
  ResourceChangeDocument,
  ResourceMetadata
} from '@interop/storage-core'
import {
  mapError,
  NotFoundError,
  PreconditionFailedError,
  WasSyncAuthError,
  WasSyncCheckpointError,
  WasSyncConflictError,
  WasSyncNotFoundError,
  WasServerError
} from '../errors.js'
import type { WasError, WasErrorOptions } from '../errors.js'
import type { IZcap } from '../types.js'
import type {
  Json,
  MasterState,
  SyncPage,
  WasSyncPort,
  WireDoc,
  WriteAck
} from './types.js'

/**
 * The request header the server reads a content write's key-epoch id from,
 * stamping it onto the Resource's metadata. Defined next to the header
 * assembly it drives (`internal/conditional.ts`) and re-exported here as part
 * of the sync subpath's public surface.
 */
export { KEY_EPOCH_HEADER }

/**
 * The request header a content write or delete declares its writer-attribution
 * label under, stamping it onto the Resource Metadata `writerId` property.
 * Defined next to the header assembly it drives (`internal/conditional.ts`)
 * and re-exported here as part of the sync subpath's public surface.
 */
export { WRITER_ID_HEADER }

/**
 * The placeholder `updatedAt` for a 412-conflict re-read whose resource has no
 * `/meta` document yet (its server-managed timestamp is unknown). An epoch-zero
 * ISO string is a valid, sortable timestamp that sorts before every real one --
 * unlike an empty string, which is not a parseable date. The change feed remains
 * the authority on ordering, so this only feeds the one-off conflict entry.
 */
const UNKNOWN_UPDATED_AT = new Date(0).toISOString()

/**
 * The statuses a WAS server can return for an authorization failure: `401` (no
 * verifiable invocation), `403` (not permitted), and the `404` it returns when
 * it masks an authorization failure as "not found".
 *
 * @param status {number | undefined}
 * @returns {boolean}
 */
function isAuthStatus(status: number | undefined): status is number {
  return status === 401 || status === 403 || status === 404
}

/**
 * Carries a mapped error's `problem+json` fields onto the port signal built
 * from it. The `cause` is the raw transport error `mapError` recorded, or the
 * mapped error itself when there was none. A port signal is a narrowing of the
 * classification `mapError` already made, so it must not lose what the server
 * said.
 *
 * @param mapped {WasError}   the classified error
 * @returns {WasErrorOptions}
 */
function signalOptions(mapped: WasError): WasErrorOptions {
  return {
    status: mapped.status,
    type: mapped.type,
    title: mapped.title,
    problems: mapped.problems,
    details: mapped.details,
    requestUrl: mapped.requestUrl,
    cause: mapped.cause ?? mapped
  }
}

/**
 * Whether a mapped error is already one of the port's own signals, which a
 * nested port call (the write-ack re-read inside a write) can raise through a
 * write's catch block. Re-wrapping one would drop its cause for no gain.
 *
 * @param mapped {WasError}
 * @returns {boolean}
 */
function isPortSignal(mapped: WasError): boolean {
  return (
    mapped instanceof WasSyncConflictError ||
    mapped instanceof WasSyncNotFoundError ||
    mapped instanceof WasSyncCheckpointError ||
    mapped instanceof WasSyncAuthError
  )
}

/**
 * Whether a mapped `changes` failure is the server refusing the presented
 * checkpoint: `invalid-request-body` with a problem pointing at
 * `#/checkpoint`. The same kind pointing elsewhere (an unaccepted `profile`)
 * is an ordinary validation failure.
 *
 * @param mapped {WasError}
 * @returns {boolean}
 */
function isRefusedCheckpoint(mapped: WasError): boolean {
  return (
    mapped.type === ProblemTypes.INVALID_REQUEST_BODY &&
    (mapped.problems ?? []).some(problem => problem.pointer === '#/checkpoint')
  )
}

/**
 * The port's view of one JSON Resource entry (live or tombstone). The feed's
 * `deleted` becomes `_deleted`, the member the port's consumers read. The
 * feed's bodies are parsed JSON, so the shared type's `unknown` bodies narrow
 * to the `Json` the port contract promises.
 *
 * @param doc {ResourceChangeDocument}
 * @returns {WireDoc}
 */
function toWireDoc(doc: ResourceChangeDocument): WireDoc {
  const { deleted, ...rest } = doc
  return { ...rest, _deleted: deleted } as WireDoc
}

/**
 * Maps a caught write error onto the port's typed signals, rethrowing anything
 * else as the classified {@link WasError} the client's own `mapError` builds
 * (so a status outside this list -- a `500`, a `507` quota-exceeded -- still
 * leaves the sync subpath typed and carrying the server's problem details).
 * A rejected precondition becomes a {@link WasSyncConflictError} for every
 * write. `notFound` opts in to the not-found mapping, which `deleteContent`
 * and `putMeta` perform on the default port (an already-gone target is a
 * settled outcome for a delete and a delete race for a metadata write, but a
 * hard error for a content write). `authErrors` is
 * the port's `mapAuthErrors` option: it maps `401` / `403` / the masked `404`
 * to a {@link WasSyncAuthError}. `notFound` is checked first, so a port that
 * asked for both still gets the not-found signal.
 *
 * @param err {unknown}   the caught error
 * @param [options] {object}
 * @param [options.notFound] {boolean}   map a not-found to
 *   {@link WasSyncNotFoundError}
 * @param [options.authErrors] {boolean}   map `401`/`403`/`404` to
 *   {@link WasSyncAuthError}
 * @returns {never}   always throws
 */
function mapWriteError(
  err: unknown,
  {
    notFound = false,
    authErrors = false
  }: { notFound?: boolean; authErrors?: boolean } = {}
): never {
  const mapped = mapError(err)
  if (isPortSignal(mapped)) {
    throw mapped
  }
  if (notFound && mapped instanceof NotFoundError) {
    throw new WasSyncNotFoundError(mapped.message, signalOptions(mapped))
  }
  if (mapped instanceof PreconditionFailedError) {
    throw new WasSyncConflictError(mapped.message, signalOptions(mapped))
  }
  if (authErrors && isAuthStatus(mapped.status)) {
    throw new WasSyncAuthError(mapped.status, signalOptions(mapped))
  }
  throw mapped
}

/**
 * Builds a {@link WasSyncPort} bound to one Space + Collection, backed by the
 * caller's signed {@link WasClient}. With no `capability`, requests invoke the
 * client's own root capability.
 *
 * `mapAuthErrors` exists because a WAS server MASKS an authorization failure as
 * `404` ("not found or invalid authorization") rather than `403`, so an
 * unauthorized caller cannot probe which resources exist. A replica that
 * already synced its Space and Collection knows they exist, so on its sync
 * paths a `404` can only mean the invocation itself was rejected -- the
 * expired- or revoked-grant signal it needs in order to stop retrying and
 * prompt for a reconnect. The reading is only safe with that knowledge, so it
 * is opt-in: off (the default), every status behaves exactly as before.
 *
 * Two paths keep their own `404` semantics even when it is on, because there a
 * `404` is a modeled outcome rather than an anomaly: `deleteContent` resolves
 * (the tombstone's goal state already holds -- an idempotent delete), and `get`
 * resolves `null` (absent or tombstoned -- the deletion-wins input its callers
 * depend on). A `putMeta` `404` is ambiguous by design: it is either the
 * masked authorization failure or a delete race (the resource was deleted by
 * another replica after this one read it), and the option maps it to a
 * {@link WasSyncAuthError} whose `status` a push loop can corroborate against
 * a re-read. Revoked access still surfaces within one poll on `query` and on
 * the content/metadata writes.
 *
 * @param options {object}
 * @param options.was {WasClient}       the session client (holds the signer)
 * @param options.spaceId {string}      the WAS Space id
 * @param options.collectionId {string}   the WAS collection id
 * @param [options.capability] {IZcap}   a delegated capability to invoke on
 *   every request this port makes (pull, writes, and reads alike); omit to
 *   invoke the client's own root capability
 * @param [options.mapAuthErrors] {boolean}   map `401` / `403` / the masked
 *   `404` to {@link WasSyncAuthError} (default `false`)
 * @returns {WasSyncPort}
 */
export function createWasSyncPort({
  was,
  spaceId,
  collectionId,
  capability,
  mapAuthErrors = false
}: {
  was: WasClient
  spaceId: string
  collectionId: string
  capability?: IZcap
  mapAuthErrors?: boolean
}): WasSyncPort {
  // Paths come from the internal builders, so this port inherits the same
  // percent-encoding and reserved/dot-segment guards as the handle API.
  const contentPath = (id: string) => resourcePath(spaceId, collectionId, id)
  const metaPath = (id: string) => resourceMeta(spaceId, collectionId, id)

  // Construction is I/O-free (the codec is a lazy thunk) and `changes()`
  // never resolves the codec, so it ships the stored bodies verbatim -- what
  // this codec-bypassing port requires.
  const changesCollection = was
    .space(spaceId)
    .collection(collectionId, { capability })

  /** Re-reads a resource's raw content body + `ETag` (no decrypt, no `/meta`). */
  const readContent = async (id: string): Promise<MasterState | null> => {
    let response: HttpResponse
    try {
      response = await was.request({
        capability,
        path: contentPath(id),
        method: 'GET'
      })
    } catch (err) {
      const mapped = mapError(err)
      // A read's `404` stays "absent or tombstoned" even under
      // `mapAuthErrors`: it is a modeled outcome here, and the callers read it
      // as deletion-wins.
      if (mapped instanceof NotFoundError) {
        return null
      }
      if (mapAuthErrors && isAuthStatus(mapped.status)) {
        throw new WasSyncAuthError(mapped.status, signalOptions(mapped))
      }
      throw mapped
    }
    const etag = readEtag(response)
    // `.data` is populated only for a JSON media type, so a resource stored as
    // `text/jsonl`, `text/html`, or opaque bytes would otherwise produce a
    // `MasterState` carrying a real `etag` and no `data` -- which a
    // replica reads as a live-but-empty document and then pushes over the
    // content that is actually there. The port contract promises `Json`, so a
    // body it cannot deliver as `Json` is a fault, reported as one.
    if (response.data === undefined) {
      throw new WasServerError(
        `The resource "${id}" answered with a body this sync port cannot ` +
          `carry (content-type ` +
          `"${response.headers.get('content-type') ?? 'unknown'}"): the ` +
          'port moves JSON documents, so a non-JSON stored body cannot be ' +
          'reported as state.'
      )
    }
    return {
      ...(etag !== undefined && { etag }),
      updatedAt: UNKNOWN_UPDATED_AT,
      data: response.data as Json
    }
  }

  /**
   * The acked {@link WriteAck} of a write response. Taken from the response's
   * own `ETag` only: a re-read after the fact could return a concurrent
   * writer's validator as this write's ack. A response with no `ETag`, or
   * with one the client cannot see, acks no `etag`.
   */
  const writeAck = (response: HttpResponse): WriteAck => {
    const etag = readEtag(response)
    return etag === undefined ? {} : { etag }
  }

  /**
   * One page of the port's documents: the feed's JSON Resources and their
   * tombstones. The Collection's own records, a kind this client does not
   * know, and a binary or `text/jsonl` Resource are not documents the port
   * moves. A server page whose entries are all skipped is not handed back as
   * an empty page: an empty page reads as caught up, and a pull loop that
   * stops on it would never store the checkpoint that moves past those
   * entries. The pull instead resumes from that page's own checkpoint (the
   * walk `Collection.resourceChanges()` owns, repeat guard included) until it
   * has a document to return or the feed ends.
   *
   * @param options {object}
   * @param [options.checkpoint] {string}   the opaque checkpoint to resume after
   * @param options.limit {number}   max entries per server page
   * @returns {Promise<SyncPage>}
   */
  const pullDocuments = async ({
    checkpoint,
    limit
  }: {
    checkpoint?: string
    limit: number
  }): Promise<SyncPage> => {
    for await (const page of changesCollection.resourceChanges({
      checkpoint,
      limit
    })) {
      const documents = page.documents
        .filter(isJsonResourceChange)
        .map(toWireDoc)
      if (documents.length > 0 || page.checkpoint === null) {
        return { documents, checkpoint: page.checkpoint }
      }
    }
    // Unreachable: the walk's last page has `checkpoint: null` and returns.
    return { documents: [], checkpoint: null }
  }

  // The signals `deleteContent` and `putMeta` ask `mapWriteError` for: the
  // not-found mapping on the default port, the auth mapping under
  // `mapAuthErrors`.
  const writeSignals = { notFound: !mapAuthErrors, authErrors: mapAuthErrors }

  return {
    async query({ checkpoint, limit }) {
      try {
        return await pullDocuments({ checkpoint, limit })
      } catch (err) {
        // The pull path is where revoked access surfaces reliably: unlike a
        // read or a delete, a `404` on the collection's own query endpoint has
        // no benign reading once the collection is known to exist.
        const mapped = mapError(err)
        if (mapAuthErrors && isAuthStatus(mapped.status)) {
          throw new WasSyncAuthError(mapped.status, signalOptions(mapped))
        }
        if (isRefusedCheckpoint(mapped)) {
          throw new WasSyncCheckpointError(
            mapped.message,
            signalOptions(mapped)
          )
        }
        throw mapped
      }
    },

    async putContent({ id, data, ifMatch, ifNoneMatch, epoch, writerId }) {
      try {
        const response = await was.request({
          capability,
          path: contentPath(id),
          method: 'PUT',
          json: data as object,
          headers: writeHeaders({
            precondition: { ifMatch, ifNoneMatch },
            epoch,
            writerId
          })
        })
        return writeAck(response)
      } catch (err) {
        mapWriteError(err, { authErrors: mapAuthErrors })
      }
    },

    async deleteContent({ id, ifMatch, writerId }) {
      try {
        const response = await was.request({
          capability,
          path: contentPath(id),
          method: 'DELETE',
          headers: writeHeaders({ precondition: { ifMatch }, writerId })
        })
        return writeAck(response)
      } catch (err) {
        // Under `mapAuthErrors` a delete's `404` is an idempotent success: the
        // resource is already gone (deleted locally before it was ever pushed,
        // or deleted first by another replica), so the tombstone's goal state
        // holds and the batch must not be retried forever. A masked
        // authorization `404` is swallowed with it -- indistinguishable by
        // design -- but revoked access still surfaces on the next `query`.
        const mapped = mapError(err)
        if (mapAuthErrors && mapped instanceof NotFoundError) {
          return undefined
        }
        mapWriteError(mapped, writeSignals)
      }
    },

    async putMeta({ id, custom, ifMatch, ifNoneMatch, writerId }) {
      assertWriterId(writerId)
      try {
        const response = await was.request({
          capability,
          path: metaPath(id),
          method: 'PUT',
          // The `/meta` PUT fully replaces `custom`: a body omitting it writes
          // the CLEARED state (the server clears every property the body
          // leaves out), which is how a metadata clear replicates. `writerId`
          // rides as a top-level member beside `custom`, on the same
          // declare-or-clear terms: an omitted value clears the stored label.
          // Byte-identical on the wire to the `{ custom: undefined }` this
          // used to send, since `JSON.stringify` drops an `undefined` member.
          json: {
            ...(custom !== undefined ? { custom } : {}),
            ...(writerId !== undefined ? { writerId } : {})
          },
          headers: writeHeaders({ precondition: { ifMatch, ifNoneMatch } })
        })
        const ack = writeAck(response)
        return ack.etag !== undefined ? ack : undefined
      } catch (err) {
        // A `/meta` write against a nonexistent resource legitimately `404`s
        // (the resource was deleted by another replica after this one read
        // it), so the default port raises the not-found signal a push loop
        // can corroborate. Under `mapAuthErrors` the masked `404` stays the
        // auth signal, `status` telling the two apart.
        mapWriteError(err, writeSignals)
      }
    },

    async get({ id }): Promise<MasterState | null> {
      // The content and metadata reads hit independent endpoints, so both fly
      // together. The metadata read settles into a value (its rejection handler
      // is attached before any `await` that can throw, so an abandoned read can
      // never surface as an unhandled rejection).
      const metaRead = was
        .request({ capability, path: metaPath(id), method: 'GET' })
        .then(
          response => ({ ok: true as const, response }),
          (err: unknown) => ({ ok: false as const, err })
        )

      const master = await readContent(id)
      if (master === null) {
        return null // absent or tombstoned; the metadata read is discarded
      }

      // Metadata (best-effort): the `/meta` body carries the server-managed
      // write stamp (`updatedAt`, `updatedAtCounter`, `originId`), the nested
      // `meta` stamp of the `/meta` record, the creator DID, the key-epoch id,
      // the writer-attribution label, and the user-writable `custom`, plus its
      // own `metaEtag` ETag. A resource with no metadata yet 404s
      // here; only a hard error propagates.
      const meta = await metaRead
      if (!meta.ok) {
        const mapped = mapError(meta.err)
        // A `/meta` `404` is routine (the resource has no metadata document
        // yet), so it stays benign under `mapAuthErrors` -- only `401`/`403`
        // map there.
        if (mapped instanceof NotFoundError) {
          return master
        }
        if (mapAuthErrors && isAuthStatus(mapped.status)) {
          throw new WasSyncAuthError(mapped.status, signalOptions(mapped))
        }
        throw mapped
      }

      const metaBody = meta.response.data as
        (Omit<ResourceMetadata, 'custom'> & { custom?: Json }) | undefined
      // The stamp is copied whole or not at all. A bare `updatedAt` leaves the
      // placeholder in place: without its counter and origin it cannot be
      // ordered against another revision, and a counter or origin beside the
      // placeholder would read as a complete stamp that loses to every one.
      if (isWriteStamp(metaBody)) {
        master.updatedAt = metaBody.updatedAt
        master.updatedAtCounter = metaBody.updatedAtCounter
        master.originId = metaBody.originId
      }
      if (isMetaStamp(metaBody?.meta)) {
        master.meta = metaBody.meta
      }
      if (metaBody?.createdBy !== undefined) {
        master.createdBy = metaBody.createdBy
      }
      if (metaBody?.epoch !== undefined) {
        master.epoch = metaBody.epoch
      }
      if (metaBody?.writerId !== undefined) {
        master.writerId = metaBody.writerId
      }
      if (metaBody?.custom !== undefined) {
        master.custom = metaBody.custom
      }
      // The validator is kept whenever the server sent one, so a later
      // `putMeta` can pin on it.
      const metaEtag = readEtag(meta.response)
      if (metaEtag !== undefined) {
        master.metaEtag = metaEtag
      }

      return master
    }
  }
}

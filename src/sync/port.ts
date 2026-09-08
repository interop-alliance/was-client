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
 * the raw writes, ships the stored bodies verbatim without decrypting.
 *
 * Conditional writes ride the server's `ETag`: an opaque quoted string
 * (`"<generation>.<version>"`, a per-record generation marker ahead of the
 * monotonic content `version` so a hard-deleted-and-recreated id can never
 * collide with its predecessor's validators), enforced uniformly for
 * plaintext and encrypted resources, so there is no plaintext-vs-encrypted
 * fork. `putContent`/`deleteContent` return the server-acked {@link
 * WriteAck} -- the write's raw `etag` (re-read only if the backend sent
 * none) plus its `version` parsed out of it -- so a caller can record acked
 * revisions immediately and echo `etag` back verbatim as a later write's
 * `ifMatch`.
 *
 * Bypassing the codec is not bypassing the error mapper. Every failure caught
 * here goes through the client's own `mapError` first, so the port's signals
 * carry the server's `problem+json` fields and a `cause`, and a status the
 * port has no signal for still leaves this subpath as a typed `WasError`.
 */
import type { WasClient } from '../WasClient.js'
import type { HttpResponse } from '@interop/http-client'
import {
  KEY_EPOCH_HEADER,
  readEtag,
  writeHeaders
} from '../internal/conditional.js'
import { resourceMeta, resourcePath } from '../internal/paths.js'
import {
  mapError,
  NotFoundError,
  PreconditionFailedError,
  WasSyncAuthError,
  WasSyncConflictError,
  WasSyncNotFoundError
} from '../errors.js'
import type { WasError, WasErrorOptions } from '../errors.js'
import type { IZcap } from '../types.js'
import type { Json, MasterState, WasSyncPort, WriteAck } from './types.js'

/**
 * The request header the server reads a content write's key-epoch id from,
 * stamping it onto the Resource's metadata. Defined next to the header
 * assembly it drives (`internal/conditional.ts`) and re-exported here as part
 * of the sync subpath's public surface.
 */
export { KEY_EPOCH_HEADER }

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
    mapped instanceof WasSyncAuthError
  )
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
 * Parses a quoted strong `ETag` into its numeric revision: the decimal
 * integer after the LAST `.` inside the quotes (`"3mJr7AoUXx2.3"` to `3`).
 * Returns `undefined` when the header is absent, has no `.`, or the trailing
 * segment is anything other than a run of digits.
 *
 * The quoted string as a whole is opaque -- it also carries a per-record
 * generation marker ahead of the version, minted once and kept for the
 * record's life, so this is one-way: there is no `formatEtag` to build a
 * validator back out of a bare revision number. Always echo the `etag` a read
 * or write returned back verbatim for `ifMatch`/`ifNoneMatch`; this helper
 * only reads the revision out of it for comparison or display.
 *
 * @param etag {string | null | undefined}
 * @returns {number | undefined}
 */
export function parseEtag(etag: string | null | undefined): number | undefined {
  if (!etag) {
    return undefined
  }
  const unquoted = etag.replace(/"/g, '')
  const lastDot = unquoted.lastIndexOf('.')
  if (lastDot === -1) {
    return undefined
  }
  const versionPart = unquoted.slice(lastDot + 1)
  return /^\d+$/.test(versionPart) ? Number(versionPart) : undefined
}

/**
 * Reads a response's `ETag` together with the revision parsed out of it, the
 * one place the two are paired. `etag` is absent when the response carried no
 * validator (a backend that does not version the resource); `version` is
 * absent whenever `etag` is, and also when the validator does not end in a
 * revision number. Callers decide what an absent value means for them.
 *
 * @param response {HttpResponse}
 * @returns {{ etag?: string, version?: number }}
 */
function versionedEtag(response: HttpResponse): {
  etag?: string
  version?: number
} {
  const etag = readEtag(response)
  const version = parseEtag(etag)
  return {
    ...(etag !== undefined && { etag }),
    ...(version !== undefined && { version })
  }
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

  // Construction is I/O-free (the codec/feature probes are lazy thunks) and
  // `changes()` never resolves the codec, so it ships the stored bodies
  // verbatim -- what this codec-bypassing port requires.
  const changesCollection = was
    .space(spaceId)
    .collection(collectionId, { capability })

  /** Re-reads a resource's raw content body + version (no decrypt, no `/meta`). */
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
    const { etag, version } = versionedEtag(response)
    return {
      version: version ?? 0,
      etag,
      updatedAt: UNKNOWN_UPDATED_AT,
      data: response.data as Json
    }
  }

  /**
   * The acked {@link WriteAck} of a write response. Taken from the response's
   * own `ETag` only: a re-read after the fact could return a concurrent
   * writer's validator as this write's ack. A response with no `ETag` acks
   * `version: 0` and no `etag`, the shape of a backend that does not version
   * resources.
   */
  const writeAck = (response: HttpResponse): WriteAck => {
    const { etag, version } = versionedEtag(response)
    return { version: version ?? 0, etag }
  }

  // The signals `deleteContent` and `putMeta` ask `mapWriteError` for: the
  // not-found mapping on the default port, the auth mapping under
  // `mapAuthErrors`.
  const writeSignals = { notFound: !mapAuthErrors, authErrors: mapAuthErrors }

  return {
    async query({ checkpoint, limit }) {
      try {
        return await changesCollection.changes({ checkpoint, limit })
      } catch (err) {
        // The pull path is where revoked access surfaces reliably: unlike a
        // read or a delete, a `404` on the collection's own query endpoint has
        // no benign reading once the collection is known to exist.
        const mapped = mapError(err)
        if (mapAuthErrors && isAuthStatus(mapped.status)) {
          throw new WasSyncAuthError(mapped.status, signalOptions(mapped))
        }
        throw mapped
      }
    },

    async putContent({ id, data, ifMatch, ifNoneMatch, epoch }) {
      try {
        const response = await was.request({
          capability,
          path: contentPath(id),
          method: 'PUT',
          json: data as object,
          headers: writeHeaders({
            precondition: { ifMatch, ifNoneMatch },
            epoch
          })
        })
        return writeAck(response)
      } catch (err) {
        mapWriteError(err, { authErrors: mapAuthErrors })
      }
    },

    async deleteContent({ id, ifMatch }) {
      try {
        const response = await was.request({
          capability,
          path: contentPath(id),
          method: 'DELETE',
          headers: writeHeaders({ precondition: { ifMatch } })
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

    async putMeta({ id, custom, ifMatch, ifNoneMatch }) {
      try {
        const response = await was.request({
          capability,
          path: metaPath(id),
          method: 'PUT',
          // The `/meta` PUT fully replaces `custom`: a body omitting it writes
          // the CLEARED state (the server clears every property the body
          // leaves out), which is how a metadata clear replicates. Byte-
          // identical on the wire to the `{ custom: undefined }` this used to
          // send, since `JSON.stringify` drops an `undefined` member.
          json: custom === undefined ? {} : { custom },
          headers: writeHeaders({ precondition: { ifMatch, ifNoneMatch } })
        })
        const { etag, version } = versionedEtag(response)
        return etag !== undefined ? { version: version ?? 0, etag } : undefined
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
      // `updatedAt`, the creator DID, the key-epoch id, and the user-writable
      // `custom`, plus its own `metaVersion`/`metaEtag` ETag. A resource with
      // no metadata yet 404s here; only a hard error propagates.
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
        | {
            updatedAt?: string
            createdBy?: string
            epoch?: string
            custom?: Json
          }
        | undefined
      if (metaBody?.updatedAt) {
        master.updatedAt = metaBody.updatedAt
      }
      if (metaBody?.createdBy !== undefined) {
        master.createdBy = metaBody.createdBy
      }
      if (metaBody?.epoch !== undefined) {
        master.epoch = metaBody.epoch
      }
      if (metaBody?.custom !== undefined) {
        master.custom = metaBody.custom
      }
      // The validator is kept whenever the server sent one, so a later
      // `putMeta` can pin on it even when no revision number parses out of it.
      const { etag: metaEtag, version: metaVersion } = versionedEtag(
        meta.response
      )
      if (metaEtag !== undefined) {
        master.metaEtag = metaEtag
      }
      if (metaVersion !== undefined) {
        master.metaVersion = metaVersion
      }

      return master
    }
  }
}

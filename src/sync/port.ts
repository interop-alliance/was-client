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
 * Conditional writes ride the server's monotonic content `version` (`ETag`),
 * enforced uniformly for plaintext and encrypted resources, so there is no
 * plaintext-vs-encrypted fork. `putContent`/`deleteContent` return the server-
 * acked `version` (parsed from the write's `ETag`, re-read only if the backend
 * sent none), so a caller can record acked revisions immediately.
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
  errorMessage,
  httpStatus,
  WasSyncAuthError,
  WasSyncConflictError,
  WasSyncNotFoundError
} from '../errors.js'
import type { IZcap } from '../types.js'
import type { Json, MasterState, WasSyncPort } from './types.js'

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
 * Extracts an HTTP status from a raw ky/ezcap error. `was.request()` rejects on
 * any non-2xx with `err.status` set; this reads it defensively from either the
 * flat `status` or the nested `response.status` shape. The sync subpath's name
 * for the client's own {@link httpStatus}.
 */
export const errorStatus = httpStatus

/**
 * Normalizes an unknown caught error into a display string. The sync subpath's
 * name for the client's own {@link errorMessage}, the companion to
 * {@link errorStatus}.
 */
export { errorMessage }

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
 * Maps a raw write error onto the port's typed signals, rethrowing anything
 * else unchanged: `412` becomes a {@link WasSyncConflictError} for every write.
 * `notFound` opts in to the `404` mapping, which only `deleteContent` performs
 * (an already-gone target is a settled outcome for a delete, but a hard error
 * for a content or metadata write). `authErrors` is the port's `mapAuthErrors`
 * option: it maps `401` / `403` / the masked `404` to a
 * {@link WasSyncAuthError}. `notFound` is checked first, so a port that asked
 * for both still gets the delete-specific signal.
 *
 * @param err {unknown}   the caught error
 * @param [options] {object}
 * @param [options.notFound] {boolean}   map `404` to {@link WasSyncNotFoundError}
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
  const status = errorStatus(err)
  if (notFound && status === 404) {
    throw new WasSyncNotFoundError()
  }
  if (status === 412) {
    throw new WasSyncConflictError()
  }
  if (authErrors && isAuthStatus(status)) {
    throw new WasSyncAuthError(status)
  }
  throw err
}

/**
 * Formats a numeric content `version` as the quoted strong `ETag` an
 * update-if-unchanged write passes as its `ifMatch` precondition (e.g. `3` to
 * `"3"`). Inverse of {@link parseEtag}.
 *
 * @param version {number}
 * @returns {string}
 */
export function formatEtag(version: number): string {
  return `"${version}"`
}

/**
 * Parses a quoted strong `ETag` (`"3"`) into its numeric revision, or
 * `undefined` when the header is absent or non-numeric (no such revision yet).
 *
 * @param etag {string | null}
 * @returns {number | undefined}
 */
export function parseEtag(etag: string | null): number | undefined {
  if (!etag) {
    return undefined
  }
  const revision = Number(etag.replace(/"/g, ''))
  return Number.isFinite(revision) ? revision : undefined
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
 * depend on). Revoked access still surfaces within one poll on `query` and on
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
      const status = errorStatus(err)
      // A read's `404` stays "absent or tombstoned" even under
      // `mapAuthErrors`: it is a modeled outcome here, and the callers read it
      // as deletion-wins.
      if (status === 404) {
        return null
      }
      if (mapAuthErrors && isAuthStatus(status)) {
        throw new WasSyncAuthError(status)
      }
      throw err
    }
    return {
      version: parseEtag(readEtag(response) ?? null) ?? 0,
      updatedAt: UNKNOWN_UPDATED_AT,
      data: response.data as Json
    }
  }

  /** Resolves the acked version from a write response, or via a content re-read. */
  const ackedVersion = async (
    response: HttpResponse,
    id: string
  ): Promise<number> => {
    const version = parseEtag(readEtag(response) ?? null)
    if (version !== undefined) {
      return version
    }
    return (await readContent(id))?.version ?? 0
  }

  return {
    async query({ checkpoint, limit }) {
      try {
        return await changesCollection.changes({ checkpoint, limit })
      } catch (err) {
        // The pull path is where revoked access surfaces reliably: unlike a
        // read or a delete, a `404` on the collection's own query endpoint has
        // no benign reading once the collection is known to exist.
        const status = errorStatus(err)
        if (mapAuthErrors && isAuthStatus(status)) {
          throw new WasSyncAuthError(status)
        }
        throw err
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
        return await ackedVersion(response, id)
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
        return await ackedVersion(response, id)
      } catch (err) {
        // Under `mapAuthErrors` a delete's `404` is an idempotent success: the
        // resource is already gone (deleted locally before it was ever pushed,
        // or deleted first by another replica), so the tombstone's goal state
        // holds and the batch must not be retried forever. A masked
        // authorization `404` is swallowed with it -- indistinguishable by
        // design -- but revoked access still surfaces on the next `query`.
        if (mapAuthErrors && errorStatus(err) === 404) {
          return undefined
        }
        mapWriteError(err, {
          notFound: !mapAuthErrors,
          authErrors: mapAuthErrors
        })
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
        // `readEtag` reports an absent header as `undefined`; `parseEtag` reads
        // the `null` spelling of the same thing.
        return parseEtag(readEtag(response) ?? null)
      } catch (err) {
        mapWriteError(err, { authErrors: mapAuthErrors })
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
      // `custom`, plus its own `metaVersion` ETag. A resource with no metadata
      // yet 404s here; only a hard error propagates.
      const meta = await metaRead
      if (!meta.ok) {
        const status = errorStatus(meta.err)
        // A `/meta` `404` is routine (the resource has no metadata document
        // yet), so it stays benign under `mapAuthErrors` -- only `401`/`403`
        // map there.
        if (status === 404) {
          return master
        }
        if (mapAuthErrors && isAuthStatus(status)) {
          throw new WasSyncAuthError(status)
        }
        throw meta.err
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
      const metaVersion = parseEtag(readEtag(meta.response) ?? null)
      if (metaVersion !== undefined) {
        master.metaVersion = metaVersion
      }

      return master
    }
  }
}

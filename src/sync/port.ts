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
  httpStatus,
  WasSyncConflictError,
  WasSyncNotFoundError
} from '../errors.js'
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
 * Maps a raw write error onto the port's typed signals, rethrowing anything
 * else unchanged: `412` becomes a {@link WasSyncConflictError} for every write.
 * `notFound` opts in to the `404` mapping, which only `deleteContent` performs
 * (an already-gone target is a settled outcome for a delete, but a hard error
 * for a content or metadata write).
 *
 * @param err {unknown}   the caught error
 * @param [options] {object}
 * @param [options.notFound] {boolean}   map `404` to {@link WasSyncNotFoundError}
 * @returns {never}   always throws
 */
function mapWriteError(
  err: unknown,
  { notFound = false }: { notFound?: boolean } = {}
): never {
  const status = errorStatus(err)
  if (notFound && status === 404) {
    throw new WasSyncNotFoundError()
  }
  if (status === 412) {
    throw new WasSyncConflictError()
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
 * caller's signed {@link WasClient}. Requests invoke the client's own root
 * capability (no delegated `capability` is attached).
 *
 * @param options {object}
 * @param options.was {WasClient}       the session client (holds the signer)
 * @param options.spaceId {string}      the WAS Space id
 * @param options.collectionId {string}   the WAS collection id
 * @returns {WasSyncPort}
 */
export function createWasSyncPort({
  was,
  spaceId,
  collectionId
}: {
  was: WasClient
  spaceId: string
  collectionId: string
}): WasSyncPort {
  // Paths come from the internal builders, so this port inherits the same
  // percent-encoding and reserved/dot-segment guards as the handle API.
  const contentPath = (id: string) => resourcePath(spaceId, collectionId, id)
  const metaPath = (id: string) => resourceMeta(spaceId, collectionId, id)

  // Construction is I/O-free (the codec/feature probes are lazy thunks) and
  // `changes()` never resolves the codec, so it ships the stored bodies
  // verbatim -- what this codec-bypassing port requires.
  const changesCollection = was.space(spaceId).collection(collectionId)

  /** Re-reads a resource's raw content body + version (no decrypt, no `/meta`). */
  const readContent = async (id: string): Promise<MasterState | null> => {
    let response: HttpResponse
    try {
      response = await was.request({ path: contentPath(id), method: 'GET' })
    } catch (err) {
      if (errorStatus(err) === 404) {
        return null // absent or tombstoned -- caller treats as deletion-wins
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
      return changesCollection.changes({ checkpoint, limit })
    },

    async putContent({ id, data, ifMatch, ifNoneMatch, epoch }) {
      try {
        const response = await was.request({
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
        mapWriteError(err)
      }
    },

    async deleteContent({ id, ifMatch }) {
      try {
        const response = await was.request({
          path: contentPath(id),
          method: 'DELETE',
          headers: writeHeaders({ precondition: { ifMatch } })
        })
        return await ackedVersion(response, id)
      } catch (err) {
        mapWriteError(err, { notFound: true })
      }
    },

    async putMeta({ id, custom, ifMatch, ifNoneMatch }) {
      try {
        await was.request({
          path: metaPath(id),
          method: 'PUT',
          json: { custom },
          headers: writeHeaders({ precondition: { ifMatch, ifNoneMatch } })
        })
      } catch (err) {
        mapWriteError(err)
      }
    },

    async get({ id }): Promise<MasterState | null> {
      // The content and metadata reads hit independent endpoints, so both fly
      // together. The metadata read settles into a value (its rejection handler
      // is attached before any `await` that can throw, so an abandoned read can
      // never surface as an unhandled rejection).
      const metaRead = was.request({ path: metaPath(id), method: 'GET' }).then(
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
        if (errorStatus(meta.err) !== 404) {
          throw meta.err
        }
        return master
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

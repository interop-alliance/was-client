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
import { writeHeaders } from '../internal/conditional.js'
import { WasSyncConflictError, WasSyncNotFoundError } from '../errors.js'
import type {
  Json,
  MasterState,
  SyncCheckpoint,
  WasSyncPort,
  WireDoc
} from './types.js'

/**
 * The request header the server reads a content write's key-epoch id from,
 * stamping it onto the Resource's metadata (an absent header clears any prior
 * stamp). HTTP header names are case-insensitive; the wire form is `WAS-Key-Epoch`.
 */
export const WAS_KEY_EPOCH_HEADER = 'WAS-Key-Epoch'

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
 * flat `status` or the nested `response.status` shape.
 *
 * @param err {unknown}   the caught error
 * @returns {number | undefined}
 */
export function errorStatus(err: unknown): number | undefined {
  return (
    (err as { status?: number }).status ??
    (err as { response?: { status?: number } }).response?.status
  )
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
  const collectionPath = `/space/${spaceId}/${collectionId}`
  const resourcePath = (id: string) =>
    `${collectionPath}/${encodeURIComponent(id)}`

  // Construction is I/O-free (the codec/feature probes are lazy thunks) and
  // `changes()` never resolves the codec, so it ships the stored bodies
  // verbatim -- what this codec-bypassing port requires.
  const changesCollection = was.space(spaceId).collection(collectionId)

  /** Re-reads a resource's raw content body + version (no decrypt, no `/meta`). */
  const readContent = async (id: string): Promise<MasterState | null> => {
    let response: HttpResponse
    try {
      response = await was.request({ path: resourcePath(id), method: 'GET' })
    } catch (err) {
      if (errorStatus(err) === 404) {
        return null // absent or tombstoned -- caller treats as deletion-wins
      }
      throw err
    }
    return {
      version: parseEtag(response.headers.get('etag')) ?? 0,
      updatedAt: UNKNOWN_UPDATED_AT,
      deleted: false,
      data: response.data as Json
    }
  }

  /** Resolves the acked version from a write response, or via a content re-read. */
  const ackedVersion = async (
    response: HttpResponse,
    id: string
  ): Promise<number> => {
    const version = parseEtag(response.headers.get('etag'))
    if (version !== undefined) {
      return version
    }
    return (await readContent(id))?.version ?? 0
  }

  return {
    async query({ checkpoint, limit }) {
      const page = await changesCollection.changes({ checkpoint, limit })
      return {
        documents: page.documents as WireDoc[],
        checkpoint: page.checkpoint as SyncCheckpoint | null
      }
    },

    async putContent({ id, data, ifMatch, ifNoneMatch, epoch }) {
      try {
        const response = await was.request({
          path: resourcePath(id),
          method: 'PUT',
          json: data as object,
          headers: writeHeaders({
            precondition: { ifMatch, ifNoneMatch },
            epoch
          })
        })
        return await ackedVersion(response, id)
      } catch (err) {
        if (errorStatus(err) === 412) {
          throw new WasSyncConflictError()
        }
        throw err
      }
    },

    async deleteContent({ id, ifMatch }) {
      try {
        const response = await was.request({
          path: resourcePath(id),
          method: 'DELETE',
          headers: writeHeaders({ precondition: { ifMatch } })
        })
        return await ackedVersion(response, id)
      } catch (err) {
        const status = errorStatus(err)
        if (status === 404) {
          throw new WasSyncNotFoundError()
        }
        if (status === 412) {
          throw new WasSyncConflictError()
        }
        throw err
      }
    },

    async putMeta({ id, custom, ifMatch, ifNoneMatch }) {
      try {
        await was.request({
          path: `${resourcePath(id)}/meta`,
          method: 'PUT',
          json: { custom },
          headers: writeHeaders({ precondition: { ifMatch, ifNoneMatch } })
        })
      } catch (err) {
        if (errorStatus(err) === 412) {
          throw new WasSyncConflictError()
        }
        throw err
      }
    },

    async get({ id }): Promise<MasterState | null> {
      const master = await readContent(id)
      if (master === null) {
        return null
      }

      // Metadata re-read (best-effort): the `/meta` body carries the server-
      // managed `updatedAt`, the creator DID, the key-epoch id, and the user-
      // writable `custom`, plus its own `metaVersion` ETag. A resource with no
      // metadata yet 404s here; only a hard error propagates.
      try {
        const metaResponse = await was.request({
          path: `${resourcePath(id)}/meta`,
          method: 'GET'
        })
        const metaBody = metaResponse.data as
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
        const metaVersion = parseEtag(metaResponse.headers.get('etag'))
        if (metaVersion !== undefined) {
          master.metaVersion = metaVersion
        }
      } catch (err) {
        if (errorStatus(err) !== 404) {
          throw err
        }
      }

      return master
    }
  }
}

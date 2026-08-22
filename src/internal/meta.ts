/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Shared `/meta` I/O for the Collection and Resource handles. The two read and
 * write the same metadata document shape and differ only in the metadata type,
 * whether the `custom` envelope is bound to a resource id, and whether the
 * codec's key epoch travels in the PUT body. Each handle wraps these with its
 * own JSDoc.
 */
import { WasServerError } from '../errors.js'
import type { ResourceCodec } from '../codec.js'
import type { ClientContext } from './request.js'
import { send } from './request.js'
import { readEtag, writeHeaders } from './conditional.js'
import { withCodec } from './withCodec.js'
import type {
  IZcap,
  ResourceMetadataCustom,
  ResourceMetadataCustomInput
} from '../types.js'

/**
 * Reads a metadata document and decodes its user-writable `custom` value.
 * Returns `null` when the target is missing or not visible (404 conflation
 * caveat), and carries the metadata's `etag` when the backend versions it.
 *
 * @param context {ClientContext}
 * @param options {object}
 * @param options.metaPath {string}   the `/meta` sub-resource path
 * @param options.codec {Promise<ResourceCodec>}   the resolving codec, awaited
 *   concurrently with the read
 * @param options.subject {string}   the metadata's owner as it reads in the
 *   malformed-response error message
 * @param [options.id] {string}   the resource id the metadata belongs to, for
 *   an encrypting codec's envelope-binding check. Omitted at Collection level.
 * @param [options.capability] {IZcap}
 * @returns {Promise<(Metadata & { etag?: string }) | null>}
 */
export async function readMeta<
  Metadata extends { custom?: ResourceMetadataCustom }
>(
  context: ClientContext,
  {
    metaPath,
    codec: codecPromise,
    subject,
    id,
    capability
  }: {
    metaPath: string
    codec: Promise<ResourceCodec>
    subject: string
    id?: string
    capability?: IZcap
  }
): Promise<(Metadata & { etag?: string }) | null> {
  // The metadata GET does not depend on the codec (only its `custom` decode
  // below does), so the two overlap.
  const [codec, response] = await withCodec(
    codecPromise,
    send(context, {
      path: metaPath,
      method: 'GET',
      capability,
      read: true
    })
  )
  if (response === null) {
    return null
  }
  if (response.data === undefined) {
    // A 200 whose body `@interop/http-client` did not pre-parse into `.data`
    // (a non-JSON content-type, or an empty/204 body): a metadata document
    // always carries its server-managed fields as JSON, so an absent `.data`
    // is a malformed response. Fail with a typed error rather than
    // dereferencing `metadata.custom` off `undefined` as a raw `TypeError`.
    // (Kept distinct from the `null` return, which means the target is missing
    // or not visible -- not that the server answered malformed.)
    throw new WasServerError(
      `Metadata response for ${subject} carried no JSON body ` +
        `(content-type ` +
        `"${response.headers.get('content-type') ?? 'unknown'}").`
    )
  }
  const metadata = response.data as Metadata
  // Decode the user-writable `custom` (decrypting it on an encrypted
  // collection) so callers uniformly see plaintext `{ name, tags }`. With no
  // resource id -- the Collection-level read -- the slot belongs to the
  // collection itself, and the encrypting codec refuses a resource-bound
  // envelope served there.
  const custom = await codec.decodeMeta({ custom: metadata.custom }, id)
  const decoded = { ...metadata, custom }
  const etag = readEtag(response)
  return etag !== undefined ? { ...decoded, etag } : decoded
}

/**
 * Replaces a metadata document's user-writable `custom`, encoding it through
 * the codec first (which seals it into an opaque envelope on an encrypted
 * collection).
 *
 * @param context {ClientContext}
 * @param options {object}
 * @param options.metaPath {string}   the `/meta` sub-resource path
 * @param options.codec {Promise<ResourceCodec>}   the resolving codec
 * @param options.custom {ResourceMetadataCustomInput}   the user-writable
 *   properties, as a full replacement
 * @param options.sendEpoch {boolean}   whether the codec's key epoch travels as
 *   a top-level member of this PUT body. True at Collection level, where the
 *   stamp describes the `custom` envelope itself; false at Resource level,
 *   where a Resource's epoch instead stamps its content write via the
 *   `Key-Epoch` header, so an epoch surfaced here is deliberately dropped.
 * @param [options.id] {string}   the resource id to bind the envelope to.
 *   Omitted at Collection level.
 * @param [options.ifMatch] {string}       update only if the `/meta` ETag matches
 * @param [options.ifNoneMatch] {boolean}  write only if no metadata is set
 * @param [options.capability] {IZcap}
 * @returns {Promise<{ etag?: string }>}   the metadata's new ETag
 */
export async function writeMeta(
  context: ClientContext,
  {
    metaPath,
    codec: codecPromise,
    custom,
    sendEpoch,
    id,
    ifMatch,
    ifNoneMatch,
    capability
  }: {
    metaPath: string
    codec: Promise<ResourceCodec>
    custom: ResourceMetadataCustomInput
    sendEpoch: boolean
    id?: string
    ifMatch?: string
    ifNoneMatch?: boolean
    capability?: IZcap
  }
): Promise<{ etag?: string }> {
  const codec = await codecPromise
  const { custom: encoded, epoch } = await codec.encodeMeta(
    id !== undefined ? { custom, id } : { custom }
  )
  const response = await send(context, {
    path: metaPath,
    method: 'PUT',
    capability,
    // The key epoch travels in the body here, not in the `Key-Epoch` header:
    // the header channel stamps a Resource's *content* write, while the
    // Collection metadata stamp describes the `custom` envelope itself and is
    // a top-level member of this PUT body. The server clears the stored stamp
    // when the member is omitted -- which is exactly right on a plaintext
    // collection, whose codec surfaces no epoch.
    json:
      sendEpoch && epoch !== undefined
        ? { custom: encoded, epoch }
        : { custom: encoded },
    headers: writeHeaders({ precondition: { ifMatch, ifNoneMatch } })
  })
  return { etag: readEtag(response) }
}

/**
 * The shared read-then-CAS body of the handles' `setName` / `setTags`: reads
 * the current metadata, merges `patch` over its `custom`, and writes it back
 * pinned to the read's `etag` (when the backend supports `conditional-writes`),
 * so a concurrent metadata write surfaces as `PreconditionFailedError` instead
 * of being silently erased by the full-replacement write.
 *
 * @param handle {object}   the Collection or Resource handle to patch
 * @param patch {ResourceMetadataCustom}   the properties to merge over the
 *   current `custom`
 * @returns {Promise<void>}
 */
export async function patchCustom(
  handle: {
    meta(): Promise<{ custom?: ResourceMetadataCustom; etag?: string } | null>
    setMeta(
      meta: { custom?: ResourceMetadataCustom },
      options: { ifMatch?: string }
    ): Promise<{ etag?: string }>
  },
  patch: ResourceMetadataCustom
): Promise<void> {
  const current = await handle.meta()
  await handle.setMeta(
    { custom: { ...current?.custom, ...patch } },
    { ifMatch: current?.etag }
  )
}

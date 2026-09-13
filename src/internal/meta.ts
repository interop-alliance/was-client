/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Shared `meta` I/O for the Collection and Resource handles. `readMeta` serves
 * both: the two read the same metadata document shape and differ only in the
 * metadata type and the slot the `custom` envelope is bound to.
 *
 * `writeMeta` is the Resource side alone. A Collection's `meta` write is a full
 * replacement of the merged Collection Metadata object -- configuration
 * members included -- so it is composed against a fresh read of that object in
 * `Collection`, and `patchCustom` below drives both handles' read-modify-write
 * helpers through a bounded compare-and-swap.
 */
import { WasServerError } from '../errors.js'
import { compareAndSwap } from './cas.js'
import type { MetaReadSlot, MetaWriteSlot, ResourceCodec } from '../codec.js'
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
 * @param options.slot {MetaReadSlot}   the `/meta` slot being read, for an
 *   encrypting codec's envelope-binding check
 * @param [options.capability] {IZcap}
 * @param [options.onStored] {function}   receives the document as served, with
 *   its validator and its `custom` still undecoded, before the decode -- so a
 *   caller whose next step is a full-replacement write of the same document
 *   can compose that write against the read it just paid for
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
    slot,
    capability,
    onStored
  }: {
    metaPath: string
    codec: Promise<ResourceCodec>
    subject: string
    slot: MetaReadSlot
    capability?: IZcap
    onStored?: (read: {
      metadata: Record<string, unknown>
      etag?: string
    }) => void
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
  const etagBeforeDecode = readEtag(response)
  onStored?.({
    metadata: metadata as Record<string, unknown>,
    ...(etagBeforeDecode !== undefined && { etag: etagBeforeDecode })
  })
  // Decode the user-writable `custom` (decrypting it on an encrypted
  // collection) so callers uniformly see plaintext `{ name, tags }`. The
  // stated slot drives the encrypting codec's binding check: in the
  // Collection slot it refuses a resource-bound envelope served there.
  const custom = await codec.decodeMeta({ custom: metadata.custom }, slot)
  const decoded = { ...metadata, custom }
  return etagBeforeDecode !== undefined
    ? { ...decoded, etag: etagBeforeDecode }
    : decoded
}

/**
 * Replaces a Resource metadata document's user-writable `custom`, encoding it
 * through the codec first (which seals it into an opaque envelope on an
 * encrypted collection). A key epoch the codec surfaces is deliberately
 * dropped: a Resource's epoch stamps its *content* write through the
 * `Key-Epoch` header, not its metadata.
 *
 * @param context {ClientContext}
 * @param options {object}
 * @param options.metaPath {string}   the `meta` sub-resource path
 * @param options.codec {Promise<ResourceCodec>}   the resolving codec
 * @param options.custom {ResourceMetadataCustomInput}   the user-writable
 *   properties, as a full replacement
 * @param options.slot {MetaWriteSlot}   the `meta` slot being written, which
 *   an encrypting codec binds into the envelope
 * @param [options.ifMatch] {string}       update only if the `meta` ETag matches
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
    slot,
    ifMatch,
    ifNoneMatch,
    capability
  }: {
    metaPath: string
    codec: Promise<ResourceCodec>
    custom: ResourceMetadataCustomInput
    slot: MetaWriteSlot
    ifMatch?: string
    ifNoneMatch?: boolean
    capability?: IZcap
  }
): Promise<{ etag?: string }> {
  const codec = await codecPromise
  const { custom: encoded } = await codec.encodeMeta({ custom, slot })
  const response = await send(context, {
    path: metaPath,
    method: 'PUT',
    capability,
    json: { custom: encoded },
    headers: writeHeaders({ precondition: { ifMatch, ifNoneMatch } })
  })
  return { etag: readEtag(response) }
}

/**
 * The shared read-then-CAS body of the handles' `setName` / `setTags`: reads
 * the current metadata, merges `patch` over its `custom`, and writes it back
 * pinned to the read's `etag` (when the backend supports `conditional-writes`),
 * so a concurrent metadata write is rebased on rather than silently erased by
 * the full-replacement write.
 *
 * A lost race (`412`) re-reads and re-applies the patch, up to the shared
 * compare-and-swap attempt limit. A handle whose metadata cannot be read at
 * all patches nothing onto an empty object: the write it drives is the one
 * that refuses (`Collection.setMeta` throws `NotFoundError`), so a masked 404
 * cannot turn a rename into a create. At Collection level that is not a rare event:
 * one `metaVersion` covers the configuration members and the annotations
 * alike, so a concurrent `configure` -- or an epoch rotation -- legitimately
 * invalidates an in-flight annotation write.
 *
 * @param handle {object}   the Collection or Resource handle to patch
 * @param patch {ResourceMetadataCustom}   the properties to merge over the
 *   current `custom`
 * @param operation {string}   what the caller is doing, for the exhaustion
 *   error (e.g. `Metadata update`)
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
  patch: ResourceMetadataCustom,
  operation = 'Metadata update'
): Promise<void> {
  await compareAndSwap<ResourceMetadataCustom>({
    store: {
      read: async () => {
        const current = await handle.meta()
        return {
          value: current?.custom ?? {},
          ...(current?.etag !== undefined && { etag: current.etag })
        }
      },
      replace: async (custom, { ifMatch }) => {
        await handle.setMeta({ custom }, { ifMatch })
      }
    },
    operation,
    mutate: custom => ({ ...custom, ...patch })
  })
}

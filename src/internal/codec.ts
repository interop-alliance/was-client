/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The identity (plaintext) resource codec and the per-collection codec
 * resolver. The identity codec wraps the existing `prepareBody` /
 * `parseResource` helpers so plaintext writes and reads are byte-for-byte
 * unchanged.
 *
 * The resolver splits policy from keys. Policy -- is this collection encrypted,
 * and under which scheme? -- is decided by, in order: (1) a per-handle
 * override, (2) the Collection's declared `encryption` descriptor (read lazily
 * via `readCollectionMetadata`), (3) plaintext. Only once policy says
 * "encrypted" does it ask the injected `EncryptionProvider` (a pure keystore)
 * to build the codec; if the keystore holds no keys it fails closed (throws),
 * never silently downgrading to plaintext. A plaintext-only client (no
 * provider) and an override both short-circuit the read, so only an
 * encryption-capable client reading an undeclared handle pays the one-time
 * round-trip.
 *
 * That round-trip is one `GET` of the Collection Metadata object, which carries
 * the `encryption` descriptor and the persisted index schema together: the
 * descriptor decides the codec, and the codec then decodes the same object's
 * `custom` to recover the schema, with no second read. An override skips the
 * read, so a blinded-index handle opened with one still fetches the object for
 * its schema.
 */
import type { HttpResponse } from '@interop/http-client'
import type { EncodedWrite, ResourceCodec } from '../codec.js'
import type { ClientContext } from './request.js'
import { prepareBody, parseResource } from './content.js'
import {
  asCollectionMetadata,
  readCollectionMetadata,
  storedEncryption,
  unreadableDescriptionError
} from './describe.js'
import type { StoredCollectionMetadata } from './describe.js'
import { readIndexSchema } from './indexSchema.js'
import { Memo } from './memo.js'
import { EncryptionError, NotImplementedError } from '../errors.js'
import type {
  CollectionEncryption,
  CollectionMetadata,
  EncryptionOverride,
  IZcap,
  Json,
  ResourceData,
  ResourceMetadataCustom,
  ResourceMetadataCustomInput
} from '../types.js'

/**
 * The outcome of one codec resolution: the codec itself, plus the collection
 * metadata snapshot the resolution happened to read on the way (the index
 * schema read a blinded-index codec performs). `meta` is absent when the
 * resolution read no metadata at all -- a plaintext or non-indexing codec, or a
 * server with no Collection metadata surface -- and `null` when the read found
 * none (missing or not visible).
 */
export interface CodecResolution {
  codec: ResourceCodec
  meta?: (CollectionMetadata & { etag?: string }) | null
}

/**
 * A per-handle codec cache. Memoizes the in-flight resolution so concurrent
 * callers share one round-trip, but drops it on rejection so a transient
 * failure (e.g. a 500/network error during descriptor discovery) does not
 * permanently poison the handle, and exposes `reset()` for when a handle's
 * encryption state changes (e.g. `Collection.configure()` adds the descriptor).
 *
 * It also carries the metadata snapshot a resolution read, so the caller that
 * paid for that read can reuse it instead of GETting `/meta` a second time.
 * The snapshot is consume-once and initiator-only (see {@link
 * CodecHolder.resolve}): it is a point-in-time copy, and handing it to a later
 * caller would serve metadata another client may have overwritten since.
 */
export class CodecHolder {
  readonly #memo: Memo<CodecResolution>

  /**
   * @param resolve {function}   resolves a fresh codec; re-invoked after a
   *   rejection or a `reset()`, else called at most once
   */
  constructor(resolve: () => Promise<CodecResolution>) {
    this.#memo = new Memo(resolve)
  }

  /**
   * Returns the memoized codec, resolving it on first use. Discards any
   * metadata snapshot the resolution read, so no copy of it outlives the call.
   *
   * @returns {Promise<ResourceCodec>}
   */
  async get(): Promise<ResourceCodec> {
    const resolution = await this.#memo.get()
    resolution.meta = undefined
    return resolution.codec
  }

  /**
   * Returns the memoized codec together with the metadata snapshot its
   * resolution read -- but only when this very call started that resolution.
   * Any other caller (the codec was already resolved, or another call is
   * already resolving it) gets `meta: undefined` and must read `/meta` itself,
   * because a snapshot taken for an earlier operation may already be stale. The
   * snapshot is handed out at most once, and `reset()` drops it.
   *
   * @returns {Promise<CodecResolution>}
   */
  async resolve(): Promise<CodecResolution> {
    const initiated = !this.#memo.started
    const resolution = await this.#memo.get()
    const { codec, meta } = resolution
    // Consume it: whether or not this caller is entitled to the snapshot, no
    // copy of it survives the call.
    resolution.meta = undefined
    return initiated && meta !== undefined ? { codec, meta } : { codec }
  }

  /**
   * Drops any memoized codec so the next `get()` re-resolves.
   *
   * @returns {void}
   */
  reset(): void {
    this.#memo.reset()
  }
}

/**
 * The collection a codec is being resolved for, plus the per-handle inputs that
 * decide it: the encryption override and the handle's bound capability. Shared
 * by {@link collectionCodecHolder} and {@link resolveCodec}, which forwards it
 * through unchanged.
 */
interface CodecTarget {
  spaceId: string
  collectionId: string
  override?: EncryptionOverride
  capability?: IZcap
}

/**
 * Builds the per-handle {@link CodecHolder} for a collection's codec -- the
 * one resolver wiring shared by the `Collection` and standalone `Resource`
 * constructors, so the two cannot drift.
 *
 * @param context {ClientContext}
 * @param options {object}
 * @param options.spaceId {string}
 * @param options.collectionId {string}
 * @param [options.override] {EncryptionOverride}   per-handle override
 * @param [options.capability] {IZcap}   the handle's bound capability
 * @returns {CodecHolder}
 */
export function collectionCodecHolder(
  context: ClientContext,
  options: CodecTarget
): CodecHolder {
  return new CodecHolder(() => resolveCodec(context, options))
}

/**
 * The default codec: passes plaintext through unchanged. `encode` echoes the
 * caller's `id` (so `put(id, ...)` is a `PUT` and `add(...)`, with no id, stays
 * a server-minting `POST`) and reuses `prepareBody` -- including the
 * filename-extension content-type guess when an id is present. `decode` reuses
 * `parseResource`. `encodeMeta` / `decodeMeta` are the identity transform, so
 * metadata round-trips as server-visible plaintext byte-for-byte.
 */
export const identityCodec: ResourceCodec = {
  async encode({
    id,
    data,
    contentType
  }: {
    id?: string
    data: ResourceData
    contentType?: string
  }): Promise<EncodedWrite> {
    const prepared = prepareBody(data, { contentType, filename: id })
    return { id, ...prepared }
  },

  // Deliberately narrower than the seam's `ResponseLike`: a byte-exact
  // pass-through needs the full response stream surface (blob, content-type),
  // and core's read path only ever hands it a real HttpResponse.
  async decode(response: HttpResponse): Promise<Json | Blob> {
    return (await parseResource(response)) as Json | Blob
  },

  async encodeMeta({
    custom
  }: {
    custom: ResourceMetadataCustomInput
  }): Promise<{ custom: object }> {
    return { custom }
  },

  async decodeMeta(stored: {
    custom?: unknown
  }): Promise<ResourceMetadataCustom> {
    return (stored.custom ?? {}) as ResourceMetadataCustom
  }
}

/**
 * Resolves the codec for a collection by deciding policy (override > descriptor
 * > plaintext) and then, when encrypted, building the encrypting codec from the
 * keystore. Fails closed: a collection declared encrypted (by override or
 * descriptor) for which no codec can be built throws {@link EncryptionError}
 * rather than falling back to {@link identityCodec}.
 *
 * @param context {ClientContext}
 * @param options {object}
 * @param options.spaceId {string}
 * @param options.collectionId {string}
 * @param [options.override] {EncryptionOverride}   per-handle override; wins
 *   over the descriptor and skips the descriptor read
 * @param [options.capability] {IZcap}   the handle's bound capability, used for
 *   the descriptor-discovery describe (which happens only when there is no
 *   override and the client has a keystore)
 * @returns {Promise<CodecResolution>}   the codec, plus the metadata snapshot
 *   the index-schema read produced when there was one
 */
export async function resolveCodec(
  context: ClientContext,
  { spaceId, collectionId, override, capability }: CodecTarget
): Promise<CodecResolution> {
  // 1. A per-handle override wins and skips the descriptor read.
  if (override !== undefined) {
    if (override === 'plaintext') {
      return { codec: identityCodec }
    }
    // An override is a `CollectionEncryption` descriptor (plus optional inline
    // keys), so it is forwarded whole: the provider's `codecFor` routes on the
    // descriptor's epoch roster and refuses an override without one
    // fail-closed, so dropping the descriptor here would break every read and
    // write.
    const { codec } = await buildEncryptingCodec(context, {
      spaceId,
      collectionId,
      scheme: override.scheme,
      keys: override.keys,
      encryption: override
    })
    // The override skipped the Collection Metadata read, so a searchable
    // collection's persisted index schema is fetched here.
    const meta = await loadIndexSchema(context, {
      spaceId,
      collectionId,
      capability,
      codec
    })
    return meta !== undefined ? { codec, meta } : { codec }
  }
  // 2. A plaintext-only client (no keystore) never encrypts; no round-trip.
  if (!context.encryption) {
    return { codec: identityCodec }
  }
  // 3. Otherwise the Collection's declared `encryption` descriptor decides -- but
  // only if we could actually read the Collection Metadata object. An
  // unreadable object (a resource-scoped capability cannot GET it, and WAS
  // masks that as a 404) is ambiguous: it is indistinguishable from "absent",
  // so an encryption-capable client fails closed rather than silently
  // downgrading to plaintext and writing the caller's secret as server-visible
  // plaintext into a possibly-encrypted collection.
  const read = await readCollectionMetadata(context, {
    spaceId,
    collectionId,
    capability
  })
  if (read === null) {
    throw unreadableDescriptionError({
      operation:
        `determine whether collection ${spaceId}/${collectionId} is ` +
        'encrypted',
      consequence:
        'an encryption-capable client refuses to fall back to plaintext',
      advice:
        'Pass an explicit per-handle encryption override -- ' +
        "`{ encryption: 'plaintext' }` to write plaintext, or a scheme/keys " +
        'override to encrypt.',
      ErrorClass: EncryptionError
    })
  }
  const declared = storedEncryption(read.metadata)
  const { codec } = declared
    ? await buildEncryptingCodec(context, {
        spaceId,
        collectionId,
        scheme: declared.scheme,
        encryption: declared
      })
    : { codec: identityCodec }
  // The read that decided policy IS the Collection Metadata object, so it is
  // also the index schema and the `meta()` answer: decode its `custom` with the
  // codec just built and hand the snapshot on, rather than reading the same
  // document again. A `custom` this reader cannot open is not the resolution's
  // business -- only `meta()` and the search paths need it -- so the decode
  // failure leaves the schema empty and the snapshot absent instead of failing
  // every operation on the handle.
  const meta = await snapshotFrom({ read, codec })
  return meta !== undefined ? { codec, meta } : { codec }
}

/**
 * Builds the codec a descriptor names, for a write that states the descriptor
 * itself rather than discovering it from stored state: the identity codec when
 * there is no descriptor, and the keystore's codec when there is. Resolves
 * `null` when this client cannot build that codec (no keystore, no keys, or an
 * unhandled scheme) -- a caller that must not guess treats `null` as its own
 * refusal, since nothing here is stored state to fail closed on.
 *
 * @param context {ClientContext}
 * @param options {object}
 * @param options.spaceId {string}
 * @param options.collectionId {string}
 * @param [options.descriptor] {CollectionEncryption}   the descriptor the write
 *   declares; absent means plaintext
 * @returns {Promise<ResourceCodec | null>}
 */
export async function codecForDescriptor(
  context: ClientContext,
  {
    spaceId,
    collectionId,
    descriptor
  }: {
    spaceId: string
    collectionId: string
    descriptor?: CollectionEncryption
  }
): Promise<ResourceCodec | null> {
  if (descriptor === undefined) {
    return identityCodec
  }
  if (!context.encryption) {
    return null
  }
  const codec = await context.encryption.codecFor({
    spaceId,
    collectionId,
    scheme: descriptor.scheme,
    encryption: descriptor
  })
  return codec ?? null
}

/**
 * Turns the Collection Metadata object a resolution read into the snapshot the
 * resolution carries: `custom` decoded through the codec just built (an opaque
 * envelope on an encrypted collection), and the codec's persisted index schema
 * installed from it along the way.
 *
 * A `custom` the decode refuses -- a reader removed from the collection whose
 * epoch key no longer unwraps it, an envelope bound to another slot, a
 * plaintext object where an envelope belongs -- resolves `undefined` rather
 * than throwing. The schema then stays empty (a search on an undeclared
 * attribute still fails loudly at `find()`), and the operations that do not
 * need `custom` keep working; a `meta()` reads and decodes for itself and is
 * the call that surfaces the refusal.
 *
 * @param options {object}
 * @param options.read {object}   the stored object and its validator
 * @param options.codec {ResourceCodec}
 * @returns {Promise<(CollectionMetadata & { etag?: string }) | undefined>}
 */
async function snapshotFrom({
  read,
  codec
}: {
  read: { metadata: StoredCollectionMetadata; etag?: string }
  codec: ResourceCodec
}): Promise<(CollectionMetadata & { etag?: string }) | undefined> {
  let custom
  try {
    // The stated slot drives the encrypting codec's binding check: in the
    // Collection slot it refuses a resource-bound envelope served there.
    custom = await codec.decodeMeta(
      { custom: read.metadata.custom },
      { kind: 'collection' }
    )
  } catch {
    return undefined
  }
  codec.indexing?.applySchema(readIndexSchema(custom))
  return {
    ...asCollectionMetadata(read.metadata),
    custom,
    ...(read.etag !== undefined && { etag: read.etag })
  }
}

/**
 * Builds the encrypting codec for a collection known to be encrypted, failing
 * closed: throws {@link EncryptionError} when no keystore is configured or it
 * returns no codec (no keys / unhandled scheme), so an encrypted collection is
 * never silently read/written as plaintext.
 *
 * @param context {ClientContext}
 * @param options {object}
 * @param options.spaceId {string}
 * @param options.collectionId {string}
 * @param options.scheme {string}
 * @param [options.encryption] {CollectionEncryption}   the descriptor, passed
 *   whole to the provider
 * @param [options.keys] {unknown}   override-supplied key material
 * @returns {Promise<CodecResolution>}
 */
async function buildEncryptingCodec(
  context: ClientContext,
  {
    spaceId,
    collectionId,
    scheme,
    encryption,
    keys
  }: {
    spaceId: string
    collectionId: string
    scheme: string
    encryption?: CollectionEncryption
    keys?: unknown
  }
): Promise<CodecResolution> {
  const where = `${spaceId}/${collectionId}`
  if (!context.encryption) {
    throw new EncryptionError(
      `Collection ${where} is encrypted (scheme "${scheme}") but this client ` +
        'has no encryption provider. Construct the WasClient with an ' +
        '`encryption` provider (see @interop/was-client/edv).'
    )
  }
  const codec = await context.encryption.codecFor({
    spaceId,
    collectionId,
    scheme,
    encryption,
    keys
  })
  if (!codec) {
    throw new EncryptionError(
      `Collection ${where} is encrypted (scheme "${scheme}") but this client ` +
        'holds no keys for it (or does not handle the scheme). Supply keys via ' +
        'your keystore (resolveKeys) or a per-handle encryption override.'
    )
  }
  return { codec }
}

/**
 * Loads the collection's persisted index schema onto a codec built from a
 * per-handle encryption override -- the one path that skipped the Collection
 * Metadata read, so the schema is not already in hand. A no-op for a codec with
 * no search capability, which is every codec on a collection whose descriptor
 * declares no blinding key.
 *
 * The schema is discovered rather than declared per app: it is the reason
 * declarations are persisted at all, so a reader that did not create the
 * collection can learn what is searchable. It is read once per codec
 * resolution, which means it is as fresh as the handle -- a `declareIndex` on
 * this handle updates it in place, and the codec is re-resolved (and the schema
 * re-read) whenever `CodecHolder.reset()` fires.
 *
 * A server with no Collection metadata surface, and a collection whose metadata
 * is not visible to this capability, both leave the schema empty rather than
 * failing the resolution: neither says the collection is broken, and every
 * search on an undeclared attribute still fails loudly at `find()`.
 *
 * The decoded metadata is returned so the caller that paid for the read can
 * hand it to a `meta()` that would otherwise repeat it -- it is exactly what
 * `Collection.meta()` produces, decrypted `custom` and `etag` included.
 *
 * @param context {ClientContext}
 * @param options {object}
 * @param options.spaceId {string}
 * @param options.collectionId {string}
 * @param [options.capability] {IZcap}
 * @param options.codec {ResourceCodec}   the codec to install the schema on
 * @returns {Promise<(CollectionMetadata & { etag?: string }) | null | undefined>}
 *   the metadata read, `null` when there is none to read, and `undefined` when
 *   no read happened at all
 */
async function loadIndexSchema(
  context: ClientContext,
  {
    spaceId,
    collectionId,
    capability,
    codec
  }: {
    spaceId: string
    collectionId: string
    capability?: IZcap
    codec: ResourceCodec
  }
): Promise<(CollectionMetadata & { etag?: string }) | null | undefined> {
  if (!codec.indexing) {
    return undefined
  }
  let read
  try {
    read = await readCollectionMetadata(context, {
      spaceId,
      collectionId,
      capability
    })
  } catch (err) {
    if (err instanceof NotImplementedError) {
      return undefined
    }
    throw err
  }
  if (read === null) {
    return null
  }
  return snapshotFrom({ read, codec })
}

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
 * via `describeCollection`), (3) plaintext. Only once policy says "encrypted"
 * does it ask the injected `EncryptionProvider` (a pure keystore) to build the
 * codec; if the keystore holds no keys it fails closed (throws), never silently
 * downgrading to plaintext. A plaintext-only client (no provider) and an
 * override both short-circuit the descriptor read, so only an
 * encryption-capable client reading an undeclared handle pays the one-time
 * `describe()` round-trip.
 */
import type { HttpResponse } from '@interop/http-client'
import type { EncodedWrite, ResourceCodec } from '../codec.js'
import type { ClientContext } from './request.js'
import { prepareBody, parseResource } from './content.js'
import { describeCollection, unreadableDescriptionError } from './describe.js'
import { readIndexSchema } from './indexSchema.js'
import { collectionMeta } from './paths.js'
import { send } from './request.js'
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
 * A per-handle codec cache. Memoizes the in-flight resolution so concurrent
 * callers share one round-trip, but drops it on rejection so a transient
 * failure (e.g. a 500/network error during descriptor discovery) does not
 * permanently poison the handle, and exposes `reset()` for when a handle's
 * encryption state changes (e.g. `Collection.configure()` adds the descriptor).
 */
export class CodecHolder {
  #promise?: Promise<ResourceCodec>
  readonly #resolve: () => Promise<ResourceCodec>

  /**
   * @param resolve {function}   resolves a fresh codec; re-invoked after a
   *   rejection or a `reset()`, else called at most once
   */
  constructor(resolve: () => Promise<ResourceCodec>) {
    this.#resolve = resolve
  }

  /**
   * Returns the memoized codec, resolving it on first use.
   *
   * @returns {Promise<ResourceCodec>}
   */
  get(): Promise<ResourceCodec> {
    if (this.#promise) {
      return this.#promise
    }
    const promise = this.#resolve()
    // Memoize the in-flight promise so concurrent callers share one round-trip,
    // but drop it on rejection so a transient failure does not permanently
    // poison the handle. The identity guard avoids clobbering a newer promise.
    this.#promise = promise
    promise.catch((): void => {
      if (this.#promise === promise) {
        this.#promise = undefined
      }
    })
    return promise
  }

  /**
   * Drops any memoized codec so the next `get()` re-resolves.
   *
   * @returns {void}
   */
  reset(): void {
    this.#promise = undefined
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
 * @returns {Promise<ResourceCodec>}
 */
export async function resolveCodec(
  context: ClientContext,
  { spaceId, collectionId, override, capability }: CodecTarget
): Promise<ResourceCodec> {
  // 1. A per-handle override wins and skips the descriptor read.
  if (override !== undefined) {
    if (override === 'plaintext') {
      return identityCodec
    }
    return buildEncryptingCodec(context, {
      spaceId,
      collectionId,
      scheme: override.scheme,
      keys: override.keys,
      capability,
      // A full `CollectionEncryption` descriptor is itself a valid override
      // (Space.createCollection pre-seeds exactly this). Forward the whole
      // override as the `encryption` descriptor so an epoch-bearing override
      // resolves the epoch codec -- the provider's `codecFor` routes solely
      // on the descriptor's epoch roster and refuses an override without one
      // fail-closed, so dropping it here would break every read and write.
      encryption: override as CollectionEncryption
    })
  }
  // 2. A plaintext-only client (no keystore) never encrypts; no round-trip.
  if (!context.encryption) {
    return identityCodec
  }
  // 3. Otherwise the Collection's declared `encryption` descriptor decides -- but
  // only if we could actually read the description. An unreadable description
  // (a resource-scoped capability cannot GET the collection description, and
  // WAS masks that as a 404) is ambiguous: it is indistinguishable from
  // "absent", so an encryption-capable client fails closed rather than
  // silently downgrading to plaintext and writing the caller's secret as
  // server-visible plaintext into a possibly-encrypted collection.
  const description = await describeCollection(context, {
    spaceId,
    collectionId,
    capability
  })
  if (description === null) {
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
  if (!description.encryption) {
    return identityCodec
  }
  return buildEncryptingCodec(context, {
    spaceId,
    collectionId,
    scheme: description.encryption.scheme,
    encryption: description.encryption,
    capability
  })
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
 * @param [options.keys] {unknown}   override-supplied key material
 * @param [options.capability] {IZcap}   the handle's bound capability, used for
 *   the index-schema read
 * @returns {Promise<ResourceCodec>}
 */
async function buildEncryptingCodec(
  context: ClientContext,
  {
    spaceId,
    collectionId,
    scheme,
    encryption,
    keys,
    capability
  }: {
    spaceId: string
    collectionId: string
    scheme: string
    encryption?: CollectionEncryption
    keys?: unknown
    capability?: IZcap
  }
): Promise<ResourceCodec> {
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
  await loadIndexSchema(context, { spaceId, collectionId, capability, codec })
  return codec
}

/**
 * Loads the collection's persisted index schema onto a freshly-built codec, so
 * writes through it emit index tokens for the declared attributes and searches
 * can be built for them. A no-op for a codec with no search capability -- which
 * is every codec on a collection whose descriptor declares no blinding key, so
 * an ordinary encrypted collection pays no round-trip here.
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
 * @param context {ClientContext}
 * @param options {object}
 * @param options.spaceId {string}
 * @param options.collectionId {string}
 * @param [options.capability] {IZcap}
 * @param options.codec {ResourceCodec}   the codec to install the schema on
 * @returns {Promise<void>}
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
): Promise<void> {
  const { indexing } = codec
  if (!indexing) {
    return
  }
  let response
  try {
    response = await send(context, {
      path: collectionMeta(spaceId, collectionId),
      method: 'GET',
      capability,
      read: true
    })
  } catch (err) {
    if (err instanceof NotImplementedError) {
      return
    }
    throw err
  }
  if (response === null || response.data === undefined) {
    return
  }
  const { custom } = response.data as CollectionMetadata
  indexing.applySchema(readIndexSchema(await codec.decodeMeta({ custom })))
}

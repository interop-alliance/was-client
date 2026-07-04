/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The identity (plaintext) resource codec and the per-collection codec
 * resolver. The identity codec wraps the existing `prepareBody` / `parseResource`
 * helpers so plaintext writes and reads are byte-for-byte unchanged.
 *
 * The resolver splits policy from keys. Policy -- is this collection encrypted,
 * and under which scheme? -- is decided by, in order: (1) a per-handle override,
 * (2) the Collection's declared `encryption` marker (read lazily via
 * `describeCollection`), (3) plaintext. Only once policy says "encrypted" does it
 * ask the injected `EncryptionProvider` (a pure keystore) to build the codec;
 * if the keystore holds no keys it fails closed (throws), never silently
 * downgrading to plaintext. A plaintext-only client (no provider) and an
 * override both short-circuit the marker read, so only an encryption-capable
 * client reading an undeclared handle pays the one-time `describe()` round-trip.
 */
import type { HttpResponse } from '@interop/http-client'
import type { EncodedWrite, ResourceCodec } from '../codec.js'
import type { ClientContext } from './request.js'
import { prepareBody, parseResource } from './content.js'
import { describeCollection } from './describe.js'
import { EncryptionError } from '../errors.js'
import type {
  EncryptionOverride,
  IZcap,
  Json,
  ResourceData,
  ResourceMetadataCustom
} from '../types.js'

/**
 * A per-handle codec cache. Memoizes the in-flight resolution so concurrent
 * callers share one round-trip, but drops it on rejection so a transient
 * failure (e.g. a 500/network error during marker discovery) does not
 * permanently poison the handle, and exposes `reset()` for when a handle's
 * encryption state changes (e.g. `Collection.configure()` adds the marker).
 */
export class CodecHolder {
  private _promise?: Promise<ResourceCodec>
  private readonly _resolve: () => Promise<ResourceCodec>

  /**
   * @param resolve {function}   resolves a fresh codec; re-invoked after a
   *   rejection or a `reset()`, else called at most once
   */
  constructor(resolve: () => Promise<ResourceCodec>) {
    this._resolve = resolve
  }

  /**
   * Returns the memoized codec, resolving it on first use.
   *
   * @returns {Promise<ResourceCodec>}
   */
  get(): Promise<ResourceCodec> {
    if (this._promise) {
      return this._promise
    }
    const promise = this._resolve()
    // Memoize the in-flight promise so concurrent callers share one round-trip,
    // but drop it on rejection so a transient failure does not permanently
    // poison the handle. The identity guard avoids clobbering a newer promise.
    this._promise = promise
    promise.catch((): void => {
      if (this._promise === promise) {
        this._promise = undefined
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
    this._promise = undefined
  }
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
  metadataMode: 'plaintext',

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
    return {
      id,
      json: prepared.json,
      body: prepared.body,
      contentType: prepared.contentType
    }
  },

  async decode(response: HttpResponse): Promise<Json | Blob> {
    return (await parseResource(response)) as Json | Blob
  },

  async encodeMeta({
    custom
  }: {
    custom: ResourceMetadataCustom
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
 * Resolves the codec for a collection by deciding policy (override > marker >
 * plaintext) and then, when encrypted, building the encrypting codec from the
 * keystore. Fails closed: a collection declared encrypted (by override or
 * marker) for which no codec can be built throws {@link EncryptionError} rather
 * than falling back to {@link identityCodec}.
 *
 * @param context {ClientContext}
 * @param options {object}
 * @param options.spaceId {string}
 * @param options.collectionId {string}
 * @param [options.override] {EncryptionOverride}   per-handle override; wins
 *   over the marker and skips the marker read
 * @param [options.capability] {IZcap}   the handle's bound capability, used for
 *   the marker-discovery describe (which happens only when there is no
 *   override and the client has a keystore)
 * @returns {Promise<ResourceCodec>}
 */
export async function resolveCodec(
  context: ClientContext,
  {
    spaceId,
    collectionId,
    override,
    capability
  }: {
    spaceId: string
    collectionId: string
    override?: EncryptionOverride
    capability?: IZcap
  }
): Promise<ResourceCodec> {
  // 1. A per-handle override wins and skips the marker read.
  if (override !== undefined) {
    if (override === 'plaintext') {
      return identityCodec
    }
    return buildEncryptingCodec(context, {
      spaceId,
      collectionId,
      scheme: override.scheme,
      keys: override.keys
    })
  }
  // 2. A plaintext-only client (no keystore) never encrypts; no round-trip.
  if (!context.encryption) {
    return identityCodec
  }
  // 3. Otherwise the Collection's declared `encryption` marker decides -- but
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
    throw new EncryptionError(
      `Cannot determine whether collection ${spaceId}/${collectionId} is ` +
        'encrypted: its description is not readable (a resource-scoped ' +
        'capability cannot read the collection description, and WAS returns ' +
        '404 for both not-found and unauthorized). Refusing to fall back to ' +
        'plaintext. Pass an explicit per-handle encryption override -- ' +
        "`{ encryption: 'plaintext' }` to write plaintext, or a scheme/keys " +
        'override to encrypt.'
    )
  }
  if (!description.encryption) {
    return identityCodec
  }
  return buildEncryptingCodec(context, {
    spaceId,
    collectionId,
    scheme: description.encryption.scheme
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
 * @returns {Promise<ResourceCodec>}
 */
async function buildEncryptingCodec(
  context: ClientContext,
  {
    spaceId,
    collectionId,
    scheme,
    keys
  }: { spaceId: string; collectionId: string; scheme: string; keys?: unknown }
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
    keys
  })
  if (!codec) {
    throw new EncryptionError(
      `Collection ${where} is encrypted (scheme "${scheme}") but this client ` +
        'holds no keys for it (or does not handle the scheme). Supply keys via ' +
        'your keystore (resolveKeys) or a per-handle encryption override.'
    )
  }
  return codec
}

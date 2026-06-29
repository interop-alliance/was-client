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
 * (2) the Collection's declared `encryption` marker (read lazily via the
 * `readMarker` thunk), (3) plaintext. Only once policy says "encrypted" does it
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
import { EncryptionError } from '../errors.js'
import type {
  CollectionEncryption,
  EncryptionOverride,
  Json
} from '../types.js'

/**
 * The outcome of a marker read. The distinction is load-bearing: `readable:
 * false` means the Collection Description could not be read at all (a null/404,
 * which WAS also returns for an *unauthorized* read -- e.g. a resource-scoped
 * capability cannot GET the collection description), which is indistinguishable
 * from "absent". That ambiguity must NOT be collapsed into "plaintext", or an
 * encryption-capable client would fail open and write server-visible plaintext
 * into an encrypted collection. `readable: true` means the description was read;
 * its `encryption` is the declared marker (absent for a genuine plaintext
 * collection).
 */
export type MarkerReadResult =
  { readable: false } | { readable: true; encryption?: CollectionEncryption }

/**
 * The default codec: passes plaintext through unchanged. `encode` echoes the
 * caller's `id` (so `put(id, ...)` is a `PUT` and `add(...)`, with no id, stays
 * a server-minting `POST`) and reuses `prepareBody` -- including the
 * filename-extension content-type guess when an id is present. `decode` reuses
 * `parseResource`.
 */
export const identityCodec: ResourceCodec = {
  allowsServerMetadata: true,

  async encode({
    id,
    data,
    contentType
  }: {
    id?: string
    data: Json | Blob | Uint8Array
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
 * @param options.readMarker {function}   lazily reads the Collection's declared
 *   `encryption` marker, distinguishing a readable description (with or without
 *   a marker) from an unreadable one (see {@link MarkerReadResult}); called only
 *   when there is no override and the client has a keystore
 * @returns {Promise<ResourceCodec>}
 */
export async function resolveCodec(
  context: ClientContext,
  {
    spaceId,
    collectionId,
    override,
    readMarker
  }: {
    spaceId: string
    collectionId: string
    override?: EncryptionOverride
    readMarker: () => Promise<MarkerReadResult>
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
  // 3. Otherwise the Collection's declared marker decides -- but only if we
  // could actually read it. An unreadable description (a resource-scoped
  // capability cannot GET the collection description, and WAS masks that as a
  // 404) is ambiguous: it is indistinguishable from "absent", so an
  // encryption-capable client fails closed rather than silently downgrading to
  // plaintext and writing the caller's secret as server-visible plaintext into
  // a possibly-encrypted collection.
  const marker = await readMarker()
  if (!marker.readable) {
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
  if (!marker.encryption) {
    return identityCodec
  }
  return buildEncryptingCodec(context, {
    spaceId,
    collectionId,
    scheme: marker.encryption.scheme
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
